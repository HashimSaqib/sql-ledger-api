#=====================================================================
# SQL-Ledger ERP
# Copyright (C) 2006
#
#  Author: DWS Systems Inc.
#     Web: http://www.sql-ledger.com
#
#======================================================================
#
# General ledger backend code
#
#======================================================================

package GL;

use DateTime;
use JSON::PP qw(decode_json encode_json);


sub delete_transaction {
  my ($self, $myconfig, $form) = @_;

  # connect to database
  my $dbh = $form->dbconnect_noauto($myconfig);

  $form->{id} *= 1;

  # accrual GL entries are managed through their source AR/AP — refuse direct delete
  my ($accrual_source) = $dbh->selectrow_array(qq|SELECT accrual_source FROM gl WHERE id = $form->{id}|);
  if ($accrual_source) {
    $dbh->disconnect;
    $form->error("Accrual GL entry $form->{id} cannot be deleted directly. Edit the source $accrual_source to change or remove the accrual.");
  }

  my %audittrail = ( tablename  => 'gl',
                     reference  => $form->{reference},
		     formname   => 'transaction',
		     action     => 'deleted',
		     id         => $form->{id} );

  $form->audittrail($dbh, "", \%audittrail);

  if ($form->{batchid} *= 1) {
    $query = qq|SELECT sum(amount)
		FROM acc_trans
		WHERE trans_id = $form->{id}
		AND amount < 0|;
    my ($mount) = $dbh->selectrow_array($query);
    
    $amount = $form->round_amount($amount, $form->{precision});
    $form->update_balance($dbh,
			  'br',
			  'amount',
			  qq|id = $form->{batchid}|,
			  $amount);
    
    $query = qq|DELETE FROM vr WHERE trans_id = $form->{id}|;
    $dbh->do($query) || $form->dberror($query);
  }
  
  $query = qq|DELETE FROM gl WHERE id = $form->{id}|;
  $dbh->do($query) || $form->dberror($query);

  $query = qq|SELECT trans_id FROM pay_trans
              WHERE glid = $form->{id}|;
  ($form->{apid}) = $dbh->selectrow_array($query);
  
  my $id;
  for $id (qw(id apid)) {
    for (qw(acc_trans dpt_trans yearend pay_trans status)) {
      if ($form->{$id} *= 1) {
	$query = qq|DELETE FROM $_ WHERE trans_id = $form->{$id}|;
	$dbh->do($query) || $form->dberror($query);
      }
    }
  }
  
  for (qw(recurring recurringemail recurringprint)) {
    $query = qq|DELETE FROM $_ WHERE id = $form->{id}|;
    $dbh->do($query) || $form->dberror($query);
  }
  # delete bank transaction distribution
  $query = qq|DELETE FROM transaction_distribution WHERE trans_id = $form->{id}|;
  $dbh->do($query) || $form->dberror($query);
  $form->delete_references($dbh);

  $form->remove_locks($myconfig, $dbh, 'gl');

  # commit and redirect
  my $rc = $dbh->commit;
  $dbh->disconnect;
  
  $rc;
  
}


sub post_transaction {
  my ($self, $myconfig, $form, $dbh) = @_;

  my $project_id;
  my $department_id;
  my $i;
  my $keepcleared;

  my $disconnect = ($dbh) ? 0 : 1;

  # connect to database, turn off AutoCommit
  if (! $dbh) {
    $dbh = $form->dbconnect_noauto($myconfig);
  }

  my $query;
  my $sth;

  # accrual GL entries are managed through their source AR/AP — refuse direct edits
  # (allow the internal accrual flow itself by passing $form->{_accrual_internal})
  if (($form->{id} || 0) * 1 && !$form->{_accrual_internal}) {
    my ($accrual_source) = $dbh->selectrow_array(qq|SELECT accrual_source FROM gl WHERE id = |.($form->{id} * 1));
    if ($accrual_source) {
      $dbh->rollback if $disconnect;
      $dbh->disconnect if $disconnect;
      $form->error("Accrual GL entry $form->{id} cannot be edited directly. Edit the source $accrual_source to change or remove the accrual.");
    }
  }
  
  my $approved = ($form->{pending}) ? '0' : '1';
  my $action = ($approved) ? 'posted' : 'saved';

  my %defaults = $form->get_defaults($dbh, \@{['precision']});
  $form->{precision} = $defaults{precision};

  if ($form->{id} *= 1) {
    $keepcleared = 1;
    
    if ($form->{batchid} *= 1) {
      $query = qq|SELECT * FROM vr
		  WHERE trans_id = $form->{id}|;
      $sth = $dbh->prepare($query) || $form->dberror($query);
      $sth->execute || $form->dberror($query);
      $ref = $sth->fetchrow_hashref(NAME_lc);
      $form->{voucher}{transaction} = $ref;
      $sth->finish;
     
      $query = qq|SELECT SUM(amount)
		  FROM acc_trans
		  WHERE amount < 0
		  AND trans_id = $form->{id}|;
      ($amount) = $dbh->selectrow_array($query);
      
      $form->update_balance($dbh,
			    'br',
			    'amount',
			    qq|id = $form->{batchid}|,
			    $amount);
      
      # delete voucher
      $query = qq|DELETE FROM vr
                  WHERE trans_id = $form->{id}|;
      $dbh->do($query) || $form->dberror($query);

    }

    $query = qq|SELECT id FROM gl
                WHERE id = $form->{id}|;
    ($form->{id}) = $dbh->selectrow_array($query);

    if ($form->{id}) {
      # delete individual transactions
      for (qw(acc_trans dpt_trans)) {
	$query = qq|DELETE FROM $_ WHERE trans_id = $form->{id}|;
	$dbh->do($query) || $form->dberror($query);
      }
    }
  }

  if (!$form->{id}) {
   
    my $uid = localtime;
    $uid .= $$;

    $query = qq|INSERT INTO gl (reference, employee_id, approved)
                VALUES ('$uid', (SELECT id FROM employee
		                 WHERE login = '$form->{login}'),
		'$approved')|;
    $dbh->do($query) || $form->dberror($query);

    $query = qq|SELECT id FROM gl
                WHERE reference = '$uid'|;
    ($form->{id}) = $dbh->selectrow_array($query);
  }
  
  (undef, $department_id) = split /--/, $form->{department};
  $department_id *= 1;

  $form->{reference} = $form->update_defaults($myconfig, 'glnumber', $dbh) unless $form->{reference};

  $form->{currency} ||= $form->{defaultcurrency};

  $form->{exchangerate} = $form->parse_amount($myconfig, $form->{exchangerate}) || 1;

  $form->{taxincluded} = ( $form->{taxincluded} && $form->{taxincluded} !~ /^(0|f|false)$/i ) ? 1 : 0;
  my $taxincluded_sql = $form->{taxincluded} ? "'true'" : "'false'";

  $query = qq|UPDATE gl SET 
	      reference = |.$dbh->quote($form->{reference}).qq|,
	      description = |.$dbh->quote($form->{description}).qq|,
	      notes = |.$dbh->quote($form->{notes}).qq|,
	      transdate = '$form->{transdate}',
	      department_id = $department_id,
	      curr = '$form->{currency}',
	      exchangerate = $form->{exchangerate},
	      taxincluded = $taxincluded_sql
	      WHERE id = $form->{id}|;
  $dbh->do($query) || $form->dberror($query);

  if ($department_id) {
    $query = qq|INSERT INTO dpt_trans (trans_id, department_id)
                VALUES ($form->{id}, $department_id)|;
    $dbh->do($query) || $form->dberror($query);
  }
  
  # update exchangerate
  $form->update_exchangerate($dbh, $form->{currency}, $form->{transdate}, $form->{exchangerate});

  my $amount;
  my $debit;
  my $credit;
  my $linetaxamount;
  my $cleared = 'NULL';
  my $bramount = 0;
  my %dist_amounts;
  # insert acc_trans transactions
  for $i (1 .. $form->{rowcount}) {

    $amount = 0;
    
    $debit = $form->parse_amount($myconfig, $form->{"debit_$i"});
    $credit = $form->parse_amount($myconfig, $form->{"credit_$i"});
    $linetaxamount = $form->parse_amount($myconfig, $form->{"linetaxamount_$i"});
    $linetaxamount *= 1;

    # extract accno
    ($accno) = split(/--/, $form->{"accno_$i"});
    ( $tax_accno, $null ) = split /--/, $form->{"tax_$i"};
    ($tax_chart_id) = $dbh->selectrow_array("SELECT id FROM chart WHERE accno = '$tax_accno'");
    $tax_chart_id *= 1;

    if ($credit) {
      $amount = $credit;
      $bramount += $form->round_amount($amount * $form->{exchangerate}, $form->{precision});
    }
    if ($debit) {
      $amount = $debit * -1;
    }
    # If taxincluded, subtract tax from the line amount before storing in acc_trans
    if ($form->{taxincluded} && $tax_chart_id && $linetaxamount) {
      if ($credit) {
        $amount = $form->round_amount($credit - $linetaxamount, $form->{precision});
      } else {
        $amount = -$form->round_amount($debit - $linetaxamount, $form->{precision});
      }
    }
    if ($form->{"source_$i"}) {
      my $abs = abs($amount);
      $dist_amounts{$form->{"source_$i"}} = $abs
        if $abs > ($dist_amounts{$form->{"source_$i"}} || 0);
    }
    # add the record
    (undef, $project_id) = split /--/, $form->{"projectnumber_$i"};
    $project_id ||= 'NULL';
    
    if ($keepcleared) {
      $cleared = $form->dbquote($form->{"cleared_$i"}, SQL_DATE);
    }

    if ($form->{"fx_transaction_$i"} *= 1) {
      $cleared = $form->dbquote($form->{transdate}, SQL_DATE);
    }
    
    if ($amount || $form->{"source_$i"} || $form->{"memo_$i"} || ($project_id ne 'NULL')) {

      $query = qq|INSERT INTO acc_trans (trans_id, chart_id, amount, transdate,
		  source, fx_transaction, project_id, memo, cleared, approved, tax_chart_id, linetaxamount)
      VALUES
		  ($form->{id}, (SELECT id
				 FROM chart
				 WHERE accno = '$accno'),
		   $amount, '$form->{transdate}', |.
		   $dbh->quote($form->{"source_$i"}) .qq|,
		  '$form->{"fx_transaction_$i"}',
		  $project_id, |.$dbh->quote($form->{"memo_$i"}).qq|,
		  $cleared, '$approved', $tax_chart_id, $linetaxamount)|;
      $dbh->do($query) || $form->dberror($query);

      # For each linetax with a tax account and linetaxamount, add an additional acc_trans line for the tax
      if ($tax_chart_id && $linetaxamount) {
        my $tax_line_amount = $credit ? $linetaxamount : -$linetaxamount;
        $query = qq|INSERT INTO acc_trans (trans_id, chart_id, amount, transdate,
		  source, fx_transaction, project_id, memo, cleared, approved, tax_chart_id, linetaxamount)
		  VALUES
		  ($form->{id}, $tax_chart_id, $tax_line_amount, '$form->{transdate}', |
		  .$dbh->quote($form->{"source_$i"}).qq|,
		  '0', $project_id, |.$dbh->quote($form->{"memo_$i"}).qq|,
		  $cleared, '$approved', 0, 0)|;
        $dbh->do($query) || $form->dberror($query);
      }

      if ($form->{currency} ne $form->{defaultcurrency}) {

				$amount = $form->round_amount($amount * ($form->{exchangerate} - 1), $form->{precision});
	
				if ($amount) {
					$query = qq|INSERT INTO acc_trans (trans_id, chart_id, amount, transdate,
								source, project_id, fx_transaction, memo, cleared, approved)
								VALUES
								($form->{id}, (SELECT id
									 FROM chart
									 WHERE accno = '$accno'),
								 $amount, '$form->{transdate}', |.
								 $dbh->quote($form->{"source_$i"}) .qq|,
								$project_id, '1', |.$dbh->quote($form->{"memo_$i"}).qq|,
								$cleared, '$approved')|;
					$dbh->do($query) || $form->dberror($query);
				}
      }
    }
  }
  my @valid_sources;
  if (keys %dist_amounts) {
    my $placeholders = join ', ', ('?') x keys %dist_amounts;
    my $query = qq|SELECT transaction_id FROM bank_transactions WHERE transaction_id IN ($placeholders)|;
    my $sth = $dbh->prepare($query);
    $sth->execute(keys %dist_amounts) || $form->dberror($query);
    while (my ($source) = $sth->fetchrow_array) {
      push @valid_sources, $source;
      my $abs_amount = abs($dist_amounts{$source});
      
      my $query_check = qq|SELECT id FROM transaction_distribution WHERE transaction_id = ? AND trans_id = ?|;
      my $sth_check = $dbh->prepare($query_check);
      $sth_check->execute($source, $form->{id});
      my ($dist_id) = $sth_check->fetchrow_array;
      $sth_check->finish;

      $abs_amount = $abs_amount * 1;
      if ($dist_id) {
        my $query_update = qq|UPDATE transaction_distribution SET amount = ? WHERE id = ?|;
        my $sth_update = $dbh->prepare($query_update);
        $sth_update->execute($abs_amount, $dist_id) || $form->dberror($query_update);
      } else {
        my $query_insert = qq|INSERT INTO transaction_distribution (transaction_id, trans_id, amount, module) VALUES (?, ?, ?, 'gl')|;
        my $sth_insert = $dbh->prepare($query_insert);
        $sth_insert->execute($source, $form->{id}, $abs_amount) || $form->dberror($query_insert);
      }
    }
    $sth->finish;
  }

  if (@valid_sources) {
     my $placeholders = join ', ', ('?') x @valid_sources;
     my $query_clean = qq|DELETE FROM transaction_distribution WHERE trans_id = $form->{id} AND transaction_id NOT IN ($placeholders)|;
     my $sth_clean = $dbh->prepare($query_clean);
     $sth_clean->execute(@valid_sources) || $form->dberror($query_clean);
  } else {
     my $query_clean = qq|DELETE FROM transaction_distribution WHERE trans_id = $form->{id}|;
     $dbh->do($query_clean) || $form->dberror($query_clean);
  }

  if ($form->{batchid} *= 1) {
    # add voucher
    $form->{voucher}{transaction}{vouchernumber} = $form->update_defaults($myconfig, 'vouchernumber', $dbh) unless $form->{voucher}{transaction}{vouchernumber};

    $query = qq|INSERT INTO vr (br_id, trans_id, id, vouchernumber)
                VALUES ($form->{batchid}, $form->{id}, $form->{id}, |
		.$dbh->quote($form->{voucher}{transaction}{vouchernumber}).qq|)|;
    $dbh->do($query) || $form->dberror($query);

    # update batch
    $form->update_balance($dbh,
			  'br',
			  'amount',
			  qq|id = $form->{batchid}|,
			  $bramount);
   
  }

  # save reference documents
  $form->save_reference($dbh, 'gl');
    
  my %audittrail = ( tablename  => 'gl',
                     reference  => $form->{reference},
		     formname   => 'transaction',
		     action     => $action,
		     id         => $form->{id} );
 
  $form->audittrail($dbh, "", \%audittrail);

  $form->save_recurring($dbh, $myconfig);

  $form->remove_locks($myconfig, $dbh, 'gl');

  # commit and redirect
  my $rc;
  
  if ($disconnect) {
    $rc = $dbh->commit;
    $dbh->disconnect;
  }

  $rc;

}
sub transactions {
  my ($self, $myconfig, $form) = @_;

  # connect to database
  my $dbh = $form->dbconnect($myconfig);
  my $query;
  my $sth;
  my $var;
  my %balance;
  my $balance;
  
  my %defaults = $form->get_defaults($dbh, \@{['precision', 'company']});
  for (keys %defaults) { $form->{$_} = $defaults{$_} }

  my ($glwhere, $arwhere, $apwhere) = ("g.approved = '1'", "a.approved = '1'", "a.approved = '1'");
  # Match balance sheet / RP::get_accounts: only posted acc_trans lines
  $glwhere .= " AND ac.approved = '1'";
  $arwhere .= " AND ac.approved = '1'";
  $apwhere .= " AND ac.approved = '1'";

  if ($form->{reference}) {
    $var = $form->like(lc $form->{reference});
    $glwhere .= " AND lower(g.reference) LIKE '$var'";
    $arwhere .= " AND lower(a.invnumber) LIKE '$var'";
    $apwhere .= " AND lower(a.invnumber) LIKE '$var'";
  }
  if ($form->{description}) {
    $var = $form->like(lc $form->{description});
    $glwhere .= " AND lower(g.description) LIKE '$var'";
    $arwhere .= " AND lower(a.description) LIKE '$var'";
    $apwhere .= " AND lower(a.description) LIKE '$var'";
  }
  if ($form->{name}) {
    $var = $form->like(lc $form->{name});
    $glwhere .= " AND lower(g.description) LIKE '$var'";
    $arwhere .= " AND lower(ct.name) LIKE '$var'";
    $apwhere .= " AND lower(ct.name) LIKE '$var'";
  }
  if ($form->{vcnumber}) {
    $var = $form->like(lc $form->{vcnumber});
    $glwhere .= " AND g.id = 0";
    $arwhere .= " AND lower(ct.customernumber) LIKE '$var'";
    $apwhere .= " AND lower(ct.vendornumber) LIKE '$var'";
  }
  if ($form->{department}) {
    (undef, $var) = split /--/, $form->{department};
    $glwhere .= " AND g.department_id = $var";
    $arwhere .= " AND a.department_id = $var";
    $apwhere .= " AND a.department_id = $var";
  }
  
  my $gdescription = "''";
  my $invoicejoin;
  my $lineitem = "''";
 
  if ($form->{lineitem}) {
    $var = $form->like(lc $form->{lineitem});
    $glwhere .= " AND lower(ac.memo) LIKE '$var'";
    $arwhere .= " AND lower(i.description) LIKE '$var'";
    $apwhere .= " AND lower(i.description) LIKE '$var'";

    $gdescription = "ac.memo";
    $lineitem = "i.description";
    $invoicejoin = qq|
		 LEFT JOIN invoice i ON (i.id = ac.id)|;
  }
 
  if ($form->{l_lineitem}) {
    $gdescription = "ac.memo";
    $lineitem = "i.description";
  }

  $invoicejoin = qq|
             LEFT JOIN invoice i ON (i.id = ac.id)|;

  if ($form->{source}) {
    $var = $form->like(lc $form->{source});
    $glwhere .= " AND lower(ac.source) LIKE '$var'";
    $arwhere .= " AND lower(ac.source) LIKE '$var'";
    $apwhere .= " AND lower(ac.source) LIKE '$var'";
  }
  
  my $where;

  if ($form->{accnofrom}) {
    $query = qq|SELECT c.description,
                l.description AS translation
		FROM chart c
		LEFT JOIN translation l ON (l.trans_id = c.id AND l.language_code = '$myconfig->{countrycode}')
		WHERE c.accno = '$form->{accnofrom}'|;
    ($form->{accnofrom_description}, $form->{accnofrom_translation}) = $dbh->selectrow_array($query);
      $form->{accnofrom_description} = $form->{accnofrom_translation} if $form->{accnofrom_translation};
 
    $where = " AND c.accno >= '$form->{accnofrom}'";
    $glwhere .= $where;
    $arwhere .= $where;
    $apwhere .= $where;
  }

  if ($form->{accnoto}) {
    $query = qq|SELECT c.description,
                l.description AS translation
		FROM chart c
		LEFT JOIN translation l ON (l.trans_id = c.id AND l.language_code = '$myconfig->{countrycode}')
		WHERE c.accno = '$form->{accnoto}'|;
    ($form->{accnoto_description}, $form->{accnoto_translation}) = $dbh->selectrow_array($query);
      $form->{accnoto_description} = $form->{accnoto_translation} if $form->{accnoto_translation};
 
    $where = " AND c.accno <= '$form->{accnoto}'";
    $glwhere .= $where;
    $arwhere .= $where;
    $apwhere .= $where;
  }

  if ($form->{memo}) {
    $var = $form->like(lc $form->{memo});
    $glwhere .= " AND lower(ac.memo) LIKE '$var'";
    $arwhere .= " AND lower(ac.memo) LIKE '$var'";
    $apwhere .= " AND lower(ac.memo) LIKE '$var'";
  }
  
  if ($form->{project_id}) {
    $glwhere .= " AND ac.project_id = '$form->{project_id}'";
    $arwhere .= " AND ac.project_id = '$form->{project_id}'";
    $apwhere .= " AND ac.project_id = '$form->{project_id}'";
  }
  if (!$form->{fx_transaction}) {
    $glwhere .= " AND ac.fx_transaction = '0'";
    $arwhere .= " AND ac.fx_transaction = '0'";
    $apwhere .= " AND ac.fx_transaction = '0'";
  }
 

  unless ($form->{datefrom} || $form->{dateto}) {
    ($form->{datefrom}, $form->{dateto}) = $form->from_to($form->{year}, $form->{month}, $form->{interval}) if $form->{year} && $form->{month};
  }
  
  if ($form->{datefrom}) {
    $glwhere .= " AND ac.transdate >= '$form->{datefrom}'";
    $arwhere .= " AND ac.transdate >= '$form->{datefrom}'";
    $apwhere .= " AND ac.transdate >= '$form->{datefrom}'";
  }
  if ($form->{dateto}) {
    $glwhere .= " AND ac.transdate <= '$form->{dateto}'";
    $arwhere .= " AND ac.transdate <= '$form->{dateto}'";
    $apwhere .= " AND ac.transdate <= '$form->{dateto}'";
  }
  if ($form->{createdfrom}) {
      $glwhere .= " AND g.created >= '$form->{createdfrom}'";
      $arwhere .= " AND a.created >= '$form->{createdfrom}'";
      $apwhere .= " AND a.created >= '$form->{createdfrom}'";
  }
  if ($form->{createdto}) {
      $glwhere .= " AND g.created < (DATE '$form->{createdto}' + INTERVAL '1 day')";
      $arwhere .= " AND a.created < (DATE '$form->{createdto}' + INTERVAL '1 day')";
      $apwhere .= " AND a.created < (DATE '$form->{createdto}' + INTERVAL '1 day')";
  }

  if ($form->{updatedfrom}) {
      $glwhere .= " AND g.updated >= '$form->{updatedfrom}'";
      $arwhere .= " AND a.updated >= '$form->{updatedfrom}'";
      $apwhere .= " AND a.updated >= '$form->{updatedfrom}'";
  }
  if ($form->{updatedto}) {
      $glwhere .= " AND g.updated < (DATE '$form->{updatedto}' + INTERVAL '1 day')";
      $arwhere .= " AND a.updated < (DATE '$form->{updatedto}' + INTERVAL '1 day')";
      $apwhere .= " AND a.updated < (DATE '$form->{updatedto}' + INTERVAL '1 day')";
  }
  if ($form->{amountfrom}) {
    $form->{amountfrom} = $form->parse_amount($myconfig, $form->{amountfrom});
    $glwhere .= " AND abs(ac.amount) >= $form->{amountfrom}";
    $arwhere .= " AND abs(ac.amount) >= $form->{amountfrom}";
    $apwhere .= " AND abs(ac.amount) >= $form->{amountfrom}";
  }
  if ($form->{amountto}) {
    $form->{amountto} = $form->parse_amount($myconfig, $form->{amountto});
    $glwhere .= " AND abs(ac.amount) <= $form->{amountto}";
    $arwhere .= " AND abs(ac.amount) <= $form->{amountto}";
    $apwhere .= " AND abs(ac.amount) <= $form->{amountto}";
  }
  if ($form->{notes}) {
    $var = $form->like(lc $form->{notes});
    $glwhere .= " AND lower(g.notes) LIKE '$var'";
    $arwhere .= " AND lower(a.notes) LIKE '$var'";
    $apwhere .= " AND lower(a.notes) LIKE '$var'";
  }
  if ($form->{accno}) {
    $glwhere .= " AND c.accno = '$form->{accno}'";
    $arwhere .= " AND c.accno = '$form->{accno}'";
    $apwhere .= " AND c.accno = '$form->{accno}'";
  }
  if ($form->{gifi_accno}) {
    $glwhere .= " AND c.gifi_accno = '$form->{gifi_accno}'";
    $arwhere .= " AND c.gifi_accno = '$form->{gifi_accno}'";
    $apwhere .= " AND c.gifi_accno = '$form->{gifi_accno}'";
  }
  if ($form->{category} ne 'X') {
    $glwhere .= " AND c.category = '$form->{category}'";
    $arwhere .= " AND c.category = '$form->{category}'";
    $apwhere .= " AND c.category = '$form->{category}'";

    delete $form->{l_contra};
  }

  $glwhere .= " AND ac.amount <> 0";
  $arwhere .= " AND ac.amount <> 0";
  $apwhere .= " AND ac.amount <> 0";

  if ($form->{accno} || $form->{gifi_accno}) {
    
    # get category for account
    if ($form->{accno}) {
      $query = qq|SELECT c.category, c.link, c.contra, c.description,
                  l.description AS translation
		  FROM chart c
		  LEFT JOIN translation l ON (l.trans_id = c.id AND l.language_code = '$myconfig->{countrycode}')
		  WHERE c.accno = '$form->{accno}'|;
      ($form->{category}, $form->{link}, $form->{contra}, $form->{account_description}, $form->{account_translation}) = $dbh->selectrow_array($query);
      $form->{account_description} = $form->{account_translation} if $form->{account_translation};
    }
    
    if ($form->{gifi_accno}) {
      $query = qq|SELECT c.category, c.link, c.contra, g.description
		  FROM chart c
		  LEFT JOIN gifi g ON (g.accno = c.gifi_accno)
		  WHERE c.gifi_accno = '$form->{gifi_accno}'|;
      ($form->{category}, $form->{link}, $form->{contra}, $form->{gifi_account_description}) = $dbh->selectrow_array($query);
    }
 
    if ($form->{datefrom}) {

      $query = qq|SELECT SUM(ac.amount)
                  FROM acc_trans ac
                  JOIN chart c ON (ac.chart_id = c.id)
                  JOIN gl g ON (g.id = ac.trans_id)
                  WHERE c.accno = '$form->{accno}'
                  AND ac.approved = '1'
                  AND g.approved = '1'
                  AND ac.transdate < date '$form->{datefrom}'
                  |;
      my ($balance) = $dbh->selectrow_array($query);
      $form->{balance} = $balance;

      $query = qq|SELECT SUM(ac.amount)
                  FROM acc_trans ac
                  JOIN chart c ON (ac.chart_id = c.id)
                  JOIN ar a ON (a.id = ac.trans_id)
                  JOIN customer ct ON (ct.id = a.customer_id)
                  WHERE c.accno = '$form->{accno}'
                  AND ac.approved = '1'
                  AND a.approved = '1'
                  AND ac.transdate < date '$form->{datefrom}'
                  |;
      ($balance) = $dbh->selectrow_array($query);
      $form->{balance} += $balance;

      $query = qq|SELECT SUM(ac.amount)
                  FROM acc_trans ac
                  JOIN chart c ON (ac.chart_id = c.id)
                  JOIN ap a ON (a.id = ac.trans_id)
                  JOIN vendor ct ON (ct.id = a.vendor_id)
                  WHERE c.accno = '$form->{accno}'
                  AND ac.approved = '1'
                  AND a.approved = '1'
                  AND ac.transdate < date '$form->{datefrom}'
                  |;
      
      ($balance) = $dbh->selectrow_array($query);
      $form->{balance} += $balance;
    }
  }

  if ($form->{l_splitledger}) {
    if ($form->{datefrom}) {

      $query = qq|SELECT SUM(ac.amount)
		  FROM acc_trans ac
		  JOIN chart c ON (ac.chart_id = c.id)
		  JOIN gl g ON (g.id = ac.trans_id)
		  WHERE ac.transdate < date '$form->{datefrom}'
                  AND ac.approved = '1'
                  AND g.approved = '1'
                  AND c.accno = ?
		  |;
      $bgl = $dbh->prepare($query);

      $query = qq|SELECT SUM(ac.amount)
		  FROM acc_trans ac
		  JOIN chart c ON (ac.chart_id = c.id)
		  JOIN ar a ON (a.id = ac.trans_id)
		  JOIN customer ct ON (ct.id = a.customer_id)
		  WHERE ac.transdate < date '$form->{datefrom}'
                  AND ac.approved = '1'
                  AND a.approved = '1'
                  AND c.accno = ?
		  |;
      $bar = $dbh->prepare($query);
 
      $query = qq|SELECT SUM(ac.amount)
		  FROM acc_trans ac
		  JOIN chart c ON (ac.chart_id = c.id)
		  JOIN ap a ON (a.id = ac.trans_id)
		  JOIN vendor ct ON (ct.id = a.vendor_id)
		  WHERE ac.transdate < date '$form->{datefrom}'
                  AND ac.approved = '1'
                  AND a.approved = '1'
                  AND c.accno = ?
		  |;
      $bap = $dbh->prepare($query);
    }
  }

  my $false = ($myconfig->{dbdriver} =~ /Pg/) ? FALSE : q|'0'|;
 
  my $query = qq|SELECT g.id, 'gl' AS type, $false AS invoice, g.reference,
                 g.description, g.created, g.updated, ac.transdate, ac.source,
		 ac.amount, ac.entry_id AS acc_trans_id, c.accno, c.description as account_description,
                 l.description AS account_translation, c.category,
                 c.contra AS ca,
                 c.gifi_accno, g.notes, c.link,
		 '' AS till, ac.cleared, d.description AS department,
		 ac.memo, '0' AS name_id, '' AS db,
		 $gdescription AS lineitem, '' AS name, '' AS vcnumber,
		 '' AS address1, '' AS address2, '' AS city,
		 '' AS zipcode, '' AS country,
                 CASE WHEN tc.accno IS NOT NULL THEN CONCAT(tc.accno, '--', tc.description) END AS linetax_account, ac.linetaxamount,
                 ac.project_id, COALESCE(tp.description, p.description) AS project_description,
                 g.accrual_source
                 FROM gl g
		 JOIN acc_trans ac ON (g.id = ac.trans_id)
		 JOIN chart c ON (ac.chart_id = c.id)
                 LEFT JOIN chart tc ON (ac.tax_chart_id = tc.id)
		 LEFT JOIN department d ON (d.id = g.department_id)
		 LEFT JOIN translation l ON (l.trans_id = c.id AND l.language_code = '$myconfig->{countrycode}')
                 LEFT JOIN project p ON (ac.project_id = p.id)
                 LEFT JOIN translation tp ON (tp.trans_id = p.id AND tp.language_code = '$myconfig->{countrycode}')
                 WHERE $glwhere
	UNION ALL
	         SELECT a.id, 'ar' AS type, a.invoice, a.invnumber,
		 a.description, a.created, a.updated, ac.transdate, ac.source,
		 ac.amount, ac.entry_id AS acc_trans_id, c.accno, c.description as account_description,
                 l.description AS account_translation, c.category,
                 c.contra AS ca,
                 c.gifi_accno, a.notes, c.link,
		 a.till, ac.cleared, d.description AS department,
		 ac.memo, ct.id AS name_id, 'customer' AS db,
		 $lineitem AS lineitem, ct.name, ct.customernumber,
		 ad.address1, ad.address2, ad.city,
		 ad.zipcode, ad.country,
                 CASE 
                     WHEN a.invoice AND ac.id IS NOT NULL AND i.id IS NOT NULL THEN 
                         (SELECT STRING_AGG(DISTINCT CONCAT(tc2.accno, '--', tc2.description), ', ' ORDER BY CONCAT(tc2.accno, '--', tc2.description)) 
                          FROM invoicetax it 
                          JOIN chart tc2 ON it.chart_id = tc2.id 
                          WHERE it.trans_id = a.id AND it.invoice_id = i.id)
                     ELSE CASE WHEN tc.accno IS NOT NULL THEN CONCAT(tc.accno, '--', tc.description) END
                 END AS linetax_account,
                 CASE
                     WHEN a.invoice AND ac.id IS NOT NULL AND i.id IS NOT NULL THEN
                         (SELECT SUM(it.taxamount)
                          FROM invoicetax it
                          WHERE it.trans_id = a.id AND it.invoice_id = i.id)
                     ELSE ac.linetaxamount
                 END AS linetaxamount,
                 ac.project_id, COALESCE(tp.description, p.description) AS project_description,
                 NULL::text AS accrual_source
		 FROM ar a
		 JOIN acc_trans ac ON (a.id = ac.trans_id)
		 $invoicejoin
		 JOIN chart c ON (ac.chart_id = c.id)
		 JOIN customer ct ON (a.customer_id = ct.id)
		 JOIN address ad ON (ad.trans_id = ct.id)
                 LEFT JOIN chart tc ON (ac.tax_chart_id = tc.id)
		 LEFT JOIN department d ON (d.id = a.department_id)
		 LEFT JOIN translation l ON (l.trans_id = c.id AND l.language_code = '$myconfig->{countrycode}')
                 LEFT JOIN project p ON (ac.project_id = p.id)
                 LEFT JOIN translation tp ON (tp.trans_id = p.id AND tp.language_code = '$myconfig->{countrycode}')
		 WHERE $arwhere
	UNION ALL
	         SELECT a.id, 'ap' AS type, a.invoice, a.invnumber,
		 a.description, a.created, a.updated, ac.transdate, ac.source,
		 ac.amount, ac.entry_id AS acc_trans_id, c.accno, c.description as account_description,
                 l.description AS account_translation, c.category,
                 c.contra AS ca,
                 c.gifi_accno, a.notes, c.link,
		 a.till, ac.cleared, d.description AS department,
		 ac.memo, ct.id AS name_id, 'vendor' AS db,
		 $lineitem AS lineitem, ct.name, ct.vendornumber,
		 ad.address1, ad.address2, ad.city,
		 ad.zipcode, ad.country,
                CASE 
                    WHEN a.invoice AND ac.id IS NOT NULL AND i.id IS NOT NULL THEN 
                        (SELECT STRING_AGG(DISTINCT CONCAT(tc2.accno, '--', tc2.description), ', ' ORDER BY CONCAT(tc2.accno, '--', tc2.description)) 
                         FROM invoicetax it 
                         JOIN chart tc2 ON it.chart_id = tc2.id 
                         WHERE it.trans_id = a.id AND it.invoice_id = i.id)
                   WHEN NOT a.invoice
                        AND aprt.trans_id IS NOT NULL
                        AND (c.link = 'AP_amount' OR COALESCE(ac.fx_transaction, FALSE))
                   THEN aprt.rt_account
                   WHEN NOT a.invoice
                        AND COALESCE(ac.fx_transaction, FALSE)
                        AND tc_fx_pair.accno IS NOT NULL
                   THEN CONCAT(tc_fx_pair.accno, '--', tc_fx_pair.description)
                     ELSE CASE WHEN tc.accno IS NOT NULL THEN CONCAT(tc.accno, '--', tc.description) END
                 END AS linetax_account,
                 CASE
                     WHEN a.invoice AND ac.id IS NOT NULL AND i.id IS NOT NULL THEN
                         (SELECT SUM(it.taxamount)
                          FROM invoicetax it
                          WHERE it.trans_id = a.id AND it.invoice_id = i.id)
                     ELSE ac.linetaxamount
                 END AS linetaxamount,
                 ac.project_id, COALESCE(tp.description, p.description) AS project_description,
                 NULL::text AS accrual_source
		 FROM ap a
		 JOIN acc_trans ac ON (a.id = ac.trans_id)
		 $invoicejoin
		 JOIN chart c ON (ac.chart_id = c.id)
		 JOIN vendor ct ON (a.vendor_id = ct.id)
		 JOIN address ad ON (ad.trans_id = ct.id)
                 LEFT JOIN chart tc ON (ac.tax_chart_id = tc.id)
                 LEFT JOIN acc_trans ac_fx_pair
                     ON COALESCE(ac.fx_transaction, FALSE) IS TRUE
                    AND ac_fx_pair.trans_id = ac.trans_id
                    AND ac_fx_pair.id       = ac.id
                    AND ac_fx_pair.chart_id = ac.chart_id
                    AND COALESCE(ac_fx_pair.fx_transaction, FALSE) IS FALSE
                 LEFT JOIN chart tc_fx_pair ON (tc_fx_pair.id = ac_fx_pair.tax_chart_id)
                 LEFT JOIN (
                     SELECT at2.trans_id,
                            STRING_AGG(DISTINCT CONCAT(c2.accno, '--', c2.description), ', ' ORDER BY CONCAT(c2.accno, '--', c2.description)) AS rt_account
                     FROM acc_trans at2
                     JOIN chart c2 ON at2.chart_id = c2.id
                     WHERE c2.accno IN ('11761', '22041')
                     GROUP BY at2.trans_id
                     HAVING COUNT(DISTINCT c2.accno) = 2
                 ) aprt ON (aprt.trans_id = a.id)
		 LEFT JOIN department d ON (d.id = a.department_id)
		 LEFT JOIN translation l ON (l.trans_id = c.id AND l.language_code = '$myconfig->{countrycode}')
                 LEFT JOIN project p ON (ac.project_id = p.id)
                 LEFT JOIN translation tp ON (tp.trans_id = p.id AND tp.language_code = '$myconfig->{countrycode}')
		 WHERE $apwhere|;
 
  my @sf = qw(id transdate reference);
  push @sf, "accno" unless $form->{l_splitledger};
  my %ordinal = $form->ordinal_order($dbh, $query);
  my $sort_order = $form->sort_order(\@sf, \%ordinal);

  if ($form->{l_splitledger}) {
    $sort_order = $ordinal{accno} .", $sort_order";
  }
  $query .= qq| ORDER BY $sort_order|;

  my $sth = $dbh->prepare($query);
  $sth->execute || $form->dberror($query);

  my %trans;
  my $i = 0;

  while (my $ref = $sth->fetchrow_hashref(NAME_lc)) {

    $ref->{account_description} = $ref->{account_translation} if $ref->{account_translation};

    if ($form->{l_splitledger}) {
      $ref->{balance} = 0;
      if ($form->{datefrom}) {
        if (exists $balance{$ref->{accno}}) {
          $ref->{balance} = $balance{$ref->{accno}};
        } else {
          $bgl->execute($ref->{accno}) || $form->dberror;
          ($balance) = $bgl->fetchrow_array;
          $ref->{balance} = $balance;
          $bgl->finish;

          $bar->execute($ref->{accno}) || $form->dberror;
          ($balance) = $bar->fetchrow_array;
          $ref->{balance} += $balance;
          $bar->finish;

          $bap->execute($ref->{accno}) || $form->dberror;
          ($balance) = $bap->fetchrow_array;
          $ref->{balance} += $balance;
          $bap->finish;

          $balance{$ref->{accno}} = $ref->{balance};
        }
      }
    }
     
    # gl
    if ($ref->{type} eq "gl") {
      $ref->{module} = "gl";
    }

    # ap
    if ($ref->{type} eq "ap") {
      $ref->{memo} ||= $ref->{lineitem};
      $ref->{description} ||= $ref->{name};
      if ($ref->{invoice}) {
        $ref->{module} = "ir";
      } else {
        $ref->{module} = "ap";
      }
    }

    # ar
    if ($ref->{type} eq "ar") {
      $ref->{memo} ||= $ref->{lineitem};
      $ref->{description} ||= $ref->{name};
      if ($ref->{invoice}) {
        $ref->{module} = ($ref->{till}) ? "ps" : "is";
      } else {
        $ref->{module} = "ar";
      }
    }

    if ($ref->{amount} < 0) {
      $ref->{debit} = $ref->{amount} * -1;
      $ref->{credit} = 0;
    } else {
      $ref->{credit} = $ref->{amount};
      $ref->{debit} = 0;
    }

    for (qw(address1 address2 city zipcode country)) { $ref->{address} .= "$ref->{$_} " }


    $trans{$ref->{id}}{$i} = {
                 transdate => $ref->{transdate},
                      link => $ref->{link},
                      type => $ref->{type},
                     accno => $ref->{accno},
                gifi_accno => $ref->{gifi_accno},
                     debit => $ref->{debit},
                    credit => $ref->{credit},
                    amount => $ref->{debit} + $ref->{credit},
                   balance => $ref->{balance},
              acc_trans_id => $ref->{acc_trans_id}
		             };
    push @{ $form->{GL} }, $ref;

    $i++;
    
  }
  $sth->finish;

  if ($form->{initreport}) {
    $form->retrieve_report($myconfig, $dbh);
  }
  
  $form->report_level($myconfig, $dbh);

  # Load full journal for ALL visible transactions in one query, then
  # group by trans_id in Perl.  This replaces N per-transaction queries
  # with a single bulk fetch.
  my %full_by_trans;   # trans_id => { entry_id => line_hashref }
  if (%trans) {
    my $ids       = join ',', map { $_ * 1 } keys %trans;
    my $fx_clause = $form->{fx_transaction}
      ? ''
      : " AND ac.fx_transaction = $false";
    my $full_lines_q = qq|
      SELECT ac.trans_id, ac.entry_id, ac.transdate, ac.amount,
             c.accno, c.gifi_accno, c.link
      FROM acc_trans ac
      JOIN chart c ON ac.chart_id = c.id
      WHERE ac.trans_id IN ($ids)
        AND ac.approved = '1'
        AND ac.amount <> 0
        $fx_clause
      ORDER BY ac.entry_id
    |;
    my $sth_full = $dbh->prepare($full_lines_q);
    $sth_full->execute || $form->dberror($full_lines_q);
    while ( my $row = $sth_full->fetchrow_hashref(NAME_lc) ) {
      my $debit  = $row->{amount} < 0  ? -$row->{amount} : 0;
      my $credit = $row->{amount} >= 0 ? $row->{amount}  : 0;
      $full_by_trans{ $row->{trans_id} }{ $row->{entry_id} } = {
        transdate  => $row->{transdate},
        link       => $row->{link},
        accno      => $row->{accno},
        gifi_accno => $row->{gifi_accno},
        debit      => $debit,
        credit     => $credit,
        amount     => $debit + $credit,
      };
    }
    $sth_full->finish;
  }

  # For range-filtered reports with a start date, also include accounts
  # that sit within the account-number range but had no transactions in
  # the period.  They are added as debit=0/credit=0 rows so the caller
  # can still display the opening balance.
  if ( ($form->{accnofrom} || $form->{accnoto}) && $form->{datefrom} ) {
    my %seen_accno;
    $seen_accno{ $_->{accno} } = 1 for @{ $form->{GL} };

    my @rc;
    push @rc, "c.accno >= '$form->{accnofrom}'" if $form->{accnofrom};
    push @rc, "c.accno <= '$form->{accnoto}'"   if $form->{accnoto};
    my $range_cond = join ' AND ', @rc;

    my $ob_q = qq|
      SELECT c.accno,
             COALESCE(l.description, c.description) AS account_description,
             c.gifi_accno, c.category, c.link, c.contra AS ca,
             SUM(ac.amount) AS balance
        FROM chart c
        JOIN acc_trans ac ON (ac.chart_id = c.id
                              AND ac.approved = TRUE
                              AND ac.transdate < date '$form->{datefrom}'
                              AND ac.amount <> 0
                              AND ac.fx_transaction = $false)
        LEFT JOIN translation l ON (l.trans_id = c.id
                                    AND l.language_code = '$myconfig->{countrycode}')
       WHERE $range_cond
       GROUP BY c.accno, c.description, l.description,
                c.gifi_accno, c.category, c.link, c.contra
      HAVING SUM(ac.amount) <> 0
      ORDER BY c.accno
    |;

    my $sth_ob = $dbh->prepare($ob_q);
    $sth_ob->execute || $form->dberror($ob_q);
    while ( my $ref = $sth_ob->fetchrow_hashref(NAME_lc) ) {
      next if $seen_accno{ $ref->{accno} };
      next if $form->{category} ne 'X' && $ref->{category} ne $form->{category};
      push @{ $form->{GL} }, {
        id                  => 0,
        type                => 'gl',
        module              => 'gl',
        invoice             => $false,
        reference           => '',
        description         => '',
        transdate           => undef,
        source              => '',
        amount              => 0,
        accno               => $ref->{accno},
        account_description => $ref->{account_description},
        category            => $ref->{category},
        ca                  => $ref->{ca},
        gifi_accno          => $ref->{gifi_accno},
        notes               => '',
        link                => $ref->{link},
        till                => '',
        cleared             => undef,
        department          => '',
        memo                => '',
        name_id             => 0,
        db                  => '',
        lineitem            => '',
        name                => '',
        vcnumber            => '',
        address             => '',
        debit               => 0,
        credit              => 0,
        balance             => $ref->{balance} + 0,
        contra              => '',
        gifi_contra         => '',
      };
    }
    $sth_ob->finish;
  }

  $dbh->disconnect;

  for my $id (keys %trans) {
    my ($any_i) = keys %{ $trans{$id} };
    my $doctype  = $trans{$id}{$any_i}{type};
    my $full_ref = $full_by_trans{$id} // {};

    # stamp the doc type onto each line (needed by _assign_contra_lines)
    my %full;
    for my $eid (keys %$full_ref) {
      $full{$eid} = { %{ $full_ref->{$eid} }, type => $doctype };
    }

    my ( $contra_f, $gifi_f ) = _assign_contra_lines( $form, \%full );

    for my $gl_i ( keys %{ $trans{$id} } ) {
      my $atid = $trans{$id}{$gl_i}{acc_trans_id};
      next unless defined $atid;
      $form->{GL}[$gl_i]{contra}      = $contra_f->{$atid}
        if defined $contra_f->{$atid};
      $form->{GL}[$gl_i]{gifi_contra} = $gifi_f->{$atid}
        if defined $gifi_f->{$atid};
    }
  }

}

sub _assign_contra_lines {
  my ( $form, $lines ) = @_;
  my %contra;
  my %gifi_contra;

  my $arap      = "";
  my $ARAP;
  my $gifi_arap = "";
  my $paid      = "";
  my $gifi_paid = "";
  my @arap;
  my @paid;
  my @accno;
  my %accno;
  my $aa = 0;
  my $j;
  my $i;
  my %seen;

  for $i (
    reverse sort { $lines->{$a}{amount} <=> $lines->{$b}{amount} }
    keys %$lines )
  {
    if ( $lines->{$i}{type} =~ /(ar|ap)/ ) {
      $ARAP = uc $lines->{$i}{type};
      $aa   = 1;
      if ( $lines->{$i}{link} eq $ARAP ) {
        $arap      = $lines->{$i}{accno};
        $gifi_arap = $lines->{$i}{gifi_accno};
        push @arap, $i;
      }
      elsif ( $lines->{$i}{link} =~ /${ARAP}_paid/ ) {
        $paid      = $lines->{$i}{accno};
        $gifi_paid = $lines->{$i}{gifi_accno};
        push @paid, $i;
      }
      else {
        push @accno,
          {
          accno     => $lines->{$i}{accno},
          gifi_accno => $lines->{$i}{gifi_accno},
          transdate => $lines->{$i}{transdate},
          i         => $i
          };
      }
    }
  }

  if ($aa) {
    for (@paid) {
      $contra{$_}      = $arap;
      $gifi_contra{$_} = $gifi_arap;
    }
    if (@paid) {
      $i = pop @arap;
      $contra{$i}      = $paid;
      $gifi_contra{$i} = $gifi_paid;
    }
    %seen = ();
    for (@arap) {
      for my $ref (@accno) {
        $contra{$_} .= "$ref->{accno} "
          unless $seen{"$ref->{accno}$ref->{transdate}"};
        $seen{"$ref->{accno}$ref->{transdate}"} = 1;

        $gifi_contra{$_} .= "$ref->{gifi_accno} "
          unless $seen{"$ref->{gifi_accno}$ref->{transdate}"};
        $seen{"$ref->{gifi_accno}$ref->{transdate}"} = 1;
      }
    }
    for my $ref (@accno) {
      $contra{$ref->{i}}      = $arap;
      $gifi_contra{$ref->{i}} = $gifi_arap;
    }
  }
  else {
    %accno = %$lines;

    for $i (
      reverse sort { $lines->{$a}{amount} <=> $lines->{$b}{amount} }
      keys %$lines )
    {
      my $found  = 0;
      my $amount = $lines->{$i}{amount};
      $j = $i;

      my ( $amt, $rev );
      if ( $lines->{$i}{debit} ) {
        $amt = "debit";
        $rev = "credit";
      }
      else {
        $amt = "credit";
        $rev = "debit";
      }

      if ($amount) {
        for ( keys %accno ) {
          if ( $accno{$_}{$rev} == $amount ) {
            $contra{$i}      = $accno{$_}{accno};
            $gifi_contra{$i} = $accno{$_}{gifi_accno};
            $found           = 1;
            last;
          }
        }
      }

      if ( !$found ) {
        if ($amount) {
          for my $ak (
            reverse sort { $accno{$a}{amount} <=> $accno{$b}{amount} }
            keys %accno )
          {
            if ( $accno{$ak}{$rev} ) {

              # add contra to accno
              $contra{$j}      .= "$accno{$ak}{accno} ";
              $gifi_contra{$j} .= "$accno{$ak}{gifi_accno} ";

              $amount =
                $form->round_amount( $amount - $accno{$ak}{$rev}, 10 );
              last if $amount <= 0;

            }
          }
          $contra{$j}      ||= '';
          $gifi_contra{$j} ||= '';
          $contra{$j} =
            join ' ', sort split / /, $contra{$j};
          $gifi_contra{$j} =
            join ' ', sort split / /, $gifi_contra{$j};
        }
      }
    }
  }

  return ( \%contra, \%gifi_contra );

}

sub transaction {
  my ($self, $myconfig, $form) = @_;
  
  my $query;
  my $sth;
  my $ref;
  my @gl;
  
  # connect to database
  my $dbh = $form->dbconnect($myconfig);

  $form->remove_locks($myconfig, $dbh, 'gl');
  
  my %defaults = $form->get_defaults($dbh, \@{[qw(closedto revtrans precision referenceurl linetax lock_%)]});
  for (keys %defaults) { $form->{$_} = $defaults{$_} }

  $form->{currencies} = $form->get_currencies($myconfig, $dbh);
  
  if ($form->{id} *= 1) {
    $query = qq|SELECT g.*, 
                d.description AS department,
		br.id AS batchid, br.description AS batchdescription
                FROM gl g
	        LEFT JOIN department d ON (d.id = g.department_id)
		LEFT JOIN vr ON (vr.trans_id = g.id)
		LEFT JOIN br ON (br.id = vr.br_id)
	        WHERE g.id = $form->{id}|;
    $sth = $dbh->prepare($query);
    $sth->execute || $form->dberror($query);

    $ref = $sth->fetchrow_hashref(NAME_lc);
    for (keys %$ref) { $form->{$_} = $ref->{$_} }
    $form->{currency} = $form->{curr};
    $sth->finish;
  
    # retrieve individual rows in insertion order (ac.id) so tax-only lines follow their main line
    $query = qq|SELECT ac.*, c.accno, c.description, p.projectnumber,
                    l.description AS translation, tc.accno tax_accno, tc.description tax_description,
                    (SELECT chart_id FROM tax WHERE chart_id = ac.chart_id LIMIT 1) AS tax_table_chart_id
	        FROM acc_trans ac
	        JOIN chart c ON (ac.chart_id = c.id)
	        LEFT JOIN project p ON (p.id = ac.project_id)
		LEFT JOIN translation l ON (l.trans_id = c.id AND l.language_code = '$myconfig->{countrycode}')
        LEFT JOIN chart tc ON tc.id = ac.tax_chart_id
	        WHERE ac.trans_id = $form->{id}
	        ORDER BY ac.id|;
    $sth = $dbh->prepare($query);
    $sth->execute || $form->dberror($query);

    my $taxincluded = $form->{taxincluded} ? 1 : 0;
    while ($ref = $sth->fetchrow_hashref(NAME_lc)) {
      # Tax-only line: tax_chart_id is 0, linetaxamount is 0, and this chart is a tax account (from tax table).
      # These were inserted as separate acc_trans rows for the tax; skip them so we don't duplicate lines.
      my $is_tax_only = ( !$ref->{tax_chart_id} || $ref->{tax_chart_id} == 0 )
        && ( !defined $ref->{linetaxamount} || $ref->{linetaxamount} == 0 )
        && $ref->{tax_table_chart_id};
      if ($is_tax_only) {
        next;
      }
      $ref->{description} = $ref->{translation} if $ref->{translation};
      # When taxincluded, we stored net amount (debit/credit minus tax); add tax back for display
      if ($taxincluded && $ref->{tax_chart_id} && $ref->{linetaxamount}) {
        my $linetax = $form->round_amount($ref->{linetaxamount}, $form->{precision});
        if ($ref->{amount} > 0) {
          $ref->{amount} = $form->round_amount($ref->{amount} + $linetax, $form->{precision});
        } else {
          $ref->{amount} = $form->round_amount($ref->{amount} - $linetax, $form->{precision});
        }
      }
      push @gl, $ref;
      if ($ref->{fx_transaction}) {
	$fxdr += $ref->{amount} if $ref->{amount} < 0;
	$fxcr += $ref->{amount} if $ref->{amount} > 0;
      }
    }
    $sth->finish;
    
    if ($fxdr < 0 || $fxcr > 0) {
      $form->{fxadj} = 1 if $form->round_amount($fxdr * -1, $form->{precision}) != $form->round_amount($fxcr, $form->{precision});
    }

    if ($form->{fxadj}) {
      @{ $form->{GL} } = @gl;
    } else {
      foreach $ref (@gl) {
	if (! $ref->{fx_transaction}) {
	  push @{ $form->{GL} }, $ref;
	}
      }
    }
    
    # get recurring transaction
    $form->get_recurring($dbh);

    $form->all_references($dbh);

    $form->create_lock($myconfig, $dbh, $form->{id}, 'gl');

  } else {
    $form->{transdate} = $form->current_date($myconfig);
  }

  # get chart of accounts
  $query = qq|SELECT c.accno, c.description,
              l.description AS translation
              FROM chart c
              LEFT JOIN translation l ON (l.trans_id = c.id AND l.language_code = '$myconfig->{countrycode}')
              WHERE c.charttype = 'A'
              AND c.closed = '0'
              ORDER by 1|;
  $sth = $dbh->prepare($query);
  $sth->execute || $form->dberror($query);
  
  while ($ref = $sth->fetchrow_hashref(NAME_lc)) {
    $ref->{description} = $ref->{translation} if $ref->{translation};
    push @{ $form->{all_accno} }, $ref;
  }
  $sth->finish;

  # get departments
  $form->all_departments($myconfig, $dbh);
  
  # get projects
  $form->all_projects($myconfig, $dbh, $form->{transdate});

  if ($form->{linetax}) {
    my $sth = $dbh->prepare(qq|
         SELECT DISTINCT c.accno, c.description, t.rate
         FROM chart c
         JOIN tax t ON t.chart_id = c.id
         WHERE (t.validto >= '$form->{transdate}' OR t.validto IS NULL)
         ORDER BY accno
         |
    );
    $sth->execute;
    $form->{selecttax} = "\n";
    while ( my $row = $sth->fetchrow_hashref(NAME_lc) ) {
        $form->{selecttax} .= "$row->{accno}--$row->{description}\n";
        $form->{taxaccounts} .= "$row->{accno} ";
        $form->{"$row->{accno}_rate"} = $row->{rate};
    }
    chop $form->{taxaccounts};
    $sth->finish;
  }
  
  $dbh->disconnect;

}


# ---------------------------------------------------------------------------
# Accrual accounting
#
# Called from SL::AA::post_transaction and SL::IS::post_invoice AFTER the source
# AR/AP has written its own acc_trans rows and ar/ap row is UPDATEd. Operates on
# the same $dbh so it joins the source transaction's DB transaction.
#
# Inputs (all on $form):
#   $form->{id}                    source AR/AP id (already set by caller)
#   $form->{accrual}               hashref: {period, length, startdate}
#                                  or undef/empty when no accrual is wanted
#   $form->{transdate}             source invoice transdate (used as default startdate)
#   $form->{invnumber}             used as the accrual GL reference
#   $form->{currency}, exchangerate (already locked at posting time)
#   $form->{precision}             from get_defaults
#   $form->{employee_id}, department_id
#
# $module is 'ar' or 'ap'.
#
# Side effects:
#   - DELETE existing accrual GL entry if config was removed or changed
#   - INSERT/refresh a gl row with accrual_source = "<module>:<source_id>"
#   - INSERT acc_trans pairs (accrual + reversal) for each period and chart
#   - UPDATE $table.accrual (JSONB) to include accrual_id so caller's UPDATE is
#     not required to know the new gl.id
# ---------------------------------------------------------------------------
sub post_accrual_entry {
  my ($self, $myconfig, $form, $dbh, $module) = @_;

  $module = lc($module || '');
  return unless $module eq 'ar' || $module eq 'ap';

  my $source_id = $form->{id} * 1;
  return unless $source_id;

  # Normalize accrual config: accept hashref or JSON string
  my $accrual = $form->{accrual};
  if (defined $accrual && !ref($accrual)) {
    eval { $accrual = decode_json($accrual); };
    $accrual = undef if $@;
  }

  # Find existing accrual_id if any (UPDATE has already run for AA, may not have for IS)
  my ($existing_accrual_id) = $dbh->selectrow_array(
    qq|SELECT (accrual->>'accrual_id')::int FROM $module WHERE id = $source_id|
  );

  # Determine whether to post or skip
  my $period = ($accrual && ref($accrual) eq 'HASH') ? lc($accrual->{period} || '') : '';
  my $length = ($accrual && ref($accrual) eq 'HASH') ? ($accrual->{length} * 1) : 0;
  my $startdate_str = ($accrual && ref($accrual) eq 'HASH') ? ($accrual->{startdate} || $form->{transdate}) : '';
  my $valid = ($period =~ /^(monthly|quarterly|yearly)$/) && $length > 0 && $startdate_str;

  # Cleanup-only path: tear down any existing accrual GL and clear the column
  unless ($valid) {
    if ($existing_accrual_id) {
      $dbh->do(qq|DELETE FROM acc_trans WHERE trans_id = $existing_accrual_id|);
      $dbh->do(qq|DELETE FROM gl WHERE id = $existing_accrual_id|);
    }
    $dbh->do(qq|UPDATE $module SET accrual = NULL WHERE id = $source_id|);
    return;
  }

  # Resolve accrual chart from defaults
  my $defaults_key = ($module eq 'ap') ? 'accrual_ap_chart_id' : 'accrual_ar_chart_id';
  my ($accrual_chart_id) = $dbh->selectrow_array(
    qq|SELECT fldvalue FROM defaults WHERE fldname = '$defaults_key'|
  );
  $accrual_chart_id = ($accrual_chart_id || '') * 1;
  $form->error("Accrual is enabled on $module $source_id but $defaults_key is not configured in Company Defaults.")
    unless $accrual_chart_id;

  # Validate startdate parses
  my ($sy, $sm, $sd) = $startdate_str =~ /^(\d{4})-(\d{2})-(\d{2})$/;
  $form->error("Invalid accrual.startdate '$startdate_str' on $module $source_id")
    unless $sy && $sm && $sd;
  my $start_dt = DateTime->new(year => $sy + 0, month => $sm + 0, day => $sd + 0);

  # Compute period_end dates and the service_end day (day AFTER last period close)
  my @period_ends;
  for my $k (1 .. $length) {
    my $pe;
    if ($period eq 'monthly') {
      # Last day of (start_month + k - 1)
      my $y = $start_dt->year;
      my $m = $start_dt->month + $k - 1;
      while ($m > 12) { $m -= 12; $y++; }
      my $next_m = $m + 1; my $next_y = $y;
      if ($next_m > 12) { $next_m = 1; $next_y++; }
      $pe = DateTime->new(year => $next_y, month => $next_m, day => 1)->subtract(days => 1);
    } elsif ($period eq 'quarterly') {
      # Quarter containing start, plus (k - 1) quarters
      my $sq = int(($start_dt->month - 1) / 3); # 0..3
      my $q_index = $sq + $k - 1;
      my $y = $start_dt->year + int($q_index / 4);
      my $q = $q_index % 4; # 0..3
      my $next_q_first_month = ($q + 1) * 3 + 1;
      my $next_y = $y;
      if ($next_q_first_month > 12) { $next_q_first_month -= 12; $next_y++; }
      $pe = DateTime->new(year => $next_y, month => $next_q_first_month, day => 1)->subtract(days => 1);
    } else { # yearly
      $pe = DateTime->new(year => $start_dt->year + $k - 1, month => 12, day => 31);
    }
    push @period_ends, $pe;
  }

  my $service_end = $period_ends[-1]->clone->add(days => 1);
  my $total_days = $service_end->delta_days($start_dt)->in_units('days');
  $form->error("Accrual length too short on $module $source_id: total_days=$total_days")
    unless $total_days > 0;

  # closedto guard — applies to every posting date in the schedule (accrual + reversal)
  my ($closedto) = $dbh->selectrow_array(qq|SELECT fldvalue FROM defaults WHERE fldname = 'closedto'|);
  if ($closedto && $closedto =~ /^\d{8}$/) {
    my $cd = DateTime->new(year => substr($closedto,0,4)+0, month => substr($closedto,4,2)+0, day => substr($closedto,6,2)+0);
    for my $pe (@period_ends) {
      $form->error("Accrual posting on " . $pe->ymd . " falls in the closed period (closedto = " . $cd->ymd . ")")
        if $pe <= $cd;
      my $rv = $pe->clone->add(days => 1);
      $form->error("Accrual reversal on " . $rv->ymd . " falls in the closed period (closedto = " . $cd->ymd . ")")
        if $rv <= $cd;
    }
  }

  # Per-chart base-currency totals from the source AR/AP's just-written acc_trans rows.
  # Tax lines (chart.link LIKE '%_tax') and fx_transaction rows are excluded — only the
  # expense/income recognition lines are subject to accrual.
  my $arap_amount_link = ($module eq 'ar') ? 'AR_amount' : 'AP_amount';
  my $line_sth = $dbh->prepare(qq|
    SELECT c.id AS chart_id, c.accno, SUM(ac.amount) AS amount
    FROM acc_trans ac
    JOIN chart c ON c.id = ac.chart_id
    WHERE ac.trans_id = ?
      AND ac.fx_transaction = '0'
      AND COALESCE(c.link, '') LIKE ?
      AND COALESCE(c.link, '') NOT LIKE '%_tax%'
    GROUP BY c.id, c.accno
    HAVING SUM(ac.amount) <> 0
  |);
  $line_sth->execute($source_id, '%' . $arap_amount_link . '%') || $form->dberror;
  my @source_lines;
  while (my $r = $line_sth->fetchrow_hashref) { push @source_lines, $r; }
  $line_sth->finish;

  unless (@source_lines) {
    # Nothing accruable — clean up any stale GL and bail.
    if ($existing_accrual_id) {
      $dbh->do(qq|DELETE FROM acc_trans WHERE trans_id = $existing_accrual_id|);
      $dbh->do(qq|DELETE FROM gl WHERE id = $existing_accrual_id|);
    }
    $dbh->do(qq|UPDATE $module SET accrual = NULL WHERE id = $source_id|);
    return;
  }

  # Pre-compute deferred amounts per period per source chart, using "last period =
  # total - sum(previous)" to absorb rounding so each chart's deferrals close exactly.
  my $precision = $form->{precision} || 2;
  my @schedule;  # array of { period_end, reversal_date, lines => [{chart_id, accno, amount}] }
  for my $k (1 .. $length) {
    my $pe = $period_ends[$k - 1];
    my $rv = $pe->clone->add(days => 1);
    push @schedule, { period_end => $pe, reversal_date => $rv, lines => [] };
  }

  for my $line (@source_lines) {
    my $total = $line->{amount} + 0; # base currency, signed
    my @per_period;
    my $running = 0;
    for my $k (1 .. $length) {
      my $pe = $period_ends[$k - 1];
      my $days_elapsed = $pe->clone->add(days => 1)->delta_days($start_dt)->in_units('days');
      my $remaining_days = $total_days - $days_elapsed;
      $remaining_days = 0 if $remaining_days < 0;
      my $deferred;
      if ($k == $length) {
        # last period: by construction this is 0 (service_end == period_end + 1),
        # but we keep the explicit formula for clarity.
        $deferred = $remaining_days == 0 ? 0 : $form->round_amount($total * $remaining_days / $total_days, $precision);
      } else {
        $deferred = $form->round_amount($total * $remaining_days / $total_days, $precision);
      }
      $running = $deferred;
      push @per_period, $deferred;
    }
    for my $k (1 .. $length) {
      push @{ $schedule[$k - 1]{lines} }, {
        chart_id => $line->{chart_id},
        accno    => $line->{accno},
        amount   => $per_period[$k - 1],
      };
    }
  }

  # Acquire/reuse the accrual GL header
  my $gl_id = $existing_accrual_id;
  my $default_currency = $form->{defaultcurrency} || $form->{currency};
  my $reference = $dbh->quote($form->{invnumber} || ($module . '-' . $source_id));
  my $description = $dbh->quote("Accrual schedule for " . uc($module) . " " . ($form->{invnumber} || $source_id));
  my $notes = $dbh->quote("auto-generated; period=$period, length=$length, start=$startdate_str");
  my $employee_id = ($form->{employee_id} || 0) * 1;
  my $department_id = ($form->{department_id} || 0) * 1;
  my $accrual_source_tag = $dbh->quote("$module:$source_id");

  if ($gl_id) {
    # wipe prior acc_trans rows for clean regeneration
    $dbh->do(qq|DELETE FROM acc_trans WHERE trans_id = $gl_id|) || $form->dberror;
    $dbh->do(qq|UPDATE gl SET
                reference = $reference,
                description = $description,
                notes = $notes,
                transdate = '$startdate_str',
                curr = '$default_currency',
                exchangerate = 1,
                employee_id = $employee_id,
                department_id = $department_id,
                approved = '1',
                accrual_source = $accrual_source_tag
                WHERE id = $gl_id|) || $form->dberror;
  } else {
    # Insert a fresh gl row using the legacy reference-uniqueness trick used elsewhere
    my $uid = localtime;
    $uid .= $$ . '-acc';
    $dbh->do(qq|INSERT INTO gl (reference, approved, accrual_source) VALUES ('$uid', '1', $accrual_source_tag)|)
      || $form->dberror;
    ($gl_id) = $dbh->selectrow_array(qq|SELECT id FROM gl WHERE reference = '$uid'|);
    $dbh->do(qq|UPDATE gl SET
                reference = $reference,
                description = $description,
                notes = $notes,
                transdate = '$startdate_str',
                curr = '$default_currency',
                exchangerate = 1,
                employee_id = $employee_id,
                department_id = $department_id
                WHERE id = $gl_id|) || $form->dberror;
  }

  # Sign convention:
  #   AP (expense accrual): each period defers expense back to accrual.
  #     Cr expense (source chart, negative)  ==  acc_trans.amount = -deferred
  #     Dr accrual chart (positive)          ==  acc_trans.amount = +deferred
  #   AR (revenue accrual): each period defers revenue into accrual.
  #     Dr revenue (source chart, positive)  ==  acc_trans.amount = +deferred
  #     Cr accrual chart (negative)          ==  acc_trans.amount = -deferred
  #
  # acc_trans uses positive=credit / negative=debit (matches SQL-Ledger convention used
  # elsewhere in this codebase). The source AR/AP rows already follow this with $ml/$arapml.
  #
  # In acc_trans on the SOURCE AR/AP: expense lines are stored as negative (debit) for AP
  # invoices. To unwind that we need to move the same magnitude in the OPPOSITE direction
  # in the accrual GL: i.e. on AP, the source-chart row in the accrual GL is positive
  # (credit, +deferred), and the accrual-chart row is negative (debit, -deferred).
  # That matches the user's example: Dr 1300 (accrual) Cr 6500 (expense) for the deferral.
  #
  # For AR the source-chart row in the original AR is positive (revenue, credit), so
  # the deferral debits it: source-chart row -deferred, accrual chart +deferred.
  #
  # Implementation: $source_sign multiplies $deferred for the source-chart row;
  #                 the accrual-chart row uses -$source_sign.
  my $source_sign = ($module eq 'ap') ? 1 : -1;

  for my $entry (@schedule) {
    my $pe_str = $entry->{period_end}->ymd;
    my $rv_str = $entry->{reversal_date}->ymd;
    for my $ln (@{ $entry->{lines} }) {
      next unless $ln->{amount};
      my $src_amount     =  $source_sign * $ln->{amount};
      my $accrual_amount = -$source_sign * $ln->{amount};
      my $src_id = $ln->{chart_id} * 1;
      my $memo = $dbh->quote("Accrual: " . $ln->{accno});
      my $rev_memo = $dbh->quote("Accrual reversal: " . $ln->{accno});

      # Accrual posting at period end
      $dbh->do(qq|INSERT INTO acc_trans
        (trans_id, chart_id, amount, transdate, source, fx_transaction, memo, approved)
        VALUES ($gl_id, $src_id, $src_amount, '$pe_str', 'accrual', '0', $memo, '1')|)
        || $form->dberror;
      $dbh->do(qq|INSERT INTO acc_trans
        (trans_id, chart_id, amount, transdate, source, fx_transaction, memo, approved)
        VALUES ($gl_id, $accrual_chart_id, $accrual_amount, '$pe_str', 'accrual', '0', $memo, '1')|)
        || $form->dberror;

      # Reversal on the next day
      $dbh->do(qq|INSERT INTO acc_trans
        (trans_id, chart_id, amount, transdate, source, fx_transaction, memo, approved)
        VALUES ($gl_id, $src_id, |.(-$src_amount).qq|, '$rv_str', 'accrual_reversal', '0', $rev_memo, '1')|)
        || $form->dberror;
      $dbh->do(qq|INSERT INTO acc_trans
        (trans_id, chart_id, amount, transdate, source, fx_transaction, memo, approved)
        VALUES ($gl_id, $accrual_chart_id, |.(-$accrual_amount).qq|, '$rv_str', 'accrual_reversal', '0', $rev_memo, '1')|)
        || $form->dberror;
    }
  }

  # Persist the accrual config (including the new accrual_id) on the source row
  my $accrual_json_obj = {
    period    => $period,
    length    => $length + 0,
    startdate => $startdate_str,
    accrual_id => $gl_id + 0,
  };
  my $accrual_json = encode_json($accrual_json_obj);
  my $q_json = $dbh->quote($accrual_json);
  $dbh->do(qq|UPDATE $module SET accrual = $q_json :: jsonb WHERE id = $source_id|)
    || $form->dberror;

  return $gl_id;
}


1;

