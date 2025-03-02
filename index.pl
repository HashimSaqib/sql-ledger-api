#!/usr/bin/env perl

BEGIN {
    push @INC, '.';
}

use Mojolicious::Lite;
use XML::Hash::XS;
use Data::Dumper;
use Mojo::Util qw(unquote);
use Mojo::JSON qw(encode_json);
use JSON       qw (decode_json);
use Mojo::File;
use Encode;
use MIME::Base64;
use Mojo::UserAgent;
use DBI;
use DBIx::Simple;
use SQL::Abstract;
use XML::Simple;
use SL::Form;
use SL::AM;
use SL::CT;
use SL::RP;
use SL::AA;
use SL::IS;
use SL::IR;
use SL::CA;
use SL::CP;
use SL::GL;
use SL::RC;
use DateTime;
use DateTime::Format::ISO8601;
use Date::Parse;
use File::Path qw(make_path);
use POSIX      qw(strftime);
use Time::Piece;
use Mojo::Template;
use File::Slurp;

app->config( hypnotoad => { listen => ['http://*:3000'] } );

my %myconfig = (
    dateformat   => 'yyyy/mm/dd',
    dbdriver     => 'Pg',
    dbhost       => '',
    dbname       => '',
    dbpasswd     => '',
    dbport       => '',
    dbuser       => 'postgres',
    numberformat => '1,000.00',
);

helper slconfig => sub { \%myconfig };

helper dbs => sub {
    my ( $c, $dbname ) = @_;

    my $dbh;
    eval {
        $dbh = DBI->connect( "dbi:Pg:dbname=$dbname", 'postgres', '',
            { RaiseError => 1, PrintError => 1 } );
    };

    if ( $@ || !$dbh ) {
        my $error_message = $DBI::errstr // $@ // "Unknown error";

        # Ensure no further processing or responses are sent after this
        $c->render(
            status => 500,
            json   => {
                message =>
                  "Failed to connect to the database '$dbname': $error_message"
            }
        );
        $c->app->log->error(
            "Failed to connect to the database '$dbname': $error_message");
        return undef;    # Return undef to prevent further processing
    }

    my $dbs = DBIx::Simple->connect($dbh);
    return $dbs;
};

helper validate_date => sub {
    my ( $c, $date ) = @_;
    unless ( $date =~ /^\d{4}-\d{2}-\d{2}$/ ) {
        return $c->render(
            status => 400,
            json   => {
                message =>
"Invalid date format. Expected ISO 8601 date format (YYYY-MM-DD).",
            },
        );
    }
    return 1;    # return true if the date is valid
};

#Ledger API Calls

my $r = app->routes;

my $api = $r->under('/client/:client');

# Enable CORS for all routes
app->hook(
    before_dispatch => sub {
        my $c = shift;
        $c->res->headers->header( 'Access-Control-Allow-Origin' => '*' );
        $c->res->headers->header( 'Access-Control-Allow-Methods' =>
              'GET, POST, PUT, DELETE, OPTIONS' );
        $c->res->headers->header( 'Access-Control-Allow-Headers' =>
              'Origin, X-Requested-With, Content-Type, Accept, Authorization' );
        $c->res->headers->header( 'Access-Control-Max-Age' => '3600' );
        $c->res->headers->header(
            'Access-Control-Allow-Credentials' => 'true' );
        return unless $c->req->method eq 'OPTIONS';
        $c->render( text => '', status => 204 );
        return 1;
    }
);

# Override render_exception to return JSON and include CORS headers
app->hook(
    around_dispatch => sub {
        my ( $next, $c ) = @_;
        eval { $next->(); 1 } or do {
            my $error = $@ || 'Unknown error';
            $c->res->headers->header( 'Access-Control-Allow-Origin' => '*' );
            $c->res->headers->header( 'Access-Control-Allow-Methods' =>
                  'GET, POST, PUT, DELETE, OPTIONS' );
            $c->res->headers->header( 'Access-Control-Allow-Headers' =>
'Origin, X-Requested-With, Content-Type, Accept, Authorization'
            );
            $c->render(
                status => 500,
                json   => { message => "$error" }
            );
        };
    }
);

#########################
####                 ####
####    LANGUAGE     ####
####                 ####
#########################
# Route to serve language packs
$api->get(
    '/languages/:locale' => sub {
        my $c = shift;

        my $locale = $c->stash('locale');

        my $file_path = "languages/$locale.json";

        # Check if file exists
        unless ( -e $file_path ) {
            return $c->reply->not_found;
        }

        # Read the file content
        my $json_text;
        {
            local $/;
            open my $fh, $file_path or do {

                return $c->render(
                    status => 500,
                    json   =>
                      { error => "Unable to read language file for $locale" }
                );
            };
            $json_text = <$fh>;
            close $fh;
        }

        my $data;
        eval {
            $data = decode_json($json_text);
            1;
        } or do {

            # If JSON is invalid, return a server error
            return $c->render(
                status => 500,
                json   => { error => "Invalid JSON in $file_path" }
            );
        };

        # Return the JSON data
        $c->render( json => $data );
    }
);

#########################
#### AUTH   +        ####
#### ACCESS CONTROL  ####
####                 ####
#########################

my $allMenuItems =
qq'AR--AR;AR--Add Transaction;AR--Sales Invoice;AR--Credit Note;AR--Credit Invoice;AR--Reports;POS--POS;POS--Sale;POS--Open;POS--Receipts;Customers--Customers;Customers--Add Customer;Customers--Reports;AP--AP;AP--Add Transaction;AP--Vendor Invoice;AP--Debit Note;AP--Debit Invoice;AP--Reports;Vendors--Vendors;Vendors--Add Vendor;Vendors--Reports;Cash--Cash;Cash--Receipt;Cash--Receipts;Cash--Payment;Cash--Payments;Cash--Void Check;Cash--Reissue Check;Cash--Void Receipt;Cash--Reissue Receipt;Cash--FX Adjustment;Cash--Reconciliation;Cash--Reports;Vouchers--Vouchers;Vouchers--Payable;Vouchers--Payment;Vouchers--Payments;Vouchers--Payment Reversal;Vouchers--General Ledger;Vouchers--Reports;HR--HR;HR--Employees;HR--Payroll;Order Entry--Order Entry;Order Entry--Sales Order;Order Entry--Purchase Order;Order Entry--Reports;Order Entry--Generate;Order Entry--Consolidate;Logistics--Logistics;Logistics--Merchandise;Logistics--Reports;Quotations--Quotations;Quotations--Quotation;Quotations--RFQ;Quotations--Reports;General Ledger--General Ledger;General Ledger--Add Transaction;General Ledger--Reports;Goods & Services--Goods & Services;Goods & Services--Add Part;Goods & Services--Add Service;Goods & Services--Add Kit;Goods & Services--Add Assembly;Goods & Services--Add Labor/Overhead;Goods & Services--Add Group;Goods & Services--Add Pricegroup;Goods & Services--Stock Assembly;Goods & Services--Stock Adjustment;Goods & Services--Reports;Goods & Services--Changeup;Goods & Services--Translations;Projects & Jobs--Projects & Jobs;Projects & Jobs--Projects;Projects & Jobs--Jobs;Projects & Jobs--Translations;Reference Documents--Reference Documents;Reference Documents--Add Document;Reference Documents--List Documents;Image Files--Image Files;Image Files--Add File;Image Files--List Files;Reports--Reports;Reports--Chart of Accounts;Reports--Trial Balance;Reports--Income Statement;Reports--Balance Sheet;Recurring Transactions--Recurring Transactions;Batch--Batch;Batch--Print;Batch--Email;Batch--Queue;Exchange Rates--Exchange Rates;Import--Import;Import--Customers;Import--Vendors;Import--Parts;Import--Services;Import--Labor/Overhead;Import--Sales Invoices;Import--Groups;Import--Payments;Import--Sales Orders;Import--Purchase Orders;Import--Chart of Accounts;Import--General Ledger;Export--Export;Export--Payments;System--System;System--Defaults;System--Audit Control;System--Audit Log;System--Bank Accounts;System--Taxes;System--Currencies;System--Payment Methods;System--Workstations;System--Roles;System--Warehouses;System--Departments;System--Type of Business;System--Language;System--Mimetypes;System--SIC;System--Yearend;System--Maintenance;System--Backup;System--Chart of Accounts;System--html Templates;System--XML Templates;System--LaTeX Templates;System--Text Templates;Stylesheet--Stylesheet;Preferences--Preferences;New Window--New Window;Version--Version;Logout--Logout';
my $neoLedgerMenu =
qq'General Ledger--General Ledger;General Ledger--Add Transaction;General Ledger--Reports;System--System;System--Currencies';

helper check_perms => sub {
    my ( $c, $permission ) = @_;
    my $client     = $c->param('client');
    my $sessionkey = $c->req->headers->header('Authorization');
    my $dbs        = $c->dbs($client);

    # Step 1: Validate session
    my $session =
      $dbs->query( 'SELECT employeeid FROM session WHERE sessionkey = ?',
        $sessionkey )->hash;

    unless ($session) {
        $c->render(
            status => 401,
            json   => { message => "Invalid session key" }
        );
        return 0;    # Return false after rendering
    }

    my $employee_id = $session->{employeeid};

    # Step 2: Check if user is admin
    my $is_admin =
      $dbs->query( 'SELECT admin FROM login WHERE employeeid = ?',
        $employee_id )->hash->{admin};

    return 1 if $is_admin;    # Allow if user is admin

    # Step 3: Get acsrole_id
    my $acsrole_id =
      $dbs->query( 'SELECT acsrole_id FROM employee WHERE id = ?',
        $employee_id )->hash->{acsrole_id};

    # Step 4: Get restricted permissions
    my $acs_string =
      $dbs->query( 'SELECT acs FROM acsrole WHERE id = ?', $acsrole_id )
      ->hash->{acs};

    # Step 5: Check permission against restricted list
    my @restricted_perms = split( ';', $acs_string );
    if ( grep { $_ eq $permission } @restricted_perms ) {
        $c->render(
            status => 403,
            json   => { message => "Permission '$permission' is not allowed" }
        );
        return 0;    # Return false after rendering
    }

    return 1;        # Permission is allowed
};

$api->post(
    '/auth/validate' => sub {
        my $c          = shift;
        my $client     = $c->param('client');
        my $sessionkey = $c->req->params->to_hash->{sessionkey};
        my $dbs        = $c->dbs($client);

        # Query the database to validate the sessionkey
        my $result =
          $dbs->query( "SELECT * FROM session WHERE sessionkey = ?",
            $sessionkey )->hash;
        warn($result);
        if ($result) {

            # Session key is valid, return true
            $c->render( json => { success => 1 } );
        }
        else {
# Session key is not valid, return a 401 Not Authorized code with an error message
            $c->render(
                status => 401,
                json   => { message => "Not Authorized: Invalid session key" }
            );
        }
    }
);

$api->post(
    '/auth/login' => sub {
        my $c      = shift;
        my $params = $c->req->json;
        my $client = $c->param('client');

        my $username_with_db = $params->{username};
        my $password         = $params->{password};

        # Split the username based on "@"
        my ( $username, $dbname ) = split( '@', $username_with_db );

        # Check if dbname is provided
        unless ($dbname) {
            return $c->render(
                status => 400,
                json   =>
                  { message => "Database name is required in the username" }
            );
        }

        # Establish a database connection using the dbname
        my $dbs = $c->dbs($dbname);

# If the database connection failed, it would have already returned an error response
        return unless $dbs;

        # Check for the username in the employee table
        my $employee =
          $dbs->query( 'SELECT id FROM employee WHERE login = ?', $username )
          ->hash;
        unless ($employee) {
            return $c->render(
                status => 400,
                json   => { message => "Employee record does not exist" }
            );
        }

        my $employee_id = $employee->{id};

    # Check if the API account exists in the login table and verify the password
        my $login = $dbs->query( '
        SELECT password
        FROM login
        WHERE employeeid = ? AND crypt(?, password) = password
    ', $employee_id, $password )->hash;

        unless ($login) {
            return $c->render(
                status => 400,
                json   => { message => "Incorrect username or password" }
            );
        }

        my $session_key = $dbs->query(
'INSERT INTO session (employeeid, sessionkey) VALUES (?, encode(gen_random_bytes(32), ?)) RETURNING sessionkey',
            $employee_id, 'hex'
        )->hash->{sessionkey};

        my $company =
          $dbs->query( "SELECT * FROM defaults WHERE fldname = ?", "company" )
          ->hash;

        # Return the session key
        return $c->render(
            json => {
                sessionkey => $session_key,
                client     => $dbname,
                company    => $company->{fldvalue}
            }
        );
    }
);

$api->post(
    '/auth/create_api_login' => sub {
        my $c          = shift;
        my $client     = $c->param('client');
        my $params     = $c->req->params->to_hash;
        my $employeeid = $params->{employeeid};
        my $password   = $params->{password};

        # Step 1: Check for missing parameters
        unless ( $employeeid && $password ) {
            return $c->render(
                status => 400,
                json   => {
                    message =>
                      "Missing required parameters 'employeeid' or 'password'"
                }
            );
        }

        # Step 2: Try to connect to the existing database using the client name
        my $dbs;
        eval { $dbs = $c->dbs($client); };
        if ($@) {
            return $c->render(
                status => 500,
                json   => {
                    message =>
                      "Failed to connect to the client database '$client': $@"
                }
            );
        }

        # Step 3: Use PostgreSQL to hash the password with bcrypt
        my $hashed_password;
        eval {
            my $query = '
            INSERT INTO login (employeeid, password)
            VALUES (?, crypt(?, gen_salt(\'bf\')))
        ';
            $dbs->query( $query, $employeeid, $password );
        };
        if ($@) {
            return $c->render(
                status => 500,
                json   => { message => "Failed to create API login: $@" }
            );
        }

        # Step 4: Return success message
        return $c->render(
            json => {
                message =>
                  "API login created successfully for user '$employeeid'"
            }
        );
    }
);

#########################
####                 ####
#### GL Transactions ####
####                 ####
#########################
$api->get(
    '/gl/transactions/lines' => sub {
        my $c      = shift;
        my $params = $c->req->params->to_hash;
        my $client = $c->param('client');

        my $permission = "General Ledger--Reports";
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        my $form = new Form;
        for ( keys %$params ) { $form->{$_} = $params->{$_} if $params->{$_} }
        $form->{category} = 'X';
        GL->transactions( $c->slconfig, $form );

        # Check if the result is undefined, empty, or has no entries
        if (  !defined( $form->{GL} )
            || ref( $form->{GL} ) ne 'ARRAY'
            || scalar( @{ $form->{GL} } ) == 0 )
        {
            return $c->render(
                status => 404,
                json   => { message => "No transactions found" },
            );
        }

        # Assuming $form->{GL} is an array reference with hash references
        foreach my $transaction ( @{ $form->{GL} } ) {
            my $full_address = join( ' ',
                $form->{address1} // '',
                $form->{address2} // '',
                $form->{city}     // '',
                $form->{state}    // '',
                $form->{country}  // '' );

        }

        $c->render( status => 200, json => $form->{GL} );
    }
);

$api->get(
    '/gl/transactions' => sub {
        my $c      = shift;
        my $client = $c->param('client');

        # Create the DBIx::Simple handle
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        my $dbs = $c->dbs($client);

        # Searching Parameters
        my $datefrom    = $c->param('datefrom');
        my $dateto      = $c->param('dateto');
        my $description = $c->param('description');
        my $notes       = $c->param('notes');
        my $reference   = $c->param('reference');
        my $accno       = $c->param('accno');

        # Validate Date
        if ($datefrom) { $c->validate_date($datefrom) or return; }
        if ($dateto)   { $c->validate_date($dateto)   or return; }

        my $query =
'SELECT id, reference, transdate, description, notes, curr, department_id AS department, approved, ts, exchangerate AS exchangeRate, employee_id FROM gl';
        my @query_params;

        my @conditions;
        if ( $datefrom && $dateto ) {
            push @conditions, 'transdate BETWEEN ? AND ?';
            push @query_params, $datefrom, $dateto;
        }
        elsif ($datefrom) {
            push @conditions,   'transdate = ?';
            push @query_params, $datefrom;
        }

        if ($description) {
            push @conditions,   'description ILIKE ?';
            push @query_params, "%$description%";
        }

        if ($notes) {
            push @conditions,   'notes ILIKE ?';
            push @query_params, "%$notes%";
        }

        if ($reference) {
            push @conditions,   'reference ILIKE ?';
            push @query_params, "%$reference%";
        }

        if (@conditions) {
            $query .= ' WHERE ' . join( ' AND ', @conditions );
        }

# If accno is specified, collect transaction IDs that involve the specified account number
        my %transaction_ids_for_accno;
        if ($accno) {
            my $accno_query =
'SELECT DISTINCT acc_trans.trans_id FROM acc_trans JOIN chart ON acc_trans.chart_id = chart.id WHERE chart.accno = ?';
            my $accno_results = $dbs->query( $accno_query, $accno );
            while ( my $row = $accno_results->hash ) {
                $transaction_ids_for_accno{ $row->{trans_id} } = 1;
            }
        }

        my $ngl_results = $dbs->query( $query, @query_params );
        my @transactions;

        while ( my $transaction = $ngl_results->hash ) {

      # If accno is specified and the transaction ID is not in the list, skip it
            next
              if ( $accno
                && !$transaction_ids_for_accno{ $transaction->{id} } );

            my $entries_results = $dbs->query(
'SELECT chart.accno, chart.description, acc_trans.amount, acc_trans.source, acc_trans.memo, acc_trans.tax_chart_id, acc_trans.taxamount, acc_trans.fx_transaction, acc_trans.cleared FROM acc_trans JOIN chart ON acc_trans.chart_id = chart.id WHERE acc_trans.trans_id = ?',
                $transaction->{id}
            );
            my @lines;

            while ( my $line = $entries_results->hash ) {
                my $debit  = $line->{amount} < 0  ? -$line->{amount}   : 0;
                my $credit = $line->{amount} >= 0 ? $line->{amount}    : 0;
                my $fx_transaction = $line->{fx_transaction} == 1 ? \1 : \0;
                my $taxAccount =
                  $line->{tax_chart_id} == 0 ? undef : $line->{tax_chart_id};

                push @lines,
                  {
                    accno          => $line->{accno},
                    debit          => $debit,
                    credit         => $credit,
                    memo           => $line->{memo},
                    source         => $line->{source},
                    taxAccount     => $taxAccount,
                    taxAmount      => $line->{taxamount},
                    fx_transaction => $fx_transaction,
                    cleared        => $line->{cleared},
                  };
            }

            $transaction->{lines} = \@lines;
            push @transactions, $transaction;
        }

        $c->render( json => \@transactions );
    }
);

#Get An Individual GL transaction
$api->get(
    '/gl/transactions/:id' => sub {
        my $c      = shift;
        my $id     = $c->param('id');
        my $client = $c->param('client');

        # Create the DBIx::Simple handle
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        my $dbs = $c->dbs($client);

        # Check if the ID exists in the gl table
        my $result = $dbs->select( 'gl', '*', { id => $id } );

        unless ( $result->rows ) {

            # ID not found, return a 404 error with JSON response
            return $c->render(
                status => 404,
                json   => {
                    message => "The requested GL transaction was not found."
                }
            );
        }

        # If the ID exists, proceed with the rest of the code
        my $form = new Form;

        $form->{id} = $id;
        GL->transaction( $c->slconfig, $form );

        warn( Dumper $form );

        # Extract the GL array and rename it to "LINES" in the JSON response
        my @lines;
        if ( exists $form->{GL} && ref $form->{GL} eq 'ARRAY' ) {
            @lines = @{ $form->{GL} };
            for my $line (@lines) {

                # Create a new hash with only the required fields
                my %new_line;

                $new_line{credit} =
                    $line->{amount} > 0
                  ? $line->{amount}
                  : 0;    # Assuming amount > 0 is debit
                $new_line{debit} =
                  $line->{amount} < 0
                  ? -$line->{amount}
                  : 0;    # Assuming amount < 0 is credit
                $new_line{linetaxamount} = $line->{linetaxamount};

                $new_line{accno} = $line->{accno};
                $new_line{taxAccount} =
                  $line->{tax_chart_id} == 0
                  ? undef
                  : $line->{tax_chart_id};
                $new_line{cleared} = $line->{cleared};
                $new_line{memo}    = $line->{memo};
                $new_line{source}  = $line->{source};

                # Modify fx_transaction assignment based on fx_transaction value
                $new_line{fx_transaction} =
                  $line->{fx_transaction} == 1 ? \1 : \0;

                $line = \%new_line;
            }
        }

        my $response = {
            id           => $form->{id},
            reference    => $form->{reference},
            approved     => $form->{approved},
            ts           => $form->{ts},
            curr         => $form->{curr},
            description  => $form->{description},
            notes        => $form->{notes},
            department   => $form->{department},
            transdate    => $form->{transdate},
            ts           => $form->{ts},
            exchangeRate => $form->{exchangerate},
            employeeId   => $form->{employee_id},
            lines        => \@lines,
        };

        $c->render( status => 200, json => $response );
    }
);

$api->post(
    '/gl/transactions' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $data   = $c->req->json;

        # Create the DBIx::Simple handle
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        my $dbs = $c->dbs($client);

        api_gl_transaction( $c, $dbs, $data );
    }
);

$api->put(
    '/gl/transactions/:id' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $id;
        $id = $c->param('id');
        my $data = $c->req->json;

        # Create the DBIx::Simple handle
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        my $dbs = $c->dbs($client);

        # Check for existing id in the GL table if id is provided
        if ($id) {
            my $existing_entry =
              $dbs->query( "SELECT id FROM gl WHERE id = ?", $id )->hash;
            unless ($existing_entry) {
                return $c->render(
                    status => 404,
                    json   => {
                        message => "Transaction with ID $id not found."
                    }
                );
            }
        }
        api_gl_transaction( $c, $dbs, $data, $id );
    }
);

sub api_gl_transaction () {
    my ( $c, $dbs, $data, $id ) = @_;

    # Check if 'transdate' is present in the data
    unless ( exists $data->{transdate} ) {
        return $c->render(
            status => 400,
            json   => { message => "The 'transdate' field is required.", }
        );
    }

    my $transdate = $data->{transdate};

    # Validate 'transdate' format (ISO date format)
    unless ( $transdate =~ /^\d{4}-\d{2}-\d{2}$/ ) {
        return $c->render(
            status => 400,
            json   => {
                message =>
"Invalid 'transdate' format. Expected ISO 8601 date format (YYYY-MM-DD)."
            }

        );
    }

    # Check if 'lines' is present and is an array reference
    unless ( exists $data->{lines} && ref $data->{lines} eq 'ARRAY' ) {
        return $c->render(
            status => 400,
            json   => { message => "The 'lines' array is required." },
        );
    }

    # Find the default currency from the database
    my $default_result = $dbs->query("SELECT curr FROM curr WHERE rn = 1");
    my $default_row    = $default_result->hash;
    unless ($default_row) {
        die "Default currency not found in the database!";
    }
    my $default_currency = $default_row->{curr};

# Check if the provided currency exists in the 'curr' column of the database table
    my $result =
      $dbs->query( "SELECT rn, curr FROM curr WHERE curr = ?", $data->{curr} );
    unless ( $result->rows ) {
        return $c->render(
            status => 400,
            json   => { message => "The specified currency does not exist." },
        );
    }

 # If the provided currency is not the default currency, check for exchange rate
    my $row = $result->hash;
    if ( $row->{curr} ne $default_currency
        && !exists $data->{exchangeRate} )
    {
        return $c->render(
            status => 400,
            json   => {
                message =>
"A non-default currency has been used. Exchange rate is required."
            },
        );
    }

    # Create a new form
    my $form = new Form;

    if ($id) {
        $form->{id} = $id;
    }

    if ( !$data->{department} ) { $data->{department} = 0 }

    # Load the input data into the form
    $form->{reference}       = $data->{reference};
    $form->{department}      = $data->{department};
    $form->{notes}           = $data->{notes};
    $form->{description}     = $data->{description};
    $form->{curr}            = $data->{curr};
    $form->{currency}        = $data->{curr};
    $form->{exchangerate}    = $data->{exchangeRate};
    $form->{transdate}       = $transdate;
    $form->{defaultcurrency} = $default_currency;

    my $total_debit  = 0;
    my $total_credit = 0;
    my $i            = 1;
    foreach my $line ( @{ $data->{lines} } ) {

        my $acc_id =
          $dbs->query( "SELECT id from chart WHERE accno = ?", $line->{accno} );

        if ( !$acc_id ) {
            return $c->render(
                status => 400,
                json   => {
                        message => "Account with the accno "
                      . $line->{accno}
                      . " does not exist.",
                },
            );
        }

        # Process the regular line
        $form->{"debit_$i"}         = $line->{debit};
        $form->{"credit_$i"}        = $line->{credit};
        $form->{"accno_$i"}         = $line->{accno};
        $form->{"tax_$i"}           = $line->{taxAccount};
        $form->{"linetaxamount_$i"} = $line->{linetaxamount};
        $form->{"cleared_$i"}       = $line->{cleared};
        $form->{"memo_$i"}          = $line->{memo};
        $form->{"source_$i"}        = $line->{source};

        $i++;    # Increment the counter after processing the regular line
    }

    # Check if total_debit equals total_credit
    unless ( $total_debit == $total_credit ) {
        return $c->render(
            status => 400,
            json   => {
                message =>
"Total Debits ($total_debit) must equal Total Credits ($total_credit).",
            },
        );
    }

    # Adjust row count based on the counter
    $form->{rowcount} = $i - 1;

    # Call the function to add the transaction
    $id = GL->post_transaction( $c->slconfig, $form );

    warn $c->dumper($form);

    # Convert the Form object back into a JSON-like structure
    my $response_json = {
        id           => $form->{id},
        reference    => $form->{reference},
        department   => $form->{department},
        notes        => $form->{notes},
        description  => $form->{description},
        curr         => $form->{curr},
        exchangeRate => $form->{exchangerate},
        transdate    => $form->{transdate},
        employeeId   => $form->{employee_id},
        lines        => []
    };

    for my $i ( 1 .. $form->{rowcount} ) {

        my $taxAccount =
          $form->{"tax_$i"} == 0
          ? undef
          : $form->{"tax_$i"};    # Set to undef if the tax value is 0

        push @{ $response_json->{lines} },
          {
            debit          => $form->{"debit_$i"},
            credit         => $form->{"credit_$i"},
            accno          => $form->{"accno_$i"},
            taxAccount     => $taxAccount,
            taxAmount      => $form->{"taxamount_$i"},
            cleared        => $form->{"cleared_$i"},
            memo           => $form->{"memo_$i"},
            source         => $form->{"source_$i"},
            fx_transaction => \0,
          };
    }

    my $status_code =
      $c->param('id') ? 200 : 201;    # 200 for update, 201 for create

    $c->render(
        status => $status_code,
        json   => $response_json,
    );
}

$api->delete(
    '/gl/transactions/:id' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $id     = $c->param('id');

        # Create the DBIx::Simple handle
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        my $dbs = $c->dbs($client);

        # Check for existing id in the GL table
        my $existing_entry =
          $dbs->query( "SELECT id FROM gl WHERE id = ?", $id )->hash;
        unless ($existing_entry) {
            return $c->render(
                status => 404,
                json   => {
                    message => "Transaction with ID $id not found."
                }
            );
        }

        # Create a new form and add the id
        my $form = new Form;
        $form->{id} = $id;

        # Delete the transaction
        GL->delete_transaction( $c->slconfig, $form );

        # Delete the entry from the gl table
        $dbs->query( "DELETE FROM gl WHERE id = ?", $id );

        $c->render( status => 204, data => '' );
    }
);

#########################
####                 ####
####      Chart      ####
####                 ####
#########################

$api->get(
    '/charts' => sub {
        my $c      = shift;
        my $client = $c->param('client');

        # Create the DBIx::Simple handle
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        my $dbs = $c->dbs($client);

        # Get link strings from query parameters (e.g., ?link=AR_tax,AP_tax)
        my @links = $c->param('link') ? split( ',', $c->param('link') ) : ();

        # Start with the base query
        my $sql = "SELECT * FROM chart";

        # If links are provided, add a WHERE clause to filter entries
        if (@links) {
            my @conditions;
            foreach my $link (@links) {
            }
            my $where_clause = join( ' AND ', @conditions );
            $sql .= " WHERE $where_clause";
        }

        # Execute the query with the necessary parameters
        my $entries = $dbs->query( $sql, map { "%$_%" } @links )->hashes;

        # Add the "label" property to each entry
        foreach my $entry (@$entries) {
            $entry->{label} = $entry->{accno} . '--' . $entry->{description};
        }

        if ($entries) {
            return $c->render(
                status => 200,
                json   => $entries
            );
        }
        else {
            return $c->render(
                status => 404,
                json   => { message => "No accounts found" }
            );
        }
    }
);

$api->post(
    '/charts' => sub {
        my $c      = shift;
        my $client = $c->param('client');

        # Create the DBIx::Simple handle
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        my $dbs = $c->dbs($client);

        # Parse JSON request body
        my $data = $c->req->json;

        unless ($data) {
            return $c->render(
                status => 400,
                json   => { message => "Invalid JSON in request body" }
            );
        }

        # Get the necessary parameters from the parsed JSON
        my $accno       = $data->{accno};
        my $description = $data->{description};
        my $charttype   = $data->{charttype} // 'A';
        my $category    = $data->{category};
        my $link        = $data->{link};
        my $gifi_accno  = $data->{gifi_accno};
        my $contra      = $data->{contra} // 'false';
        my $allow_gl    = $data->{allow_gl};

        # Validate required fields
        unless ( $accno && $description ) {
            return $c->render(
                status => 400,
                json   =>
                  { message => "Missing required fields: accno, description" }
            );
        }

        # Validate charttype
        unless ( $charttype eq 'A' || $charttype eq 'H' ) {
            return $c->render(
                status => 400,
                json   =>
                  { message => "Invalid charttype. Must be either 'A' or 'H'" }
            );
        }

        # Validate category
        my @valid_categories = qw(A L I Q E);
        unless ( $category && length($category) == 1 && grep { $_ eq $category }
            @valid_categories )
        {
            return $c->render(
                status => 400,
                json   => {
                    message =>
                      "Invalid category. Must be one of 'A', 'L', 'I', 'Q', 'E'"
                }
            );
        }

        # Prepare SQL for insertion
        my $sql_insert =
"INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl) 
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

        # Execute the insertion
        my $result = $dbs->query(
            $sql_insert, $accno,      $description, $charttype, $category,
            $link,       $gifi_accno, $contra,      $allow_gl
        );

        if ( $result->affected ) {

            # Retrieve the newly created entry
            my $new_entry =
              $dbs->query( "SELECT * FROM chart WHERE accno = ?", $accno )
              ->hash;

            return $c->render(
                status => 201,
                json   => {
                    message => "Chart entry created successfully",
                    entry   => $new_entry
                }
            );
        }
        else {
            return $c->render(
                status => 500,
                json   => { message => "Failed to create chart entry" }
            );
        }
    }
);

###############################
####                       ####
####    System Settings    ####
####                       ####
###############################

$api->get(
    '/system/currencies' => sub {
        my $c      = shift;
        my $client = $c->param('client');

        my $dbs = $c->dbs($client);

        my $currencies;
        eval { $currencies = $dbs->query("SELECT * FROM curr")->hashes; };

        if ($@) {
            return $c->render(
                status => 500,
                json   =>
                  { error => { message => 'Failed to retrieve currencies' } }
            );
        }

        $c->render( json => $currencies );
    }
);

$api->any(
    [qw(POST PUT)] => '/system/currencies' => sub {
        my $c      = shift;
        my $client = $c->param('client');

        # Get JSON body params
        my $params = $c->req->json;
        my $curr   = $params->{curr} || '';
        my $prec   = $params->{prec} || '';

        # Validate input parameters
        unless ( $curr =~ /^[A-Z]{3}$/
            && $prec =~ /^\d+$/
            && $prec >= 0
            && $prec <= 10 )
        {
            return $c->render(
                status => 400,
                json   => { message => 'Invalid input parameters' }
            );
        }

        my $dbs = $c->dbs($client);

        my $form = new Form;
        $form->{curr}             = $curr;
        $form->{prec}             = $prec;
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        AM->save_currency( $c->slconfig, $form );

        return $c->render(
            status => 201,
            json   => { message => 'Currency created successfully' }
        );
    }
);

$api->delete(
    '/system/currencies/:curr' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $curr   = $c->param('curr');

        # Validate input parameter
        unless ( $curr =~ /^[A-Z]{3}$/ ) {
            return $c->render(
                status => 400,
                json   => { message => 'Invalid currency code' }
            );
        }

        my $dbs = $c->dbs($client);

        # Create a form object with the currency code
        my $form = new Form;
        $form->{curr} = $curr;
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        # Call the delete method from AM module
        AM->delete_currency( $c->slconfig, $form );

        # Return no content (204)
        return $c->rendered(204);
    }
);
$api->get(
    '/system/companydefaults' => sub {
        my $c      = shift;
        my $client = $c->param('client');

        my $dbs = $c->dbs($client);

        my $form = Form->new;
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        AM->defaultaccounts( $c->slconfig, $form );

        # Build arrays for "select$key" instead of a string
        foreach my $key ( keys %{ $form->{accno} } ) {
            my @select_array;

            foreach my $accno ( sort keys %{ $form->{accno}{$key} } ) {
                my $acc_entry = {
                    accno       => $accno,
                    description => $form->{accno}{$key}{$accno}{description},
                    id          => $form->{accno}{$key}{$accno}{id},
                };

                # Check if this is the default selection
                if ( $form->{accno}{$key}{$accno}{id} ==
                    $form->{defaults}{$key} )
                {
                    # Instead of a string, store the chosen entry as a hash
                    $form->{$key} = {
                        accno       => $accno,
                        description =>
                          $form->{accno}{$key}{$accno}{description},
                        id => $form->{accno}{$key}{$accno}{id},
                    };
                }

                push @select_array, $acc_entry;
            }

            # Assign the array to $form->{"select$key"}
            $form->{$key} = \@select_array;
        }

        # Remove raw data we no longer need
        for (qw(accno defaults)) {
            delete $form->{$_};
        }

        # Query to check if linetaxamount is greater than 0 in any row
        my $lock_linetax_query = $dbs->query(
"SELECT EXISTS (SELECT 1 FROM acc_trans WHERE linetaxamount <> 0) AS locklinetax"
        );

        my $lock_linetax_result = $lock_linetax_query->hash;
        $form->{locklinetax} = $lock_linetax_result->{locklinetax} ? \1 : \0;

        my %checked;
        $checked{cash}          = "checked" if $form->{method} eq 'cash';
        $checked{namesbynumber} = "checked" if $form->{namesbynumber};
        $checked{company}       = "checked" unless $form->{typeofcontact};
        $checked{person}      = "checked" if $form->{typeofcontact} eq 'person';
        $checked{roundchange} = "checked" if $form->{roundchange};

        for (qw(cdt checkinventory hideaccounts linetax forcewarehouse)) {
            $checked{$_} = "checked" if $form->{$_};
        }

        for (
            qw(glnumber sinumber sonumber ponumber sqnumber rfqnumber employeenumber customernumber vendornumber)
          )
        {
            $checked{"lock_$_"} = "checked" if $form->{"lock_$_"};
        }

        # Combine form data and checked settings.
        my %form_data = ( %{$form}, checked => \%checked );

        $c->render( json => \%form_data );
    }
);

$api->post(
    '/system/companydefaults' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $form   = Form->new;

        # Get form data from JSON request body
        my $json_data = $c->req->json;
        warn( Dumper $json_data );

        # Transfer JSON data to form object
        foreach my $key ( keys %$json_data ) {
            $form->{$key} = $json_data->{$key};
        }
        warn( Dumper $form );

        # Set up configuration for the client
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        $form->{optional} =
"company address tel fax companyemail companywebsite yearend weightunit businessnumber closedto revtrans audittrail method cdt namesbynumber typeofcontact roundchange referenceurl annualinterest latepaymentfee restockingcharge checkinventory hideaccounts linetax forcewarehouse glnumber sinumber sonumber vinumber batchnumber vouchernumber ponumber sqnumber rfqnumber partnumber projectnumber employeenumber customernumber vendornumber lock_glnumber lock_sinumber lock_sonumber lock_ponumber lock_sqnumber lock_rfqnumber lock_employeenumber lock_customernumber lock_vendornumber";

        # Save the defaults
        my $result = AM->save_defaults( $c->slconfig, $form );

        if ($result) {
            $c->render(
                json => {
                    status  => 'success',
                    message => 'Company defaults saved successfully'
                }
            );
        }
        else {
            $c->render(
                status => 500,
                json   => {
                    status  => 'error',
                    message => 'Failed to save company defaults'
                }
            );
        }
    }
);

$api->get(
    '/system/chart/accounts' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $form   = Form->new;
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        my $result = CA->all_accounts( $c->slconfig, $form );
        if ($result) {
            $c->render( json => $form->{CA} );
        }
        else {
            $c->render(
                status => 500,
                json   => {
                    status  => 'error',
                    message => 'Failed to save company defaults'
                }
            );
        }
    }
);

$api->get(
    '/system/chart/accounts/:id' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $id     = $c->param('id');
        my $form   = Form->new;
        my $dbs    = $c->dbs($client);

        # Execute queries and check for records
        my $transactions =
          $dbs->query( "SELECT * FROM acc_trans WHERE chart_id = ? ", $id );
        my $defaults =
          $dbs->query( "SELECT * FROM defaults WHERE fldvalue = ? ", $id );
        my $parts = $dbs->query(
"SELECT * FROM parts WHERE inventory_accno_id = ? OR income_accno_id = ? OR expense_accno_id = ?",
            $id, $id, $id );

        $form->{id} = $id;
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        my $result = AM->get_account( $c->slconfig, $form );

        $form->{has_transactions} = $transactions->rows > 0 ? \1 : \0;
        $form->{has_defaults}     = $defaults->rows > 0     ? \1 : \0;
        $form->{has_parts}        = $parts->rows > 0        ? \1 : \0;
        if ($result) {
            $c->render( json => {%$form} );
        }
        else {
            $c->render(
                status => 500,
                json   => {
                    status  => 'error',
                    message => 'Failed to get chart'
                }
            );
        }
    }
);

$api->post(
    '/system/chart/accounts/:id' => { id => undef } => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $form   = Form->new;
        my $id     = $c->param("id");
        my $params = $c->req->json;
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        for ( keys %$params ) { $form->{$_} = $params->{$_} if $params->{$_} }
        $form->{id} = $id // undef;

        my $result = AM->save_account( $c->slconfig, $form );

        if ($result) {
            $c->render( json => {%$form} );
        }
        else {
            $c->render(
                status => 500,
                json   => {
                    status  => 'error',
                    message => 'Failed to save account'
                }
            );
        }
    }
);
$api->delete(
    '/system/chart/accounts/:id' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $id     = $c->param('id');
        my $dbs    = $c->dbs($client);

        # Execute queries to check for related records
        my $transactions =
          $dbs->query( "SELECT 1 FROM acc_trans WHERE chart_id = ? LIMIT 1",
            $id );
        my $defaults =
          $dbs->query( "SELECT 1 FROM defaults WHERE fldvalue = ? LIMIT 1",
            $id );
        my $parts = $dbs->query(
"SELECT 1 FROM parts WHERE inventory_accno_id = ? OR income_accno_id = ? OR expense_accno_id = ? LIMIT 1",
            $id, $id, $id );

        if ( $transactions->rows > 0 ) {
            return $c->render(
                status => 400,
                json   => {
                    status  => 'error',
                    message => 'Cannot delete account: transactions exist'
                }
            );
        }
        if ( $defaults->rows > 0 ) {
            return $c->render(
                status => 400,
                json   => {
                    status  => 'error',
                    message => 'Cannot delete account: used in defaults'
                }
            );
        }
        if ( $parts->rows > 0 ) {
            return $c->render(
                status => 400,
                json   => {
                    status  => 'error',
                    message => 'Cannot delete account: linked to parts'
                }
            );
        }

        my $form = new Form;
        $form->{id} = $id;
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        my $delete = AM->delete_account( $c->slconfig, $form );

        if ($delete) {
            $c->render(
                json => { status => 'success', message => 'Account deleted' } );
        }
        else {
            $c->render(
                status => 500,
                json   => {
                    status  => 'error',
                    message => 'Failed to delete account'
                }
            );
        }
    }
);

##########################
####                  ####
#### Goods & Services ####
####                  ####
##########################

$api->get(
    '/items' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);

        my $parts = $dbs->query("SELECT * FROM parts")->hashes;

        foreach my $part (@$parts) {
            my $taxaccounts = $dbs->query( "
            SELECT chart.accno 
            FROM partstax 
            JOIN chart ON partstax.chart_id = chart.id 
            WHERE partstax.parts_id = ?",
                $part->{id} )->arrays;

            # Add tax accounts as an array of accnos
            $part->{taxaccounts} = [ map { $_->[0] } @$taxaccounts ];
        }

        # Render the response as JSON
        $c->render( json => { parts => $parts } );
    }
);

###############################
####                       ####
####        LINKS          ####
####                       ####
###############################

$api->get(
    '/create_links/:module' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);

        my $line_tax_q =
          $dbs->query( "SELECT fldvalue FROM defaults WHERE fldname = ?",
            'linetax' )->hash;

        my $line_tax = $line_tax_q ? 1 : 0;

        my $tax_accounts = $dbs->query(
            "SELECT t.rate, t.taxnumber, t.chart_id, c.description, c.accno,
            CONCAT(c.accno, '--', c.description) AS label
     FROM tax t
     JOIN chart c ON (c.id = t.chart_id)
     ORDER BY c.accno"
        )->hashes;

        $c->render(
            json => {
                tax_accounts => $tax_accounts,
                linetax      => $line_tax
            }
        );
    }
);

###############################
####                       ####
####         ARAP          ####
####                       ####
###############################

# Shared Routines for ARAP. AR Value is Customer & AP Value is Vendor

$api->get(
    '/arap/transactions/:vc' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $vc     = $c->param('vc');
        my $data   = $c->req->params->to_hash;

        unless ( $vc eq 'vendor' || $vc eq 'customer' ) {
            return $c->render(
                json => {
                    error => 'Invalid type. Must be either vendor or customer.'
                },
                status => 400
            );
        }

        warn( Dumper $data );
        my $form = new Form;
        $form->{vc}               = $vc;
        $form->{summary}          = 1;
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        my @date_filters = qw(transdatefrom transdateto);
        my @text_filters =
          qw(invnumber ordnumber ponumber shipvia shippingpoint waybill notes description memo source);
        my @entity_filters = qw(warehouse employee department);
        my @boolean_filters =
          qw(outstanding open closed paidlate paidearly onhold);

        # Apply the predefined values from $data
        for my $key ( keys %$data ) {
            $form->{$key} = $data->{$key} if defined $data->{$key};
        }

        # Additional validation for date fields if they're not empty
        for my $filter (@date_filters) {
            if ( $form->{$filter} && $form->{$filter} !~ /^\d{4}-\d{2}-\d{2}$/ )
            {
                return $c->render(
                    json => {
                        error =>
                          "Invalid date format for $filter. Use YYYY-MM-DD."
                    },
                    status => 400
                );
            }
        }

        # Handle entity-specific fields
        if ( my $entity_id = $data->{"${vc}_id"} ) {
            $form->{"${vc}_id"} = $entity_id;
        }
        if ( my $number = $data->{"${vc}number"} ) {
            $form->{"${vc}number"} = $number;
        }
        if ( my $name = $data->{$vc} ) {
            $form->{$vc} = $name;
        }
        if ( exists $data->{till} ) {
            $form->{till} = $data->{till};
        }

        AA->transactions( $c->slconfig, $form );

        if (  !defined $form->{transactions}
            || ref $form->{transactions} ne 'ARRAY'
            || !@{ $form->{transactions} } )
        {
            return $c->render(
                status => 404,
                json   => { message => "No transactions found" }
            );
        }

        # Calculate totals for specific fields
        my $totals = {
            amount      => 0,
            netamount   => 0,
            paid        => 0,
            paymentdiff => 0
        };

        foreach my $transaction ( @{ $form->{transactions} } ) {
            $totals->{amount}      += $transaction->{amount}      || 0;
            $totals->{netamount}   += $transaction->{netamount}   || 0;
            $totals->{paid}        += $transaction->{paid}        || 0;
            $totals->{paymentdiff} += $transaction->{paymentdiff} || 0;
        }

        # Return both transactions and totals
        return $c->render(
            json => {
                transactions => $form->{transactions},
                totals       => $totals
            }
        );
    }
);

# Used to fetch & load information in other forms AR/AP
$api->get(
    '/arap/list/:vc' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $vc     = $c->param('vc');

        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        my $form = new Form;

        $form->{vc} = $vc;
        AA->all_names( $c->slconfig, $form );

        my $number =
          ( $vc eq 'customer' )
          ? 'customernumber'
          : 'vendornumber';

        for my $item ( @{ $form->{all_vc} } ) {
            $item->{label} =
              $item->{name} . " -- " . $item->{$number};   # Use the dynamic key
        }

        $c->render( json => $form->{all_vc} );
    }
);

$api->get(
    '/arap/list/:vc/:id' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $vc     = $c->param('vc');
        my $id     = $c->param('id');

        # Validate the type parameter
        unless ( $vc eq 'vendor' || $vc eq 'customer' ) {
            return $c->render(
                json => {
                    error => 'Invalid VC. Must be either vendor or customer.'
                },
                status => 400
            );
        }

        # Set the database connection dynamically
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        my $form = new Form;
        $form->{vc}         = $vc;
        $form->{"${vc}_id"} = $id;

        # Fetch the name and other details based on type
        AA->get_name( $c->slconfig, $form );

        # Construct the full address
        my $full_address = join( ' ',
            $form->{address1} // '',
            $form->{address2} // '',
            $form->{city}     // '',
            $form->{state}    // '',
            $form->{country}  // '' );

        my $label = $form->{$vc} . ' -- ' . $form->{ $form->{vc} . 'number' };
        $form->{id}    = $id;
        $form->{label} = $label;
        $form->{name}  = $form->{$vc};

        # Add the full address to the form object
        $form->{full_address} = $full_address;

        # Render the form object as JSON
        $c->render( json => {%$form} );
    }
);

# Used for Customer/Vendor Forms

$api->get(
    '/arap/:vc/' => sub {
        my $c      = shift;
        my $vc     = $c->param('vc');
        my $client = $c->param('client');
        my $params = $c->req->params->to_hash;
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        my $form = Form->new;
        $form->{db} = $vc;
        for ( keys %$params ) { $form->{$_} = $params->{$_} if $params->{$_} }

        CT->search( $c->slconfig, $form );
        my @results = $form->{CT};

        # Render the filtered JSON response
        $c->render( json => @results );
    }
);
$api->get(
    '/arap/:vc/:id' => sub {
        my $c      = shift;
        my $id     = $c->param('id');
        my $vc     = $c->param('vc');
        my $client = $c->param('client');

        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        my $form = Form->new;
        $form->{id} = $id;
        $form->{db} = $vc;

        CT->create_links( $c->slconfig, $form );

        delete $form->{arap_accounts};
        delete $form->{payment_accounts};

        if ( defined $form->{taxaccounts} ) {
            my @tax_codes = split ' ', $form->{taxaccounts};
            foreach my $code (@tax_codes) {
                my $description_key = "tax_${code}_description";
                delete $form->{$description_key}
                  if exists $form->{$description_key};
            }
        }

        $form->{discount} *= 100;

        # Render the filtered JSON response
        $c->render( json => {%$form} );
    }
);

$api->post(
    '/arap/:vc/' => sub {
        my $c      = shift;
        my $vc     = $c->param('vc');
        my $client = $c->param('client');
        my $params = $c->req->json;
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        my $form = Form->new;
        $form->{db} = lc($vc);
        for ( keys %$params ) { $form->{$_} = $params->{$_} if $params->{$_} }
        $form->{ $vc =~ /^vendor$/i ? 'vendornumber' : 'customernumber' } =
          $params->{vcnumber};
        CT->save( $c->slconfig, $form );

        # Render the filtered JSON response
        $c->render( json => {%$form} );
    }
);
$api->get(
    '/:vc/history/' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $vc     = $c->param('vc');       # Either 'customer' or 'vendor'

        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        my $form = new Form;
        $form->{db} = $vc;

        $form->{transdatefrom} = $c->param('transdatefrom')
          // '';                            # Start date (YYYY-MM-DD)
        $form->{transdateto} = $c->param('transdateto')
          // '';                            # End date (YYYY-MM-DD)
        $form->{sort} = $c->param('sort')
          // 'partnumber';    # Sorting field (e.g., 'name', 'date')
        $form->{direction} = $c->param('direction')
          // 'ASC';           # Sorting order ('ASC' or 'DESC')
        $form->{employee} = $c->param('employee') // '';   # Employee ID or Name
        $form->{business} = $c->param('business') // '';   # Business ID or Name
        $form->{open}     = $c->param('open')
          // '';    # Open transactions filter (1 or 0)
        $form->{closed} = $c->param('closed')
          // '';    # Closed transactions filter (1 or 0)
        $form->{customernumber} = $c->param('customernumber') // ''
          if $vc eq 'customer';
        $form->{vendornumber} = $c->param('vendornumber') // ''
          if $vc eq 'vendor';
        $form->{name}    = $c->param('name')    // '';    # Customer/Vendor name
        $form->{contact} = $c->param('contact') // '';    # Contact person name
        $form->{email}   = $c->param('email')   // '';    # Email address
        $form->{phone}   = $c->param('phone')   // '';    # Phone number
        $form->{city}    = $c->param('city')    // '';    # City
        $form->{state}   = $c->param('state')   // '';    # State/Province
        $form->{zipcode} = $c->param('zipcode') // '';    # Zip/Postal Code
        $form->{country} = $c->param('country') // '';    # Country
        $form->{notes}   = $c->param('notes')   // '';
        $form->{type}    = $c->param('type')    // 'invoice';
        $form->{history} = 'summary';

        # Notes or additional information

        CT->get_history( $c->slconfig, $form );

        # Format the response as JSON
        $c->render( json => $form->{CT} );
    }
);

$api->get(
    '/arap/transaction/:vc/:id' => sub {
        my $c                = shift;
        my $client           = $c->param('client');
        my $data             = $c->req->json;
        my $id               = $c->param('id');
        my $vc               = $c->param('vc');
        my $transaction_type = $vc eq 'vendor' ? 'AP'      : 'AR';
        my $vc_field    = $vc eq 'vendor' ? 'vendornumber' : 'customernumber';
        my $vc_id_field = $vc eq 'vendor' ? 'vendor_id'    : 'customer_id';

        # Initialize required variables
        my $dbs = $c->dbs($client);
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        my $ml       = 1;
        my %myconfig = ();
        my $form     = Form->new;
        $form->{id} = $id;
        $form->{vc} = $vc;
        $form->create_links( $transaction_type, $c->slconfig, $vc );
        Dumper( warn $form );

        # Amount multiplier for AR transactions
        my $amount_multiplier = $transaction_type eq 'AR' ? -1 : 1;

        my @line_items;

        # For each transaction item
        my @sorted_entries = sort { $a->{id} <=> $b->{id} }
          @{ $form->{acc_trans}{"${transaction_type}_amount"} };

        for my $entry (@sorted_entries) {
            push @line_items,
              {
                accno       => $entry->{accno},
                description => $entry->{memo} || '',
                amount      => $amount_multiplier * ( -$entry->{amount} ),
                taxAccount  => $entry->{tax_accno},
                taxAmount   => $entry->{linetaxamount},
              };
        }

        # Create payments array
        my @payments;

        # Check if payments exist
        if ( defined $form->{acc_trans}{"${transaction_type}_paid"}
            && ref( $form->{acc_trans}{"${transaction_type}_paid"} ) eq
            'ARRAY' )
        {
            for my $i (
                1 .. scalar @{ $form->{acc_trans}{"${transaction_type}_paid"} }
              )
            {
                my $payment =
                  $form->{acc_trans}{"${transaction_type}_paid"}[ $i - 1 ];
                push @payments,
                  {
                    date         => $payment->{transdate},
                    source       => $payment->{source},
                    memo         => $payment->{memo},
                    exchangerate => $payment->{exchangerate},
                    amount       => $amount_multiplier * $payment->{amount},
                    account      => "$payment->{accno}--$payment->{description}"
                  };
            }
        }

        # Process tax information
        my @taxes;
        if ( $form->{acc_trans}{"${transaction_type}_tax"} ) {
            @taxes = map {
                {
                    accno  => $_->{accno},
                    amount => $amount_multiplier * $_->{amount},
                    rate   => $_->{rate}
                }
            } @{ $form->{acc_trans}{"${transaction_type}_tax"} };
        }

        my $link = $dbs->query( "SELECT link from files WHERE reference = ?",
            $form->{invnumber} )->hash;

        # Create the transformed data structure
        my $json_data = {
            $vc_field     => $form->{$vc_field},
            shippingPoint => $form->{shippingpoint},
            shipVia       => $form->{shipvia},
            wayBill       => $form->{waybill},
            description   => $form->{description},
            notes         => $form->{notes},
            intnotes      => $form->{intnotes},
            invNumber     => $form->{invnumber},
            ordNumber     => $form->{ordnumber},
            invDate       => $form->{transdate},
            dueDate       => $form->{duedate},
            poNumber      => $form->{ponumber},
            currency      => $form->{currency},
            exchangerate  => $form->{exchangerate},
            id            => $form->{id},
            recordAccount => $form->{acc_trans}{$transaction_type}[0],
            $vc_id_field  => $form->{$vc_id_field},
            lineitems     => \@line_items,
            payments      => \@payments,
        };

        if ($link) {
            $json_data->{file} = $link->{link};
        }

        # Add tax information if present
        if (@taxes) {
            $json_data->{taxes}       = \@taxes;
            $json_data->{taxincluded} = $form->{taxincluded};
        }

        warn( Dumper $form );

        # Render the structured response in JSON format
        $c->render( json => $json_data );
    }
);
$api->get(
    '/arap/invoice/:vc/:id' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $data   = $c->req->json;
        my $id     = $c->param('id');
        my $vc     = $c->param('vc');

        # Determine if this is AR or AP
        my $invoice_type = $vc eq 'vendor' ? 'AP' : 'AR';
        my $arap_key     = $vc eq 'vendor' ? 'AP' : 'AR';

        # Configure database connection
        my $dbs = $c->dbs($client);
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        # Initialize form
        my $form = Form->new;
        $form->{id} = $id;
        $form->{vc} = $vc;    # 'customer' or 'vendor'

        # For AR we use the IS module, for AP we use the IR module
        if ( $invoice_type eq 'AR' ) {
            IS->retrieve_invoice( $c->slconfig, $form );
            IS->invoice_details( $c->slconfig, $form );
        }
        else {
            IR->retrieve_invoice( $c->slconfig, $form );
            IR->invoice_details( $c->slconfig, $form );
        }

        # Debug
        warn Dumper($form);

        my $ml = 1;

        # Create payments array
        my @payments;

        # For AR-paid or AP-paid, the key is the same pattern:
        #   AR_paid or AP_paid in the acc_trans hash.
        my $paid_key = $arap_key . '_paid';

        if ( $vc eq 'customer' ) { $ml = -1; }

        if ( defined $form->{acc_trans}{$paid_key}
            && ref $form->{acc_trans}{$paid_key} eq 'ARRAY' )
        {

            for my $payment_entry ( @{ $form->{acc_trans}{$paid_key} } ) {
                push @payments, {
                    date   => $payment_entry->{transdate},
                    source => $payment_entry->{source},
                    memo   => $payment_entry->{memo},

                    # Amount needs to invert sign appropriately
                    amount       => $payment_entry->{amount} * $ml,
                    exchangerate => $payment_entry->{exchangerate},
                    account      => $payment_entry->{accno} . '--'
                      . $payment_entry->{description},
                };
            }
        }

        if (
            $form->{type}
            && (   $form->{type} eq 'credit_invoice'
                || $form->{type} eq 'debit_invoice' )
          )
        {
            $ml = -1;
        }
        else {
            $ml = 1;
        }

      # Build line items
      # (The same structure should come out of invoice_details whether AR or AP)
        my @lines;
        if ( ref $form->{invoice_details} eq 'ARRAY' ) {
            @lines = map {
                {
                    id          => $_->{id},
                    partnumber  => $_->{partnumber},
                    description => $_->{description},
                    qty         => $_->{qty} * $ml,
                    oh          => $_->{onhand},
                    unit        => $_->{unit},
                    price       => $_->{fxsellprice}
                    ? $_->{fxsellprice}
                    : $_->{sellprice},
                    discount         => $_->{discount} * 100,
                    taxaccounts      => [ split ' ', $_->{taxaccounts} || '' ],
                    lineitemdetail   => $_->{lineitemdetail},
                    deliverydate     => $_->{deliverydate},
                    itemnotes        => $_->{itemnotes},
                    ordernumber      => $_->{ordernumber},
                    serialnumber     => $_->{serialnumber},
                    customerponumber => $_->{customerponumber},
                    cost             => $_->{cost},
                    costvendor       => $_->{costvendor},
                    costvendorid     => $_->{costvendorid},
                    package          => $_->{package},
                    volume           => $_->{volume},
                    weight           => $_->{weight},
                    netweight        => $_->{netweight},
                    volume           => $_->{volume},
                }
            } @{ $form->{invoice_details} };
        }

        # Process tax information
        my @taxes;
        my $tax_key = $invoice_type . '_tax';
        if ( $form->{acc_trans}{$tax_key} ) {
            @taxes = map {
                {
                    accno => $_->{accno},

               # For AP/AR, you might invert or not depending on how your system
               # stores the amounts. Adjust if needed:
                    amount => $_->{amount},
                    rate   => $_->{rate},
                }
            } @{ $form->{acc_trans}{$tax_key} };
        }

        # Because in AR the main account is stored under AR,
        # and in AP it's stored under AP.
        my $main_account_key = $invoice_type;

        # For the vc_field and vc_id_field:
        #   If vendor => vendornumber, vendor_id
        #   If customer => customernumber, customer_id
        my ( $vc_field, $vc_id_field ) =
          $vc eq 'vendor'
          ? ( 'vendornumber', 'vendor_id' )
          : ( 'customernumber', 'customer_id' );

        # Build JSON response
        my $json_data = {

            # Dynamic fields for vendor or customer
            $vc_field    => $form->{$vc_field},
            $vc_id_field => $form->{$vc_id_field},

            shippingPoint => $form->{shippingpoint},
            shipVia       => $form->{shipvia},
            wayBill       => $form->{waybill},
            description   => $form->{invdescription},
            notes         => $form->{notes},
            intnotes      => $form->{intnotes},
            invNumber     => $form->{invnumber},
            ordNumber     => $form->{ordnumber},
            invDate       => $form->{transdate},
            dueDate       => $form->{duedate},
            poNumber      => $form->{ponumber},
            recordAccount => $form->{acc_trans}{$arap_key}[0],
            type          => $form->{type},
            currency      => $form->{currency},
            exchangerate  => $form->{"$form->{currency}"},
            id            => $form->{id},

            lines    => \@lines,
            payments => \@payments,
        };

        if (@taxes) {
            $json_data->{taxes}       = \@taxes;
            $json_data->{taxincluded} = $form->{taxincluded};
        }

        # Optional: If you store a document link
        my $link = $dbs->query( "SELECT link FROM files WHERE reference = ?",
            $form->{invnumber} )->hash;
        if ($link) {
            $json_data->{file} = $link->{link};
        }

        warn Dumper($json_data);

        $c->render( json => $json_data );
    }
);
$api->post(
    '/arap/invoice/:vc/:id' => { id => undef } => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $data   = $c->req->json;
        my $id     = $c->param('id');
        my $vc     = $c->param('vc');

        warn Dumper($data);

        # Determine if this should be AR or AP
        my $invoice_type = ( $vc eq 'vendor' ) ? 'AP' : 'AR';

        # Configure DB connection
        my $dbs = $c->dbs($client);
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        # Initialize form
        my $form = Form->new;

        # Set the ID if provided; otherwise it will post as a new invoice
        $form->{id} = $id if $id;

        # Basic invoice details common to both AR and AP
        $form->{invnumber}   = $data->{invNumber}   || '';
        $form->{description} = $data->{description} || '';

        $form->{type}         = $data->{type};
        $form->{transdate}    = $data->{invDate};
        $form->{duedate}      = $data->{dueDate};
        $form->{currency}     = $data->{selectedCurrency}->{curr};
        $form->{exchangerate} = $data->{exchangerate} || 1;
        $form->{notes}        = $data->{notes}        || '';
        $form->{intnotes}     = $data->{intnotes}     || '';
        $form->{till}         = $data->{till}         || '';

        # Set up AR or AP account from JSON
        # for AR, it's $form->{AR}, for AP, it's $form->{AP}.
        if ( $invoice_type eq 'AR' ) {

            # AR fields
            $form->{AR}          = $data->{recordAccount}->{accno};
            $form->{customer_id} = $data->{selectedCustomer}->{id};
            $form->{customer}    = $data->{selectedCustomer}->{name};
        }
        else {
            # AP fields
            $form->{AP} =
              $data->{recordAccount}->{accno};
            $form->{vendor_id} = $data->{selectedVendor}->{id};
            $form->{vendor}    = $data->{selectedVendor}->{name};
        }

        # Additional invoice details
        $form->{ordnumber}     = $data->{ordNumber}     || '';
        $form->{ponumber}      = $data->{poNumber}      || '';
        $form->{shippingpoint} = $data->{shippingPoint} || '';
        $form->{shipvia}       = $data->{shipVia}       || '';
        $form->{waybill}       = $data->{wayBill}       || '';

        # Build line items
        $form->{rowcount} = scalar @{ $data->{lines} || [] };
        for my $i ( 1 .. $form->{rowcount} ) {
            my $line = $data->{lines}[ $i - 1 ];
            $form->{"id_$i"}               = $line->{number};
            $form->{"description_$i"}      = $line->{description};
            $form->{"qty_$i"}              = $line->{qty};
            $form->{"sellprice_$i"}        = $line->{price};
            $form->{"discount_$i"}         = $line->{discount}         || 0;
            $form->{"unit_$i"}             = $line->{unit}             || '';
            $form->{"lineitemdetail_$i"}   = $line->{lineitemdetail}   || 0;
            $form->{"deliverydate_$i"}     = $line->{deliverydate}     || '';
            $form->{"itemnotes_$i"}        = $line->{itemnotes}        || '';
            $form->{"ordernumber_$i"}      = $line->{ordernumber}      || '';
            $form->{"serialnumber_$i"}     = $line->{serialnumber}     || '';
            $form->{"customerponumber_$i"} = $line->{customerponumber} || '';
            $form->{"costvendor_$i"}       = $line->{costvendor}       || '';
            $form->{"package_$i"}          = $line->{package}          || '';
            $form->{"volume"}              = $line->{volume}           || '';
            $form->{"weight"}              = $line->{weight}           || '';
            $form->{"netweight"}           = $line->{netweight}        || '';
            $form->{"cost"}                = $line->{cost}             || '';

        }

        # Build payments
        $form->{paidaccounts} = 0;    # Start with zero processed payments
        for my $payment ( @{ $data->{payments} || [] } ) {

            # Only process positive amounts
            next unless $payment->{amount} && $payment->{amount} > 0;
            $form->{paidaccounts}++;
            my $i = $form->{paidaccounts};

            # Payment date, memo, etc.
            $form->{"datepaid_$i"}     = $payment->{date}   || '';
            $form->{"source_$i"}       = $payment->{source} || '';
            $form->{"memo_$i"}         = $payment->{memo}   || '';
            $form->{"paid_$i"}         = $payment->{amount};
            $form->{"exchangerate_$i"} = $payment->{exchangerate} || 1;

          # For AR invoices, the paid key is AR_paid_$i; for AP, it's AP_paid_$i
            my $paid_key = $invoice_type . "_paid_$i";
            $form->{$paid_key} = $payment->{account};
        }

        # Taxes
        $form->{taxincluded} = 0;
        if ( $data->{taxes} && ref( $data->{taxes} ) eq 'ARRAY' ) {
            my @taxaccounts;
            for my $tax ( @{ $data->{taxes} } ) {
                push @taxaccounts, $tax->{accno};

                # e.g. $form->{"$tax->{accno}_rate"} = $tax->{rate};
                $form->{"$tax->{accno}_rate"} = $tax->{rate};
            }
            $form->{taxaccounts} = join( ' ', @taxaccounts );
            $form->{taxincluded} = $data->{taxincluded};
        }

        # Other defaults
        $form->{department_id} = undef;
        $form->{employee_id}   = undef;
        $form->{language_code} = 'en';
        $form->{precision}     = $data->{selectedCurrency}->{prec} || 2;

        warn Dumper($form);

        # Finally, post invoice to LedgerSMB
        if ( $invoice_type eq 'AR' ) {
            IS->post_invoice( $c->slconfig, $form );
        }
        else {
            IR->post_invoice( $c->slconfig, $form );
        }

        # Return the newly posted or updated invoice ID
        $c->render( json => { id => $form->{id} } );
    }
);
$api->delete(
    '/arap/invoice/:vc/:id' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $id     = $c->param('id');
        my $vc     = $c->param('vc');
        my $form   = new Form;
        $form->{id} = $id;
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        if ( $vc eq 'customer' ) {
            IS->delete_invoice( $c->slconfig, $form );
        }
        else {
            IR->delete_invoice( $c->slconfig, $form );
        }
        $c->render( status => 204, data => '' );
    }
);
$api->post(
    '/arap/transaction/:vc/:id' => { id => undef } => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $data   = $c->req->json;
        my $vc     = $c->param('vc');
        my $dbs    = $c->dbs($client);
        my $id     = $c->param('id');
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        my $form = new Form;

        $form->{type} = 'transaction';
        $form->{vc}   = $vc eq 'vendor' ? 'vendor' : 'customer';

        # Basic transaction details
        $form->{id}           = $id if $id;
        $form->{invnumber}    = $data->{invNumber}   || '';
        $form->{description}  = $data->{description} || '';
        $form->{transdate}    = $data->{invDate};
        $form->{duedate}      = $data->{dueDate};
        $form->{exchangerate} = $data->{exchangerate} || 1;

        # Handle vendor/customer specific fields
        if ( $vc eq 'vendor' ) {
            $form->{vendor_id} = $data->{selectedVendor}->{id};
            $form->{vendor}    = $data->{selectedVendor}->{name};
            $form->{AP}        = $data->{recordAccount}->{accno};
        }
        else {
            $form->{customer_id} = $data->{selectedCustomer}->{id};
            $form->{customer}    = $data->{selectedCustomer}->{name};
            $form->{AR}          = $data->{recordAccount}->{accno};
        }

        # Currency and other details
        $form->{currency}  = $data->{curr};
        $form->{notes}     = $data->{notes}     || '';
        $form->{intnotes}  = $data->{intnotes}  || '';
        $form->{ordnumber} = $data->{ordNumber} || '';
        $form->{ponumber}  = $data->{poNumber}  || '';

        # Line items
        $form->{rowcount} = scalar @{ $data->{lines} };
        for my $i ( 1 .. $form->{rowcount} ) {
            my $line   = $data->{lines}[ $i - 1 ];
            my $amount = $line->{amount};
            $form->{"amount_$i"}        = $amount;
            $form->{"description_$i"}   = $line->{description};
            $form->{"tax_$i"}           = $line->{taxAccount};
            $form->{"linetaxamount_$i"} = $line->{taxAmount};
            $form->{ $form->{vc} eq 'vendor' ? "AP_amount_$i" : "AR_amount_$i" }
              = $line->{account};

            # Project number if exists
            if ( $line->{project} ) {
                $form->{"projectnumber_$i"} =
                  $line->{project}->{number} . "--" . $line->{project}->{id};
            }
        }

        # Payments
        $form->{paidaccounts} = 0;
        for my $payment ( @{ $data->{payments} } ) {
            next unless $payment->{amount} > 0;
            $form->{paidaccounts}++;
            my $i = $form->{paidaccounts};

            $form->{"datepaid_$i"}     = $payment->{date};
            $form->{"source_$i"}       = $payment->{source} || '';
            $form->{"memo_$i"}         = $payment->{memo}   || '';
            $form->{"paid_$i"}         = $payment->{amount};
            $form->{"exchangerate_$i"} = $payment->{exchangerate} || 1;

            # Payment account with -- suffix
            $form->{ $form->{vc} eq 'vendor' ? "AP_paid_$i" : "AR_paid_$i" } =
              $payment->{account} . "--";

            # Payment method if exists
            if ( $payment->{method} ) {
                $form->{"paymentmethod_$i"} =
                  $payment->{method}->{name} . "--" . $payment->{method}->{id};
            }
        }

        # Taxes
        my @taxaccounts;
        if ( $data->{taxes} && ref( $data->{taxes} ) eq 'ARRAY' ) {
            for my $tax ( @{ $data->{taxes} } ) {
                push @taxaccounts, $tax->{accno};
                $form->{"tax_$tax->{accno}"} = $tax->{amount};
                my $accno = $tax->{accno};

                # Validate and store tax rate
                my $rate = $tax->{rate};
                $form->{"${accno}_rate"}    = $rate;
                $form->{"calctax_${accno}"} = 1;
            }
            $form->{taxaccounts} = join( ' ', @taxaccounts );
            $form->{taxincluded} = $data->{taxincluded} ? 1 : 0;
        }

        warn( Dumper($form) );

        AA->post_transaction( $c->slconfig, $form );

        $c->render( json => { id => $form->{id} } );
    }
);

###############################
####                       ####
####        Reports        ####
####                       ####
###############################

$api->get(
    '/reports/trial_balance' => sub {
        my $c      = shift;
        my $client = $c->param('client');

        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        my $form = new Form;

        my $datefrom = $c->param('fromdate');
        my $dateto   = $c->param('todate');

        $form->{fromdate} = $datefrom || '';
        $form->{todate}   = $dateto   || '';

        RP->trial_balance( $c->slconfig, $form );

        warn($form);
        $c->render( json => $form->{TB} );

    }
);

$api->get(
    '/reports/transactions' => sub {
        my $c      = shift;
        my $client = $c->param('client');

        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        my $form = new Form;

        my $fromdate = $c->param('fromdate');
        my $todate   = $c->param('todate');
        my $accno    = $c->param('accno');

        $form->{fromdate}    = $fromdate || '';
        $form->{todate}      = $todate   || '';
        $form->{accno}       = $accno;
        $form->{accounttype} = 'standard';

        CA->all_transactions( $c->slconfig, $form );

        warn($form);
        my $response;
        $response->{transactions} = $form->{CA};
        $response->{accno}        = $form->{accno};
        $response->{description}  = $form->{description};
        $c->render( json => $response );

    }
);
$api->get(
    '/reports/metrics' => sub {
        my $c           = shift;
        my $client      = $c->param('client');
        my $start_date  = $c->param('start_date');     # Format: YYYY-MM-DD
        my $end_date    = $c->param('end_date');       # Format: YYYY-MM-DD
        my $consolidate = $c->param('consolidate');    # 'monthly' or 'daily'

        # Create the DBIx::Simple handle
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        my $dbs = $c->dbs($client);

        my $period_field =
          $consolidate eq 'monthly'
          ? "date_trunc('month', transdate)"
          : "transdate::date";

        # Query for expenses
        my $expenses_query = qq{
            SELECT 
                $period_field as period,
                ABS(SUM(amount)) as amount
            FROM acc_trans ac
            JOIN chart c ON c.id = ac.chart_id
            WHERE c.category = 'E'
            AND transdate >= ?
            AND transdate <= ?
            AND amount < 0
            GROUP BY period
            ORDER BY period
        };

        # Query for sales
        my $sales_query = qq{
            SELECT 
                $period_field as period,
                SUM(amount) as amount
            FROM acc_trans ac
            JOIN chart c ON c.id = ac.chart_id
            WHERE c.category = 'I'
            AND transdate >= ?
            AND transdate <= ?
            AND amount > 0
            GROUP BY period
            ORDER BY period
        };

        my @results;

        # Fetch and format expenses data
        my $expenses_results =
          $dbs->query( $expenses_query, $start_date, $end_date );
        while ( my $row = $expenses_results->hash ) {
            push @results,
              {
                period => $row->{period},
                type   => 'expenses',
                amount => $row->{amount}
              };
        }

        # Fetch and format sales data
        my $sales_results = $dbs->query( $sales_query, $start_date, $end_date );
        while ( my $row = $sales_results->hash ) {
            push @results,
              {
                period => $row->{period},
                type   => 'sales',
                amount => $row->{amount}
              };
        }
        warn( "Expenses Results: " . Dumper( \@results ) );
        warn( "Sales Results: " . Dumper( \@results ) );

        # Return combined results
        $c->render( json => \@results );
    }
);

###############################
####                       ####
####    Invoice Loading    ####
####                       ####
###############################
my $openai_endpoint = "https://api.openai.com/v1/chat/completions";
my $openai_api_key  = '';

$api->post(
    '/upload_invoice' => sub {
        my $c = shift;
        warn "Starting upload_invoice handler";

        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);

        # Get AP accounts
        my @accounts =
          $dbs->query("SELECT * FROM chart WHERE link ILIKE '%AP_amount%'")
          ->hashes;
        my $accounts_string =
          join( ", ", map { "$_->{accno}: $_->{description}" } @accounts );
        warn($accounts_string);

        my $ua = Mojo::UserAgent->new;

        # Get the single uploaded file
        my $file = $c->req->upload('files');
        unless ($file) {
            warn "No file uploaded";
            return $c->render(
                json   => { success => \0, message => 'No file uploaded.' },
                status => 400
            );
        }

        # Process filename
        my $original_filename = $file->filename;
        my $content_type      = $file->headers->content_type;
        my $filename          = lc($original_filename);
        $filename =~ s/\s+/_/g;               # Replace spaces with underscores
        $filename =~ s/[^a-zA-Z0-9._-]//g;    # Remove special characters

        # Save and process file
        my $upload_path = $c->app->home->rel_file("public/$filename");
        $file->move_to($upload_path);
        my $share_link = $c->upload_to_nextcloud( $upload_path, $filename );
        warn "Saved $filename to $upload_path";

        # Convert to base64
        open my $fh, '<', $upload_path
          or die "Could not open file '$upload_path': $!";
        binmode $fh;
        my $image_data = do { local $/; <$fh> };
        close $fh;
        my $base64_image = encode_base64($image_data);
        my $data_uri     = "data:image/png;base64,$base64_image";

        my $system_prompt =
"You are an AI assistant specialized in analyzing invoices. Your task is to extract key information from the provided invoice and return it in a structured JSON format. Use the following chart of accounts to map line items , make sure these are accurate: $accounts_string . Make sure your response is UTF-8 ENCODED";

        my $user_prompt =
"Please analyze this invoice and provide the following information in JSON format:
            - vendor: information about the vendor
                - name: Name of vendor
                - phonenumber: Phonenumber of vendor
                - email: vendor email
                - iban: vendor IBAN
                - website: vendor website
                - address1: vendor address1
                - address2: vendor address2
                - city: vendor city
                - country: vendor country
                - postal_code: vendor postal code
            - invDate: Invoice date (format should be yyy-mm-dd)
            - lineitems: An array of objects, each containing:
              - accno: chart accno this item should be logged in according to our accounts array
              - description: Item description
              - price: Item price
            - subtotal: Subtotal amount
            - total: Total amount
            - taxes: An array of objects, each containing:
              - rate: Tax rate
              - amount: Tax amount

            Ensure all numeric values are represented as numbers, not strings. If any information is not available, use null for that field.";

        # Make API request
        my $gpt_tx = $ua->post(
            $openai_endpoint => {
                'Authorization' => "Bearer $openai_api_key",
                'Content-Type'  => 'application/json'
            } => json => {
                model    => "gpt-4o",
                messages => [
                    {
                        role    => "system",
                        content => $system_prompt
                    },
                    {
                        role    => "user",
                        content => [
                            {
                                type => "text",
                                text => $user_prompt
                            },
                            {
                                type      => "image_url",
                                image_url => {
                                    url => $data_uri
                                }
                            }
                        ]
                    }
                ],
                max_tokens      => 4096,
                response_format => { type => "json_object" }
            }
        );

        if ( my $err = $gpt_tx->error ) {
            warn "Analysis failed: " . ( $err->{message} || $err->{code} );
            return $c->render(
                json => {
                    success => \0,
                    error   => "Analysis failed: "
                      . ( $err->{message} || $err->{code} )
                },
                status => 500
            );
        }

        # Process response
        my $raw_body     = $gpt_tx->res->body;
        my $decoded_body = Encode::encode_utf8($raw_body);
        my $analysis     = decode_json($decoded_body);

        eval {
            my $text = $analysis->{choices}[0]{message}{content};
            $text =~ s/```json\n//;    # Remove any JSON code block markers
            $text =~ s/\n```$//;

            my $invoice_data = decode_json($text);
            my $vendor_id = &loadVendor( $c, $invoice_data->{vendor}, $client );
            $invoice_data->{vendor_id} = $vendor_id;

            return $c->render( json => $invoice_data );
        };

        if ($@) {
            warn "Failed to process GPT response: $@";
            return $c->render(
                json => {
                    success => \0,
                    error   => "Failed to process GPT response: $@"
                },
                status => 500
            );
        }
    }
);

sub loadVendor {
    my ( $c, $vendorData, $client ) = @_;

    my $dbs = $c->dbs($client);

    # Search for an existing vendor by name, phone, or email
    my $vendor = $dbs->query(
"SELECT * FROM vendor WHERE name ILIKE '%' || ? || '%' OR phone ILIKE '%' || ? || '%' OR email = ?",
        $vendorData->{name}, $vendorData->{phone}, $vendorData->{email} )->hash;

    # If vendor doesn't exist, create a new one
    if ( !$vendor ) {
        warn("VENDOR NOT FOUND");
        my $form = new Form;
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        $form->{db}               = 'vendor';
        $form->{name}             = $vendorData->{name}        || '';
        $form->{phone}            = $vendorData->{phonenumber} || '';
        $form->{email}            = $vendorData->{email}       || '';
        $form->{website}          = $vendorData->{website}     || '';
        $form->{address1}         = $vendorData->{address1}    || '';
        $form->{address2}         = $vendorData->{address2}    || '';
        $form->{city}             = $vendorData->{city}        || '';
        $form->{state}            = $vendorData->{state}       || '';
        $form->{zipcode}          = $vendorData->{postal_code} || '';
        $form->{country}          = $vendorData->{country}     || '';
        $form->{iban}             = $vendorData->{iban}        || '';
        CT->save( $c->slconfig, $form );
    }

    $vendor = $dbs->query(
"SELECT * FROM vendor WHERE name ILIKE '%' || ? || '%' OR phone ILIKE '%' || ? || '%' OR email = ?",
        $vendorData->{name}, $vendorData->{phone}, $vendorData->{email} )->hash;

    # Return the completed form object
    return $vendor->{id};
}

# Helper to upload a file to Nextcloud and create a share link
helper upload_to_nextcloud => sub {
    my ( $c, $local_file_path, $remote_filename ) = @_;

    my $nextcloud_url  = '';
    my $nextcloud_user = '';
    my $nextcloud_pw   = '';

    # Initialize Mojo::UserAgent for making HTTP requests
    my $ua = Mojo::UserAgent->new;

    # WebDAV URL for file upload
    my $remote_file_url = $nextcloud_url . $remote_filename;

    # Read the file content as binary
    open my $fh, '<', $local_file_path
      or do {
        warn "Could not open file '$local_file_path': $!";
        return undef;
      };
    binmode $fh;
    my $file_content = do { local $/; <$fh> };
    close $fh;

    # Determine the Content-Type based on the file extension
    my $mime_type = 'application/octet-stream';    # Default MIME type
    if ( $remote_filename =~ /\.png$/i ) {
        $mime_type = 'image/png';
    }
    elsif ( $remote_filename =~ /\.jpg$/i || $remote_filename =~ /\.jpeg$/i ) {
        $mime_type = 'image/jpeg';
    }

    # Add more MIME types as needed

    # Step 1: Upload the file to Nextcloud using PUT with raw binary data
    my $upload_tx = $ua->put(
        $remote_file_url => {
            Authorization => 'Basic '
              . MIME::Base64::encode( "$nextcloud_user:$nextcloud_pw", '' ),
            'Content-Type'   => $mime_type,
            'Content-Length' => length($file_content),
        } => $file_content
    );

    # Check if the upload was successful
    if ( !$upload_tx->result->is_success ) {
        warn( "File upload failed: " . $upload_tx->result->message );
        return undef;
    }
    warn("File uploaded to Nextcloud at: $remote_file_url");

    # Step 2: Create a shareable link
    my $share_api_url = '';
    my $share_tx      = $ua->post(
        $share_api_url => {
            Authorization => 'Basic '
              . MIME::Base64::encode( "$nextcloud_user:$nextcloud_pw", '' ),
            'OCS-APIREQUEST' => 'true',
            'Content-Type'   => 'application/x-www-form-urlencoded',
        } => form => {
            path        => '/' . $remote_filename,
            shareType   => 3,                        # Public link
            permissions => 1,                        # Read-only
        }
    );

    # Check if the share link was successfully created
    if ( $share_tx->result->is_success ) {

        # Parse the XML response from Nextcloud
        use XML::Simple;
        my $xml = XML::Simple::XMLin(
            $share_tx->result->body,
            ForceArray => 0,
            KeyAttr    => []
        );
        if ( $xml->{ocs}->{meta}->{status} eq 'ok' ) {
            my $share_url = $xml->{ocs}->{data}->{url};
            warn("Share link created: $share_url");
            return $share_url;    # Return the share URL for further use
        }
        else {
            warn( "Failed to create share link: "
                  . $xml->{ocs}->{meta}->{status} );
            return undef;
        }
    }
    else {
        warn( "Failed to create share link: " . $share_tx->result->message );
        return undef;
    }
};
$api->get(
    '/get_files' => { id => undef } => sub {
        my $c = shift;

        # Nextcloud configuration
        my $nextcloud_url  = '';
        my $nextcloud_user = '';
        my $nextcloud_pw   = '';

        # Initialize Mojo::UserAgent for making HTTP requests
        my $ua = Mojo::UserAgent->new;

        # XML data for the PROPFIND request body to get file properties
        my $propfind_xml = <<'XML';
<?xml version="1.0" encoding="UTF-8" ?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:displayname />
    <d:getcontentlength />
    <d:getlastmodified />
    <d:resourcetype />
  </d:prop>
</d:propfind>
XML

        # Build the PROPFIND transaction
        my $tx = $ua->build_tx(
            'PROPFIND' => $nextcloud_url => {
                Authorization => 'Basic '
                  . MIME::Base64::encode( "$nextcloud_user:$nextcloud_pw", '' ),
                Depth => '1',    # Depth: 1 to list only immediate files/folders
                'Content-Type' => 'application/xml',
            },
            $propfind_xml
        );

        # Send the request
        my $res = $ua->start($tx)->result;

        # Check if the request was successful
        if ( !$res->is_success ) {
            $c->render(
                json   => { error => "Failed to list files: " . $res->message },
                status => 500
            );
            return;
        }

        # Parse the XML response
        my $xml = XML::Simple::XMLin(
            $res->body,
            ForceArray => [ 'd:response', 'd:propstat' ],
            KeyAttr    => []
        );

        # Extract file information from the XML
        my @files;
        for my $response ( @{ $xml->{'d:response'} } ) {
            my $filename;
            my $size = 0;
            my $modified;
            my $is_dir = 0;

         # Iterate through each d:propstat entry to find the relevant properties
            for my $propstat ( @{ $response->{'d:propstat'} } ) {

                # Only process if the status is "200 OK"
                next
                  unless $propstat->{'d:status'}
                  && $propstat->{'d:status'} eq 'HTTP/1.1 200 OK';

                my $prop = $propstat->{'d:prop'};
                $filename = $prop->{'d:displayname'}
                  if $prop->{'d:displayname'};
                $size     = $prop->{'d:getcontentlength'} // 0;
                $modified = $prop->{'d:getlastmodified'}
                  if $prop->{'d:getlastmodified'};
                $is_dir =
                  exists $prop->{'d:resourcetype'}{'d:collection'} ? 1 : 0;
            }

            # Skip entries that don't have a filename
            next unless $filename;

            # Append file info to the list
            push @files,
              {
                filename => $filename,
                size     => $size,
                modified => $modified,
                is_dir   => $is_dir,
              };
        }

        # Render the file list as a JSON response
        $c->render( json => { files => \@files } );
    }
);

$api->get(
    '/process_files' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);

        # Nextcloud configuration
        my $nextcloud_url  = "";
        my $nextcloud_user = '';
        my $nextcloud_pw   = '';

        # Initialize Mojo::UserAgent for making HTTP requests
        my $ua = Mojo::UserAgent->new;

        # XML data for the PROPFIND request body to get file properties
        my $propfind_xml = <<'XML';
<?xml version="1.0" encoding="UTF-8" ?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:displayname />
    <d:getcontentlength />
    <d:getlastmodified />
    <d:resourcetype />
  </d:prop>
</d:propfind>
XML

        # Retrieve all processed filenames from the database
        my $existing_files_rs = $dbs->query('SELECT filename FROM files');
        my %processed_files =
          map { $_->{filename} => 1 } @{ $existing_files_rs->hashes };

        # Build the PROPFIND transaction
        my $tx = $ua->build_tx(
            'PROPFIND' => $nextcloud_url => {
                Authorization => 'Basic '
                  . MIME::Base64::encode( "$nextcloud_user:$nextcloud_pw", '' ),
                Depth => '1',    # Depth: 1 to list only immediate files/folders
                'Content-Type' => 'application/xml',
            },
            $propfind_xml
        );

        # Send the request
        my $res = $ua->start($tx)->result;

        # Check if the request was successful
        if ( !$res->is_success ) {
            $c->render(
                json   => { error => "Failed to list files: " . $res->message },
                status => 500
            );
            return;
        }

        # Parse the XML response
        my $xml = XML::Simple::XMLin(
            $res->body,
            ForceArray => [ 'd:response', 'd:propstat' ],
            KeyAttr    => []
        );

        # Extract file information from the XML
        my @files;
        for my $response ( @{ $xml->{'d:response'} } ) {
            my $filename;
            my $size = 0;
            my $modified;
            my $is_dir = 0;

         # Iterate through each d:propstat entry to find the relevant properties
            for my $propstat ( @{ $response->{'d:propstat'} } ) {

                # Only process if the status is "200 OK"
                next
                  unless $propstat->{'d:status'}
                  && $propstat->{'d:status'} eq 'HTTP/1.1 200 OK';

                my $prop = $propstat->{'d:prop'};
                $filename = $prop->{'d:displayname'}
                  if $prop->{'d:displayname'};
                $size     = $prop->{'d:getcontentlength'} // 0;
                $modified = $prop->{'d:getlastmodified'}
                  if $prop->{'d:getlastmodified'};
                $is_dir =
                  exists $prop->{'d:resourcetype'}{'d:collection'} ? 1 : 0;
            }

            next unless $filename && !$is_dir;

            # Append file info to the list
            push @files,
              {
                filename => $filename,
                size     => $size,
                modified => $modified,
                is_dir   => $is_dir,
              };
        }

        # Initialize an array to hold files processed
        my @processed_files;

        # Iterate over each file and download it if it's new
        for my $file (@files) {

            # Skip the file if it has already been processed
            if ( exists $processed_files{ $file->{filename} } ) {
                push @processed_files,
                  {
                    filename => $file->{filename},
                    status   => 'Skipped (already processed)',
                  };
                next;
            }

            my $file_url = $nextcloud_url . $file->{filename};
            my $file_tx  = $ua->build_tx(
                'GET' => $file_url => {
                    Authorization => 'Basic '
                      . MIME::Base64::encode(
                        "$nextcloud_user:$nextcloud_pw", ''
                      ),
                }
            );

            my $file_res = $ua->start($file_tx)->result;

            if ( $file_res->is_success ) {
                my $file_content = $file_res->body;

                my $upload_path =
                  $c->app->home->rel_file("public/$file->{filename}");

                # Ensure the public directory exists
                my $public_dir = $c->app->home->rel_file("public");
                unless ( -d $public_dir ) {
                    mkdir $public_dir or do {
                        push @processed_files,
                          {
                            filename => $file->{filename},
                            status   => 'Failed to create public directory',
                            error    => $!,
                          };
                        next;
                    };
                }

                my $path = File::Spec->rel2abs($upload_path);
                open my $fh, '>', $path
                  or do {
                    push @processed_files,
                      {
                        filename => $file->{filename},
                        status   => "Cannot open '$path' for writing: $!",
                      };
                    next;
                  };
                binmode $fh;
                print $fh $file_content;
                close $fh;

                # Convert modified time to epoch
                my $modified_epoch = Time::Piece->strptime( $file->{modified},
                    '%a, %d %b %Y %H:%M:%S %Z' )->epoch;

                # Convert epoch to date/time string
                my $timestamp_str = strftime( "%Y-%m-%d %H:%M:%S",
                    localtime( $modified_epoch || time ) );
                my $file_id;

                # Insert file metadata into the database
                eval {
                    $file_id = $dbs->query(
'INSERT INTO files (filename, timestamp) VALUES (?, ?) RETURNING id',
                        $file->{filename}, $timestamp_str
                    )->hash->{id};
                };
                if ($@) {
                    push @processed_files,
                      {
                        filename => $file->{filename},
                        status   => 'Failed to insert into database',
                        error    => $@,
                      };
                    next;
                }

                # Step 2: Create a shareable link
                my $share_api_url = '';
                my $share_tx      = $ua->post(
                    $share_api_url => {
                        Authorization => 'Basic '
                          . MIME::Base64::encode(
                            "$nextcloud_user:$nextcloud_pw", ''
                          ),
                        'OCS-APIREQUEST' => 'true',
                        'Content-Type'   => 'application/x-www-form-urlencoded',
                    } => form => {
                        path        => '//' . $file->{filename},
                        shareType   => 3,                          # user link
                        permissions => 1,                          # Read-only

                    }
                );
                warn( Dumper $share_tx );

                # Check if the share link was successfully created
                my $share_url;
                if ($share_tx) {
                    my $xml = XML::Simple::XMLin(
                        $share_tx->res->body,
                        ForceArray => 0,
                        KeyAttr    => []
                    );

                    if ( $xml->{meta}->{status} eq 'ok' ) {
                        $share_url = $xml->{data}->{url};
                        warn("Share link created: $share_url");
                    }
                    else {
                        warn( "Failed to create share link: "
                              . $xml->{meta}->{status} );
                    }
                }
                else {
                    warn("IS NOT SUCCESS");
                }

                my $invoice_data = $c->ai_invoice( $file->{filename} );

                my $created_inv = &create_invoice( $c, $invoice_data, $client );
                $dbs->query(
"UPDATE files SET reference = ?, module = ?, processed = ?, link = ? WHERE id = ?",
                    $created_inv->{invnumber}, "ap", 1, $share_url, $file_id
                );

                push @processed_files,
                  {
                    filename => $file->{filename},
                    status   => 'Downloaded and stored successfully',
                  };
            }
            else {
                push @processed_files,
                  {
                    filename => $file->{filename},
                    status   => 'Failed to download',
                    error    => $file_res->message,
                  };
            }
        }

        # Render the status of processed files
        $c->render( json => { processed_files => \@processed_files } );
    }
);

# Define the ai_invoice helper
helper ai_invoice => sub {
    my ( $c, $filename ) = @_;

    my $dbs = $c->dbs("");
    my $ua  = Mojo::UserAgent->new;

    # Get AP accounts
    my @accounts =
      $dbs->query("SELECT * FROM chart WHERE link ILIKE '%AP_amount%'")->hashes;
    my $accounts_string =
      join( ", ", map { "$_->{accno}: $_->{description}" } @accounts );
    $c->app->log->debug("Accounts: $accounts_string");

    # Locate the file in the public directory
    my $upload_path = File::Spec->catfile( $c->app->home, "public", $filename );
    unless ( -e $upload_path ) {
        $c->app->log->warn("File '$filename' not found in public directory");
        return {
            success => \0,
            message => 'File not found.'
        };
    }

    $c->app->log->debug("Processing file: $upload_path");

    # Convert to base64
    open my $fh, '<', $upload_path or do {
        my $error = "Could not open file '$upload_path': $!";
        $c->app->log->warn($error);
        return {
            success => \0,
            message => "Could not open file: $!"
        };
    };
    binmode $fh;
    my $image_data = do { local $/; <$fh> };
    close $fh;
    my $base64_image = encode_base64( $image_data, '' );    # Remove line breaks
    my $data_uri     = "data:image/png;base64,$base64_image";

    # Prepare GPT-4 Vision request
    my $system_prompt =
"You are an AI assistant specialized in analyzing invoices. Your task is to extract key information from the provided invoice and return it in a structured JSON format. Use the following chart of accounts to map line items , make sure these are accurate: $accounts_string . Make sure your response is UTF-8 ENCODED";

    my $user_prompt =
"Please analyze this invoice and provide the following information in JSON format:
            - vendor: information about the vendor
                - name: Name of vendor
                - phonenumber: Phonenumber of vendor
                - email: vendor email
                - iban: vendor IBAN
                - website: vendor website
                - address1: vendor address1
                - address2: vendor address2
                - city: vendor city
                - country: vendor country
                - postal_code: vendor postal code
            - invDate: Invoice date (format should be yyy-mm-dd)
            - lineitems: An array of objects, each containing:
              - accno: chart accno this item should be logged in according to our accounts array
              - description: Item description
              - price: Item price
            - subtotal: Subtotal amount
            - total: Total amount
            - taxes: An array of objects, each containing:
              - rate: Tax rate
              - amount: Tax amount

            Ensure all numeric values are represented as numbers, not strings. If any information is not available, use null for that field.";

    # Make API request
    my $gpt_tx = $ua->post(
        $openai_endpoint => {
            'Authorization' => "Bearer $openai_api_key",
            'Content-Type'  => 'application/json'
        } => json => {
            model    => "gpt-4o",
            messages => [
                {
                    role    => "system",
                    content => $system_prompt
                },
                {
                    role    => "user",
                    content => [
                        {
                            type => "text",
                            text => $user_prompt
                        },
                        {
                            type      => "image_url",
                            image_url => {
                                url => $data_uri
                            }
                        }
                    ]
                }
            ],
            max_tokens      => 4096,
            response_format => { type => "json_object" }
        }
    );

    if ( my $err = $gpt_tx->error ) {
        warn "Analysis failed: " . ( $err->{message} || $err->{code} );
        return $c->render(
            json => {
                success => \0,
                error   => "Analysis failed: "
                  . ( $err->{message} || $err->{code} )
            },
            status => 500
        );
    }

    # Process response
    my $raw_body     = $gpt_tx->res->body;
    my $decoded_body = Encode::encode_utf8($raw_body);
    my $analysis     = decode_json($decoded_body);
    my $invoice_data;
    eval {
        my $text = $analysis->{choices}[0]{message}{content};
        $text =~ s/```json\n//;
        $text =~ s/\n```$//;

        $invoice_data = decode_json($text);
        my $vendor_id = &loadVendor( $c, $invoice_data->{vendor}, "" );
        $invoice_data->{vendor_id} = $vendor_id;
        return $invoice_data;
    };
    return $invoice_data;
    if ($@) {
        my $error         = $@;
        my $error_message = "Failed to process GPT response: $error";
        $c->app->log->warn($error_message);
        return {
            success => \0,
            error   => $error_message
        };
    }

};

sub create_invoice {
    my ( $c, $data, $client ) = @_;

    # Configure the database connection
    $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
    my $dbs = $c->dbs("");

    # Prepare form data
    my $form = new Form;
    $form->{type} = "transaction";
    $form->{vc}   = "vendor";

    # Basic invoice details
    $form->{invnumber}   = $data->{invNumber}   || '';
    $form->{description} = $data->{description} || '';
    $form->{transdate}   = $data->{invDate}     || '';
    $form->{duedate}     = $data->{dueDate}     || '';
    $form->{vendor_id}   = $data->{vendor_id}   || '';
    $form->{currency}    = "USD";
    $form->{AP}          = "2100";
    $form->{notes}       = $data->{notes}    || '';
    $form->{intnotes}    = $data->{intnotes} || '';

    # Other invoice details
    $form->{ordnumber}     = $data->{ordNumber}     || '';
    $form->{ponumber}      = $data->{poNumber}      || '';
    $form->{shippingpoint} = $data->{shippingPoint} || '';
    $form->{shipvia}       = $data->{shipVia}       || '';
    $form->{waybill}       = $data->{wayBill}       || '';

    # Line items
    my $lineitems = $data->{lineitems} || [];
    $form->{rowcount} = scalar @$lineitems;
    for my $i ( 1 .. $form->{rowcount} ) {
        my $line = $lineitems->[ $i - 1 ];
        $form->{"AP_amount_$i"}   = $line->{accno};
        $form->{"description_$i"} = $line->{description};
        $form->{"amount_$i"}      = $line->{price};
    }

    $form->{taxincluded}   = 0;
    $form->{department_id} = undef;
    $form->{employee_id}   = undef;
    $form->{language_code} = 'en';
    $form->{precision}     = $data->{currency}->{prec} || 2;
    my $auto_inv =
      $dbs->query( 'SELECT fldvalue FROM defaults WHERE fldname = ?',
        "auto_invoice" )->hash;
    my $auto_invoice = $auto_inv->{fldvalue} // '0';

    # Post the invoice
    AA->post_transaction( $c->slconfig, $form );
    return $form;

}
#########################
####                 ####
####       Cash      ####
####                 ####
#########################

$api->get(
    '/cash/reconciliation/paymentaccounts' => sub {
        my $c      = shift;
        my $client = $c->param('client');

        # Configure database connection for the client
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        # Initialize form and retrieve payment accounts
        my $form = new Form;
        RC->paymentaccounts( $c->slconfig, $form );

        # Check if any accounts were found
        unless ( $form->{PR} && ref $form->{PR} eq 'ARRAY' && @{ $form->{PR} } )
        {
            return $c->render(
                status => 404,
                json   => { error => "No payment accounts found" }
            );
        }

        # Return the list of payment accounts
        $c->render(
            status => 200,
            json   => $form->{PR}
        );
    }
);
$api->get(
    '/cash/reconciliation/' => sub {
        my $c      = shift;
        my $params = $c->req->params->to_hash;
        my $client = $c->param('client');

        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        # Initialize form and load parameters
        my $form = new Form;
        $form->{$_} = $params->{$_} for keys %$params;

        # Validate required parameters
        unless ( $form->{accno} ) {
            return $c->render(
                status => 400,
                json   => { error => "Account number (accno) is required" }
            );
        }
        my $dbs = $c->dbs($client);

        # - accno:           Account number (required)
        # - fromdate:        Start date (YYYY-MM-DD)
        # - todate:          End date (YYYY-MM-DD)
        # - interval:        Date interval (days)
        # - year:            Fiscal year
        # - month:           Month number
        # - report:          1 for cleared transactions only
        # - summary:         1 for summarized transactions
        # - fx_transaction:  1 to include FX transactions

        # Force 'summary' only if needed. If you want it to be user-driven,
        # remove the next line or set it conditionally.
        # $form->{summary} = 1 unless defined $form->{summary};

        # Retrieve payment transactions
        RC->payment_transactions( $c->slconfig, $form );

        # If no transactions returned
        unless ( defined $form->{PR}
            && ref $form->{PR} eq 'ARRAY'
            && @{ $form->{PR} } )
        {
            return $c->render(
                status => 404,
                json   => {
                    message =>
                      "No transactions found for account $form->{accno}"
                }
            );
        }

        # Fix: old code sets $form->{beginningbalance}, $form->{endingbalance},
        # but we want to return them as beginning_balance / ending_balance.
        my $category =
          $dbs->query( "SELECT category FROM chart WHERE accno = ?",
            $form->{accno} )->list;
        $c->render(
            status => 200,
            json   => {
                account             => $form->{accno},
                account_category    => $category || 'A',
                beginning_balance   => $form->{beginningbalance} + 0,
                ending_balance      => $form->{endingbalance} + 0,
                fx_balance          => $form->{fx_balance} + 0,
                fx_endingbalance    => $form->{fx_endingbalance},
                reconciliation_date => $form->{recdate},
                transactions        => $form->{PR},
                fromdate            => $form->{fromdate},
                todate              => $form->{todate}
            }
        );
    }
);

$api->post(
    '/cash/reconciliation/' => sub {
        my $c      = shift;
        my $data   = $c->req->json;
        my $client = $c->param('client');

        # Check permissions if needed
        my $permission = "Banking--Reconciliation";
        return unless $c->check_perms($permission);

        # Validate required data
        unless ( $data->{accno} && $data->{transactions} ) {
            return $c->render(
                status => 400,
                json   => {
                    error =>
"Account number (accno) and transactions array are required"
                }
            );
        }

        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        # Prepare form data structure
        my $form = new Form;
        $form->{accno} = $data->{accno};

        # If a UI-supplied reconciliation date is provided, use it;
        # otherwise default to current date.
        $form->{recdate} = $data->{reconciliation_date}
          || DateTime->now->ymd;

        # Transaction data structure requirements:
        # transactions: [
        #   {
        #     id:             Transaction ID (required)
        #     date_cleared:   New cleared date (YYYY-MM-DD or '')
        #     old_cleared:    Original cleared date (YYYY-MM-DD or '')
        #     transdate:      Transaction date (YYYY-MM-DD)
        #     source:         Transaction source (optional)
        #   },
        # ]

        my $rowcount = 1;
        foreach my $txn ( @{ $data->{transactions} } ) {

            unless ( $txn->{id}
                && defined $txn->{date_cleared}
                && $txn->{transdate} )
            {
                return $c->render(
                    status => 400,
                    json   => { error => "Invalid transaction format" }
                );
            }

            $form->{"id_$rowcount"} = $txn->{id};

            # If date_cleared is non-empty, we interpret it as 'cleared = 1'
            $form->{"cleared_$rowcount"}     = $txn->{date_cleared} ? 1 : 0;
            $form->{"datecleared_$rowcount"} = $txn->{date_cleared};
            $form->{"oldcleared_$rowcount"}  = $txn->{old_cleared} || '';
            $form->{"transdate_$rowcount"}   = $txn->{transdate};
            $form->{"source_$rowcount"}      = $txn->{source} || '';

            $rowcount++;
        }
        $form->{rowcount} = $rowcount - 1;

        # Perform reconciliation
        eval { RC->reconcile( $c->slconfig, $form ); };
        if ($@) {
            return $c->render(
                status => 500,
                json   => { error => "Reconciliation failed: $@" }
            );
        }

        $c->render(
            status => 200,
            json   => {
                message =>
                  "Successfully reconciled $form->{rowcount} transactions",
                account             => $form->{accno},
                reconciliation_date => $form->{recdate}
            }
        );
    }
);

###############################
####                       ####
####  Template Processing  ####
####                       ####
###############################

sub build_letterhead {
    my ($c) = @_;
    my $client = $c->param('client');

    my $dbs = $c->dbs($client);

    my $results = $dbs->query(
"SELECT fldname, fldvalue FROM defaults WHERE fldname IN (?, ?, ?, ?, ?)",
        'company',
        'address',
        'tel',
        'companyemail',
        'companywebsite'
    )->hashes;

    # Create a structured letterhead object
    my %letterhead = map { $_->{fldname} => $_->{fldvalue} } @$results;

    return \%letterhead;
}

sub build_vc {
    my ( $c, $id, $vc ) = @_;

    my $client = $c->param('client');
    my $dbs    = $c->dbs($client);

    my ( $ledger_table, $vc_id_col, $vc_table );
    if ( $vc eq 'customer' ) {
        $ledger_table = 'ar';
        $vc_id_col    = 'customer_id';
        $vc_table     = 'customer';
    }
    else {
        $ledger_table = 'ap';
        $vc_id_col    = 'vendor_id';
        $vc_table     = 'vendor';
    }

    my $ledger_row =
      $dbs->query( "SELECT $vc_id_col FROM $ledger_table WHERE id = ?", $id )
      ->hash;
    return {} unless $ledger_row && $ledger_row->{$vc_id_col};

    my $trans_id = $ledger_row->{$vc_id_col};
    my $vc_row =
      $dbs->query( "SELECT * FROM $vc_table WHERE id = ?", $trans_id )->hash
      // {};

    my $address_row =
      $dbs->query( "SELECT * FROM address WHERE trans_id = ? LIMIT 1",
        $trans_id )->hash // {};
    my $contact_row =
      $dbs->query( "SELECT * FROM contact WHERE trans_id = ? LIMIT 1",
        $trans_id )->hash // {};

    my $phone = $contact_row->{phone} || $vc_row->{phone} || '';
    my $fax   = $contact_row->{fax}   || $vc_row->{fax}   || '';
    my $email = $contact_row->{email} || $vc_row->{email} || '';

    my $contact_name = '';
    if ( $contact_row->{firstname} || $contact_row->{lastname} ) {
        $contact_name = join( ' ',
            grep { $_ }
              ( $contact_row->{firstname}, $contact_row->{lastname} ) );
    }
    $contact_name ||= $vc_row->{contact} // '';

    my %result = (
        name     => $vc_row->{name}          // '',
        address1 => $address_row->{address1} // '',
        address2 => $address_row->{address2} // '',
        city     => $address_row->{city}     // '',
        state    => $address_row->{state}    // '',
        zipcode  => $address_row->{zipcode}  // '',
        country  => $address_row->{country}  // '',
        contact  => $contact_name,
        email    => $email,
        (
            $vc eq 'customer'
            ? (
                customerphone => $phone,
                customerfax   => $fax,
              )
            : (
                vendorphone     => $phone,
                vendorfax       => $fax,
                vendortaxnumber => $vc_row->{taxnumber} // '',
            )
        ),
    );

    return \%result;
}

sub build_invoice {
    my ( $c, $client, $vc, $id ) = @_;

    my $invoice_type = $vc eq 'vendor' ? 'AP' : 'AR';
    my $arap_key     = $invoice_type;

    my $form = Form->new;
    $form->{id} = $id;
    $form->{vc} = $vc;

    my $letterhead = build_letterhead($c);
    $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

    # Retrieve & populate $form->{invoice_details}, etc.
    if ( $invoice_type eq 'AR' ) {
        IS->retrieve_invoice( $c->slconfig, $form );
        IS->invoice_details( $c->slconfig, $form );
    }
    else {
        IR->retrieve_invoice( $c->slconfig, $form );
        IR->invoice_details( $c->slconfig, $form );
    }

    # Flatten line items into parallel arrays.
    my (
        @items,      @numbers,       @descriptions, @deliverydates,
        @qtys,       @units,         @makes,        @models,
        @sellprices, @discountrates, @linetotals
    );

    my $subtotal = 0;
    my $i        = 1;
    foreach my $item ( @{ $form->{invoice_details} } ) {
        my $qty      = $item->{qty}         || 0;
        my $price    = $item->{fxsellprice} || $item->{sellprice} || 0;
        my $discount = $item->{discount}    || 0;

        my $linetotal = $qty * $price * ( 1 - $discount );
        $subtotal += $linetotal;
        push @items, $i;
        push @numbers,       ( $item->{partnumber}  || '' );
        push @descriptions,  ( $item->{description} || '' );
        push @deliverydates, ( $form->{transdate}   || '' );
        push @qtys, $form->format_amount( $c->slconfig, $qty );
        push @units,  ( $item->{unit}  || '' );
        push @makes,  ( $item->{make}  || '' );
        push @models, ( $item->{model} || '' );
        push @sellprices, $form->format_amount( $c->slconfig, $price );
        push @discountrates, ( $discount ? $discount * 100 : '0' );
        push @linetotals, $form->format_amount( $c->slconfig, $linetotal );
        $i++;
    }

    # Flatten tax data into parallel arrays.
    my ( @taxdescriptions, @taxbases, @taxrates, @taxamounts );
    my $taxtotal = 0;
    foreach my $t ( @{ $form->{acc_trans}{ $arap_key . '_tax' } } ) {
        my $tax_amt = $t->{amount} || 0;
        $taxtotal += $tax_amt;

        push @taxdescriptions, ( $t->{description} =~ s/%//gr || '' );

        push @taxbases,
          $form->format_amount( $c->slconfig, $form->{netamount} || 0 );
        push @taxrates, ( $t->{description} =~ /(\d+)%/ ? $1 : 0 );
        push @taxamounts, $form->format_amount( $c->slconfig, $tax_amt );
    }

    # Determine multiplier for payments if needed:
    my $ml = (
        $form->{type} && ( $form->{type} eq 'credit_invoice'
            || $form->{type} eq 'debit_invoice' )
    ) ? -1 : 1;
    $ml *= -1 if $vc eq 'customer';

    # Flatten payment data into parallel arrays.
    my ( @paymentdates, @paymentaccounts, @paymentsources, @paymentamounts );
    my $paid_sum = 0;
    foreach my $pay ( @{ $form->{acc_trans}{ $arap_key . '_paid' } } ) {
        my $payment_amount = ( $pay->{amount} || 0 ) * $ml;

        push @paymentdates,    ( $pay->{transdate}   || '' );
        push @paymentaccounts, ( $pay->{description} || '' );
        push @paymentsources,  ( $pay->{source}      || '' );
        push @paymentamounts,
          $form->format_amount( $c->slconfig, $payment_amount );

        $paid_sum += $payment_amount;
    }

    my $paid  = $paid_sum;
    my $total = ( $subtotal + $taxtotal ) - $paid;

    # Grab vendor/customer info
    my $vc_data = build_vc( $c, $id, $vc );

    # Attempt to get one row from "shipto"
    my $dbs = $c->dbs($client);
    my $shipto_row =
      $dbs->query( "SELECT * FROM shipto WHERE trans_id = ? LIMIT 1", $id )
      ->hash;

    my %shipto_data;
    if ($shipto_row) {
        %shipto_data = (
            shiptoname     => $shipto_row->{shiptoname}     || "",
            shiptoaddress1 => $shipto_row->{shiptoaddress1} || "",
            shiptoaddress2 => $shipto_row->{shiptoaddress2} || "",
            shiptocity     => $shipto_row->{shiptocity}     || "",
            shiptostate    => $shipto_row->{shiptostate}    || "",
            shiptozipcode  => $shipto_row->{shiptozipcode}  || "",
            shiptocountry  => $shipto_row->{shiptocountry}  || "",
            shiptocontact  => $shipto_row->{shiptocontact}  || "",
            shiptophone    => $shipto_row->{shiptophone}    || "",
            shiptofax      => $shipto_row->{shiptofax}      || "",
            shiptoemail    => $shipto_row->{shiptoemail}    || "",
        );
    }
    else {
        # Fallback if no shipto row
        if ( $vc eq 'customer' ) {
            %shipto_data = (
                shiptoname     => $form->{customer}         || '',
                shiptoaddress1 => $vc_data->{address1}      || '',
                shiptoaddress2 => $vc_data->{address2}      || '',
                shiptocity     => $vc_data->{city}          || '',
                shiptostate    => $vc_data->{state}         || '',
                shiptozipcode  => $vc_data->{zipcode}       || '',
                shiptocountry  => $vc_data->{country}       || '',
                shiptocontact  => $vc_data->{contact}       || '',
                shiptophone    => $vc_data->{customerphone} || '',
                shiptofax      => $vc_data->{customerfax}   || '',
                shiptoemail    => $vc_data->{email}         || '',
            );
        }
        else {
            my @address_lines = split( /\n/, $letterhead->{address} || '' );
            %shipto_data = (
                shiptoname     => $letterhead->{company} || '',
                shiptoaddress1 => $address_lines[0]      || '',
                shiptoaddress2 => $address_lines[1]      || '',
                shiptocity     => $address_lines[2]      || '',
                shiptostate    => '',
                shiptozipcode  => '',
                shiptocountry  => $address_lines[3] || '',
                shiptocontact  => '',
                shiptophone    => $letterhead->{tel} || '',
                shiptofax      => '',
                shiptoemail    => $letterhead->{companyemail} || '',
            );
        }
    }

    my $num2text;
    if ( $form->{language_code} ne "" ) {
        $num2text = new CP $form->{language_code};
    }
    else {
        $num2text = new CP $c->slconfig->{countrycode};
    }
    $num2text->init;

    my %data = (

        # Basic address / vendor-customer info
        name => $vc_data->{name}
          || '',
        address1 => $vc_data->{address1}
          || '',
        address2 => $vc_data->{address2}
          || '',
        city => $vc_data->{city}
          || '',
        state => $vc_data->{state}
          || '',
        zipcode => $vc_data->{zipcode}
          || '',
        country => $vc_data->{country}
          || '',
        contact => $vc_data->{contact}
          || '',
        email => $vc_data->{email}
          || '',
        vendortaxnumber => $vc_data->{vendortaxnumber}
          || '',
        (
            $vc eq 'customer'
            ? (
                customerphone => $vc_data->{customerphone}
                  || '',
                customerfax => $vc_data->{customerfax}
                  || '',
              )
            : (
                vendorphone => $vc_data->{vendorphone}
                  || '',
                vendorfax => $vc_data->{vendorfax}
                  || '',
            )
        ),

        # Shipto data
        shiptoname     => $shipto_data{shiptoname},
        shiptoaddress1 => $shipto_data{shiptoaddress1},
        shiptoaddress2 => $shipto_data{shiptoaddress2},
        shiptocity     => $shipto_data{shiptocity},
        shiptostate    => $shipto_data{shiptostate},
        shiptozipcode  => $shipto_data{shiptozipcode},
        shiptocountry  => $shipto_data{shiptocountry},
        shiptocontact  => $shipto_data{shiptocontact},
        shiptophone    => $shipto_data{shiptophone},
        shiptofax      => $shipto_data{shiptofax},
        shiptoemail    => $shipto_data{shiptoemail},

        # Invoice meta
        invnumber     => $form->{invnumber}     || '',
        invdate       => $form->{transdate}     || '',
        duedate       => $form->{duedate}       || '',
        ordnumber     => $form->{ordnumber}     || '',
        employee      => $form->{employee}      || '',
        shippingpoint => $form->{shippingpoint} || '',
        shipvia       => $form->{shipvia}       || '',
        taxincluded   => $form->{taxincluded}   || 0,

        # Totals
        subtotal    => $form->format_amount( $c->slconfig, $subtotal ),
        paid        => $form->format_amount( $c->slconfig, $paid ),
        invtotal    => $form->format_amount( $c->slconfig, $total ),
        total       => $form->format_amount( $c->slconfig, $total ),
        text_amount => $num2text->num2text($total),
        decimal     => $form->{decimal}  || '00',
        currency    => $form->{currency} || '',
        notes       => $form->{notes}    || '',
        terms       => $form->{terms}    || '0',

        # Letterhead
        company      => $letterhead->{company}      || '',
        address      => $letterhead->{address}      || '',
        tel          => $letterhead->{tel}          || '',
        companyemail => $letterhead->{companyemail} || '',

        # ---- PARALLEL ARRAYS FOR LINE ITEMS ----
        runningnumber => \@items,
        number        => \@numbers,
        description   => \@descriptions,
        deliverydate  => \@deliverydates,
        qty           => \@qtys,
        unit          => \@units,
        make          => \@makes,
        model         => \@models,
        sellprice     => \@sellprices,
        discountrate  => \@discountrates,
        linetotal     => \@linetotals,

        # ---- PARALLEL ARRAYS FOR TAXES ----
        taxdescription => \@taxdescriptions,
        taxbase        => \@taxbases,
        taxrate        => \@taxrates,
        tax            => \@taxamounts,

        # ---- PARALLEL ARRAYS FOR PAYMENTS ----
        paymentdate    => \@paymentdates,
        paymentaccount => \@paymentaccounts,
        paymentsource  => \@paymentsources,
        payment        => \@paymentamounts,

        # This indicates there's at least 1 payment
        paid_1 => @paymentamounts ? 1 : "",
    );

    return \%data;
}
$api->get(
    "/print_invoice" => sub {
        my $c = shift;

        # Extract parameters
        my $client   = $c->param('client') || die "Missing client parameter";
        my $vc       = $c->param('vc')     || die "Missing vc parameter";
        my $id       = $c->param('id')     || die "Missing invoice id";
        my $template = $vc eq 'customer' ? 'invoice' : 'vendor_invoice';

        # Fetch invoice data dynamically
        my $invoice_data = build_invoice( $c, $client, $vc, $id );
        my $letterhead   = build_letterhead($c);

        # Merge letterhead details into invoice data
        $invoice_data->{company}           = $letterhead->{company};
        $invoice_data->{address}           = $letterhead->{address};
        $invoice_data->{tel}               = $letterhead->{tel};
        $invoice_data->{companyemail}      = $letterhead->{companyemail};
        $invoice_data->{companywebsite}    = $letterhead->{companywebsite};
        $invoice_data->{lastpage}          = 0;
        $invoice_data->{sumcarriedforward} = 0;
        $invoice_data->{templates}         = "templates/$client";
        $invoice_data->{language_code}     = "en";
        $invoice_data->{IN}                = "$template.tex";
        $invoice_data->{OUT}               = ">temp/invoice.pdf";
        $invoice_data->{format}            = "pdf";
        $invoice_data->{media}             = "screen";
        $invoice_data->{copies}            = 1;

        my $form      = new Form;
        my $user_path = "temp/";
        for my $k ( keys %$invoice_data ) {
            $form->{$k} = $invoice_data->{$k};
        }
        my $dvipdf    = "";
        my $xelatex   = "";
        my $userspath = "temp/";
        $form->parse_template( $c->slconfig, $userspath, $dvipdf, $xelatex )
          or die "parse_template failed!";
        my $pdf_path = "temp/invoice.pdf";

        # Read the PDF file content
        open my $fh, $pdf_path or die "Cannot open file $pdf_path: $!";
        binmode $fh;
        my $pdf_content = do { local $/; <$fh> };
        close $fh;

        # Delete the PDF file after reading
        unlink $pdf_path or warn "Could not delete $pdf_path: $!";

        # Return the PDF content as response
        $c->res->headers->content_type('application/pdf');
        $c->res->headers->content_disposition(
            "attachment; filename=\"$invoice_data->{invnumber}.pdf\"");
        $c->render( data => $pdf_content );
    }
);

sub build_transaction {
    my ( $c, $client, $vc, $id ) = @_;

    # Determine transaction type and corresponding field names.
    my $transaction_type = $vc eq 'vendor' ? 'AP'           : 'AR';
    my $vc_field         = $vc eq 'vendor' ? 'vendornumber' : 'customernumber';
    my $vc_id_field      = $vc eq 'vendor' ? 'vendor_id'    : 'customer_id';

    # Establish database connection.
    my $dbs = $c->dbs($client);
    $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

    # Process letterhead.
    my $letterhead = build_letterhead($c);

    # AR transactions use -1 as a multiplier for amounts.
    my $amount_multiplier = $transaction_type eq 'AR' ? -1 : 1;

    # Initialize form object.
    my $form = Form->new;
    $form->{id} = $id;
    $form->{vc} = $vc;

    # Prepare the form with transaction links/info.
    $form->create_links( $transaction_type, $c->slconfig, $vc );
    warn( Dumper $form );
    ### --- FLATTEN LINE ITEMS --- ###
    # Build parallel arrays for line item data (similar to build_invoice)
    my ( @lineitem_ids, @lineitem_accno, @lineitem_account,
        @lineitem_amount, @lineitem_description, @lineitem_projectnumber );

    my $subtotal       = 0;
    my $i              = 1;
    my @sorted_entries = sort { $a->{id} <=> $b->{id} }
      @{ $form->{acc_trans}{"${transaction_type}_amount"} || [] };

    foreach my $entry (@sorted_entries) {

        # Calculate adjusted amount.
        my $amt = $amount_multiplier * ( -$entry->{amount} );
        $subtotal += $amt;

        push @lineitem_ids,         $i++;
        push @lineitem_accno,       $entry->{accno};
        push @lineitem_account,     $entry->{description};
        push @lineitem_amount,      $form->format_amount( $c->slconfig, $amt );
        push @lineitem_description, $entry->{memo} // '';
        push @lineitem_projectnumber, '';
    }

    ### --- FLATTEN PAYMENTS --- ###
    # Build parallel arrays for payments.
    my (
        @paymentdate, @paymentaccount, @paymentsource,
        @paymentmemo, @paymentamount
    );
    my $payment_total = 0;
    if ( defined $form->{acc_trans}{"${transaction_type}_paid"}
        && ref( $form->{acc_trans}{"${transaction_type}_paid"} ) eq 'ARRAY' )
    {
        foreach my $pay ( @{ $form->{acc_trans}{"${transaction_type}_paid"} } )
        {
            my $p_amt = $amount_multiplier * $pay->{amount};
            $payment_total += $p_amt;

            push @paymentdate, $pay->{transdate} // '';
            push @paymentaccount,
              (
                defined $pay->{accno} && defined $pay->{description}
                ? "$pay->{accno}--$pay->{description}"
                : ''
              );
            push @paymentsource, $pay->{source} // '';
            push @paymentmemo,   $pay->{memo}   // '';
            push @paymentamount, $form->format_amount( $c->slconfig, $p_amt );
        }
    }
    my $paid_1 = @paymentdate ? 1 : 0;

    ### --- FLATTEN TAX INFORMATION --- ###
    # Build parallel arrays for tax data.
    my ( @taxaccno, @taxamount, @taxrate, @taxdescription );
    my $taxtotal = 0;
    if ( $form->{acc_trans}{"${transaction_type}_tax"}
        && ref( $form->{acc_trans}{"${transaction_type}_tax"} ) eq 'ARRAY' )
    {
        foreach my $tax ( @{ $form->{acc_trans}{"${transaction_type}_tax"} } ) {
            my $t_amt = $amount_multiplier * $tax->{amount};
            $taxtotal += $t_amt;

            push @taxaccno,       $tax->{accno} // '';
            push @taxamount,      $form->format_amount( $c->slconfig, $t_amt );
            push @taxrate,        defined $tax->{rate} ? $tax->{rate} : '';
            push @taxdescription, '';    # Supply tax description if available
        }
    }

    my $num2text;
    if ( $form->{language_code} ne "" ) {
        $num2text = new CP $form->{language_code};
    }
    else {
        $num2text = new CP $c->slconfig->{countrycode};
    }
    $num2text->init;

    # Compute overall invoice total.
    my $invtotal = ( $subtotal + $taxtotal ) - $payment_total;

    # Compute text representation and decimal portion of the invoice total.
    my $formatted_total = sprintf( "%.2f", $invtotal );
    my ( $integer, $decimal ) = split( /\./, $formatted_total );
    my $text_amount = $num2text->num2text($integer);
    my $vc_data     = build_vc( $c, $id, $vc );

    ### --- Build the Flattened Transaction Data Structure --- ###
    my %transaction = (

        # Basic address / vendor-customer info
        name => $vc_data->{name}
          || '',
        address1 => $vc_data->{address1}
          || '',
        address2 => $vc_data->{address2}
          || '',
        city => $vc_data->{city}
          || '',
        state => $vc_data->{state}
          || '',
        zipcode => $vc_data->{zipcode}
          || '',
        country => $vc_data->{country}
          || '',
        contact => $vc_data->{contact}
          || '',
        email => $vc_data->{email}
          || '',
        vendortaxnumber => $vc_data->{vendortaxnumber}
          || '',
        (
            $vc eq 'customer'
            ? (
                customerphone => $vc_data->{customerphone}
                  || '',
                customerfax => $vc_data->{customerfax}
                  || '',
              )
            : (
                vendorphone => $vc_data->{vendorphone}
                  || '',
                vendorfax => $vc_data->{vendorfax}
                  || '',
            )
        ),
        ## Invoice Details
        invnumber => $form->{invnumber},
        invdate   => $form->{transdate},
        duedate   => $form->{duedate},
        ponumber  => $form->{ponumber},
        ordnumber => $form->{ordnumber},
        employee  => $form->{employee} || '',

        ## Line Items as parallel arrays
        item_id       => \@lineitem_ids,
        accno         => \@lineitem_accno,
        account       => \@lineitem_account,
        amount        => \@lineitem_amount,
        description   => \@lineitem_description,
        projectnumber => \@lineitem_projectnumber,

        ## Totals & Amount in Words
        subtotal    => $form->format_amount( $c->slconfig, $subtotal ),
        invtotal    => $form->format_amount( $c->slconfig, $invtotal ),
        text_amount => $text_amount,
        decimal     => $decimal,
        currency    => $form->{currency},

        ## Payments as parallel arrays
        paid_1         => $paid_1,
        paymentdate    => \@paymentdate,
        paymentaccount => \@paymentaccount,
        paymentsource  => \@paymentsource,
        paymentmemo    => \@paymentmemo,
        payment        => \@paymentamount,

        ## Tax Information as parallel arrays
        taxaccno       => \@taxaccno,
        taxamount      => \@taxamount,
        taxrate        => \@taxrate,
        taxdescription => \@taxdescription,
    );

    # Include tax inclusion flag if applicable.
    if (@taxaccno) {
        $transaction{taxincluded} = $form->{taxincluded};
    }

    # Pass through vendor/customer identifiers.
    $transaction{$vc_field}    = $form->{$vc_field};
    $transaction{$vc_id_field} = $form->{$vc_id_field};

    # Optionally, add discount information if applicable:
    # $transaction{cd_amount}     = ...;
    # $transaction{discountterms} = ...;
    # $transaction{cashdiscount}  = ...;

    return \%transaction;
}
$api->get(
    "/print_transaction" => sub {
        my $c = shift;

        # Extract parameters
        my $client = $c->param('client') || die "Missing client parameter";
        my $vc     = $c->param('vc')     || die "Missing vc parameter";
        my $id     = $c->param('id')     || die "Missing transaction id";

# Determine the template based on a 'template' parameter or default based on vc type
        my $template = $c->param('template')
          || ( $vc eq 'customer' ? 'ar_transaction' : 'ap_transaction' );

        # Validate template selection (optional)
        die "Invalid template selection"
          unless $template =~
          /^(ap_transaction|ar_transaction|credit_note|debit_note)$/;

        # Fetch transaction data dynamically
        my $transaction_data = build_transaction( $c, $client, $vc, $id );
        my $letterhead       = build_letterhead($c);

        # Merge additional parameters into the transaction data
        $transaction_data->{company}           = $letterhead->{company};
        $transaction_data->{address}           = $letterhead->{address};
        $transaction_data->{tel}               = $letterhead->{tel};
        $transaction_data->{companyemail}      = $letterhead->{companyemail};
        $transaction_data->{companywebsite}    = $letterhead->{companywebsite};
        $transaction_data->{lastpage}          = 0;
        $transaction_data->{sumcarriedforward} = 0;
        $transaction_data->{templates}         = "templates/$client";
        $transaction_data->{language_code}     = "en";
        $transaction_data->{IN}                = "$template.tex";
        $transaction_data->{OUT}               = ">temp/transaction.pdf";
        $transaction_data->{format}            = "pdf";
        $transaction_data->{media}             = "screen";
        $transaction_data->{copies}            = 1;

        my $form      = new Form;
        my $user_path = "temp/";
        for my $k ( keys %$transaction_data ) {
            $form->{$k} = $transaction_data->{$k};
        }
        warn( Dumper $form );
        my $dvipdf    = "";
        my $xelatex   = "";
        my $userspath = "temp/";

        $form->parse_template( $c->slconfig, $userspath, $dvipdf, $xelatex )
          or die "parse_template failed!";

        my $pdf_path = "temp/transaction.pdf";

        # Read the PDF file content
        open my $fh, $pdf_path or die "Cannot open file $pdf_path: $!";
        binmode $fh;
        my $pdf_content = do { local $/; <$fh> };
        close $fh;

        # Delete the PDF file after reading
        unlink $pdf_path or warn "Could not delete $pdf_path: $!";

# Return the PDF content as response using the transaction's invoice number for the file name
        $c->res->headers->content_type('application/pdf');
        $c->res->headers->content_disposition(
            "attachment; filename=\"$transaction_data->{invnumber}.pdf\"");
        $c->render( data => $pdf_content );
    }
);

app->start;
