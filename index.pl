#!/usr/bin/env perl

BEGIN {
    push @INC, '.';
}

use Mojolicious::Lite;
use Minion;
use XML::Hash::XS;
use Data::Dumper;
use Mojo::Util qw(unquote);
use Mojo::JSON qw(encode_json decode_json);
use Mojo::File;
use Mojo::Upload;
use Mojo::Asset::File;
use Mojo::Headers;
use Encode qw(decode encode);
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
use SL::IC;
use SL::PE;
use SL::HR;
use SL::FM;
use SL::BP;
use SL::IM;
use DateTime;
use DateTime::Format::ISO8601;
use Date::Parse;
use File::Path qw(make_path);
use File::Basename;
use File::Copy::Recursive qw(dircopy);
use POSIX                 qw(strftime);
use Time::Piece;
use Mojo::Template;
use File::Slurp;
use Dotenv;
use IO::Compress::Zip qw(zip $ZipError);
use Archive::Zip      qw( :ERROR_CODES :CONSTANTS );
use utf8;
use open qw(:std :utf8);
use Text::CSV;
use Digest::HMAC_SHA1 qw(hmac_sha1);
use MIME::Base64;
use Imager::QRCode;
Dotenv->load;
app->config( hypnotoad => { listen => ['http://*:3000'] } );
my $base_url          = $ENV{BACKEND_URL};
my $front_end         = $ENV{FRONT_END_URL};
my $postgres_user     = $ENV{POSTGRES_USER};
my $postgres_password = $ENV{POSTGRES_PASSWORD};

#$front_end = "http://localhost:9000";

my %myconfig = (
    dateformat   => 'yyyy/mm/dd',
    dbdriver     => 'Pg',
    dbhost       => 'localhost',
    dbname       => '',
    dbpasswd     => $postgres_password,
    dbport       => '5432',
    dbuser       => $postgres_user,
    numberformat => '1,000.00',
);

helper slconfig => sub { \%myconfig };

helper dbs => sub {
    my ( $c, $dbname ) = @_;

    my $dbh;
    eval {
        $dbh = DBI->connect( "dbi:Pg:dbname=$dbname", $postgres_user,
            $postgres_password, { RaiseError => 1, PrintError => 1 } );
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

# Subroutine to ensure profile table has config column
sub _ensure_profile_config_column {
    my ( $dbh, $app_log ) = @_;

    eval {
        my $column_check_sql = q{
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'profile' 
            AND column_name = 'config'
        };

        my $sth = $dbh->prepare($column_check_sql);
        $sth->execute();
        my $column_exists = $sth->fetchrow_array();
        $sth->finish();

        # If column doesn't exist, add it
        if ( !$column_exists ) {
            my $alter_sql = "ALTER TABLE profile ADD COLUMN config JSONB";
            $dbh->do($alter_sql);
            $app_log->info("Added 'config' column (JSONB) to 'profile' table")
              if $app_log;
        }
    };
    if ($@) {
        die "Schema update failed: "
          . ( $DBI::errstr // $@ // "Unknown error" );
    }
}

helper central_dbs => sub {
    my $c      = shift;
    my $dbname = "centraldb";
    my $dbh;
    eval {
        $dbh = DBI->connect( "dbi:Pg:dbname=$dbname", $postgres_user,
            $postgres_password, { RaiseError => 1, PrintError => 1 } );
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

    # Ensure profile table has config column
    eval { _ensure_profile_config_column( $dbh, $c->app->log ); };
    if ($@) {
        my $error_message = "$@";
        $c->render(
            status => 500,
            json   => {
                message => "Database schema update failed: $error_message"
            }
        );
        $c->app->log->error("Database schema update failed: $error_message");
        return undef;
    }

    my $dbs = DBIx::Simple->connect($dbh);
    return $dbs;
};

plugin Minion => { Pg =>
      "postgresql://$postgres_user:$postgres_password\@localhost/centraldb" };

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

# plugin 'Minion::Admin' => { return_to => '/minion' };

# Database Updates on Startup
app->hook(
    before_server_start => sub {
        my ( $server, $app ) = @_;

        $app->log->info("Running database updates on startup...");

        # Check if db_updates directory exists
        unless ( -d "db_updates/" ) {
            $app->log->info(
                "No db_updates directory found, skipping startup updates");
            return;
        }

        eval {
            run_startup_database_updates($app);
            $app->log->info("Database updates completed successfully");
        } or do {
            my $error = $@ || 'Unknown error';
            $app->log->error("Database updates failed: $error");
            exit 1;
        };
    }
);

# Enable CORS for all routes
app->hook(
    before_dispatch => sub {
        my $c = shift;
        $c->res->headers->header( 'Access-Control-Allow-Origin' => '*' );
        $c->res->headers->header( 'Access-Control-Allow-Methods' =>
              'GET, POST, PUT, PATCH, DELETE, OPTIONS' );
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
                  'GET, POST, PUT, PATCH, DELETE, OPTIONS' );
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

my $ai_plugin = 0;
if ( $ENV{AI_PLUGIN} && -d './neo_ai_plugin' ) {
    use neo_ai_plugin::AIPlugin;
    app->plugin('AIPlugin');
    $ai_plugin = 1;
}

my $r       = app->routes;
my $central = $r->under('/');
my $api     = $r->under('/client/:client');

get '/logo/:client/' => sub {
    my $c      = shift;
    my $dbname = $c->param('client');
    my $path   = $c->app->home->rel_file("templates/$dbname/logo.png");

    # Check if the file exists, and serve it if it does
    if ( -e $path ) {
        $c->reply->file($path);
    }
    else {
        $c->reply->not_found;
    }
};
###############################
####                       ####
####   CENTRAL DATABASE    ####
####                       ####
###############################

my $neoledger_perms =
'["dashboard", "cash", "cash.recon", "gl", "gl.add", "gl.transactions", "ledger.batchupdate", "items", "items.part", "items.service", "items.search.allitems", "items.search.parts", "items.search.services", "reports", "reports.trial", "reports.income", "system", "system.currencies", "system.projects", "system.departments", "system.defaults", "system.chart", "system.chart.list", "system.chart.add", "system.chart.gifi", "system.taxes",  "system.templates", "system.audit", "system.yearend", "system.batch", "import", "import.gl", "import.customer", "import.ar_invoice", "import.ar_transaction", "import.vendor", "import.ap_invoice", "import.ap_transaction", "reports.balance", "customer", "customer.transaction", "customer.invoice", "customer.transaction_return", "customer.invoice_return", "customer.add", "customer.batch", "customer.batchupdate", "customer.reminder", "customer.consolidate", "customer.transactions", "customer.search", "customer.history", "vendor", "vendor.transaction", "vendor.invoice", "vendor.transaction_return", "vendor.invoice_return", "vendor.add", "vendor.batchupdate", "vendor.transactions", "vendor.search", "vendor.history", "reports.alltaxes", "vendor.taxreport", "customer.taxreport", "cash.payments", "cash.receipts", "cash.report.customer", "cash.report.vendor", "system.bank", "import.bank", "customer.order", "customer.orders", "customer.quotation", "customer.quotations", "vendor.order", "vendor.orders", "vendor.quotation", "vendor.quotations", "stations.manage", "stations.get", "ai.prompts", "bank.payments", "stations.bank_transactions", "customer.upload", "vendor.upload", "document.list","integrations.manage","customer.overview","vendor.overview", "system.notifications", "system.messages", "cockpit.inbox"]';

my $reports_only =
'["dashboard", "gl", "gl.transactions", "items", "items.search.allitems", "items.search.parts", "items.search.services", "reports", "reports.trial", "reports.income",  "reports.balance", "customer", "customer.transactions", "customer.search", "customer.history", "vendor", "vendor.search", "vendor.history", "vendor.transactions", "reports.alltaxes", "vendor.taxreport", "customer.taxreport", "cash.report.customer", "cash.report.vendor", "customer.orders", "customer.quotations", "vendor.orders", "vendor.quotations","customer.overview","vendor.overview"]';
helper send_email_central => sub {
    use Email::Sender::Transport::SMTP;
    use Email::Stuffer;
    use Data::Dumper;
    use MIME::Base64;
    my ( $c, $to, $subject, $content, $attachments, $options, $client ) = @_;

    # Options can include: cc => [], bcc => []
    $options //= {};
    my $cc_list  = $options->{cc}  || [];
    my $bcc_list = $options->{bcc} || [];

    # Resolve per-DB SMTP config when a client is provided
    my ( $smtp_host, $smtp_port, $smtp_ssl, $smtp_sasl,
        $smtp_username, $smtp_password, $smtp_from_name );

    if ($client) {
        my $dbs = eval { $c->dbs($client) };
        if ($dbs) {
            my $defaults_rows = $dbs->query("SELECT fldname, fldvalue FROM defaults WHERE fldname IN ('smtp_host','smtp_port','smtp_ssl','smtp_sasl','smtp_username','smtp_from_name')")->hashes;
            my %d = map { $_->{fldname} => $_->{fldvalue} } @$defaults_rows;

            if ( $d{smtp_host} && $d{smtp_username} ) {
                my $key_row = $dbs->query(
                    "SELECT fldvalue FROM connection_keys WHERE fldname = 'smtp_password'"
                )->hash;

                if ($key_row) {
                    my $aes_key = $ENV{aes_key};
                    if ($aes_key) {
                        my $fldvalue = $key_row->{fldvalue};
                        my $enc_pw = eval {
                            my $decoded = ref($fldvalue) eq 'HASH'
                                ? $fldvalue
                                : decode_json($fldvalue);
                            $decoded->{password};
                        };
                        if ($enc_pw) {
                            my $decrypted = _aes_decrypt( $enc_pw, $aes_key );
                            if ($decrypted) {
                                $smtp_host      = $d{smtp_host};
                                $smtp_port      = $d{smtp_port}     || 587;
                                $smtp_ssl       = $d{smtp_ssl}      || 'starttls';
                                $smtp_sasl      = $d{smtp_sasl}     // 1;
                                $smtp_username  = $d{smtp_username};
                                $smtp_from_name = $d{smtp_from_name} || '';
                                $smtp_password  = $decrypted;
                            }
                        } # end if $enc_pw
                    }
                }
            }
        }
    }

    # Fall back to system-level env vars if no per-DB config resolved
    unless ($smtp_host) {
        $smtp_host      = $ENV{SMTP_HOST};
        $smtp_port      = $ENV{SMTP_PORT};
        $smtp_ssl       = $ENV{SMTP_SSL};
        $smtp_sasl      = $ENV{SMTP_SASL};
        $smtp_username  = $ENV{SMTP_USERNAME};
        $smtp_password  = $ENV{SMTP_PASSWORD};
        $smtp_from_name = $ENV{SMTP_FROM_NAME};
    }

    # Check if Send in Blue should be used (system-level only, no per-DB override)
    if ( $ENV{SEND_IN_BLUE} && !$client ) {

        # Use Send in Blue API with Mojo::UserAgent
        my $api_key = $ENV{SEND_IN_BLUE};
        my $ua      = $c->ua;

       # Convert newlines to <br> for HTML email (only if content is plain text)
       # Provide fallback content if empty (SendinBlue requires htmlContent)
        my $html_content =
          ( defined($content) && $content ne '' )
          ? $content
          : '<p>&nbsp;</p>';

        # Skip conversion if content is already HTML (contains HTML tags)
        unless ( $html_content =~ /<(html|div|table|p|h[1-6]|span|a|br)/i ) {
            $html_content =~ s/\n/<br>\n/g;
        }

        # Prepare the payload for Send in Blue API
        my $payload = {
            sender => {
                email => $smtp_username,
                name  => $smtp_from_name
            },
            to => [
                {
                    email => $to,
                    name  => $to
                }
            ],
            subject     => $subject,
            htmlContent => $html_content
        };

        # Add CC recipients if provided
        if ( $cc_list && ref($cc_list) eq 'ARRAY' && @$cc_list ) {
            $payload->{cc} = [ map { { email => $_, name => $_ } } @$cc_list ];
        }

        # Add BCC recipients if provided
        if ( $bcc_list && ref($bcc_list) eq 'ARRAY' && @$bcc_list ) {
            $payload->{bcc} =
              [ map { { email => $_, name => $_ } } @$bcc_list ];
        }

        # Add attachments if provided
        if ( $attachments && ref($attachments) eq 'ARRAY' ) {
            my @attachment_list;
            foreach my $file_path (@$attachments) {
                if ( -f $file_path ) {
                    my $filename = ( split( '/', $file_path ) )[-1];
                    open my $fh, '<:raw', $file_path or next;
                    my $content = do { local $/; <$fh> };
                    close $fh;

                    push @attachment_list,
                      {
                        name    => $filename,
                        content => MIME::Base64::encode_base64($content)
                      };
                }
            }
            $payload->{attachment} = \@attachment_list if @attachment_list;
        }

        # Make the API request
        my $tx = $ua->post(
            'https://api.sendinblue.com/v3/smtp/email' => {
                'api-key'      => $api_key,
                'Content-Type' => 'application/json',
                'Accept'       => 'application/json'
            } => json => $payload
        );

        # Handle the response
        if ( $tx->res->code == 201 ) {
            return {
                message => "Email sent successfully via Send in Blue.",
                status  => 200
            };
        }
        else {
            my $error = $tx->res->json || { message => $tx->res->message };
            return {
                error => "Failed to send email via Send in Blue: "
                  . ( $error->{message} || "Unknown error" ),
                status => 500
            };
        }
    }

    # Fall back to the original email sending method
    my $transport = Email::Sender::Transport::SMTP->new(
        host          => $smtp_host,
        port          => $smtp_port,
        ssl           => $smtp_ssl,
        sasl_username => $smtp_username,
        sasl_password => $smtp_password,
        sasl          => $smtp_sasl,
    );

    # Create the Email::Stuffer object
    my $from_name = $smtp_from_name || $ENV{PRODUCT_NAME};
    my $from =
      $from_name
      ? "$from_name <$smtp_username>"
      : $smtp_username;

    # Detect if content is HTML or plain text
    my $email_obj = Email::Stuffer->from($from)->to($to)->subject($subject);

    # Add CC recipients if provided
    if ( $cc_list && ref($cc_list) eq 'ARRAY' && @$cc_list ) {
        $email_obj->cc( join( ', ', @$cc_list ) );
    }

    # Add BCC recipients if provided
    if ( $bcc_list && ref($bcc_list) eq 'ARRAY' && @$bcc_list ) {
        $email_obj->bcc( join( ', ', @$bcc_list ) );
    }

    if ( $content =~ /<(html|div|table|p|h[1-6]|span|a|br)/i ) {
        $email_obj->html_body($content);
    }
    else {
        $email_obj->text_body($content);
    }

    # Attach files if provided
    if ( $attachments && ref($attachments) eq 'ARRAY' ) {
        foreach my $file_path (@$attachments) {
            $email_obj->attach_file($file_path);
        }
    }

    # Attempt to send the email using send_or_die
    my $success = eval {
        $email_obj->transport($transport)->send_or_die;
        1;
    };

    if ( !$success ) {
        my $error_message = Dumper($@);
        return {
            error =>
              "Failed to send email. Please try again later. $error_message",
            status => 500
        };
    }

    return {
        message => "Email sent successfully.",
        status  => 200
    };
};

helper get_user_profile => sub {
    my $c          = shift;
    my $dbs        = $c->central_dbs();
    my $sessionkey = $c->req->headers->header('Authorization');
    my $profile    = $dbs->query(
        "SELECT s.profile_id, p.email, p.config
FROM session s
LEFT JOIN profile p ON s.profile_id = p.id
WHERE s.sessionkey = ?",
        $sessionkey
    )->hash;
    unless ( $profile && $profile->{profile_id} ) {
        return $c->render(
            status => 401,
            json   => { message => "Invalid session key" }
        );
    }
    return $profile;
};
helper is_admin => sub {
    my $c            = shift;
    my $check_only   = shift;    # if true, return 0 instead of rendering 403
    my $client       = $c->param('client');
    my $profile      = $c->get_user_profile();
    my $dbs          = $c->central_dbs();

    my $dataset =
      $dbs->query( "SELECT id from dataset WHERE db_name = ?", $client )->hash;
    return 0 if $check_only && !$dataset;

    my $sql =
"SELECT access_level FROM dataset_access WHERE profile_id = ? AND dataset_id = ?";
    my $access =
      $dbs->query( $sql, $profile->{profile_id}, $dataset->{id} )->hash;

    unless (
        $access
        && (   $access->{access_level} eq 'admin'
            || $access->{access_level} eq 'owner' )
      )
    {
        return 0 if $check_only;
        return $c->render(
            status => 403,
            json   => { message => "Insufficient permissions" }
        );
    }

    return 1;
};

# Route to generate an OTP for signup
$central->post(
    '/signup_otp' => sub {
        my $c      = shift;
        my $params = $c->req->json;

        my $email    = $params->{email};
        my $password = $params->{password};

        unless ( $email && $password ) {
            return $c->render(
                status => 400,
                json   => { message => "Missing required info" }
            );
        }

        # Check if public signup is allowed.
        my $public_signup = $ENV{PUBLIC_SIGNUP} // 0;
        unless ( $public_signup == 1 ) {
            return $c->render(
                status => 403,
                json   => { message => "Public signups are not allowed" }
            );
        }

        my $central_dbs = $c->central_dbs();
        return unless $central_dbs;

        # Check if the user already exists in the profile table
        my $existing_user =
          $central_dbs->query( 'SELECT id FROM profile WHERE email = ?',
            $email )->hash;
        if ($existing_user) {
            return $c->render(
                status => 409,
                json   => { message => "User already exists" }
            );
        }

        # Generate a 6-digit OTP (for demo purposes)
        my $otp = int( rand(900000) ) + 100000;

        $central_dbs->query( 'INSERT INTO otp (email, code) VALUES (?, ?)',
            $email, $otp );

        my $sent =
          $c->send_email_central( $email, "Your OTP", "Your OTP is: $otp", [] );
        unless ($sent) {
            return $c->render(
                status => 500,
                json   => { message => "Failed to send OTP email" }
            );
        }

        return $c->render( json => { message => "OTP generated" } );
    }
);

$central->post(
    '/signup' => sub {
        my $c      = shift;
        my $params = $c->req->json;

        my $email    = $params->{email};
        my $password = $params->{password};
        my $otp      = $params->{otp};
        my $invite   = $params->{invite};

        # Always require email and password.
        unless ( $email && $password ) {
            return $c->render(
                status => 400,
                json   => { message => "Missing required info" }
            );
        }

        # Check PUBLIC_SIGNUP flag (defaults to 0 if undefined)
        my $public_signup = $ENV{PUBLIC_SIGNUP} // 0;

        # When public signup is not allowed, an invite is mandatory.
        if ( $public_signup != 1 && !$invite ) {
            return $c->render(
                status => 400,
                json   => { message => "Invite code required for signup" }
            );
        }

        my $central_dbs = $c->central_dbs();
        return unless $central_dbs;

        # Check if the user already exists (to handle duplicate requests)
        my $existing_user =
          $central_dbs->query( 'SELECT id FROM profile WHERE email = ?',
            $email )->hash;
        if ($existing_user) {
            return $c->render(
                status => 409,
                json   => { message => "User already exists" }
            );
        }

        # If an invite is provided, validate it
        if ($invite) {
            my $invite_record = $central_dbs->query(
                'SELECT id FROM invite WHERE invite_code = ?', $invite )->hash;
            unless ($invite_record) {
                return $c->render(
                    status => 400,
                    json   => { message => "Invalid invite code" }
                );
            }
        }

        # Otherwise, if public signup is enabled, OTP is required
        else {
            unless ($otp) {
                return $c->render(
                    status => 400,
                    json   => { message => "Missing OTP" }
                );
            }
            my $otp_record = $central_dbs->query(
                'SELECT id FROM otp WHERE email = ? AND code = ?',
                $email, $otp )->hash;
            unless ($otp_record) {
                return $c->render(
                    status => 400,
                    json   => { message => "Invalid OTP or email" }
                );
            }
        }

        # Insert the new user into the profile table
        my $insert_query =
'INSERT INTO profile (email, password) VALUES (?, crypt(?, gen_salt(\'bf\')))';
        my $insert_result =
          $central_dbs->query( $insert_query, $email, $password );

        unless ($insert_result) {
            return $c->render(
                status => 500,
                json   => { message => "Failed to create profile" }
            );
        }

     # Retrieve the last inserted id using DBIx::Simple's last_insert_id method.
        my $profile_id =
          $central_dbs->last_insert_id( undef, undef, 'profile', 'id' );
        unless ($profile_id) {
            return $c->render(
                status => 500,
                json   => { message => "Failed to retrieve profile id" }
            );
        }

        my $enforce_2fa = $ENV{ENFORCE_2FA} // 0;

        if ($enforce_2fa) {
            my $temp_sessionkey = $central_dbs->query(
                'INSERT INTO temp_2fa_session (profile_id, temp_sessionkey) 
                 VALUES (?, encode(gen_random_bytes(32), ?)) 
                 RETURNING temp_sessionkey',
                $profile_id, 'hex'
            )->hash->{temp_sessionkey};

            return $c->render(
                status => 200,
                json   => {
                    requires_2fa_setup => 1,
                    temp_sessionkey    => $temp_sessionkey,
                    message            => "2FA setup required"
                }
            );
        }

        my $session_key = $central_dbs->query(
'INSERT INTO session (profile_id, sessionkey) VALUES (?, encode(gen_random_bytes(32), ?)) RETURNING sessionkey',
            $profile_id, 'hex'
        )->hash->{sessionkey};

        return $c->render(
            json => {
                sessionkey => $session_key,
            }
        );
    }
);
$central->get(
    '/check_signup' => sub {
        my $c = shift;

        my $params        = $c->req->params;
        my $invite        = $c->param('invite');
        my $public_signup = $ENV{PUBLIC_SIGNUP} || 0;
        warn($public_signup);

        # Handle public signup disabled case
        if ( $public_signup == 0 ) {
            if ($invite) {
                my $central_dbs = $c->central_dbs();
                return unless $central_dbs;

                my $invite_record = $central_dbs->query(
                    'SELECT id FROM invite WHERE invite_code = ?', $invite )
                  ->hash;

                return $c->render(
                    json => {
                        message => $invite_record
                        ? "Valid invite code"
                        : "Invalid invite code",
                        public_signup => 0,
                        invite_code   => $invite_record ? 1 : 0,
                    }
                );
            }
            else {
                return $c->render(
                    json => {
                        message       => "Public signups are not allowed",
                        public_signup => 0,
                        invite_code   => 0,
                    }
                );
            }
        }

        # Handle public signup enabled case
        my $invite_verified = 0;
        if ($invite) {
            my $central_dbs = $c->central_dbs();
            return unless $central_dbs;

            my $invite_record = $central_dbs->query(
                'SELECT id FROM invite WHERE invite_code = ?', $invite )->hash;

            if ( !$invite_record ) {
                return $c->render(
                    json => {
                        message       => "Invalid invite code",
                        public_signup => 1,
                        invite_code   => 0,
                    }
                );
            }
            $invite_verified = 1;
        }

        return $c->render(
            json => {
                message => $invite
                ? "Public signup allowed and invite verified"
                : "Public signup allowed",
                public_signup => 1,
                invite_code   => $invite_verified,
            }
        );
    }
);

helper generate_totp_secret => sub {
    my $c      = shift;
    my $chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    my $secret = '';
    for ( 1 .. 32 ) {
        $secret .= substr( $chars, int( rand(32) ), 1 );
    }
    return $secret;
};

helper generate_totp_code => sub {
    my ( $c, $secret, $time_step ) = @_;
    $time_step //= int( time() / 30 );

    my $binary_secret = $c->base32_decode($secret);

    my $time_bytes = pack( 'Q>', $time_step );
    my $hmac       = hmac_sha1( $time_bytes, $binary_secret );

    my $offset    = ord( substr( $hmac, -1 ) ) & 0x0f;
    my $truncated = unpack( 'N', substr( $hmac, $offset, 4 ) ) & 0x7fffffff;

    return sprintf( '%06d', $truncated % 1000000 );
};

helper verify_totp => sub {
    my ( $c, $secret, $code, $window ) = @_;
    $window //= 1;    # Allow 1 time step before/after

    my $current_time = int( time() / 30 );

    for my $time_step (
        ( $current_time - $window ) .. ( $current_time + $window ) )
    {
        my $expected = $c->generate_totp_code( $secret, $time_step );
        return 1 if $expected eq $code;
    }
    return 0;
};

helper base32_decode => sub {
    my ( $c, $base32 ) = @_;
    my $base32_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    my %char_map     = map { substr( $base32_chars, $_, 1 ) => $_ } 0 .. 31;

    my $bits = '';
    for my $char ( split //, uc($base32) ) {
        $bits .= sprintf( '%05b', $char_map{$char} // 0 );
    }

    my $bytes = '';
    while ( length($bits) >= 8 ) {
        $bytes .= chr( oct( '0b' . substr( $bits, 0, 8 ) ) );
        $bits = substr( $bits, 8 );
    }

    return $bytes;
};
helper generate_qr_svg => sub {
    my ( $c, $data ) = @_;

    # Generate the QR code matrix (array of array of 0/1)
    my $qrcode = Imager::QRCode->new(
        version       => 0,
        level         => 'M',
        casesensitive => 1,
        lightcolor    => Imager::Color->new('white'),
        darkcolor     => Imager::Color->new('black'),
    );

    my $matrix = $qrcode->plot($data)->to_paletted;  # convert to paletted image
    my ( $w, $h ) = ( $matrix->getwidth, $matrix->getheight );

    my $module_size = 4;
    my $margin      = 4;
    my $total_size  = ( $w + 2 * $margin ) * $module_size;

    my $svg =
qq{<svg width="$total_size" height="$total_size" viewBox="0 0 $total_size $total_size" xmlns="http://www.w3.org/2000/svg">};
    $svg .= qq{<rect width="$total_size" height="$total_size" fill="white"/>};

    for my $y ( 0 .. $h - 1 ) {
        for my $x ( 0 .. $w - 1 ) {
            my ( $r, $g, $b ) = $matrix->getpixel( x => $x, y => $y )->rgba;
            next if $r > 128;    # skip white pixels
            my $xpos = ( $x + $margin ) * $module_size;
            my $ypos = ( $y + $margin ) * $module_size;
            $svg .=
qq{<rect x="$xpos" y="$ypos" width="$module_size" height="$module_size" fill="black"/>};
        }
    }

    $svg .= qq{</svg>};
    return $svg;
};

$central->post(
    '/2fa/setup' => sub {
        my $c      = shift;
        my $params = $c->req->json;

        my $temp_sessionkey = $params->{temp_sessionkey};

        unless ($temp_sessionkey) {
            return $c->render(
                status => 400,
                json   => { message => "Missing temporary session" }
            );
        }

        my $central_dbs = $c->central_dbs();

        # Validate temp session
        my $temp_session = $central_dbs->query(
            'SELECT * FROM temp_2fa_session 
         WHERE temp_sessionkey = ? 
         AND expires_at > NOW()',
            $temp_sessionkey
        )->hash;

        unless ($temp_session) {
            return $c->render(
                status => 401,
                json   => { message => "Invalid or expired session" }
            );
        }

        my $profile = $central_dbs->query( 'SELECT * FROM profile WHERE id = ?',
            $temp_session->{profile_id} )->hash;

        my $existing = $central_dbs->query(
'SELECT id FROM totp_secrets WHERE profile_id = ? AND enabled = TRUE',
            $profile->{id}
        )->hash;

        if ($existing) {
            return $c->render(
                status => 400,
                json   => { message => "2FA already configured" }
            );
        }

        my $totp_record = $central_dbs->query(
'SELECT secret FROM totp_secrets WHERE profile_id = ? AND enabled = FALSE',
            $profile->{id}
        )->hash;

        my $secret;
        if ($totp_record) {
            $secret = $totp_record->{secret};
        }
        else {
            $secret = $c->generate_totp_secret();
            $central_dbs->query(
                'INSERT INTO totp_secrets (profile_id, secret, enabled) 
             VALUES (?, ?, FALSE)',
                $profile->{id}, $secret
            );
        }

        my $issuer      = $ENV{PRODUCT_NAME} // 'Neo-Ledger';
        my $otpauth_url = sprintf( 'otpauth://totp/%s:%s?secret=%s&issuer=%s',
            $issuer, $profile->{email}, $secret, $issuer );

        my $qr_svg = $c->generate_qr_svg($otpauth_url);

        return $c->render(
            json => {
                secret          => $secret,
                qr_svg          => $qr_svg,
                otpauth_url     => $otpauth_url,
                temp_sessionkey => $temp_sessionkey
            }
        );
    }
);
$central->post(
    '/2fa/verify_setup' => sub {
        my $c      = shift;
        my $params = $c->req->json;

        my $temp_sessionkey = $params->{temp_sessionkey};
        my $totp_code       = $params->{totp_code};

        unless ( $temp_sessionkey && $totp_code ) {
            return $c->render(
                status => 400,
                json   => { message => "Missing required parameters" }
            );
        }

        my $central_dbs = $c->central_dbs();

        my $temp_session = $central_dbs->query(
            'SELECT ts.*, p.config 
         FROM temp_2fa_session ts 
         JOIN profile p ON ts.profile_id = p.id 
         WHERE ts.temp_sessionkey = ? 
         AND ts.expires_at > NOW()',
            $temp_sessionkey
        )->hash;

        unless ($temp_session) {
            return $c->render(
                status => 401,
                json   => { message => "Invalid or expired session" }
            );
        }

        my $totp_record = $central_dbs->query(
            'SELECT * FROM totp_secrets 
         WHERE profile_id = ? AND enabled = FALSE',
            $temp_session->{profile_id}
        )->hash;

        unless ($totp_record) {
            return $c->render(
                status => 400,
                json   => { message => "No pending 2FA setup found" }
            );
        }

        unless ( $c->verify_totp( $totp_record->{secret}, $totp_code ) ) {
            return $c->render(
                status => 400,
                json   => { message => "Invalid code" }
            );
        }

        my @backup_codes;
        for ( 1 .. 10 ) {
            my $code = sprintf( '%08d', int( rand(100000000) ) );
            push @backup_codes, $code;
        }

        my @hashed_codes = map {
            crypt(
                $_,
                '$2b$10$'
                  . substr(
                    encode_base64(
                        pack( 'C*', map { int( rand(256) ) } 1 .. 16 )
                    ),
                    0, 22
                  )
            )
        } @backup_codes;

        $central_dbs->query(
            'UPDATE totp_secrets 
         SET enabled = TRUE, verified_at = NOW(), backup_codes = ? 
         WHERE profile_id = ?',
            encode_json( \@hashed_codes ), $temp_session->{profile_id}
        );

        $central_dbs->query(
            'DELETE FROM temp_2fa_session WHERE temp_sessionkey = ?',
            $temp_sessionkey );

        my $session_key = $central_dbs->query(
            'INSERT INTO session (profile_id, sessionkey) 
         VALUES (?, encode(gen_random_bytes(32), ?)) 
         RETURNING sessionkey',
            $temp_session->{profile_id}, 'hex'
        )->hash->{sessionkey};

        return $c->render(
            json => {
                sessionkey   => $session_key,
                config       => $temp_session->{config},
                backup_codes => \@backup_codes,
                message      => "2FA enabled successfully"
            }
        );
    }
);
$central->post(
    '/login' => sub {
        my $c      = shift;
        my $params = $c->req->json;

        my $email    = $params->{email};
        my $password = $params->{password};
        my $client   = $params->{client};

        unless ( $email && $password ) {
            return $c->render(
                status => 400,
                json   => { message => "Missing Required Info" }
            );
        }

        my $central_dbs = $c->central_dbs();
        return unless $central_dbs;

        my $login = $central_dbs->query( '
        SELECT id, config
        FROM profile
        WHERE email = ? AND crypt(?, password) = password
    ', $email, $password )->hash;

        unless ($login) {
            return $c->render(
                status => 400,
                json   => { message => "Incorrect username or password" }
            );
        }

        if ($client) {
            my $dataset =
              $central_dbs->query( 'SELECT id FROM dataset WHERE db_name = ?',
                $client )->hash;

            unless ($dataset) {
                return $c->render(
                    status => 400,
                    json   => { message => "Invalid client" }
                );
            }

            my $access = $central_dbs->query(
'SELECT access_level FROM dataset_access WHERE profile_id = ? AND dataset_id = ?',
                $login->{id}, $dataset->{id}
            )->hash;

            unless ($access) {
                return $c->render(
                    status => 403,
                    json   =>
                      { message => "User does not have access to this client" }
                );
            }
        }

        my $enforce_2fa = $ENV{ENFORCE_2FA} // 0;

        if ($enforce_2fa) {

            my $totp_record = $central_dbs->query(
'SELECT id FROM totp_secrets WHERE profile_id = ? AND enabled = TRUE',
                $login->{id}
            )->hash;

            if ($totp_record) {

                $central_dbs->query(
                    'DELETE FROM temp_2fa_session WHERE expires_at < NOW()');

                my $temp_sessionkey = $central_dbs->query(
'INSERT INTO temp_2fa_session (profile_id, temp_sessionkey, client) 
                 VALUES (?, encode(gen_random_bytes(32), ?), ?) 
                 RETURNING temp_sessionkey',
                    $login->{id}, 'hex', $client
                )->hash->{temp_sessionkey};

                return $c->render(
                    status => 200,
                    json   => {
                        requires_2fa    => 1,
                        temp_sessionkey => $temp_sessionkey,
                        message         => "Please provide 2FA code"
                    }
                );
            }
            else {
                my $temp_sessionkey = $central_dbs->query(
'INSERT INTO temp_2fa_session (profile_id, temp_sessionkey, client) 
                 VALUES (?, encode(gen_random_bytes(32), ?), ?) 
                 RETURNING temp_sessionkey',
                    $login->{id}, 'hex', $client
                )->hash->{temp_sessionkey};

                return $c->render(
                    status => 200,
                    json   => {
                        requires_2fa_setup => 1,
                        temp_sessionkey    => $temp_sessionkey,
                        message            => "2FA setup required"
                    }
                );
            }
        }

        my $session_key = $central_dbs->query(
            'INSERT INTO session (profile_id, sessionkey) 
         VALUES (?, encode(gen_random_bytes(32), ?)) 
         RETURNING sessionkey',
            $login->{id}, 'hex'
        )->hash->{sessionkey};

        return $c->render(
            json => {
                sessionkey => $session_key,
                config     => $login->{config}
            }
        );
    }
);

$central->post(
    '/2fa/verify_login' => sub {
        my $c      = shift;
        my $params = $c->req->json;

        my $temp_sessionkey = $params->{temp_sessionkey};
        my $totp_code       = $params->{totp_code};

        unless ( $temp_sessionkey && $totp_code ) {
            return $c->render(
                status => 400,
                json   => { message => "Missing required parameters" }
            );
        }

        my $central_dbs = $c->central_dbs();

        my $temp_session = $central_dbs->query(
            'SELECT ts.*, p.email, p.config 
         FROM temp_2fa_session ts 
         JOIN profile p ON ts.profile_id = p.id 
         WHERE ts.temp_sessionkey = ? 
         AND ts.expires_at > NOW()',
            $temp_sessionkey
        )->hash;

        unless ($temp_session) {
            return $c->render(
                status => 401,
                json   => { message => "Invalid or expired session" }
            );
        }

        my $totp_record = $central_dbs->query(
            'SELECT secret FROM totp_secrets 
         WHERE profile_id = ? AND enabled = TRUE',
            $temp_session->{profile_id}
        )->hash;

        unless ($totp_record) {
            return $c->render(
                status => 400,
                json   => { message => "2FA not configured" }
            );
        }

        unless ( $c->verify_totp( $totp_record->{secret}, $totp_code ) ) {

            return $c->render(
                status => 401,
                json   => { message => "Invalid 2FA code" }
            );
        }

        $central_dbs->query(
            'DELETE FROM temp_2fa_session WHERE temp_sessionkey = ?',
            $temp_sessionkey );

        my $session_key = $central_dbs->query(
            'INSERT INTO session (profile_id, sessionkey) 
         VALUES (?, encode(gen_random_bytes(32), ?)) 
         RETURNING sessionkey',
            $temp_session->{profile_id}, 'hex'
        )->hash->{sessionkey};

        return $c->render(
            json => {
                sessionkey => $session_key,
                config     => $temp_session->{config}
            }
        );
    }
);

$central->post(
    '/update_config' => sub {
        my $c             = shift;
        my $params        = $c->req->json;
        my $number_format = $params->{number_format};
        my $profile       = $c->get_user_profile();
        if ($number_format) {

            # Define valid number formats as a hash for O(1) lookup
            my %valid_formats = map { $_ => 1 }
              ( "1,000.00", "1'000.00", "1.000,00", "1000,00", "1000.00" );

            # Check if the provided format is valid
            unless ( $valid_formats{$number_format} ) {
                return $c->render(
                    json => {
                        error => "Invalid number format. Must be one of: "
                          . join( ", ", keys %valid_formats )
                    },
                    status => 400
                );
            }

            my $central_dbs = $c->central_dbs();
            return unless $central_dbs;

            $central_dbs->query(
'UPDATE profile SET config = jsonb_set(COALESCE(config, \'{}\'::jsonb), \'{number_format}\', ?::jsonb) WHERE id = ?',
                qq("$number_format"), $profile->{profile_id}
            );

            return $c->render(
                json => {
                    success => 1,
                    message => "Number format updated successfully"
                }
            );
        }

        return $c->render(
            json   => { error => "number_format parameter is required" },
            status => 400
        );
    }
);

$api->get(
    '/get_acs' => sub {
        my $c       = shift;
        my $dbs     = $c->central_dbs();
        my $profile = $c->get_user_profile();

        # Get the client parameter (the db_name)
        my $client = $c->param('client');
        unless ($client) {
            return $c->render(
                status => 400,
                json   => { message => "Missing client parameter" }
            );
        }

        # Look up the dataset using the client (db_name)
        my $dataset =
          $dbs->query( "SELECT id FROM dataset WHERE db_name = ?", $client )
          ->hash;
        unless ( $dataset && $dataset->{id} ) {
            return $c->render(
                status => 404,
                json   => { message => "Dataset not found for client" }
            );
        }
        my $dataset_id = $dataset->{id};

        # Retrieve all roles assigned to the current profile for this dataset
        my $roles = $dbs->query(
            "SELECT r.acs, r.extra_info
     FROM dataset_access da
     JOIN role r ON da.role_id = r.id
     WHERE da.profile_id = ? AND r.dataset_id = ?",
            $profile->{profile_id}, $dataset_id
        )->hashes;

        # Merge the ACS and hidden arrays from all roles into single sets
        my %acs_union;
        my %hidden_union;
        for my $row (@$roles) {
            my $acs_val = $row->{acs};
            my $acs_array;

            # Assume that if $acs_val is not a reference, it is a JSON string
            if ( ref $acs_val eq 'ARRAY' ) {
                $acs_array = $acs_val;
            }
            else {
                eval { $acs_array = Mojo::JSON::from_json($acs_val) };
                $acs_array ||= [];
            }
            $acs_union{$_} = 1 for @$acs_array;

            # Extract hidden array from extra_info
            my $extra_info = $row->{extra_info};
            if ($extra_info) {
                $extra_info = Mojo::JSON::from_json($extra_info)
                  unless ref $extra_info eq 'HASH';
                my $hidden = $extra_info->{hidden} // [];
                $hidden = Mojo::JSON::from_json($hidden)
                  unless ref $hidden eq 'ARRAY';
                $hidden_union{$_} = 1 for @$hidden;
            }
        }
        my @merged_acs    = keys %acs_union;
        my @merged_hidden = keys %hidden_union;
        my $db_client     = $c->dbs($client);
        my $name          = eval {
            $db_client->query(
                "SELECT fldvalue FROM defaults WHERE fldname = 'company'")
              ->hash->{fldvalue};
        } // $client;

        $c->render(
            json => {
                acs     => \@merged_acs,
                hidden  => \@merged_hidden,
                company => $name
            }
        );
    }
);

#! TO BE DELETED BEFORE MAIN RELEASE
sub create_temp_columns {
    my ( $c, $datasets ) = @_;

    foreach my $dataset (@$datasets) {
        my $db_name = $dataset->{db_name};
        my $db      = $c->dbs($db_name);     # DBIx::Simple handle

        # Check and add `parent_id` to `chart` if missing
        eval {
            my $res = $db->query(
                "SELECT 1 FROM information_schema.columns 
                 WHERE table_name = 'chart' AND column_name = 'parent_id'"
            );
            unless ( $res->hash ) {
                $db->query("ALTER TABLE chart ADD parent_id INTEGER");
            }
        };

        # Check and add `id` to `tax` if missing
        eval {
            my $res = $db->query(
                "SELECT 1 FROM information_schema.columns 
                 WHERE table_name = 'tax' AND column_name = 'id'"
            );
            unless ( $res->hash ) {
                $db->query("ALTER TABLE tax ADD id SERIAL PRIMARY KEY");
            }
        };
    }
}

$central->get(
    '/db_list' => sub {
        my $c       = shift;
        my $profile = $c->get_user_profile();
        my $dbs     = $c->central_dbs();

        my $datasets = $dbs->query(
            "SELECT d.id, d.db_name, d.description, da.access_level 
             FROM dataset d
             INNER JOIN dataset_access da
               ON d.id = da.dataset_id AND da.profile_id = ?",
            $profile->{profile_id}
        )->hashes;


        foreach my $dataset (@$datasets) {
            my $db_dbs = $c->dbs( $dataset->{db_name} );

            my $name_q;
            eval {
                $name_q = $db_dbs->query(
                    "SELECT fldvalue FROM defaults WHERE fldname = 'company'")
                  ->hash;
            };

            $dataset->{name} =
              ( $name_q && $name_q->{fldvalue} )
              ? $name_q->{fldvalue}
              : $dataset->{db_name};
            my $db_name   = $dataset->{db_name};
            my $logo_path = "templates/$db_name/logo.png";

            if ( -e $logo_path ) {
                $dataset->{logo} = "$base_url/logo/$db_name/";
            }
            else {
                $dataset->{logo} = "";
            }

       # If access level is owner or admin, add additional user and role details
            if ( defined $dataset->{access_level}
                && $dataset->{access_level} =~ /^(owner|admin)$/ )
            {
            # Query all users for this dataset with their email and access level
                my $users = $dbs->query(
"SELECT p.id AS profile_id, p.email, da.access_level, da.role_id, r.name AS role
         FROM dataset_access da
         JOIN profile p ON p.id = da.profile_id
         LEFT JOIN role r ON r.id = da.role_id
         WHERE da.dataset_id = ?",
                    $dataset->{id}
                )->hashes;
                $dataset->{users} = $users;

                # Query all roles for this dataset with their name and acs value
                my $roles = $dbs->query(
                    "SELECT id, name, acs, extra_info
                     FROM role
                     WHERE dataset_id = ?",
                    $dataset->{id}
                )->hashes;
                $dataset->{roles} = $roles;
                $dataset->{admin} = 1;

                my $client_dbs = $c->dbs( $dataset->{db_name} );

                my $connections;
                eval {
                    $connections = $client_dbs->query(
                        "SELECT type, status, error, drive_id FROM connections")
                      ->hashes;
                    1
                      ; # Indicate success so we don't jump into the 'or do' block
                } or do {

                  # If the query fails for any reason (e.g. table doesn't exist)
                    $connections = [];
                };

                $dataset->{connections} = $connections;

                if ($ai_plugin) {
                    $dataset->{workstations} =
                      $c->get_pending_items( $dataset->{db_name},
                        $profile->{profile_id} );
                }

                my $onboarding =
                  $client_dbs->query("SELECT fldname, fldvalue FROM onboarding")
                  ->hashes;

                my $incomplete_count = grep { !$_->{fldvalue} } @$onboarding;
                $dataset->{onboarding} = $incomplete_count ? 1 : 0;
            }
            else {
                $dataset->{onboarding} = 0;
            }
        }

        $c->render( json => $datasets );
    }
);
$api->get(
    'get_drives' => sub {
        my $c = shift;
        return unless $c->is_admin();
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);
        my $drives = FM->get_drives( $dbs, $c );

        $c->render( json => $drives );
    }
);
$api->post(
    'select_drive' => sub {
        my $c = shift;
        return unless $c->is_admin();
        my $drive_id = $c->req->json->{'drive_id'};
        my $client   = $c->param('client');
        my $dbs      = $c->dbs($client);
        $dbs->query(
            "UPDATE connections SET drive_id = ? WHERE type = 'google_drive'",
            $drive_id );
        return $c->render(
            status => 200,
            json   => {
                success => 1,
                message => "Drive ID updated successfully for client '$client'."
            }
        );
    }
);

# ADD EDIT OR MANAGE A ROLE
$api->post(
    '/system/roles/:id' => { id => undef } => sub {
        my $c = shift;
        return unless $c->is_admin();
        my $client      = $c->param('client');
        my $dbs_central = $c->central_dbs();
        my $data        = $c->req->json;
        my $id          = $c->param('id');

        my $name = $data->{name};
        return $c->render(
            json   => { error => "Missing role name" },
            status => 400
        ) unless $name;

        # Retrieve the dataset using client as the db_name
        my $dataset =
          $dbs_central->query( "SELECT id FROM dataset WHERE db_name = ?",
            $client )->hash;
        unless ( $dataset && $dataset->{id} ) {
            return $c->render(
                json   => { error => "Dataset not found for client" },
                status => 404
            );
        }
        my $dataset_id = $dataset->{id};

        if ( !defined $id ) {

            my $dup = $dbs_central->query(
                "SELECT 1 FROM role WHERE name = ? AND dataset_id = ?",
                $name, $dataset_id )->hash;
            if ($dup) {
                return $c->render(
                    json   => { error => "Duplicate role name" },
                    status => 409
                );
            }

            my $acs        = defined $data->{acs} ? $data->{acs} : '[]';
            my $extra_info = encode_json( { hidden => $data->{hidden} // [] } );

            # Insert new record and return the new id
            my $sth = $dbs_central->query(
"INSERT INTO role (dataset_id, name, acs, extra_info) VALUES (?, ?, ?::jsonb, ?::jsonb) RETURNING id",
                $dataset_id, $name, $acs, $extra_info );
            my $row = $sth->hash;
            return $c->render(
                json   => { message => "Role inserted", id => $row->{id} },
                status => 201
            );
        }
        else {
# Update: if the name is changed, ensure it doesn't duplicate another role in the same dataset
            my $dup = $dbs_central->query(
"SELECT 1 FROM role WHERE name = ? AND id <> ? AND dataset_id = ?",
                $name, $id, $dataset_id )->hash;
            if ($dup) {
                return $c->render(
                    json   => { error => "Duplicate role name" },
                    status => 409
                );
            }

          # Update role. Only name, acs and extra_info are updated.
          # If acs/extra_info is not provided, COALESCE keeps the current value.
            my $acs = $data->{acs};
            my $extra_info =
              exists $data->{hidden}
              ? encode_json( { hidden => $data->{hidden} // [] } )
              : undef;
            my $sql = "UPDATE role
                       SET name = COALESCE(?, name),
                           acs = COALESCE(?::jsonb, acs),
                           extra_info = COALESCE(?::jsonb, extra_info)
                       WHERE id = ? AND dataset_id = ?";
            $dbs_central->query( $sql, $name, $acs, $extra_info, $id,
                $dataset_id );

            return $c->render( json => { message => "Role updated" } );
        }
    }
);

$central->get(
    'create_dataset' => sub {
        my $c = shift;

        # Retrieve environment settings
        my $allow_db_creation = $ENV{ALLOW_DB_CREATION} // 0;

        # SUPER_USERS is a comma-separated list
        my @super_users = split /,/, ( $ENV{SUPER_USERS} // '' );

        # Get the current user's profile
        my $profile = $c->get_user_profile();

        # Determine if the user is allowed to create a database
        my $db_creation = ( $allow_db_creation
              || grep { $_ eq $profile->{email} } @super_users ) ? 1 : 0;

        # If not allowed, return only the db_creation flag
        if ( !$db_creation ) {
            return $c->render( json => { db_creation => 0 } );
        }

        # Process charts if allowed
        my $sql_dir = "sql/";
        opendir( my $sql_dh, $sql_dir ) or return ();
        my @charts =
          sort map { ( basename($_) =~ s/-chart\.sql$//r ) }
          grep     { basename($_) =~ /^NEO.*-chart\.sql$/ && -f $_ }
          map      { $sql_dir . $_ } readdir($sql_dh);
        closedir($sql_dh);

        # Process templates if allowed
        my $templates_dir = "doc/templates/";
        opendir( my $templates_dh, $templates_dir ) or return ();
        my @templates = sort grep { !/^\.{1,2}$/ && -d "$templates_dir/$_" }
          readdir($templates_dh);
        closedir($templates_dh);

        $c->render(
            json => {
                charts      => \@charts,
                templates   => \@templates,
                db_creation => $db_creation,
            }
        );
    }
);

$central->get(
    "connection_keys",
    sub {
        my $c = shift;
        $c->render(
            json => {
                DROPBOX_KEY      => $ENV{DROPBOX_KEY},
                GOOGLE_CLIENT_ID => $ENV{GOOGLE_CLIENT_ID},
                ALL_DRIVE        => $ENV{ALL_DRIVE} * 1,
            }
        );
    }
);

$central->post(
    'create_dataset' => sub {
        my $c                 = shift;
        my $params            = $c->req->json;
        my $dataset           = $params->{dataset};
        my $company           = $params->{company};
        my $template_language = $params->{template_language} || 'en-US';
        my $chart             = $params->{chart};

      # Validate dataset parameter (only lower-case letters and numbers allowed)
        unless ( $dataset =~ /^[a-z0-9]+$/ ) {
            return $c->render(
                json => {
                    error =>
"Invalid dataset name. Only lower-case alphabets and numbers allowed."
                },
                status => 400
            );
        }

        # Retrieve environment settings
        my $allow_db_creation = $ENV{ALLOW_DB_CREATION} // 0;

        # SUPER_USERS is a comma-separated list
        my @super_users = split /,/, ( $ENV{SUPER_USERS} // '' );

        # Get the current user's profile
        my $profile = $c->get_user_profile();

        # If DB creation is not allowed, ensure the user is a super user
        if ( !$allow_db_creation ) {
            unless ( grep { $_ eq $profile->{email} } @super_users ) {
                return $c->render(
                    json   => { error => "Not authorized to create dataset." },
                    status => 403
                );
            }
        }

        # Create spool/images/template directories
        my $images_dir = "images/$dataset";
        my $spool_dir  = "spool/$dataset";
        mkdir $images_dir unless -d $images_dir;
        mkdir $spool_dir  unless -d $spool_dir;

        # Template directory handling - always use NEO templates
        my $templates_dir   = "doc/templates/NEO";
        my $destination_dir = "templates/$dataset";
        dircopy( $templates_dir, $destination_dir );
        rename( "$destination_dir/NEO", "$destination_dir/$dataset" );

        # Configure language in definitions_language.tex
        my $definitions_file = "$destination_dir/definitions_language.tex";
        if ( -f $definitions_file ) {
            open( my $fh, '<', $definitions_file )
              or die "Cannot open file '$definitions_file': $!";
            my @lines = <$fh>;
            close $fh;

            # Process each line to comment/uncomment based on selected language
            for my $i ( 0 .. $#lines ) {
                my $line = $lines[$i];

                # Check if this line contains a language load command
                if ( $line =~
                    /^[%\\]*(\\LANGload\{(de-CH|de-DE|en-US|fr-CH|it-CH)\})/ )
                {
                    my $lang_code = $2;
                    if ( $lang_code eq $template_language ) {

                        # Uncomment this language
                        $lines[$i] =~ s/^%+//;
                    }
                    else {
                        # Comment out this language
                        $lines[$i] = "%" . $lines[$i] unless $lines[$i] =~ /^%/;
                    }
                }

                # Check for babel package line (comes after LANGload)
                elsif ( $line =~
/^[%\\]*(\\usepackage\[(ngerman|english|french|italian)\]\{babel\})/
                  )
                {
                    my $babel_lang    = $2;
                    my $should_enable = (
                        (
                                 $template_language =~ /^de-/
                              && $babel_lang eq 'ngerman'
                        )
                          || ( $template_language eq 'en-US'
                            && $babel_lang eq 'english' )
                          || ( $template_language eq 'fr-CH'
                            && $babel_lang eq 'french' )
                          || ( $template_language eq 'it-CH'
                            && $babel_lang eq 'italian' )
                    );

                    if ($should_enable) {

                        # Uncomment this line
                        $lines[$i] =~ s/^%+//;
                    }
                    else {
                        # Comment out this line
                        $lines[$i] = "%" . $lines[$i] unless $lines[$i] =~ /^%/;
                    }
                }
            }

            # Write the modified content back to the file
            open( $fh, '>', $definitions_file )
              or die "Cannot write to file '$definitions_file': $!";
            print $fh @lines;
            close $fh;
        }

        # Connect to database and create new dataset
        my $dbh = DBI->connect( "dbi:Pg:dbname=postgres;host=localhost",
            $postgres_user, $postgres_password, { AutoCommit => 1 } )
          or die "Failed to connect to database: $DBI::errstr";

        # Create the database for the dataset
        $dbh->do("CREATE DATABASE $dataset");

        # Load SQL files for dataset creation
        my $sql_dir   = "sql/";
        my @sql_files = (
            "${sql_dir}Pg-tables.sql",    "${sql_dir}Pg-indices.sql",
            "${sql_dir}Pg-functions.sql", "api_pg_upgrade.sql"
        );
        foreach my $sql_file (@sql_files) {
            run_sql_file( $dataset, $sql_file );
        }

        # Load chart-specific SQL
        my $chart_file = "${sql_dir}${chart}-chart.sql";
        run_sql_file( $dataset, $chart_file );

        # Check if any row in chart table has parent_id value
        my $dataset_dbh = DBI->connect( "dbi:Pg:dbname=$dataset;host=localhost",
            $postgres_user, $postgres_password, { AutoCommit => 1 } )
          or die "Failed to connect to dataset '$dataset': $DBI::errstr";

        my $sth = $dataset_dbh->prepare(
            "SELECT COUNT(*) FROM chart WHERE parent_id IS NOT NULL");
        $sth->execute();
        my ($parent_id_count) = $sth->fetchrow_array();
        $sth->finish();

        # If no rows have parent_id values, run the parent mapping SQL
        if ( $parent_id_count == 0 ) {
            warn("Assigning Parent IDs to charts");
            my $parent_mapping_sql = q{
                -- Create a CTE to get each 'A' row and the most recent preceding 'H' row
                WITH parent_mapping AS (
                  SELECT
                    a.id AS child_id,
                    h.id AS parent_id
                  FROM
                    chart a
                  JOIN LATERAL (
                    SELECT id
                    FROM chart h
                    WHERE h.charttype = 'H' AND h.id < a.id
                    ORDER BY h.id DESC
                    LIMIT 1
                  ) h ON true
                  WHERE a.charttype = 'A'
                )
                -- Update the parent_id in chart
                UPDATE chart
                SET parent_id = parent_mapping.parent_id
                FROM parent_mapping
                WHERE chart.id = parent_mapping.child_id;
            };

            $dataset_dbh->do($parent_mapping_sql);
        }

        # Seed chart_categories and chart_category_links if not already populated
        my $cat_sth = $dataset_dbh->prepare(
            "SELECT COUNT(*) FROM chart_categories");
        $cat_sth->execute();
        my ($cat_count) = $cat_sth->fetchrow_array();
        $cat_sth->finish();

        if ( $cat_count == 0 ) {
            warn("Seeding chart categories from header accounts");

            # Create one category per header account, ordered by accno
            $dataset_dbh->do(q{
                INSERT INTO chart_categories (accno, description)
                SELECT accno, description
                FROM chart
                WHERE charttype = 'H'
                ORDER BY accno
            });

            # Link each bookable account to its direct parent's category
            $dataset_dbh->do(q{
                INSERT INTO chart_category_links (chart_id, category_id)
                SELECT c.id, cc.id
                FROM chart c
                JOIN chart parent ON parent.id = c.parent_id
                JOIN chart_categories cc ON cc.accno = parent.accno
                WHERE c.charttype = 'A'
                ON CONFLICT (chart_id, category_id) DO NOTHING
            });
        }

        # Check if the gifi file exists before running it
        my $gifi_file;
        if ( $chart =~ /^RMA/ ) {
            $gifi_file = "${sql_dir}RMA-gifi.sql";
        }
        else {
            $gifi_file = "${sql_dir}${chart}-gifi.sql";
        }
        if ( -e $gifi_file ) {
            run_sql_file( $dataset, $gifi_file );
        }
        else {
            warn "The gifi file '$gifi_file' does not exist!";
        }

        # Grant privileges on the database itself
        $dbh->do("GRANT ALL PRIVILEGES ON DATABASE $dataset TO $postgres_user");
        $dbh->disconnect;

     # Connect directly to the dataset database to grant schema-level privileges
        $dataset_dbh = DBI->connect( "dbi:Pg:dbname=$dataset;host=localhost",
            $postgres_user, $postgres_password, { AutoCommit => 1 } )
          or die "Failed to connect to dataset '$dataset': $DBI::errstr";

        $dataset_dbh->do(
"GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $postgres_user"
        );
        $dataset_dbh->do(
"GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO $postgres_user"
        );
        $dataset_dbh->do(
"GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO $postgres_user"
        );
        $dataset_dbh->do(
            "INSERT INTO defaults (fldname, fldvalue) VALUES ('company', ?)",
            undef, $company );

        # Set default privileges for future objects
        $dataset_dbh->do(
"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO $postgres_user"
        );
        $dataset_dbh->do(
"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO $postgres_user"
        );
        $dataset_dbh->do(
"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON FUNCTIONS TO $postgres_user"
        );

        $dataset_dbh->disconnect;

        # Insert dataset and dataset access info into central database
        my $central_dbs = $c->central_dbs();
        $central_dbs->query(
            "INSERT INTO dataset (db_name, owner_id) VALUES ( ?, ? )",
            $dataset, $profile->{profile_id} );

        my $dataset_id =
          $central_dbs->last_insert_id( undef, undef, 'dataset', 'id' );

        my $role = $central_dbs->query(
            "INSERT INTO role (dataset_id, name, acs) VALUES (?, ?, ?)",
            $dataset_id, 'Admin', $neoledger_perms );
        my $role_id =
          $central_dbs->last_insert_id( undef, undef, 'role', 'id' );

        $central_dbs->query(
"INSERT INTO dataset_access(profile_id, dataset_id, access_level, role_id) VALUES (?,?, 'owner', ?)",
            $profile->{profile_id},
            $dataset_id, $role_id
        );

        if (@super_users) {
            my $placeholders = join ', ', map { '?' } @super_users;
            my $super_profiles = $central_dbs->query(
                "SELECT id, email FROM profile WHERE email IN ($placeholders)",
                @super_users
            );
            while ( my $row = $super_profiles->hash ) {
                next if $row->{id} == $profile->{profile_id};
                $central_dbs->query(
"INSERT INTO dataset_access(profile_id, dataset_id, access_level, role_id) VALUES (?, ?, 'admin', ?)",
                    $row->{id}, $dataset_id, $role_id
                );
            }
        }

        my $reports_only_role = $central_dbs->query(
            "INSERT INTO role (dataset_id, name, acs) VALUES (?, ?, ?)",
            $dataset_id, 'Reports Only', $reports_only );

        $c->render( json => { message => "Dataset created successfully" } );
    }
);

sub run_sql_file {
    my ( $dataset, $sql_file ) = @_;

    # Attempt to connect to the dataset database
    my $dbh = DBI->connect( "dbi:Pg:dbname=$dataset;host=localhost",
        $postgres_user, $postgres_password, { AutoCommit => 1 } )
      or die
      "Failed to connect to database for dataset '$dataset': $DBI::errstr";

    # Open the SQL file
    open( my $fh, '<', $sql_file )
      or die "Cannot open file '$sql_file': $!";
    my $sql = do { local $/; <$fh> };
    close $fh;

    # Check if the file content is empty
    if ( !defined($sql) || $sql =~ /^\s*$/ ) {
        if ( $sql_file !~ /-chart\.sql$/ ) {
            warn "The SQL file '$sql_file' is empty. Skipping this file.";
            $dbh->disconnect;
            return;
        }
        else {
            die
"The chart SQL file '$sql_file' is empty and cannot be processed.";
        }
    }

    # Execute the entire SQL content as one block
    eval {
        $dbh->do($sql);
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Failed to execute SQL file '$sql_file': $error";
    };

    $dbh->disconnect;
}

$central->delete(
    'dataset' => sub {
        my $c = shift;

        my $dataset_id = $c->param('id');
        my $owner_pw   = $c->param('owner_pw');

        # Trim input
        $dataset_id =~ s/^\s+|\s+$//g if defined $dataset_id;

        # Ensure both id and owner_pw are provided
        unless ( defined $dataset_id
            && $dataset_id ne ''
            && defined $owner_pw
            && $owner_pw ne '' )
        {
            return $c->render(
                status => 400,
                json   => { message => "Missing dataset id or owner password" }
            );
        }

        # Validate dataset_id format (only lowercase alphanumeric)
        unless ( $dataset_id =~ /^[a-z0-9]+$/ ) {
            return $c->render(
                status => 400,
                json   => { message => "Invalid dataset id format" }
            );
        }

        my $central_dbs = $c->central_dbs();
        my $profile     = $c->get_user_profile();
        warn( Dumper $profile );
        warn($dataset_id);

        # Begin transaction for atomic operations
        eval {
            $central_dbs->begin_work();

          # Verify that the user has owner access to the dataset and get db_name
            my $verification = $central_dbs->query(
                "SELECT d.db_name 
                 FROM dataset_access da
                 JOIN dataset d ON da.dataset_id = d.id 
                 WHERE da.dataset_id = ? 
                 AND da.profile_id = ? 
                 AND da.access_level = ?",
                $dataset_id, $profile->{profile_id}, 'owner'
            )->hash;
            warn( Dumper $verification );
            unless ( $verification && $verification->{db_name} ) {
                $central_dbs->rollback();
                return $c->render(
                    status => 403,
                    json   => {
                        message => "You don't have owner access to this dataset"
                    }
                );
            }

            my $db_name = $verification->{db_name};

            # Validate database name format for security
            unless ( $db_name =~ /^[a-zA-Z0-9_]+$/ ) {
                $central_dbs->rollback();
                return $c->render(
                    status => 500,
                    json   => { message => "Invalid database name format" }
                );
            }

            # Verify owner password
            my $owner_verification = $central_dbs->query(
                "SELECT id FROM profile WHERE id = ? 
                 AND crypt(?, password) = password",
                $profile->{profile_id}, $owner_pw
            )->hash;

            unless ( $owner_verification->{id} ) {
                $central_dbs->rollback();
                return $c->render(
                    status => 401,
                    json   => { message => "Incorrect password" }
                );
            }

            # Delete directories related to the dataset
            use File::Path qw(rmtree);
            my $images_dir    = "images/$db_name";
            my $spool_dir     = "spool/$db_name";
            my $templates_dir = "templates/$db_name";

            if ( -d $images_dir ) {
                rmtree($images_dir)
                  or $c->app->log->warn("Failed to remove $images_dir: $!");
            }

            if ( -d $spool_dir ) {
                rmtree($spool_dir)
                  or $c->app->log->warn("Failed to remove $spool_dir: $!");
            }

            if ( -d $templates_dir ) {
                rmtree($templates_dir)
                  or $c->app->log->warn("Failed to remove $templates_dir: $!");
            }

            # Drop the dataset database
            my $dbh = DBI->connect( "dbi:Pg:dbname=postgres;host=localhost",
                $postgres_user, $postgres_password,
                { AutoCommit => 1, RaiseError => 1 } )
              or die "Failed to connect to database: $DBI::errstr";

            # Ensure nobody is connected to the database before dropping
            $dbh->do(
"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ?",
                undef, $db_name
            );

            # Drop the dataset database (if it exists)
            $dbh->do("DROP DATABASE IF EXISTS \"$db_name\"")
              or die "Could not drop database $db_name: " . $dbh->errstr;
            $dbh->disconnect;

            # Remove all dataset relations in a specific order
            # First remove any access records
            $central_dbs->query(
                "DELETE FROM dataset_access WHERE dataset_id = ?",
                $dataset_id );

            # Remove roles associated with the dataset
            $central_dbs->query( "DELETE FROM role WHERE dataset_id = ?",
                $dataset_id );

            # Finally, remove the dataset record itself
            $central_dbs->query( "DELETE FROM dataset WHERE id = ?",
                $dataset_id );

            $central_dbs->commit();
            return $c->render(
                json => { message => "Dataset deleted successfully" } );
        };

        if ($@) {

            # Handle any errors that occurred during the transaction
            $central_dbs->rollback();
            $c->app->log->error("Error deleting dataset: $@");
            return $c->render(
                status => 500,
                json   => {
                    message => "Failed to delete dataset: Internal server error"
                }
            );
        }
    }
);

# Route to download the SQL dump of the dataset
$central->get(
    'download_db' => sub {
        my $c          = shift;
        my $dataset_id = $c->param('id');

        # Ensure dataset id is provided
        unless ( defined $dataset_id && $dataset_id ne '' ) {
            return $c->render(
                status => 400,
                json   => { message => "Missing dataset id" }
            );
        }

        my $central_dbs = $c->central_dbs();
        my $profile     = $c->get_user_profile();

        # Verify that the user has owner access to the dataset and get db_name
        my $verification = $central_dbs->query(
            "SELECT d.db_name 
             FROM dataset_access da
             JOIN dataset d ON da.dataset_id = d.id 
             WHERE da.dataset_id = ? 
             AND da.profile_id = ? 
             AND da.access_level = ?",
            $dataset_id, $profile->{profile_id}, 'owner'
        )->hash;

        unless ( $verification && $verification->{db_name} ) {
            return $c->render(
                status => 403,
                json   =>
                  { message => "You don't have owner access to this dataset" }
            );
        }

        my $db_name = $verification->{db_name};

        # Validate database name format for security
        unless ( $db_name =~ /^[a-zA-Z0-9_]+$/ ) {
            return $c->render(
                status => 500,
                json   => { message => "Invalid database name format" }
            );
        }

        # Define temporary file path for SQL dump
        my $sql_file = "/tmp/${db_name}.sql";

        # Create the SQL dump (adjust pg_dump options as needed)
        my $dump_cmd = "pg_dump -U postgres -h localhost $db_name > $sql_file";
        my $dump_status = system($dump_cmd);
        if ( $dump_status != 0 ) {
            return $c->render(
                status => 500,
                json   => { message => "Failed to dump database" }
            );
        }

        # Return the dump as a file download
        $c->res->headers->content_disposition(
            "attachment; filename=${db_name}.sql");
        return $c->reply->file($sql_file);
    }
);

$central->get(
    'download_templates' => sub {
        my $c          = shift;
        my $dataset_id = $c->param('id');

        # Ensure dataset id is provided
        unless ( defined $dataset_id && $dataset_id ne '' ) {
            return $c->render(
                status => 400,
                json   => { message => "Missing dataset id" }
            );
        }

        my $central_dbs = $c->central_dbs();
        my $profile     = $c->get_user_profile();

        # Verify that the user has owner access to the dataset and get db_name
        my $verification = $central_dbs->query(
            "SELECT d.db_name 
             FROM dataset_access da
             JOIN dataset d ON da.dataset_id = d.id 
             WHERE da.dataset_id = ? 
             AND da.profile_id = ? 
             AND da.access_level = ?",
            $dataset_id, $profile->{profile_id}, 'owner'
        )->hash;

        unless ( $verification && $verification->{db_name} ) {
            return $c->render(
                status => 403,
                json   =>
                  { message => "You don't have owner access to this dataset" }
            );
        }

        my $db_name = $verification->{db_name};

        # Validate database name format for security
        unless ( $db_name =~ /^[a-zA-Z0-9_]+$/ ) {
            return $c->render(
                status => 500,
                json   => { message => "Invalid database name format" }
            );
        }

        # Define the templates directory for the dataset
        my $templates_dir = "templates/$db_name";
        unless ( -d $templates_dir ) {
            return $c->render(
                status => 404,
                json   => { message => "Templates directory not found" }
            );
        }

        my $zip_file = "/tmp/${db_name}_templates.zip";

 # Use File::Find to recursively locate all files within the templates directory
        use File::Find;
        my %files_to_zip;
        find(
            sub {
                return unless -f $_;    # Only process regular files
                my $relative_path = $File::Find::name;
                $relative_path =~ s/^\Q$templates_dir\E\/?//;
                $files_to_zip{$relative_path} = $File::Find::name;
            },
            $templates_dir
        );

        # Create the ZIP file using Archive::Zip
        my $zip = Archive::Zip->new();
        foreach my $rel_path ( keys %files_to_zip ) {
            my $full_path = $files_to_zip{$rel_path};
            $zip->addFile( $full_path, $rel_path );
        }

        # Write the ZIP file
        my $status = $zip->writeToFileNamed($zip_file);
        if ( $status != AZ_OK ) {
            return $c->render(
                status => 500,
                json   => { message => "Failed to create ZIP file: $status" }
            );
        }

        # Return the ZIP file as a download
        $c->res->headers->content_disposition(
            "attachment; filename=${db_name}_templates.zip");
        return $c->reply->file($zip_file);
    }
);

$central->post(
    '/upload_logo' => sub {
        my $c           = shift;
        my $dataset_id  = $c->param('id');
        my $central_dbs = $c->central_dbs();
        my $profile     = $c->get_user_profile();

        # Verify that the user has owner access to the dataset and get db_name
        my $verification = $central_dbs->query(
            "SELECT d.db_name 
             FROM dataset_access da
             JOIN dataset d ON da.dataset_id = d.id 
             WHERE da.dataset_id = ? 
             AND da.profile_id = ? 
             AND da.access_level = ?",
            $dataset_id, $profile->{profile_id}, 'owner'
        )->hash;

        unless ( $verification && $verification->{db_name} ) {
            return $c->render(
                status => 403,
                json   =>
                  { message => "You don't have owner access to this dataset" }
            );
        }

        my $db_name = $verification->{db_name};

        # Get uploaded file
        my $upload = $c->req->upload('file');

        unless ($upload) {
            return $c->render(
                json   => { error => "No file uploaded" },
                status => 400
            );
        }

        # Generate safe filename
        my $original_name = $upload->filename;

        # Use provided name, original filename, or template_id
        my $target_filename = 'logo.png';

        # Basic sanitization to prevent directory traversal
        $target_filename =~ s{[^\w\.-]}{}g;

        # Ensure client directory exists
        my $client_dir = "templates/$db_name";
        unless ( -d $client_dir ) {
            mkdir $client_dir
              or return $c->render(
                json   => { error => "Cannot create client directory" },
                status => 500
              );
        }

        my $target_path = "$client_dir/$target_filename";

        # Move the file to target location
        $upload->move_to($target_path);

        $c->render(
            json => {
                success => "Template uploaded successfully",
                name    => $target_filename
            }
        );
    }
);
#### INVITE MANAGEMENT

# Create An Invite
# Helper to generate a random 10-character invite code
sub generate_invite_code {
    my @chars = ( 'A' .. 'Z', 'a' .. 'z', 0 .. 9 );
    my $code  = '';
    $code .= $chars[ rand @chars ] for 1 .. 10;
    return $code;
}

$api->post(
    '/invite' => sub {
        my $c = shift;
        return unless $c->is_admin();
        my $dbs = $c->central_dbs();

        my $profile   = $c->get_user_profile();
        my $sender_id = $profile->{profile_id};

        # Get invite details from the request body
        my $params          = $c->req->json;
        my $recipient_email = $params->{recipient_email};
        my $dataset_id      = $params->{dataset_id};
        my $access_level    = $params->{access_level} // 'user';
        my $role_id         = $params->{role_id};

        unless ( $recipient_email && $dataset_id ) {
            return $c->render(
                status => 400,
                json   => {
                    message =>
                      "Missing required fields (recipient_email and dataset_id)"
                }
            );
        }

        # Validate that the dataset exists and get its db_name
        my $dataset =
          $dbs->query( "SELECT id, db_name FROM dataset WHERE id = ?",
            $dataset_id )->hash;
        unless ($dataset) {
            return $c->render(
                status => 404,
                json   => { message => "Dataset not found" }
            );
        }

        my $db_client = $c->dbs( $dataset->{db_name} );
        $dataset->{name} = eval {
            $db_client->query(
                "SELECT fldvalue FROM defaults WHERE fldname = 'company'")
              ->hash->{fldvalue};
        } // $dataset->{db_name};

        # Generate a 10-character invite code
        my $invite_code = generate_invite_code();

        # Insert the invite record including the invite_code
        my $invite = $dbs->query(
"INSERT INTO invite (sender_id, recipient_email, dataset_id, access_level, role_id, invite_code)
             VALUES (?, ?, ?, ?, ?, ?)
             RETURNING id, invite_code",
            $sender_id,    $recipient_email, $dataset_id,
            $access_level, $role_id,         $invite_code
        )->hash;

        # Check if the recipient already has an account (profile)
        my $existing_user =
          $dbs->query( "SELECT id, email FROM profile WHERE email = ?",
            $recipient_email )->hash;

        my ( $subject, $content );

        if ($existing_user) {

            # For existing users, send a login invitation email
            $subject =
              "You've been invited to access dataset '$dataset->{name}'";
            $content = <<"EMAIL";
Hello,

You have been invited by $profile->{email} to access the dataset "$dataset->{name}" on Neo-Ledger.
Please log in at: $front_end/login

Thank you, 

$dataset->{name}
EMAIL
        }
        else {
            # For new users, send a signup invitation email
            $subject =
              "Invitation to join Neo-Ledger and access '$dataset->{name}'";
            $content = <<"EMAIL";
Hello,

You have been invited by $profile->{email} to access the dataset "$dataset->{name}" on Neo-Ledger.
If you already have an account, please log in at: $front_end/login.
If not, please sign up using the following link:
$front_end/signup?invite=$invite->{invite_code}

We look forward to having you onboard.

Best regards,
$dataset->{name}
EMAIL
        }

        # Use the provided email helper to send the email
        my $email_result = $c->send_email_central(
            $recipient_email, $subject, $content,
            undef, undef, $dataset->{db_name}
        );
        if ( $email_result->{error} ) {
            return $c->render(
                status => 500,
                json   => { message => $email_result->{error} }
            );
        }

        return $c->render(
            json => {
                message     => "Invite sent",
                invite_id   => $invite->{id},
                invite_code => $invite->{invite_code}
            }
        );
    }
);

# Route to accept an invite
$central->post(
    '/invite/:id/accept' => sub {
        my $c         = shift;
        my $invite_id = $c->param('id');

        my $dbs = $c->central_dbs();

        # Validate session and get current profile id
        my $profile         = $c->get_user_profile();
        my $current_profile = $profile->{profile_id};

        # Retrieve the current user's email
        my $user = $dbs->query( "SELECT email FROM profile WHERE id = ?",
            $current_profile )->hash;
        my $user_email = $user->{email};

# Retrieve the invite record ensuring the recipient email matches the user's email
        my $invite = $dbs->query(
            "SELECT * FROM invite WHERE id = ? AND recipient_email = ?",
            $invite_id, $user_email )->hash;
        unless ($invite) {
            return $c->render(
                status => 404,
                json   => { message => "Invite not found for this user" }
            );
        }

        # Add dataset access record if not already present
        my $exists = $dbs->query(
"SELECT 1 FROM dataset_access WHERE profile_id = ? AND dataset_id = ?",
            $current_profile, $invite->{dataset_id}
        )->hash;
        unless ($exists) {
            $dbs->query(
"INSERT INTO dataset_access (profile_id, dataset_id, access_level, role_id) VALUES (?, ?, ?, ?)",
                $current_profile,        $invite->{dataset_id},
                $invite->{access_level}, $invite->{role_id}
            );
        }

        # Optionally, remove the invite after acceptance
        $dbs->query( "DELETE FROM invite WHERE id = ?", $invite_id );
        return $c->render( json => { message => "Invite accepted" } );
    }
);
$central->delete(
    '/invite/:id' => sub {
        my $c         = shift;
        my $invite_id = $c->param('id');

        my $dbs = $c->central_dbs();

        # Validate session and get current profile information
        my $profile         = $c->get_user_profile();
        my $current_profile = $profile->{profile_id};

        # Retrieve the invite by id
        my $invite =
          $dbs->query( "SELECT * FROM invite WHERE id = ?", $invite_id )->hash;

        # If invite not found, simply return success
        unless ($invite) {
            return $c->render( json => { message => "Invite deleted" } );
        }

        # Check if the current profile has admin or owner access for the dataset
        my $access = $dbs->query(
"SELECT access_level FROM dataset_access WHERE profile_id = ? AND dataset_id = ?",
            $current_profile, $invite->{dataset_id}
        )->hash;
        unless (
            $access
            && (   $access->{access_level} eq 'admin'
                || $access->{access_level} eq 'owner' )
          )
        {
            return $c->render(
                status => 403,
                json   => { message => "Insufficient permissions" }
            );
        }

        # Delete the invite as the user has the required access level
        $dbs->query( "DELETE FROM invite WHERE id = ?", $invite_id );
        return $c->render( json => { message => "Invite deleted" } );
    }
);

$api->post(
    '/access/:profile_id/' => sub {
        my $c = shift;
        return unless $c->is_admin();
        my $client     = $c->param('client');
        my $profile_id = $c->param('profile_id');
        my $dbs        = $c->central_dbs();

        my $access = $dbs->query(
"SELECT * FROM dataset_access WHERE dataset_id = ( SELECT id FROM dataset WHERE db_name = ? ) AND profile_id = ?",
            $client, $profile_id
        )->hash;
        unless ($access) {
            return $c->render(
                status => 404,
                json   => { message => "Dataset access record not found" }
            );
        }
        my $dataset_id = $access->{dataset_id};

        # Retrieve JSON payload
        my $data = $c->req->json;

        # If deletion is requested, remove the access record
        if ( $data->{delete} ) {
            $dbs->query(
"DELETE FROM dataset_access WHERE dataset_id = ? AND profile_id = ?",
                $dataset_id, $profile_id
            );
            return $c->render(
                json => { message => "Dataset access removed" } );
        }

        # If a field is not provided, retain its current value.

        $dbs->query(
            "UPDATE dataset_access 
             SET  access_level = ?, role_id = ? 
             WHERE dataset_id = ? AND profile_id = ?",
            $data->{access_level}, $data->{role_id},
            $dataset_id,           $profile_id
        );
        return $c->render( json => { message => "Dataset access updated" } );
    }
);

$central->get(
    '/invites/sent' => sub {
        my $c          = shift;
        my $sessionkey = $c->req->headers->header('Authorization');
        my $dbs        = $c->central_dbs();

        # Validate session and get sender profile id
        my $profile   = $c->get_user_profile();
        my $sender_id = $profile->{profile_id};

        # Retrieve all invites sent by this user
        my $invites = $dbs->query(
            "SELECT invite.*, dataset.db_name 
   FROM invite 
   LEFT JOIN dataset ON invite.dataset_id = dataset.id 
   WHERE sender_id = ?",
            $sender_id
        )->hashes;
        return $c->render( json => { invites => $invites } );
    }
);

# Route to list all invites received (pending) for the authenticated user
$central->get(
    '/invites/received' => sub {
        my $c          = shift;
        my $sessionkey = $c->req->headers->header('Authorization');
        my $dbs        = $c->central_dbs();

        # Validate session and get current profile id
        my $profile         = $c->get_user_profile();
        my $current_profile = $profile->{profile_id};

        # Retrieve the current user's email
        my $user = $dbs->query( "SELECT email FROM profile WHERE id = ?",
            $current_profile )->hash;
        my $email = $user->{email};

       # Retrieve all invites where the recipient email matches the user's email
        my $invites = $dbs->query(
            "SELECT invite.*, dataset.db_name, role.name AS role FROM invite
          LEFT JOIN dataset ON invite.dataset_id = dataset.id
          LEFT JOIN role  ON invite.role_id = role.id
           WHERE recipient_email = ?",
            $email
        )->hashes;
        foreach my $invite (@$invites) {
            my $db_name   = $invite->{db_name};
            my $logo_path = "templates/$db_name/logo.png";
            if ( -e $logo_path ) {
                $invite->{logo} = "$base_url/logo/$db_name/";
            }
            else {
                $invite->{logo} = "";
            }
        }
        return $c->render( json => { invites => $invites } );
    }
);

### DB UPDATES
sub run_startup_database_updates {
    my ($app) = @_;

    # First, update the central database itself - only from centraldb folder
    eval {
        my $result =
          process_startup_updates( 'centraldb', $app, 1 );  # 1 = centraldb only
        if ( $result->{updated} ) {
            $app->log->info(
"Updated centraldb to version $result->{new_version}: $result->{update_applied}"
            );
        }
        else {
            $app->log->debug(
"Central database is up to date (version $result->{current_version})"
            );
        }
    } or do {
        my $error = $@ || 'Unknown error';
        $app->log->error("Failed to update central database: $error");
        die $error;    # Stop on any error
    };

    # Get all datasets from central database that exist in the dataset table
    my $central_dbh = DBI->connect( "dbi:Pg:dbname=centraldb;host=localhost",
        $postgres_user, $postgres_password, { AutoCommit => 1 } )
      or die "Failed to connect to central database: $DBI::errstr";

    my $sth =
      $central_dbh->prepare("SELECT db_name FROM dataset ORDER BY db_name");
    $sth->execute();

    my @datasets;
    while ( my ($db_name) = $sth->fetchrow_array() ) {
        push @datasets, $db_name;
    }
    $sth->finish();
    $central_dbh->disconnect();

    return unless @datasets;

    $app->log->info(
        "Checking " . scalar(@datasets) . " datasets for updates" );

    my $updated_count = 0;

    for my $dataset (@datasets) {
        eval {
            my $result = process_startup_updates( $dataset, $app, 0 )
              ;    # 0 = dataset-specific only
            if ( $result->{updated} ) {
                $updated_count++;
                $app->log->info(
"Updated $dataset to version $result->{new_version}: $result->{update_applied}"
                );
            }
            else {
                $app->log->debug(
"Dataset '$dataset' is up to date (version $result->{current_version})"
                );
            }
        } or do {
            my $error = $@ || 'Unknown error';
            $app->log->error("Failed to update dataset '$dataset': $error");
            die $error;    # Stop on any error
        };
    }

    $app->log->info(
        "Startup updates complete: $updated_count datasets updated");
}

sub process_startup_updates {
    my ( $dataset, $app, $is_centraldb ) = @_;

    my $dbh = DBI->connect( "dbi:Pg:dbname=$dataset;host=localhost",
        $postgres_user, $postgres_password, { AutoCommit => 1 } )
      or die "Failed to connect to dataset '$dataset': $DBI::errstr";

    # Create db_updates table if it doesn't exist
    my $table_exists = $dbh->prepare(
"SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'db_updates')"
    );
    $table_exists->execute();
    my ($exists) = $table_exists->fetchrow_array();
    $table_exists->finish();

    my $current_version = '000';

    if ( !$exists ) {
        my $create_table_sql = q{
            CREATE TABLE db_updates (
                id SERIAL PRIMARY KEY,
                version VARCHAR(3) NOT NULL,
                updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_update TEXT NOT NULL
            );
        };
        $dbh->do($create_table_sql);

        my $insert_sth = $dbh->prepare(
            "INSERT INTO db_updates (version, last_update) VALUES (?, ?)");
        $insert_sth->execute( '000', 'Initial setup' );
        $insert_sth->finish();
    }
    else {
        my $version_sth = $dbh->prepare(
"SELECT version FROM db_updates ORDER BY CAST(version AS INTEGER) DESC LIMIT 1"
        );
        $version_sth->execute();
        ($current_version) = $version_sth->fetchrow_array();
        $version_sth->finish();
    }

    # Apply all pending updates
    my $updates_applied   = 0;
    my $final_version     = $current_version;
    my $final_update_name = 'No updates';

    while (1) {
        my $next_version = sprintf( "%03d", int($final_version) + 1 );

        # Determine which directories to search based on database type
        my @search_dirs;
        if ($is_centraldb) {

            # For centraldb, only check the centraldb-specific folder
            @search_dirs = ("db_updates/centraldb/");
        }
        else {
 # For other datasets, check the root db_updates folder (but not subdirectories)
            @search_dirs = ("db_updates/");
        }

        my $update_file;
        my $file_path;

        # Search in the specified directories
        for my $updates_dir (@search_dirs) {
            next unless -d $updates_dir;

            opendir( my $dh, $updates_dir )
              or die "Cannot open $updates_dir directory: $!";

            my @update_files;
            if ($is_centraldb) {

                # For centraldb, look for files directly in the centraldb folder
                @update_files =
                  grep { /^${next_version}-.*\.sql$/ } readdir($dh);
            }
            else {
# For other datasets, look for files directly in the root db_updates folder only (not in subdirectories)
                @update_files =
                  grep { /^${next_version}-.*\.sql$/ && !-d "$updates_dir$_" }
                  readdir($dh);
            }
            closedir($dh);

            if (@update_files) {
                die "Multiple files for version $next_version in $updates_dir"
                  if @update_files > 1;

                $update_file = $update_files[0];
                $file_path   = "$updates_dir$update_file";
                last;
            }
        }

        last unless $update_file;

        # Extract update name
        my $update_name = $update_file;
        $update_name =~ s/^${next_version}-//;
        $update_name =~ s/\.sql$//;
        $update_name =~ s/-/ /g;

        # Apply update
        apply_startup_update( $dbh, $file_path, $next_version, $update_name );

        $updates_applied++;
        $final_version     = $next_version;
        $final_update_name = $update_name;
    }

    $dbh->disconnect();

    return {
        current_version => $current_version,
        new_version     => $final_version,
        update_applied  => $final_update_name,
        updated         => $updates_applied > 0
    };
}

sub apply_startup_update {
    my ( $dbh, $file_path, $version, $update_name ) = @_;

    $dbh->begin_work();

    eval {
        # Read and execute SQL file
        open( my $fh, '<', $file_path ) or die "Cannot open '$file_path': $!";
        my $sql = do { local $/; <$fh> };
        close $fh;

        die "Update file '$file_path' is empty"
          if !defined($sql) || $sql =~ /^\s*$/;

        $dbh->do($sql);

        # Record the update
        my $update_sth = $dbh->prepare(
            "INSERT INTO db_updates (version, last_update) VALUES (?, ?)");
        $update_sth->execute( $version, $update_name );
        $update_sth->finish();

        $dbh->commit();

    } or do {
        my $error = $@ || 'Unknown error';
        $dbh->rollback();
        die "Failed to apply update $version ($update_name): $error";
    };
}

#########################
####                 ####
####    API KEYS     ####
####                 ####
#########################
$central->get(
    '/api_keys' => sub {
        my $c = shift;
        return unless $c->is_admin();

        my $client = $c->param('client');
        return $c->render( json => { error => 'client parameter required' } )
          unless $client;

        my $dbs = $c->central_dbs();

        # First find the dataset by db_name (client)
        my $dataset =
          $dbs->select( 'dataset', ['id'], { db_name => $client, active => 1 } )
          ->hash;
        return $c->render( json => { error => 'Dataset not found' } )
          unless $dataset;

        # Get all API keys that have access to this dataset
        my @api_keys = $dbs->query( "
        SELECT 
            ak.id,
            ak.profile_id,
            ak.apikey,
            ak.label,
            ak.scopes,
            ak.created,
            ak.expires,
            ak.last_used,
            ak.is_active,
            aka.scopes as access_scopes
        FROM api_key_access aka
        JOIN api_key ak ON ak.id = aka.apikey_id
        WHERE aka.dataset_id = ?
          AND ak.is_active = true
        ORDER BY ak.last_used DESC, ak.created DESC
    ", $dataset->{id} )->hashes;

        return $c->render(
            json   => { error => 'No API keys found' },
            status => 404
        ) unless @api_keys;
        return $c->render( json => { api_keys => \@api_keys } );
    }
);
$central->post(
    '/api_keys' => sub {
        my $c = shift;
        return unless $c->is_admin();

        my $profile_id = $c->get_user_profile->{profile_id};
        my $client     = $c->param('client');
        my $label      = $c->param('label');

        # Validation
        return $c->render(
            json   => { error => 'client parameter required' },
            status => 400
        ) unless $client;
        return $c->render(
            json   => { error => 'label required' },
            status => 400
        ) unless $label;

        my $dbs = $c->central_dbs();

        # Find dataset by db_name (client)
        my $dataset =
          $dbs->select( 'dataset', ['id'], { db_name => $client, active => 1 } )
          ->hash;
        return $c->render(
            json   => { error => 'Dataset not found or inactive' },
            status => 404
        ) unless $dataset;

        eval {
            # Begin transaction - DBIx::Simple style
            $dbs->begin;

            # Generate API key and hash it in one PostgreSQL query
            my $result = $dbs->query(
                q{
                WITH new_key AS (
                    SELECT 'ak_' || encode(gen_random_bytes(32), 'base64') AS plain_key
                )
                INSERT INTO api_key (profile_id, apikey, label, created, is_active)
                SELECT ?, crypt(plain_key, gen_salt('bf', 8)), ?, CURRENT_TIMESTAMP, true
                FROM new_key
                RETURNING id, (SELECT plain_key FROM new_key) AS api_key
            },
                $profile_id, $label
            )->hash;

            # Grant access to dataset
            $dbs->insert(
                'api_key_access',
                {
                    apikey_id  => $result->{id},
                    dataset_id => $dataset->{id},
                    created    => \'CURRENT_TIMESTAMP'
                }
            );

            # Commit transaction - call directly on $dbs
            $dbs->commit;

            $c->render(
                json => {
                    success => 1,
                    message => 'API key created successfully',
                    api_key => $result->{api_key},
                    key_id  => $result->{id},
                    warning => 'Save this key now - it will not be shown again'
                }
            );
        };

        if ($@) {

            # Rollback on error
            eval { $dbs->rollback };
            $c->render(
                json   => { error => "Failed to create API key: $@" },
                status => 500
            );
        }
    }
);

sub verify_api_key {
    my ( $dbs, $provided_key ) = @_;

    my $result = $dbs->query(
        'SELECT id, profile_id, is_active, expires 
         FROM api_key 
         WHERE apikey = crypt(?, apikey) 
         AND is_active = true 
         AND (expires IS NULL OR expires > CURRENT_TIMESTAMP)',
        $provided_key
    )->hash;

    if ($result) {
        $dbs->query(
            'UPDATE api_key SET last_used = CURRENT_TIMESTAMP WHERE id = ?',
            $result->{id} );
        return $result;
    }

    return undef;
}
$central->delete(
    '/api_keys/:id' => sub {
        my $c = shift;
        return unless $c->is_admin();

        my $key_id = $c->param('id');
        return $c->render(
            json   => { error => 'API key ID required' },
            status => 400
        ) unless $key_id;

        # Validate ID format (assuming numeric IDs)
        return $c->render(
            json   => { error => 'Invalid API key ID' },
            status => 400
        ) unless $key_id =~ /^\d+$/;

        my $dbs = $c->central_dbs();

        eval {
            # Begin transaction
            $dbs->begin;

            # First check if the API key exists and get its details
            my $api_key = $dbs->select(
                'api_key',
                [ 'id', 'label', 'profile_id' ],
                { id => $key_id }
            )->hash;

            unless ($api_key) {
                $dbs->rollback;
                return $c->render(
                    json   => { error => 'API key not found' },
                    status => 404
                );
            }

            # Check if the current user owns this API key
            my $current_profile_id = $c->get_user_profile->{profile_id};
            unless ( $api_key->{profile_id} == $current_profile_id ) {
                $dbs->rollback;
                return $c->render(
                    json => { error => 'Unauthorized to delete this API key' },
                    status => 403
                );
            }

     # Delete related entries from api_key_access first (foreign key constraint)
            my $access_deleted =
              $dbs->delete( 'api_key_access', { apikey_id => $key_id } );

            # Delete the API key itself
            my $key_deleted = $dbs->delete( 'api_key', { id => $key_id } );

            # Commit transaction
            $dbs->commit;

            # Return 204 No Content for successful deletion
            $c->rendered(204);
        };

        if ($@) {

            # Rollback on error
            eval { $dbs->rollback };
            $c->render(
                json   => { error => "Failed to delete API key: $@" },
                status => 500
            );
        }
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

helper check_perms => sub {
    my ( $c, $permissions_string ) = @_;
    my $client = $c->param('client');

    my $central = $c->central_dbs;
    my $dataset =
      $central->query( "SELECT * FROM dataset WHERE db_name = ?", $client )
      ->hash;
    unless ( $dataset && $dataset->{id} ) {
        $c->render(
            status => 404,
            json   => { message => "Unknown dataset: $client" }
        );
        return 0;
    }

    # point subsequent queries at the tenant database
    $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

    my $profile;

    # --- API-Key flow ---
    if ( my $api_key = $c->req->headers->header('X-API-Key') ) {

        # verify the key itself
        my $ak = verify_api_key( $central, $api_key );
        unless ( $ak && $ak->{id} ) {
            $c->render(
                status => 401,
                json   => { message => "Invalid API key" }
            );
            return 0;
        }

        # check this key has access to the current dataset

        my $has_access = $central->query(
"SELECT 1 FROM api_key_access WHERE apikey_id = ? AND dataset_id = ?",
            $ak->{id}, $dataset->{id}
        )->array;
        unless ($has_access) {
            $c->render(
                status => 403,
                json   =>
                  { message => "API key has no access to dataset $client" }
            );
            return 0;
        }

        # fetch the user profile via api_key.profile_id
        if ( my $pid = $ak->{profile_id} ) {
            $profile =
              $central->query( "SELECT * FROM profile WHERE id = ?", $pid )
              ->hash;
            $profile->{profile_id} = $pid;
        }
    }

    # --- Session-flow (fallback) ---
    unless ($profile) {
        $profile = $c->get_user_profile();

        unless ($profile) {
            $c->render(
                status => 401,
                json   => { message => "Invalid session key" }
            );
            return 0;
        }
    }

    # --- common setup ---
    # number format preference
    my $config = $profile->{config} ? decode_json( $profile->{config} ) : {};
    my $number_format = $config->{number_format}
      // $c->slconfig->{numberformat} // '1,000.00';
    $c->slconfig->{numberformat} = $number_format;

    # build the form object
    my $defaults = $c->get_defaults;
    my $form     = new Form;
    $form->{api_url}      = $base_url;
    $form->{frontend_url} = $front_end;
    $form->{client}       = $client;
    $form->{closedto}     = format_date( $defaults->{closedto} ) || '';
    $form->{revtrans}     = $defaults->{revtrans}                || 0;
    $form->{audittrail}   = $defaults->{audittrail}              || 0;
    $form->{profile_id}   = $profile->{profile_id};
    $form->{paymentfile}  = $defaults->{paymentfile} ? 1 : 0;

    # admin/owner bypass
    my $admin = $central->query(
        "SELECT 1 FROM dataset_access WHERE profile_id = ? 
         AND access_level IN ('admin','owner') AND dataset_id = ? LIMIT 1",
        $profile->{profile_id}, $dataset->{id}
    )->array;
    return $form if $admin;

    # enforce individual permissions
    my $acs = $central->query(
        "SELECT r.acs
         FROM role r
         JOIN dataset_access da ON r.id = da.role_id
         WHERE da.profile_id = ? AND da.dataset_id = ?",
        $profile->{profile_id}, $dataset->{id}
    )->hash->{acs} // '[]';
    my $perms   = ref($acs) eq 'ARRAY' ? $acs : decode_json($acs);
    my %allowed = map { $_ => 1 } @$perms;

    for my $perm ( split /\s*,\s*/, $permissions_string ) {
        return $form if $allowed{$perm};
    }

    $c->render(
        status => 403,
        json   => {
            message =>
              "Missing any of the required permissions: $permissions_string"
        }
    );
    return 0;
};

# Check if user has a specific permission without rendering a 403 error
# Returns 1 if user has permission, 0 otherwise
helper has_perm => sub {
    my ( $c, $form, $permission ) = @_;
    my $client = $c->param('client');

    my $central = $c->central_dbs;
    my $dataset =
      $central->query( "SELECT * FROM dataset WHERE db_name = ?", $client )
      ->hash;
    return 0 unless $dataset && $dataset->{id};

    # admin/owner bypass - they have all permissions
    my $admin = $central->query(
        "SELECT 1 FROM dataset_access WHERE profile_id = ? 
         AND access_level IN ('admin','owner') AND dataset_id = ? LIMIT 1",
        $form->{profile_id}, $dataset->{id}
    )->array;
    return 1 if $admin;

    # check individual permissions from role
    my $acs = $central->query(
        "SELECT r.acs
         FROM role r
         JOIN dataset_access da ON r.id = da.role_id
         WHERE da.profile_id = ? AND da.dataset_id = ?",
        $form->{profile_id}, $dataset->{id}
    )->hash->{acs} // '[]';
    my $perms   = ref($acs) eq 'ARRAY' ? $acs : decode_json($acs);
    my %allowed = map { $_ => 1 } @$perms;

    return $allowed{$permission} ? 1 : 0;
};

$api->post(
    '/auth/validate_api' => sub {
        my $c       = shift;
        my $client  = $c->param('client');
        my $api_key = $c->req->headers->header('X-API-Key');

        # 1. Missing key?
        unless ($api_key) {
            return $c->render(
                status => 400,
                json   => { message => "Missing X-API-Key header" }
            );
        }

        # 2. Delegate to verify_api_key
        my $central = $c->central_dbs;
        my $ak      = verify_api_key( $central, $api_key );

        unless ( $ak && $ak->{id} ) {
            return $c->render(
                status => 401,
                json   => { message => "Invalid, inactive, or expired API key" }
            );
        }

        # 3. Lookup dataset
        my $dataset =
          $central->query( "SELECT id FROM dataset WHERE db_name = ?", $client )
          ->hash;
        unless ( $dataset && $dataset->{id} ) {
            return $c->render(
                status => 404,
                json   => { message => "Unknown dataset: $client" }
            );
        }

        # 4. Check key→dataset access
        my $has_access = $central->query(
"SELECT 1 FROM api_key_access WHERE apikey_id = ? AND dataset_id = ?",
            $ak->{id}, $dataset->{id}
        )->array;

        unless ($has_access) {
            return $c->render(
                status => 403,
                json   =>
                  { message => "API key has no access to dataset $client" }
            );
        }

        # 5. Success
        return $c->render( json => { success => 1 } );
    }
);

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

   # Check if the API account exists in the login table and verify the password,
   # and retrieve the acsrole_id as well
        my $login = $dbs->query( '
            SELECT password, acsrole_id, admin
            FROM login
            WHERE employeeid = ? AND crypt(?, password) = password
        ', $employee_id, $password )->hash;

        unless ($login) {
            return $c->render(
                status => 400,
                json   => { message => "Incorrect username or password" }
            );
        }

       # Retrieve the "acs" value from the acsapirole table using the acsrole_id
        my $acs_row = $dbs->query( 'SELECT acs FROM acsapirole WHERE id = ?',
            $login->{acsrole_id} )->hash;
        my $acs = $acs_row ? $acs_row->{acs} : undef;

        if ( $login->{admin} ) {
            $acs = $neoledger_perms;
        }

        my $session_key = $dbs->query(
'INSERT INTO session (employeeid, sessionkey) VALUES (?, encode(gen_random_bytes(32), ?)) RETURNING sessionkey',
            $employee_id, 'hex'
        )->hash->{sessionkey};

        my $company =
          $dbs->query( "SELECT * FROM defaults WHERE fldname = ?", "company" )
          ->hash;

        # Return the session key, company, and acs value
        return $c->render(
            json => {
                sessionkey => $session_key,
                client     => $dbname,
                company    => $company->{fldvalue},
                acs        => $acs
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
####  User & Role    ####
####                 ####
#########################

#########################
####                 ####
#### GL Transactions ####
####                 ####
#########################
$api->get(
    '/gl/transactions/lines' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("gl.transactions");
        my $params = $c->req->params->to_hash;
        my $client = $c->param('client');

        my $dbs = $c->dbs($client);
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
        foreach my $transaction ( @{ $form->{GL} } ) {
            my $full_address = join( ' ',
                $form->{address1} // '',
                $form->{address2} // '',
                $form->{city}     // '',
                $form->{state}    // '',
                $form->{country}  // '' );
        }
        eval {
            # Fetch files for all transactions in a single operation
            FM->get_files_for_transactions(
                $dbs,
                {
                    api_url => $base_url,
                    client  => $client
                },
                $form->{GL}
            );
        };
        if ($@) {
            $c->app->log->error("Error getting files for transactions: $@");
        }

        $c->render( status => 200, json => $form->{GL} );
    }
);

$api->get(
    '/gl/transactions' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("gl.transactions");

        my $client = $c->param('client');

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
'SELECT id, reference, transdate, description, notes, curr, department_id, approved, exchangerate, created, updated FROM gl';
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
'SELECT chart.accno, chart.description, acc_trans.amount, acc_trans.source, acc_trans.memo, acc_trans.tax_chart_id, acc_trans.linetaxamount, acc_trans.fx_transaction, acc_trans.cleared FROM acc_trans JOIN chart ON acc_trans.chart_id = chart.id WHERE acc_trans.trans_id = ? AND acc_trans.amount <> 0',
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
        FM->get_files_for_transactions(
            $dbs,
            {
                api_url => $base_url,
                client  => $client
            },
            \@transactions
        );

        $c->render( json => \@transactions );
    }
);

$api->get(
    '/batch/search' => sub {
        my $c = shift;
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);

        my $module      = $c->param('module')      || '';
        my $granularity = $c->param('granularity') || '';

        unless ( $module =~ /^(gl|ar|ap)$/ ) {
            return $c->render(
                status => 400,
                json   => {
                    error =>
                      'Invalid module. Use gl, ar, or ap.',
                }
            );
        }
        unless ( $granularity =~ /^(transaction|line)$/ ) {
            return $c->render(
                status => 400,
                json   => {
                    error =>
                      'Invalid granularity. Use transaction or line.',
                }
            );
        }

        if ( $module eq 'gl' ) {
            return unless $c->check_perms("ledger.batchupdate");
        }
        elsif ( $module eq 'ar' ) {
            return unless $c->check_perms("customer.batchupdate");
        }
        else {
            return unless $c->check_perms("vendor.batchupdate");
        }

        my $cutoff = $c->batch_transdate_exclusive_min;

        my $datefrom    = $c->param('datefrom');
        my $dateto      = $c->param('dateto');
        my $description = $c->param('description');
        my $invnumber   = $c->param('invnumber');
        my $reference   = $c->param('reference');
        my $customer_id = $c->param('customer_id');
        my $vendor_id   = $c->param('vendor_id');
        my $accno       = $c->param('accno');
        my $partnumber  = $c->param('partnumber');

        # AP batch search: optional filters (transaction + line granularity)
        my $line_item_account     = $c->param('line_item_account');
        my $line_item_tax_account = $c->param('line_item_tax_account');
        my $duedatefrom           = $c->param('duedatefrom');
        my $duedateto             = $c->param('duedateto');
        my $morethanamount        = $c->param('morethanamount');
        my $lessthanamount        = $c->param('lessthanamount');
        my $equaltoamount         = $c->param('equaltoamount');
        my $morethantaxamount     = $c->param('morethantaxamount');
        my $lessthantaxamount     = $c->param('lessthantaxamount');
        my $project_id_filter     = $c->param('project_id');     # AP line / GL line: acc_trans.project_id
        my $department_id_filter  = $c->param('department_id'); # AP: ap.department_id; GL txn: gl.department_id; GL line: gl.department_id
        my $source_search         = $c->param('source');           # GL line: acc_trans.source (ILIKE)
        my $memo_search           = $c->param('memo');           # GL line: acc_trans.memo (ILIKE)

        if ($datefrom) { $c->validate_date($datefrom) or return; }
        if ($dateto)   { $c->validate_date($dateto)   or return; }
        if ($duedatefrom) { $c->validate_date($duedatefrom) or return; }
        if ($duedateto)   { $c->validate_date($duedateto)   or return; }

        my $createdfrom = $c->param('createdfrom');
        my $createdto   = $c->param('createdto');
        my $updatedfrom = $c->param('updatedfrom');
        my $updatedto   = $c->param('updatedto');
        if ($createdfrom) { $c->validate_date($createdfrom) or return; }
        if ($createdto)   { $c->validate_date($createdto)   or return; }
        if ($updatedfrom) { $c->validate_date($updatedfrom) or return; }
        if ($updatedto)   { $c->validate_date($updatedto)   or return; }

        # Transaction-level audit timestamps (ap/ar/gl.created|updated); same bounds for line granularity via join alias.
        my $batch_search_tx_timestamp_clauses = sub {
            my ( $w, $b, $alias ) = @_;
            if ($createdfrom) {
                push @$w, "$alias.created >= ?::date";
                push @$b, $createdfrom;
            }
            if ($createdto) {
                push @$w, "$alias.created < (?::date + interval '1 day')";
                push @$b, $createdto;
            }
            if ($updatedfrom) {
                push @$w, "$alias.updated >= ?::date";
                push @$b, $updatedfrom;
            }
            if ($updatedto) {
                push @$w, "$alias.updated < (?::date + interval '1 day')";
                push @$b, $updatedto;
            }
        };

        my @rows;

        if ( $module eq 'gl' && $granularity eq 'transaction' ) {
            my $q = q{
                SELECT g.id, g.reference, g.transdate, g.description, g.curr,
                       g.department_id, d.description AS department,
                       COALESCE(line_totals.amount, 0) AS amount
                FROM gl g
                LEFT JOIN department d ON d.id = g.department_id
                LEFT JOIN (
                    SELECT trans_id,
                           SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) AS amount
                      FROM acc_trans
                  GROUP BY trans_id
                ) line_totals ON line_totals.trans_id = g.id
            };
            my @w = ('g.approved = ?');
            my @b = ('1');
            if ($cutoff) {
                push @w,  'g.transdate > ?';
                push @b,  $cutoff;
            }
            if ($datefrom) {
                push @w,  'g.transdate >= ?';
                push @b,  $datefrom;
            }
            if ($dateto) {
                push @w,  'g.transdate <= ?';
                push @b,  $dateto;
            }
            if ($description) {
                push @w,  'g.description ILIKE ?';
                push @b,  "%$description%";
            }
            if ($reference) {
                push @w,  'g.reference ILIKE ?';
                push @b,  "%$reference%";
            }
            if ($accno) {
                push @w, q{
                    EXISTS (
                        SELECT 1 FROM acc_trans ac0
                        JOIN chart ch0 ON ch0.id = ac0.chart_id
                        WHERE ac0.trans_id = g.id AND ch0.accno = ?
                    )
                };
                push @b, $accno;
            }
            if ( defined $department_id_filter && $department_id_filter ne '' ) {
                push @w, 'g.department_id = ?';
                push @b, $department_id_filter + 0;
            }
            $batch_search_tx_timestamp_clauses->( \@w, \@b, 'g' );
            $q .= ' WHERE ' . join( ' AND ', @w );
            $q .= ' ORDER BY g.transdate DESC, g.id DESC';
            @rows = @{ $dbs->query( $q, @b )->hashes };
        }
        elsif ( $module eq 'gl' && $granularity eq 'line' ) {
            my $q = q{
                SELECT ac.trans_id, ac.entry_id, ac.transdate,
                       ac.amount, ac.memo, ac.source,
                       ch.accno, ch.description AS account_description,
                       g.reference, g.transdate AS document_transdate,
                       g.description AS document_description,
                       g.department_id,
                       d.description AS department,
                       ac.project_id,
                       pr.projectnumber AS projectnumber,
                       pr.description AS project_description
                FROM acc_trans ac
                JOIN chart ch ON ch.id = ac.chart_id
                JOIN gl g ON g.id = ac.trans_id
                LEFT JOIN department d ON d.id = g.department_id
                LEFT JOIN project pr ON pr.id = ac.project_id
            };
            my @w = ( 'g.approved = ?', 'ac.approved = ?' );
            my @b = ( '1', '1' );
            if ($cutoff) {
                push @w,  'g.transdate > ?';
                push @b,  $cutoff;
            }
            if ($datefrom) {
                push @w,  'g.transdate >= ?';
                push @b,  $datefrom;
            }
            if ($dateto) {
                push @w,  'g.transdate <= ?';
                push @b,  $dateto;
            }
            if ($description) {
                push @w,  'g.description ILIKE ?';
                push @b,  "%$description%";
            }
            if ($reference) {
                push @w,  'g.reference ILIKE ?';
                push @b,  "%$reference%";
            }
            if ($accno) {
                push @w,  'ch.accno = ?';
                push @b,  $accno;
            }
            if ( defined $department_id_filter && $department_id_filter ne '' ) {
                push @w, 'g.department_id = ?';
                push @b, $department_id_filter + 0;
            }
            if ( defined $project_id_filter && $project_id_filter ne '' ) {
                push @w, 'ac.project_id = ?';
                push @b, $project_id_filter + 0;
            }
            if ( defined $source_search && $source_search ne '' ) {
                push @w, 'ac.source ILIKE ?';
                push @b, "%$source_search%";
            }
            if ( defined $memo_search && $memo_search ne '' ) {
                push @w, 'ac.memo ILIKE ?';
                push @b, "%$memo_search%";
            }
            $batch_search_tx_timestamp_clauses->( \@w, \@b, 'g' );
            $q .= ' WHERE ' . join( ' AND ', @w );
            $q .= ' ORDER BY g.transdate DESC, ac.trans_id, ac.entry_id';
            @rows = @{ $dbs->query( $q, @b )->hashes };
            for my $row (@rows) {
                my $amt = $row->{amount};
                my $credit =
                  ( defined $amt && $amt > 0 ) ? $amt * 1 : 0;
                my $debit =
                  ( defined $amt && $amt < 0 ) ? ( -$amt ) * 1 : 0;
                $row->{debit}  = $debit;
                $row->{credit} = $credit;
                delete $row->{amount};
            }
        }
        elsif ( $module eq 'ar' && $granularity eq 'transaction' ) {
            my $q = q{
                SELECT a.id, a.invnumber, a.transdate, a.duedate, a.customer_id,
                       c.name AS customer_name, a.amount, a.paid, a.description,
                       a.invoice, a.curr
                FROM ar a
                JOIN customer c ON c.id = a.customer_id
            };
            my @w = ('a.approved = ?');
            my @b = ('1');
            if ($cutoff) {
                push @w,  'a.transdate > ?';
                push @b,  $cutoff;
            }
            if ($datefrom) {
                push @w,  'a.transdate >= ?';
                push @b,  $datefrom;
            }
            if ($dateto) {
                push @w,  'a.transdate <= ?';
                push @b,  $dateto;
            }
            if ($description) {
                push @w,  'a.description ILIKE ?';
                push @b,  "%$description%";
            }
            if ($invnumber) {
                push @w,  'a.invnumber ILIKE ?';
                push @b,  "%$invnumber%";
            }
            if ($customer_id) {
                push @w,  'a.customer_id = ?';
                push @b,  $customer_id;
            }
            $batch_search_tx_timestamp_clauses->( \@w, \@b, 'a' );
            $q .= ' WHERE ' . join( ' AND ', @w );
            $q .= ' ORDER BY a.transdate DESC, a.id DESC';
            @rows = @{ $dbs->query( $q, @b )->hashes };
        }
        elsif ( $module eq 'ar' && $granularity eq 'line' ) {
            my $q = q{
                SELECT i.id AS line_id, i.trans_id, i.description AS line_description,
                       i.qty, i.sellprice, i.fxsellprice, i.discount,
                       p.partnumber, p.id AS parts_id,
                       a.invnumber, a.transdate AS document_transdate,
                       a.customer_id, c.name AS customer_name,
                       a.description AS document_description, a.curr
                FROM invoice i
                JOIN ar a ON a.id = i.trans_id
                JOIN customer c ON c.id = a.customer_id
                LEFT JOIN parts p ON p.id = i.parts_id
            };
            my @w = (
                'a.invoice IS TRUE',
                'NOT COALESCE(i.assemblyitem, false)',
                'a.approved = ?'
            );
            my @b = ('1');
            if ($cutoff) {
                push @w, 'a.transdate > ?';
                push @b, $cutoff;
            }
            if ($datefrom) {
                push @w, 'a.transdate >= ?';
                push @b, $datefrom;
            }
            if ($dateto) {
                push @w, 'a.transdate <= ?';
                push @b, $dateto;
            }
            if ($description) {
                push @w, 'a.description ILIKE ?';
                push @b, "%$description%";
            }
            if ($invnumber) {
                push @w, 'a.invnumber ILIKE ?';
                push @b, "%$invnumber%";
            }
            if ($customer_id) {
                push @w, 'a.customer_id = ?';
                push @b, $customer_id;
            }
            if ($partnumber) {
                push @w, 'p.partnumber ILIKE ?';
                push @b, "%$partnumber%";
            }
            $batch_search_tx_timestamp_clauses->( \@w, \@b, 'a' );
            $q .= ' WHERE ' . join( ' AND ', @w );
            $q .= ' ORDER BY a.transdate DESC, i.trans_id, i.id';
            @rows = @{ $dbs->query( $q, @b )->hashes };
        }
        elsif ( $module eq 'ap' && $granularity eq 'transaction' ) {
            my $q = q{
                SELECT a.id, a.invnumber, a.transdate, a.duedate, a.vendor_id,
                       a.department_id, dep.description AS department,
                       v.name AS vendor_name, a.amount, a.paid, a.description,
                       a.invoice, a.curr
                FROM ap a
                JOIN vendor v ON v.id = a.vendor_id
                LEFT JOIN department dep ON dep.id = a.department_id
            };
            my @w = ('a.approved = ?');
            my @b = ('1');
            if ($cutoff) {
                push @w,  'a.transdate > ?';
                push @b,  $cutoff;
            }
            if ($datefrom) {
                push @w,  'a.transdate >= ?';
                push @b,  $datefrom;
            }
            if ($dateto) {
                push @w,  'a.transdate <= ?';
                push @b,  $dateto;
            }
            if ($description) {
                push @w,  'a.description ILIKE ?';
                push @b,  "%$description%";
            }
            if ($invnumber) {
                push @w,  'a.invnumber ILIKE ?';
                push @b,  "%$invnumber%";
            }
            if ($vendor_id) {
                push @w,  'a.vendor_id = ?';
                push @b,  $vendor_id;
            }
            if ($duedatefrom) {
                push @w,  'a.duedate >= ?';
                push @b,  $duedatefrom;
            }
            if ($duedateto) {
                push @w,  'a.duedate <= ?';
                push @b,  $duedateto;
            }
            if ( defined $morethanamount && $morethanamount ne '' ) {
                push @w,  'a.amount > ?';
                push @b,  $morethanamount + 0;
            }
            if ( defined $lessthanamount && $lessthanamount ne '' ) {
                push @w,  'a.amount < ?';
                push @b,  $lessthanamount + 0;
            }
            if ( defined $equaltoamount && $equaltoamount ne '' ) {
                push @w,  'a.amount = ?';
                push @b,  $equaltoamount + 0;
            }
            if ( defined $department_id_filter && $department_id_filter ne '' ) {
                push @w,  'a.department_id = ?';
                push @b,  $department_id_filter + 0;
            }
            $batch_search_tx_timestamp_clauses->( \@w, \@b, 'a' );
            $q .= ' WHERE ' . join( ' AND ', @w );
            $q .= ' ORDER BY a.transdate DESC, a.id DESC';
            @rows = @{ $dbs->query( $q, @b )->hashes };
        }
        elsif ( $module eq 'ap' && $granularity eq 'line' ) {
            my $q = q{
                SELECT ap.id AS trans_id,
                       ap.vendor_id,
                       ap.invnumber,
                       v.name AS vendor_name,
                       ap.transdate AS invoicedate,
                       ap.duedate,
                       ap.executiondate,
                       rec.accno AS record_accno,
                       ap.department_id,
                       d.description AS department,
                       ac.memo AS item_description,
                       ch.accno AS expense_accno,
                       ac.amount AS _amount_raw,
                       ac.linetaxamount AS _linetax_raw,
                       tax.accno AS tax_account,
                       ac.project_id,
                       ac.entry_id
                FROM acc_trans ac
                JOIN chart ch ON ch.id = ac.chart_id
                JOIN ap ON ap.id = ac.trans_id
                JOIN vendor v ON v.id = ap.vendor_id
                LEFT JOIN department d ON d.id = ap.department_id
                LEFT JOIN chart tax ON tax.id = ac.tax_chart_id
                LEFT JOIN LATERAL (
                    SELECT c2.accno
                      FROM acc_trans ac2
                      JOIN chart c2 ON c2.id = ac2.chart_id
                     WHERE ac2.trans_id = ap.id
                       AND ac2.fx_transaction = '0'
                       AND (':' || COALESCE(c2.link, '') || ':') LIKE '%:AP:%'
                       AND c2.link NOT LIKE '%AP_amount%'
                       AND c2.link NOT LIKE '%AP_paid%'
                       AND c2.link NOT LIKE '%AP_discount%'
                  ORDER BY ac2.entry_id
                     LIMIT 1
                ) rec ON TRUE
            };
            my @w = (
                'ap.approved = ?',
                'ac.approved = ?',
                'ac.fx_transaction = ?',
                q{ch.link LIKE '%AP_amount%'}
            );
            my @b = ( '1', '1', '0' );
            if ($cutoff) {
                push @w,  'ap.transdate > ?';
                push @b,  $cutoff;
            }
            if ($datefrom) {
                push @w,  'ap.transdate >= ?';
                push @b,  $datefrom;
            }
            if ($dateto) {
                push @w,  'ap.transdate <= ?';
                push @b,  $dateto;
            }
            if ($description) {
                push @w,  'ap.description ILIKE ?';
                push @b,  "%$description%";
            }
            if ($invnumber) {
                push @w,  'ap.invnumber ILIKE ?';
                push @b,  "%$invnumber%";
            }
            if ($vendor_id) {
                push @w,  'ap.vendor_id = ?';
                push @b,  $vendor_id;
            }
            my $ap_line_expense_accno = $line_item_account || $accno;
            if ($ap_line_expense_accno) {
                push @w,  'ch.accno = ?';
                push @b,  $ap_line_expense_accno;
            }
            if ($line_item_tax_account) {
                push @w,  'tax.accno = ?';
                push @b,  $line_item_tax_account;
            }
            if ($duedatefrom) {
                push @w,  'ap.duedate >= ?';
                push @b,  $duedatefrom;
            }
            if ($duedateto) {
                push @w,  'ap.duedate <= ?';
                push @b,  $duedateto;
            }
            if ( defined $department_id_filter && $department_id_filter ne '' ) {
                push @w,  'ap.department_id = ?';
                push @b,  $department_id_filter + 0;
            }
            if ( defined $project_id_filter && $project_id_filter ne '' ) {
                push @w,  'ac.project_id = ?';
                push @b,  $project_id_filter + 0;
            }
            $batch_search_tx_timestamp_clauses->( \@w, \@b, 'ap' );
            $q .= ' WHERE ' . join( ' AND ', @w );
            $q .=
              ' ORDER BY ap.transdate DESC, ac.trans_id, ac.entry_id';
            @rows = @{ $dbs->query( $q, @b )->hashes };

            my %trans_total;
            for my $row (@rows) {
                $trans_total{ $row->{trans_id} } += $row->{_amount_raw} // 0;
            }
            for my $row (@rows) {
                my $total = $trans_total{ $row->{trans_id} } // 0;
                my $is_neg = $total < 0;
                my $mult   = $is_neg ? 1 : -1;    # same as GET /arap/transaction/vendor/:id (AP)
                my $raw    = $row->{_amount_raw}  // 0;
                my $linetax = $row->{_linetax_raw};
                $row->{amount}     = $mult * ( -$raw );
                $row->{tax_amount} = defined $linetax ? $linetax * 1 : undef;
                delete $row->{_amount_raw};
                delete $row->{_linetax_raw};
                $row->{ap_id} = delete $row->{trans_id};
            }

            if (   ( defined $morethanamount    && $morethanamount ne '' )
                || ( defined $lessthanamount    && $lessthanamount ne '' )
                || ( defined $equaltoamount     && $equaltoamount ne '' )
                || ( defined $morethantaxamount && $morethantaxamount ne '' )
                || ( defined $lessthantaxamount && $lessthantaxamount ne '' ) )
            {
                my $mta =
                  ( defined $morethanamount && $morethanamount ne '' )
                  ? $morethanamount + 0
                  : undef;
                my $lta =
                  ( defined $lessthanamount && $lessthanamount ne '' )
                  ? $lessthanamount + 0
                  : undef;
                my $eqa =
                  ( defined $equaltoamount && $equaltoamount ne '' )
                  ? $equaltoamount + 0
                  : undef;
                my $mtt =
                  ( defined $morethantaxamount && $morethantaxamount ne '' )
                  ? $morethantaxamount + 0
                  : undef;
                my $ltt =
                  ( defined $lessthantaxamount && $lessthantaxamount ne '' )
                  ? $lessthantaxamount + 0
                  : undef;
                @rows = grep {
                    my $r   = $_;
                    my $amt = $r->{amount};
                    my $tax = $r->{tax_amount};
                    my $ok  = 1;
                    if ( defined $mta ) {
                        $ok = 0 unless defined $amt && $amt > $mta;
                    }
                    if ( $ok && defined $lta ) {
                        $ok = 0 unless defined $amt && $amt < $lta;
                    }
                    if ( $ok && defined $eqa ) {
                        $ok = 0
                          unless defined $amt
                          && abs( $amt - $eqa ) < 1e-8;
                    }
                    if ( $ok && defined $mtt ) {
                        $ok = 0 unless defined $tax && $tax > $mtt;
                    }
                    if ( $ok && defined $ltt ) {
                        $ok = 0 unless defined $tax && $tax < $ltt;
                    }
                    $ok;
                } @rows;
            }
        }

        $c->render(
            json => {
                module                => $module,
                granularity           => $granularity,
                transdate_after       => $cutoff,
                closed_period_applied => $cutoff ? \1 : \0,
                rows                  => \@rows,
            }
        );
    }
);

$api->get(
    '/batch/create_links' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $module = $c->param('module') || '';

        unless ( $module =~ /^(ar|ap|gl)$/ ) {
            return $c->render(
                status => 400,
                json   => {
                    error => 'Invalid module. Use ar, ap, or gl.',
                }
            );
        }

        if ( $module eq 'gl' ) {
            return unless $c->check_perms("ledger.batchupdate");
        }
        elsif ( $module eq 'ar' ) {
            return unless $c->check_perms("customer.batchupdate");
        }
        else {
            return unless $c->check_perms("vendor.batchupdate");
        }

        my $sections = scalar $c->param('sections');
        $sections = 'all' if !defined $sections || $sections eq '';

        my $payload =
          $c->batch_build_create_links( $client, $module, $sections );
        $c->render( json => $payload // {} );
    }
);

$api->post(
    '/batch/update' => sub {
        my $c    = shift;
        my $body = $c->req->json;
        unless ( ref($body) eq 'HASH' ) {
            return $c->render(
                status => 400,
                json   => { error => 'JSON object body required.' }
            );
        }
        my $module = $body->{module} // '';
        unless ( $module =~ /^(ap|gl)$/ ) {
            return $c->render(
                status => 400,
                json   => { error => 'Invalid module. Use ap or gl.' }
            );
        }
        my $granularity = $body->{granularity} // '';
        unless ( $granularity eq 'transaction' || $granularity eq 'line' ) {
            return $c->render(
                status => 400,
                json   => {
                    error => 'Invalid granularity. Use transaction or line.',
                }
            );
        }
        if ( $module eq 'gl' ) {
            return unless $c->check_perms("ledger.batchupdate");
        }
        else {
            return unless $c->check_perms("vendor.batchupdate");
        }

        my $items = $body->{items};
        unless ( ref($items) eq 'ARRAY' && @$items ) {
            return $c->render(
                status => 400,
                json   => { error => 'items must be a non-empty array.' }
            );
        }

        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);
        my @results;

        ITEM: for my $it (@$items) {
            unless ( ref($it) eq 'HASH' ) {
                push @results,
                  { id => undef, ok => 0, error => 'Each item must be an object.' };
                next;
            }

            if ( $module eq 'ap' ) {

            # ----------------------------------------------------------------
            # Resolve $id and $item_entry_id based on granularity
            # ----------------------------------------------------------------
            my ( $id, $item_entry_id );

            if ( $granularity eq 'line' ) {
                my $eid_raw = $it->{entry_id};
                unless ( defined $eid_raw && $eid_raw =~ /^\d+$/ ) {
                    push @results,
                      { id => undef, entry_id => undef, ok => 0,
                        error => 'entry_id is required for each item when granularity is line.' };
                    next ITEM;
                }
                $item_entry_id = $eid_raw + 0;

                my $ah = $dbs->query(
                    q{SELECT trans_id FROM acc_trans WHERE entry_id = ?},
                    $item_entry_id
                )->hash;
                unless ($ah) {
                    push @results,
                      { id => undef, entry_id => $item_entry_id, ok => 0,
                        error => 'acc_trans row not found for entry_id.' };
                    next ITEM;
                }
                $id = $ah->{trans_id} + 0;

                for my $k (qw(id ap_id)) {
                    my $v = $it->{$k};
                    next unless defined $v && $v =~ /^\d+$/;
                    if ( $v + 0 != $id ) {
                        push @results,
                          { id => $v + 0, entry_id => $item_entry_id, ok => 0,
                            error => 'id / ap_id does not match the AP transaction for this entry_id.' };
                        next ITEM;
                    }
                    last;
                }
            }
            else {
                my $raw_id = $it->{id} // $it->{ap_id};
                unless ( defined $raw_id && $raw_id =~ /^\d+$/ && $raw_id > 0 ) {
                    push @results,
                      { id => undef, ok => 0, error => 'id or ap_id is required for transaction granularity.' };
                    next ITEM;
                }
                $id = $raw_id + 0;
            }

            my $batch_add_result = sub {
                my (%h) = @_;
                $h{entry_id} = $item_entry_id if defined $item_entry_id;
                push @results, \%h;
            };

            # ----------------------------------------------------------------
            # Shared AP document validation
            # ----------------------------------------------------------------
            my $row = $dbs->query(
                q{SELECT id, transdate, duedate, vendor_id, department_id, approved
                    FROM ap WHERE id = ?},
                $id
            )->hash;
            unless ($row) {
                $batch_add_result->( id => $id, ok => 0, error => 'AP transaction not found.' );
                next;
            }
            if ( ( $row->{approved} // '' ) ne '1' ) {
                $batch_add_result->( id => $id, ok => 0, error => 'Only approved transactions can be updated.' );
                next;
            }

            my $cutoff = $c->batch_transdate_exclusive_min;
            if ($cutoff) {
                my $old_td = $row->{transdate};
                $old_td =~ s/\s.*//s if defined $old_td;
                $old_td = format_date($old_td) if defined $old_td;
                unless ( defined $old_td
                    && $old_td =~ /^\d{4}-\d{2}-\d{2}$/
                    && $old_td gt $cutoff )
                {
                    $batch_add_result->(
                        id => $id, ok => 0,
                        error => 'Transaction is in the closed period and cannot be modified.' );
                    next;
                }
            }

            # ----------------------------------------------------------------
            # Line granularity: direct processing
            # ----------------------------------------------------------------
            if ( $granularity eq 'line' ) {
                my %ap_set;
                my $need_acc_trans;
                my $dept_changed;

                if ( exists $it->{transdate} ) {
                    my $nd = $it->{transdate};
                    unless ( defined $nd && $nd =~ /^\d{4}-\d{2}-\d{2}$/ ) {
                        $batch_add_result->( id => $id, ok => 0, error => 'Invalid transdate format.' );
                        next;
                    }
                    if ( my $err = $c->batch_date_must_be_after_closed_period($nd) ) {
                        $batch_add_result->( id => $id, ok => 0, error => $err );
                        next;
                    }
                    $ap_set{transdate} = $nd;
                    $need_acc_trans = 1;
                }

                if ( exists $it->{duedate} ) {
                    my $nd = $it->{duedate};
                    unless ( defined $nd && $nd =~ /^\d{4}-\d{2}-\d{2}$/ ) {
                        $batch_add_result->( id => $id, ok => 0, error => 'Invalid duedate format.' );
                        next;
                    }
                    if ( my $err = $c->batch_date_must_be_after_closed_period($nd) ) {
                        $batch_add_result->( id => $id, ok => 0, error => $err );
                        next;
                    }
                    $ap_set{duedate} = $nd;
                }

                if ( exists $it->{vendor_id} ) {
                    my $vid = $it->{vendor_id};
                    unless ( defined $vid && $vid =~ /^\d+$/ && $vid > 0 ) {
                        $batch_add_result->( id => $id, ok => 0, error => 'Invalid vendor_id.' );
                        next;
                    }
                    $vid += 0;
                    unless ( $dbs->query( 'SELECT id FROM vendor WHERE id = ?', $vid )->hash ) {
                        $batch_add_result->( id => $id, ok => 0, error => 'Vendor not found.' );
                        next;
                    }
                    $ap_set{vendor_id} = $vid;
                }

                if ( exists $it->{department_id} ) {
                    my $did = $it->{department_id};
                    if ( defined $did && $did ne '' ) {
                        unless ( $did =~ /^\d+$/ && $did > 0 ) {
                            $batch_add_result->( id => $id, ok => 0, error => 'Invalid department_id.' );
                            next;
                        }
                        $did += 0;
                        unless ( $dbs->query( 'SELECT id FROM department WHERE id = ?', $did )->hash ) {
                            $batch_add_result->( id => $id, ok => 0, error => 'Department not found.' );
                            next;
                        }
                        $ap_set{department_id} = $did;
                    }
                    else {
                        $ap_set{department_id} = undef;
                    }
                    $dept_changed = 1;
                }

                my $has_exp  = exists $it->{expense_chart_id} || exists $it->{expense_accno};
                my $has_rec  = exists $it->{record_chart_id}  || exists $it->{record_accno};
                my $has_proj = exists $it->{project_id};

                my ( $expense_cid, $record_new_cid, $pay_cid_old );
                my ( $proj_val, $proj_changed );
                my $ac_row;

                if ( $has_exp || $has_proj ) {
                    $ac_row = $dbs->query(
                        q{SELECT id, chart_id FROM acc_trans
                           WHERE entry_id = ? AND trans_id = ?},
                        $item_entry_id, $id
                    )->hash;
                    unless ($ac_row) {
                        $batch_add_result->( id => $id, ok => 0,
                            error => 'entry_id not found on this AP transaction.' );
                        next ITEM;
                    }
                }

                if ( $has_exp || $has_rec ) {
                    my ( $rec_allowed, $exp_allowed ) = $c->batch_ap_allowed_chart_maps($dbs);

                    if ($has_exp) {
                        unless ( $exp_allowed->{ $ac_row->{chart_id} } ) {
                            $batch_add_result->( id => $id, ok => 0,
                                error => 'acc_trans line is not an AP expense account line.' );
                            next ITEM;
                        }
                        my ( $ecid, $eerr ) = $c->batch_ap_resolve_update_chart(
                            $dbs, $it->{expense_chart_id}, $it->{expense_accno},
                            $exp_allowed, 'expense'
                        );
                        if ($eerr) {
                            $batch_add_result->( id => $id, ok => 0, error => $eerr );
                            next ITEM;
                        }
                        $expense_cid = $ecid;
                    }

                    if ($has_rec) {
                        my ( $rcid, $rerr ) = $c->batch_ap_resolve_update_chart(
                            $dbs, $it->{record_chart_id}, $it->{record_accno},
                            $rec_allowed, 'record'
                        );
                        if ($rerr) {
                            $batch_add_result->( id => $id, ok => 0, error => $rerr );
                            next ITEM;
                        }
                        ( $pay_cid_old, my $perr ) = $c->batch_ap_payable_chart_id( $dbs, $id );
                        if ($perr) {
                            $batch_add_result->( id => $id, ok => 0, error => $perr );
                            next ITEM;
                        }
                        $record_new_cid = $rcid unless $pay_cid_old + 0 == $rcid + 0;
                    }
                }

                if ($has_proj) {
                    my $p_in = $it->{project_id};
                    if ( defined $p_in && $p_in ne '' ) {
                        unless ( $p_in =~ /^\d+$/ && $p_in > 0 ) {
                            $batch_add_result->( id => $id, ok => 0, error => 'Invalid project_id.' );
                            next ITEM;
                        }
                        unless ( $dbs->query( 'SELECT id FROM project WHERE id = ?', $p_in + 0 )->hash ) {
                            $batch_add_result->( id => $id, ok => 0, error => 'Project not found.' );
                            next ITEM;
                        }
                        $proj_val = $p_in + 0;
                    }
                    $proj_changed = 1;
                }

                unless (
                        keys %ap_set
                    || $dept_changed
                    || defined $expense_cid
                    || defined $record_new_cid
                    || $proj_changed
                  )
                {
                    $batch_add_result->( id => $id, ok => 0, error => 'No updatable fields provided.' );
                    next ITEM;
                }

                my $ok_run = eval {
                    $dbs->begin;
                    if ( keys %ap_set ) {
                        my @cols = keys %ap_set;
                        my $set  = join ', ', map { "$_ = ?" } @cols;
                        $dbs->query( "UPDATE ap SET $set WHERE id = ?", ( @ap_set{@cols} ), $id );
                    }
                    if ($need_acc_trans) {
                        $dbs->query(
                            'UPDATE acc_trans SET transdate = ? WHERE trans_id = ?',
                            $ap_set{transdate}, $id );
                    }
                    if ($dept_changed) {
                        $dbs->query( 'DELETE FROM dpt_trans WHERE trans_id = ?', $id );
                        if ( defined $ap_set{department_id} ) {
                            $dbs->query(
                                q{INSERT INTO dpt_trans (trans_id, department_id) VALUES (?, ?)},
                                $id, $ap_set{department_id} );
                        }
                    }
                    if ( defined $expense_cid ) {
                        $dbs->query(
                            q{UPDATE acc_trans SET chart_id = ?
                               WHERE entry_id = ? AND trans_id = ?},
                            $expense_cid, $item_entry_id, $id );
                    }
                    if ( defined $record_new_cid ) {
                        $dbs->query(
                            q{UPDATE acc_trans SET chart_id = ?
                               WHERE trans_id = ? AND chart_id = ?},
                            $record_new_cid, $id, $pay_cid_old );
                    }
                    if ($proj_changed) {
                        $dbs->query(
                            q{UPDATE acc_trans SET project_id = ?
                               WHERE entry_id = ? AND trans_id = ?},
                            $proj_val, $item_entry_id, $id );
                        if ( defined $ac_row->{id} ) {
                            $dbs->query(
                                q{UPDATE invoice SET project_id = ?
                                   WHERE id = ? AND trans_id = ?},
                                $proj_val, $ac_row->{id}, $id );
                        }
                    }
                    $dbs->commit;
                    1;
                };
                if ( !$ok_run ) {
                    my $e = $@ || 'Unknown error';
                    $c->app->log->error("batch/update ap line entry_id=$item_entry_id: $e");
                    eval { $dbs->rollback };
                    $batch_add_result->( id => $id, ok => 0, error => 'Update failed.' );
                    next;
                }
                $batch_add_result->( id => $id, ok => 1, error => undef );
                next ITEM;
            }

            # ----------------------------------------------------------------
            # Transaction granularity
            # ----------------------------------------------------------------
            my %ap_set;
            my $need_acc_trans;
            my $dept_changed;
            my $project_changed;
            my $project_set_val;

            if ( exists $it->{transdate} ) {
                my $nd = $it->{transdate};
                unless ( defined $nd && $nd =~ /^\d{4}-\d{2}-\d{2}$/ ) {
                    $batch_add_result->( id => $id, ok => 0, error => 'Invalid transdate format.' );
                    next;
                }
                if ( my $err = $c->batch_date_must_be_after_closed_period($nd) ) {
                    $batch_add_result->( id => $id, ok => 0, error => $err );
                    next;
                }
                $ap_set{transdate} = $nd;
                $need_acc_trans = 1;
            }

            if ( exists $it->{duedate} ) {
                my $nd = $it->{duedate};
                unless ( defined $nd && $nd =~ /^\d{4}-\d{2}-\d{2}$/ ) {
                    $batch_add_result->( id => $id, ok => 0, error => 'Invalid duedate format.' );
                    next;
                }
                if ( my $err = $c->batch_date_must_be_after_closed_period($nd) ) {
                    $batch_add_result->( id => $id, ok => 0, error => $err );
                    next;
                }
                $ap_set{duedate} = $nd;
            }

            if ( exists $it->{vendor_id} ) {
                my $vid = $it->{vendor_id};
                unless ( defined $vid && $vid =~ /^\d+$/ && $vid > 0 ) {
                    $batch_add_result->( id => $id, ok => 0, error => 'Invalid vendor_id.' );
                    next;
                }
                $vid += 0;
                unless ( $dbs->query( 'SELECT id FROM vendor WHERE id = ?', $vid )->hash ) {
                    $batch_add_result->( id => $id, ok => 0, error => 'Vendor not found.' );
                    next;
                }
                $ap_set{vendor_id} = $vid;
            }

            if ( exists $it->{department_id} ) {
                my $did = $it->{department_id};
                if ( defined $did && $did ne '' ) {
                    unless ( $did =~ /^\d+$/ && $did > 0 ) {
                        $batch_add_result->( id => $id, ok => 0, error => 'Invalid department_id.' );
                        next;
                    }
                    $did += 0;
                    unless ( $dbs->query( 'SELECT id FROM department WHERE id = ?', $did )->hash ) {
                        $batch_add_result->( id => $id, ok => 0, error => 'Department not found.' );
                        next;
                    }
                    $ap_set{department_id} = $did;
                }
                else {
                    $ap_set{department_id} = undef;
                }
                $dept_changed = 1;
            }

            if ( exists $it->{project_id} ) {
                my $pid = $it->{project_id};
                if ( defined $pid && $pid ne '' ) {
                    unless ( $pid =~ /^\d+$/ && $pid > 0 ) {
                        $batch_add_result->( id => $id, ok => 0, error => 'Invalid project_id.' );
                        next;
                    }
                    $pid += 0;
                    unless ( $dbs->query( 'SELECT id FROM project WHERE id = ?', $pid )->hash ) {
                        $batch_add_result->( id => $id, ok => 0, error => 'Project not found.' );
                        next;
                    }
                    $project_set_val = $pid;
                }
                else {
                    $project_set_val = undef;
                }
                $project_changed = 1;
            }

            my $record_new_cid;
            my $pay_cid_old;

            if ( exists $it->{record_chart_id} || exists $it->{record_accno} ) {
                my ( $rec_allowed, undef ) = $c->batch_ap_allowed_chart_maps($dbs);
                my ( $rcid, $rerr ) = $c->batch_ap_resolve_update_chart(
                    $dbs, $it->{record_chart_id}, $it->{record_accno},
                    $rec_allowed, 'record'
                );
                if ($rerr) {
                    $batch_add_result->( id => $id, ok => 0, error => $rerr );
                    next ITEM;
                }
                ( $pay_cid_old, my $perr ) = $c->batch_ap_payable_chart_id( $dbs, $id );
                if ($perr) {
                    $batch_add_result->( id => $id, ok => 0, error => $perr );
                    next ITEM;
                }
                $record_new_cid = $rcid unless $pay_cid_old + 0 == $rcid + 0;
            }

            unless ( keys %ap_set || $project_changed || defined $record_new_cid ) {
                $batch_add_result->( id => $id, ok => 0, error => 'No updatable fields provided.' );
                next ITEM;
            }

            my $ok_run = eval {
                $dbs->begin;
                if ( keys %ap_set ) {
                    my @cols = keys %ap_set;
                    my $set  = join ', ', map { "$_ = ?" } @cols;
                    $dbs->query( "UPDATE ap SET $set WHERE id = ?", ( @ap_set{@cols} ), $id );
                }
                if ($need_acc_trans) {
                    $dbs->query(
                        'UPDATE acc_trans SET transdate = ? WHERE trans_id = ?',
                        $ap_set{transdate}, $id );
                }
                if ($dept_changed) {
                    $dbs->query( 'DELETE FROM dpt_trans WHERE trans_id = ?', $id );
                    if ( defined $ap_set{department_id} ) {
                        $dbs->query(
                            q{INSERT INTO dpt_trans (trans_id, department_id) VALUES (?, ?)},
                            $id, $ap_set{department_id} );
                    }
                }
                if ($project_changed) {
                    $dbs->query(
                        'UPDATE acc_trans SET project_id = ? WHERE trans_id = ?',
                        $project_set_val, $id );
                    $dbs->query(
                        'UPDATE invoice SET project_id = ? WHERE trans_id = ?',
                        $project_set_val, $id );
                }
                if ( defined $record_new_cid ) {
                    $dbs->query(
                        q{UPDATE acc_trans SET chart_id = ?
                           WHERE trans_id = ? AND chart_id = ?},
                        $record_new_cid, $id, $pay_cid_old );
                }
                $dbs->commit;
                1;
            };
            if ( !$ok_run ) {
                my $e = $@ || 'Unknown error';
                $c->app->log->error("batch/update ap id=$id: $e");
                eval { $dbs->rollback };
                $batch_add_result->( id => $id, ok => 0, error => 'Update failed.' );
                next;
            }
            $batch_add_result->( id => $id, ok => 1, error => undef );
            }
            elsif ( $module eq 'gl' ) {
                my ( $id, $item_entry_id );

                if ( $granularity eq 'line' ) {
                    my $eid_raw = $it->{entry_id};
                    unless ( defined $eid_raw && $eid_raw =~ /^\d+$/ ) {
                        push @results,
                          { id => undef, entry_id => undef, ok => 0,
                            error => 'entry_id is required for each item when granularity is line.' };
                        next ITEM;
                    }
                    $item_entry_id = $eid_raw + 0;
                    my $ah = $dbs->query(
                        q{SELECT trans_id FROM acc_trans WHERE entry_id = ?},
                        $item_entry_id
                    )->hash;
                    unless ($ah) {
                        push @results,
                          { id => undef, entry_id => $item_entry_id, ok => 0,
                            error => 'acc_trans row not found for entry_id.' };
                        next ITEM;
                    }
                    $id = $ah->{trans_id} + 0;
                    for my $k (qw(id gl_id)) {
                        my $v = $it->{$k};
                        next unless defined $v && $v =~ /^\d+$/;
                        if ( $v + 0 != $id ) {
                            push @results,
                              { id => $v + 0, entry_id => $item_entry_id, ok => 0,
                                error => 'id / gl_id does not match the GL transaction for this entry_id.' };
                            next ITEM;
                        }
                        last;
                    }
                }
                else {
                    my $raw_id = $it->{id} // $it->{gl_id};
                    unless ( defined $raw_id && $raw_id =~ /^\d+$/ && $raw_id > 0 ) {
                        push @results,
                          { id => undef, ok => 0,
                            error => 'id or gl_id is required for transaction granularity.' };
                        next ITEM;
                    }
                    $id = $raw_id + 0;
                }

                my $batch_add_result = sub {
                    my (%h) = @_;
                    $h{entry_id} = $item_entry_id if defined $item_entry_id;
                    push @results, \%h;
                };

                my $grow = $dbs->query(
                    q{SELECT id, transdate, department_id FROM gl WHERE id = ? AND approved IS TRUE},
                    $id
                )->hash;
                unless ($grow) {
                    my $exists = $dbs->query( q{SELECT 1 FROM gl WHERE id = ?}, $id )->hash;
                    $batch_add_result->(
                        id => $id, ok => 0,
                        error => $exists
                        ? 'Only approved transactions can be updated.'
                        : 'GL transaction not found.'
                    );
                    next ITEM;
                }

                my $cutoff = $c->batch_transdate_exclusive_min;
                if ($cutoff) {
                    my $old_td = $grow->{transdate};
                    $old_td =~ s/\s.*//s if defined $old_td;
                    $old_td = format_date($old_td) if defined $old_td;
                    unless ( defined $old_td
                        && $old_td =~ /^\d{4}-\d{2}-\d{2}$/
                        && $old_td gt $cutoff )
                    {
                        $batch_add_result->(
                            id => $id, ok => 0,
                            error => 'Transaction is in the closed period and cannot be modified.' );
                        next ITEM;
                    }
                }

                if ( $granularity eq 'line' ) {
                    my %gl_set;
                    my $need_acc_trans_td;
                    my $dept_changed;
                    my $proj_changed;
                    my $proj_val;
                    my $chart_new_cid;

                    if ( exists $it->{transdate} ) {
                        my $nd = $it->{transdate};
                        unless ( defined $nd && $nd =~ /^\d{4}-\d{2}-\d{2}$/ ) {
                            $batch_add_result->( id => $id, ok => 0, error => 'Invalid transdate format.' );
                            next ITEM;
                        }
                        if ( my $err = $c->batch_date_must_be_after_closed_period($nd) ) {
                            $batch_add_result->( id => $id, ok => 0, error => $err );
                            next ITEM;
                        }
                        $gl_set{transdate} = $nd;
                        $need_acc_trans_td = 1;
                    }

                    if ( exists $it->{department_id} ) {
                        my $did = $it->{department_id};
                        if ( defined $did && $did ne '' ) {
                            unless ( $did =~ /^\d+$/ && $did > 0 ) {
                                $batch_add_result->( id => $id, ok => 0, error => 'Invalid department_id.' );
                                next ITEM;
                            }
                            $did += 0;
                            unless ( $dbs->query( 'SELECT id FROM department WHERE id = ?', $did )->hash ) {
                                $batch_add_result->( id => $id, ok => 0, error => 'Department not found.' );
                                next ITEM;
                            }
                            $gl_set{department_id} = $did;
                        }
                        else {
                            $gl_set{department_id} = 0;
                        }
                        $dept_changed = 1;
                    }

                    if ( exists $it->{project_id} ) {
                        my $p_in = $it->{project_id};
                        if ( defined $p_in && $p_in ne '' ) {
                            unless ( $p_in =~ /^\d+$/ && $p_in > 0 ) {
                                $batch_add_result->( id => $id, ok => 0, error => 'Invalid project_id.' );
                                next ITEM;
                            }
                            unless (
                                $dbs->query( 'SELECT id FROM project WHERE id = ?', $p_in + 0 )->hash )
                            {
                                $batch_add_result->( id => $id, ok => 0, error => 'Project not found.' );
                                next ITEM;
                            }
                            $proj_val = $p_in + 0;
                        }
                        else {
                            $proj_val = undef;
                        }
                        $proj_changed = 1;
                    }

                    my $ac_line = $dbs->query(
                        q{SELECT chart_id FROM acc_trans WHERE entry_id = ? AND trans_id = ?},
                        $item_entry_id, $id
                    )->hash;
                    unless ($ac_line) {
                        $batch_add_result->( id => $id, ok => 0,
                            error => 'entry_id not found on this GL transaction.' );
                        next ITEM;
                    }

                    my $allowed_gl = $c->batch_gl_chart_allowed_ids($dbs);
                    if ( exists $it->{chart_id} || exists $it->{accno} ) {
                        my ( $cid, $cerr ) = $c->batch_gl_resolve_update_chart(
                            $dbs, $it->{chart_id}, $it->{accno}, $allowed_gl );
                        if ($cerr) {
                            $batch_add_result->( id => $id, ok => 0, error => $cerr );
                            next ITEM;
                        }
                        $chart_new_cid = $cid;
                        if ( defined $chart_new_cid && $chart_new_cid + 0 == $ac_line->{chart_id} + 0 ) {
                            $chart_new_cid = undef;
                        }
                    }

                    unless (
                           keys %gl_set
                        || $dept_changed
                        || $proj_changed
                        || defined $chart_new_cid
                      )
                    {
                        $batch_add_result->( id => $id, ok => 0, error => 'No updatable fields provided.' );
                        next ITEM;
                    }

                    my $ok_run = eval {
                        $dbs->begin;
                        if ( keys %gl_set ) {
                            my @cols = keys %gl_set;
                            my $set  = join ', ', map { "$_ = ?" } @cols;
                            $dbs->query( "UPDATE gl SET $set WHERE id = ?", ( @gl_set{@cols} ), $id );
                        }
                        if ($need_acc_trans_td) {
                            $dbs->query(
                                'UPDATE acc_trans SET transdate = ? WHERE trans_id = ?',
                                $gl_set{transdate}, $id );
                        }
                        if ($dept_changed) {
                            $dbs->query( 'DELETE FROM dpt_trans WHERE trans_id = ?', $id );
                            if ( ( $gl_set{department_id} // 0 ) > 0 ) {
                                $dbs->query(
                                    q{INSERT INTO dpt_trans (trans_id, department_id) VALUES (?, ?)},
                                    $id, $gl_set{department_id} );
                            }
                        }
                        if ($proj_changed) {
                            $dbs->query(
                                q{UPDATE acc_trans SET project_id = ?
                                   WHERE entry_id = ? AND trans_id = ?},
                                $proj_val, $item_entry_id, $id );
                        }
                        if ( defined $chart_new_cid ) {
                            $dbs->query(
                                q{UPDATE acc_trans SET chart_id = ?
                                   WHERE entry_id = ? AND trans_id = ?},
                                $chart_new_cid, $item_entry_id, $id );
                        }
                        $dbs->commit;
                        1;
                    };
                    if ( !$ok_run ) {
                        my $e = $@ || 'Unknown error';
                        $c->app->log->error("batch/update gl line entry_id=$item_entry_id: $e");
                        eval { $dbs->rollback };
                        $batch_add_result->( id => $id, ok => 0, error => 'Update failed.' );
                        next ITEM;
                    }
                    $batch_add_result->( id => $id, ok => 1, error => undef );
                    next ITEM;
                }

                my %gl_set;
                my $need_acc_trans_td;
                my $dept_changed;
                my $project_changed;
                my $project_set_val;

                if ( exists $it->{transdate} ) {
                    my $nd = $it->{transdate};
                    unless ( defined $nd && $nd =~ /^\d{4}-\d{2}-\d{2}$/ ) {
                        $batch_add_result->( id => $id, ok => 0, error => 'Invalid transdate format.' );
                        next ITEM;
                    }
                    if ( my $err = $c->batch_date_must_be_after_closed_period($nd) ) {
                        $batch_add_result->( id => $id, ok => 0, error => $err );
                        next ITEM;
                    }
                    $gl_set{transdate} = $nd;
                    $need_acc_trans_td = 1;
                }

                if ( exists $it->{department_id} ) {
                    my $did = $it->{department_id};
                    if ( defined $did && $did ne '' ) {
                        unless ( $did =~ /^\d+$/ && $did > 0 ) {
                            $batch_add_result->( id => $id, ok => 0, error => 'Invalid department_id.' );
                            next ITEM;
                        }
                        $did += 0;
                        unless ( $dbs->query( 'SELECT id FROM department WHERE id = ?', $did )->hash ) {
                            $batch_add_result->( id => $id, ok => 0, error => 'Department not found.' );
                            next ITEM;
                        }
                        $gl_set{department_id} = $did;
                    }
                    else {
                        $gl_set{department_id} = 0;
                    }
                    $dept_changed = 1;
                }

                if ( exists $it->{project_id} ) {
                    my $pid = $it->{project_id};
                    if ( defined $pid && $pid ne '' ) {
                        unless ( $pid =~ /^\d+$/ && $pid > 0 ) {
                            $batch_add_result->( id => $id, ok => 0, error => 'Invalid project_id.' );
                            next ITEM;
                        }
                        $pid += 0;
                        unless ( $dbs->query( 'SELECT id FROM project WHERE id = ?', $pid )->hash ) {
                            $batch_add_result->( id => $id, ok => 0, error => 'Project not found.' );
                            next ITEM;
                        }
                        $project_set_val = $pid;
                    }
                    else {
                        $project_set_val = undef;
                    }
                    $project_changed = 1;
                }

                unless ( keys %gl_set || $project_changed ) {
                    $batch_add_result->( id => $id, ok => 0, error => 'No updatable fields provided.' );
                    next ITEM;
                }

                my $ok_run = eval {
                    $dbs->begin;
                    if ( keys %gl_set ) {
                        my @cols = keys %gl_set;
                        my $set  = join ', ', map { "$_ = ?" } @cols;
                        $dbs->query( "UPDATE gl SET $set WHERE id = ?", ( @gl_set{@cols} ), $id );
                    }
                    if ($need_acc_trans_td) {
                        $dbs->query(
                            'UPDATE acc_trans SET transdate = ? WHERE trans_id = ?',
                            $gl_set{transdate}, $id );
                    }
                    if ($dept_changed) {
                        $dbs->query( 'DELETE FROM dpt_trans WHERE trans_id = ?', $id );
                        if ( ( $gl_set{department_id} // 0 ) > 0 ) {
                            $dbs->query(
                                q{INSERT INTO dpt_trans (trans_id, department_id) VALUES (?, ?)},
                                $id, $gl_set{department_id} );
                        }
                    }
                    if ($project_changed) {
                        $dbs->query(
                            'UPDATE acc_trans SET project_id = ? WHERE trans_id = ?',
                            $project_set_val, $id );
                    }
                    $dbs->commit;
                    1;
                };
                if ( !$ok_run ) {
                    my $e = $@ || 'Unknown error';
                    $c->app->log->error("batch/update gl id=$id: $e");
                    eval { $dbs->rollback };
                    $batch_add_result->( id => $id, ok => 0, error => 'Update failed.' );
                    next ITEM;
                }
                $batch_add_result->( id => $id, ok => 1, error => undef );
            }
        }

        $c->render( json => { results => \@results } );
    }
);

$api->post(
    '/batch/delete' => sub {
        my $c    = shift;
        my $body = $c->req->json;
        unless ( ref($body) eq 'HASH' ) {
            return $c->render(
                status => 400,
                json   => { error => 'JSON object body required.' }
            );
        }
        my $module = $body->{module} // '';
        unless ( $module =~ /^(ap|gl)$/ ) {
            return $c->render(
                status => 400,
                json   => { error => 'Invalid module. Use ap or gl.' }
            );
        }
        my $granularity = $body->{granularity} // '';
        unless ( $granularity eq 'transaction' ) {
            return $c->render(
                status => 400,
                json   => {
                    error =>
                      'Invalid granularity. Only transaction is supported for batch delete.',
                }
            );
        }
        my $form;
        if ( $module eq 'gl' ) {
            return unless $form = $c->check_perms("ledger.batchupdate");
        }
        else {
            return unless $form = $c->check_perms("vendor.batchupdate");
        }

        my $ids_in = $body->{ids};
        unless ( ref($ids_in) eq 'ARRAY' && @$ids_in ) {
            return $c->render(
                status => 400,
                json   => { error => 'ids must be a non-empty array.' }
            );
        }

        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);
        my @results;
        my %seen_id;

        for my $raw_id (@$ids_in) {
            unless ( defined $raw_id && $raw_id =~ /^\d+$/ && $raw_id > 0 ) {
                push @results,
                  {
                    id    => undef,
                    ok    => 0,
                    error => 'Each id must be a positive integer.',
                  };
                next;
            }
            my $id = $raw_id + 0;
            if ( $seen_id{$id}++ ) {
                push @results,
                  {
                    id    => $id,
                    ok    => 0,
                    error => 'Duplicate id in request.',
                  };
                next;
            }

            if ( $module eq 'ap' ) {
                my $row = $dbs->query(
                    q{SELECT id, transdate FROM ap WHERE id = ?},
                    $id
                )->hash;
                unless ($row) {
                    push @results,
                      {
                        id    => $id,
                        ok    => 0,
                        error => 'AP transaction not found.',
                      };
                    next;
                }

                my $cutoff = $c->batch_transdate_exclusive_min;
                if ($cutoff) {
                    my $old_td = $row->{transdate};
                    $old_td =~ s/\s.*//s if defined $old_td;
                    $old_td = format_date($old_td) if defined $old_td;
                    unless ( defined $old_td
                        && $old_td =~ /^\d{4}-\d{2}-\d{2}$/
                        && $old_td gt $cutoff )
                    {
                        push @results,
                          {
                            id    => $id,
                            ok    => 0,
                            error =>
                              'Transaction is in the closed period and cannot be modified.',
                          };
                        next;
                    }
                }

                $form->{id} = $id;
                $form->{vc} = 'vendor';
                my $ok_del = eval { AA->delete_transaction( $c->slconfig, $form ); 1 };
                delete $form->{glid};
                if ( !$ok_del ) {
                    my $e = $@ || 'Unknown error';
                    $c->app->log->error("batch/delete ap id=$id: $e");
                    push @results,
                      { id => $id, ok => 0, error => 'Delete failed.' };
                    next;
                }
                push @results, { id => $id, ok => 1, error => undef };
                next;
            }

            # GL — same steps as DELETE /gl/transactions/:id
            my $grow = $dbs->query( q{SELECT id, transdate FROM gl WHERE id = ?}, $id )
              ->hash;
            unless ($grow) {
                push @results,
                  {
                    id    => $id,
                    ok    => 0,
                    error => 'GL transaction not found.',
                  };
                next;
            }

            my $cutoff_gl = $c->batch_transdate_exclusive_min;
            if ($cutoff_gl) {
                my $old_td = $grow->{transdate};
                $old_td =~ s/\s.*//s if defined $old_td;
                $old_td = format_date($old_td) if defined $old_td;
                unless ( defined $old_td
                    && $old_td =~ /^\d{4}-\d{2}-\d{2}$/
                    && $old_td gt $cutoff_gl )
                {
                    push @results,
                      {
                        id    => $id,
                        ok    => 0,
                        error =>
                          'Transaction is in the closed period and cannot be modified.',
                      };
                    next;
                }
            }

            $form->{id} = $id;
            my $ok_gl = eval {
                GL->delete_transaction( $c->slconfig, $form );
                FM->delete_files( $dbs, $c, $form );
                $dbs->query( "DELETE FROM gl WHERE id = ?", $id );
                $dbs->query(
q{UPDATE bank_transactions SET reference_id = null, rule_id = null, module = null WHERE reference_id = ?},
                    $id
                );
                1;
            };
            delete $form->{apid};
            if ( !$ok_gl ) {
                my $e = $@ || 'Unknown error';
                $c->app->log->error("batch/delete gl id=$id: $e");
                push @results, { id => $id, ok => 0, error => 'Delete failed.' };
                next;
            }
            push @results, { id => $id, ok => 1, error => undef };
        }

        $c->render( json => { results => \@results } );
    }
);

#Get An Individual GL transaction
$api->get(
    '/gl/transactions/:id' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("gl.add");
        my $id     = $c->param('id');
        my $client = $c->param('client');

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
                $new_line{linetaxamount} = $line->{linetaxamount} * 1;

                $new_line{accno} = $line->{accno};
                $new_line{taxAccount} =
                  $line->{tax_chart_id} == 0
                  ? undef
                  : $line->{tax_chart_id};
                $new_line{cleared} = $line->{cleared};
                $new_line{memo}    = $line->{memo};
                $new_line{source}  = $line->{source};
                $new_line{project} = $line->{project_id} || undef;

                # Modify fx_transaction assignment based on fx_transaction value
                $new_line{fx_transaction} =
                  $line->{fx_transaction} == 1 ? \1 : \0;

                $line = \%new_line;
            }
        }

        my $files = FM->get_files( $dbs, $c, $form );

        my $offset_account_id =
          $dbs->query( "SELECT offset_account_id FROM gl WHERE id = ?",
            $form->{id} )->list;
        my $offset_accno = $dbs->query( "SELECT accno FROM chart WHERE id = ?",
            $offset_account_id )->list;
        my $offset_tax_id =
          $dbs->query( "SELECT offset_tax_id FROM gl WHERE id = ?",
            $form->{id} )->list;
        my $offset_tax_accno = undef;
        if ($offset_tax_id) {
            $offset_tax_accno = $dbs->query(
"SELECT c.accno FROM tax t JOIN chart c ON c.id = t.chart_id WHERE t.id = ?",
                $offset_tax_id
            )->list;
        }
        my $response = {
            id               => $form->{id},
            reference        => $form->{reference},
            approved         => $form->{approved},
            ts               => $form->{ts},
            curr             => $form->{curr},
            description      => $form->{description},
            notes            => $form->{notes},
            department       => $form->{department},
            department_id    => $form->{department_id},
            transdate        => $form->{transdate},
            ts               => $form->{ts},
            exchangeRate     => $form->{exchangerate},
            employeeId       => $form->{employee_id},
            lines            => \@lines,
            files            => $files,
            offset_accno     => $offset_accno,
            offset_tax_accno => $offset_tax_accno,
            pending          => $form->{approved}    ? 0 : 1,
            taxincluded      => $form->{taxincluded} ? 1 : 0
        };

        $c->render( status => 200, json => $response );
    }
);

$api->post(
    '/gl/transactions' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("gl.add");
        my $client = $c->param('client');

        my $data;
        my $content_type = $c->req->headers->content_type || '';

        if ( $content_type =~ m!multipart/form-data!i ) {
            $data = handle_multipart_request($c);
        }
        else {
            $data = $c->req->json;
            if ( ref $data->{files} eq 'ARRAY' ) {
                $data->{files} = $c->decode_base64_files( $data->{files} );
            }
        }

        $data->{form} = $form;
        my $dbs = $c->dbs($client);
        my ( $status_code, $response_json ) =
          $c->api_gl_transaction( $dbs, $data );

        $c->render(
            status => $status_code,
            json   => { id => $response_json->{id} },
        );
    }
);

$api->put(
    '/gl/transactions/:id' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("gl.add");
        my $client = $c->param('client');
        my $id     = $c->param('id');

        my $data;
        my $content_type = $c->req->headers->content_type || '';

        if ( $content_type =~ m!multipart/form-data!i ) {
            $data = handle_multipart_request($c);
        }
        else {
            $data = $c->req->json;
            if ( ref $data->{files} eq 'ARRAY' ) {
                $data->{files} = $c->decode_base64_files( $data->{files} );
            }
        }

        $data->{form} = $form;
        my $dbs = $c->dbs($client);

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
        my ( $status_code, $response_json ) =
          $c->api_gl_transaction( $dbs, $data, $id );

        $c->render(
            status => $status_code,
            json   => { id => $response_json->{id} },
        );
    }
);

# Function to handle multipart form data
sub handle_multipart_request {
    my ($c) = @_;

    my $params = $c->req->params->to_hash;
    my $data   = {};

    # Copy all parameters to data hash (except files)
    foreach my $key ( keys %$params ) {
        next if $key eq 'files';    # Skip file field, handle separately

        # Decode UTF-8 data first before comparing
        my $param_value = $params->{$key};
        if ( defined $param_value ) {
            $param_value = decode( 'UTF-8', $param_value, Encode::FB_DEFAULT );
        }

        if ( defined $param_value && $param_value ne '' ) {
            $data->{$key} = $param_value;
        }
    }

    # Parse JSON fields
    for my $field (qw(lines payments taxes shipto)) {
        if ( defined $params->{$field} && $params->{$field} ne '' ) {

            my $json_text =
              decode( 'UTF-8', $params->{$field}, Encode::FB_CROAK );
            $data->{$field} = decode_json($json_text);
        }
    }

    # Handle file uploads if present
    if ( $c->param('files') ) {
        $data->{files} = $c->req->every_upload('files');
    }

    return $data;
}

helper decode_base64_files => sub {
    my ( $c, $file_array ) = @_;
    return [] unless ref $file_array eq 'ARRAY';
    use File::Temp qw(tempfile);
    my @uploads;
    for my $entry (@$file_array) {
        next unless ref $entry eq 'HASH' && $entry->{data} && $entry->{name};

        # Parse data URI: data:<MIME>;base64,<base64>
        my ( $mime, $base64 ) =
          $entry->{data} =~ m{^data:([^;]+);base64,(.+)$}i;
        next unless $mime && $base64;

        my $decoded = eval { decode_base64($base64) };
        next unless defined $decoded;

        # Write to temporary file
        my ( $fh, $filename ) = tempfile();
        binmode $fh;
        print $fh $decoded;
        seek $fh, 0, 0;

        # Create upload-like object
        my $upload = Mojo::Upload->new(
            asset    => Mojo::Asset::File->new( path => $filename ),
            filename => $entry->{name},
            headers  => Mojo::Headers->new( content_type => $mime ),
        );

        push @uploads, $upload;
    }

    return \@uploads;
};

helper dump_file => sub {
    my ( $c, $object, $filename ) = @_;

    # Use Data::Dumper to create a readable dump of the object
    use Data::Dumper;
    local $Data::Dumper::Indent   = 1;
    local $Data::Dumper::Sortkeys = 1;
    local $Data::Dumper::Terse    = 0;

    # Create the dump content
    my $dump_content = Dumper($object);

    # Use the provided filename or default to 'dump.txt'
    $filename ||= 'dump.txt';

    # Write the dump to file
    eval {
        open( my $fh, '>', $filename )
          or die "Cannot open file '$filename' for writing: $!";
        print $fh $dump_content;
        close($fh);
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        return {
            success => 0,
            error   => "Failed to write dump file: $error"
        };
    };

    return {
        success  => 1,
        message  => "Object dumped to '$filename' successfully",
        filename => $filename
    };
};

sub calc_line_tax {
    my ( $dbs, $date, $amount, $accno ) = @_;

    # Fetch the chart.id for this accno
    my ($chart_id) =
      $dbs->query( "SELECT id FROM chart WHERE accno = ?", $accno )->list;

    return 0 unless defined $chart_id;

    # Now find the rate effective at or before $date.
    # We treat NULL validto as "still valid" and sort NULL as the latest.
    my ($rate) = $dbs->query(
        q{
          SELECT rate
            FROM tax    
           WHERE chart_id = ?
             AND (validto IS NULL OR validto >= ?)
        ORDER BY
             COALESCE(validto, '9999-12-31') ASC
           LIMIT 1
        }, $chart_id, $date
    )->list;

    $rate ||= 0;

    return $amount * $rate;
}

helper api_gl_transaction => sub {
    my ( $c, $dbs, $data, $id, $dbh ) = @_;

    # Check if 'transdate' is present in the data
    unless ( exists $data->{transdate} ) {
        return ( 400, { message => "The 'transdate' field is required." } );
    }

    my $transdate = $data->{transdate};

    # Validate 'transdate' format (ISO date format)
    unless ( $transdate =~ /^\d{4}-\d{2}-\d{2}$/ ) {
        return (
            400,
            {
                message =>
"Invalid 'transdate' format. Expected ISO 8601 date format (YYYY-MM-DD)."
            }
        );
    }

    # Check if 'lines' is present and is an array reference
    unless ( exists $data->{lines} && ref $data->{lines} eq 'ARRAY' ) {
        return ( 400, { message => "The 'lines' array is required." } );
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
        return ( 400, { message => "The specified currency does not exist." } );
    }

 # If the provided currency is not the default currency, check for exchange rate
    my $row = $result->hash;
    if ( $row->{curr} ne $default_currency
        && !exists $data->{exchangeRate} )
    {
        return (
            400,
            {
                message =>
"A non-default currency has been used. Exchange rate is required."
            }
        );
    }

    # Create a new form
    my $form = $data->{form};

    if ($id) {
        $form->{id} = $id;
    }
    else {
        $form->{id} = '';
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
    $form->{department}      = $data->{department};
    $form->{transdate}       = $transdate;
    $form->{defaultcurrency} = $default_currency;
    $form->{pending}         = $data->{pending} ? 1 : 0;
    $form->{login}           = $data->{login};
    $form->{taxincluded}     = $data->{taxincluded} ? 1 : 0;

    my $total_debit       = 0;
    my $total_credit      = 0;
    my $i                 = 1;
    my $offset_accno      = $data->{offset_accno};
    my $offset_account_id = undef;
    my $offset_tax_accno  = $data->{offset_tax_accno};
    my $offset_tax_id     = undef;

    # Validate offset account if provided
    if ($offset_accno) {
        my $offset_acc_result =
          $dbs->query( "SELECT id from chart WHERE accno = ?", $offset_accno );
        unless ( $offset_acc_result->rows ) {
            return (
                400,
                {
                    message =>
"Offset account with the accno $offset_accno does not exist."
                }
            );
        }
        $offset_account_id = $offset_acc_result->hash->{id};
    }

# Validate offset tax account if provided (resolve accno -> tax id at transdate)
    if ($offset_tax_accno) {
        my $offset_tax_result = $dbs->query(
            q{
              SELECT t.id
                FROM tax t
                JOIN chart c ON c.id = t.chart_id
               WHERE c.accno = ?
                 AND (t.validto IS NULL OR t.validto >= ?)
            ORDER BY COALESCE(t.validto, '9999-12-31') ASC
               LIMIT 1
            },
            $offset_tax_accno,
            $transdate
        );
        unless ( $offset_tax_result->rows ) {
            return (
                400,
                {
                    message =>
"Offset tax account with the accno $offset_tax_accno does not exist or has no tax effective at transdate."
                }
            );
        }
        $offset_tax_id = $offset_tax_result->hash->{id};
    }

    foreach my $line ( @{ $data->{lines} } ) {

        my $acc_id =
          $dbs->query( "SELECT id from chart WHERE accno = ?", $line->{accno} );

        if ( !$acc_id ) {
            return (
                400,
                {
                        message => "Account with the accno "
                      . $line->{accno}
                      . " does not exist."
                }
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
        $form->{"projectnumber_$i"} = $line->{project};

        if ( $line->{taxAccount} && !$line->{linetaxamount} ) {
            my $amount = $line->{debit} || $line->{credit};
            my $tax_amount =
              calc_line_tax( $dbs, $transdate, $amount, $line->{taxAccount} );
            $form->{"linetaxamount_$i"} = $tax_amount;
        }

# Add offset line if offset_accno is provided and this line has a debit or credit amount
        if (
            $offset_accno
            && (   ( $line->{debit} && $line->{debit} > 0 )
                || ( $line->{credit} && $line->{credit} > 0 ) )
          )
        {
            $i++;
            my $amount = $line->{debit} || $line->{credit};

            if ( $line->{debit} && $line->{debit} > 0 ) {

                # Original line has debit, so offset line gets credit
                $form->{"debit_$i"}  = 0;
                $form->{"credit_$i"} = $amount;
            }
            else {
                # Original line has credit, so offset line gets debit
                $form->{"debit_$i"}  = $amount;
                $form->{"credit_$i"} = 0;
            }

            $form->{"accno_$i"} = $offset_accno;
            if ($offset_tax_accno) {
                $form->{"tax_$i"} = $offset_tax_accno;
                $form->{"linetaxamount_$i"} =
                  calc_line_tax( $dbs, $transdate, $amount, $offset_tax_accno );
            }
            else {
                $form->{"tax_$i"}           = 0;
                $form->{"linetaxamount_$i"} = 0;
            }
            $form->{"cleared_$i"}       = $line->{cleared};
            $form->{"memo_$i"}          = $line->{memo};
            $form->{"source_$i"}        = $line->{source};
            $form->{"projectnumber_$i"} = $line->{project};
        }

        $i++;
    }

    # Check if total_debit equals total_credit
    unless ( $total_debit == $total_credit ) {
        return (
            400,
            {
                message =>
"Total Debits ($total_debit) must equal Total Credits ($total_credit)."
            }
        );
    }

    # Adjust row count based on the counter
    $form->{rowcount} = $i - 1;

    # seperate calls with dbh is needed to account for import
    if ($dbh) {
        $id = GL->post_transaction( $c->slconfig, $form, $dbs );
        $dbh->commit;
    }
    else {
        $id = GL->post_transaction( $c->slconfig, $form );
    }

    if ( $form->{id} ) {
        my $update_sql =
          "UPDATE gl SET offset_account_id = ?, offset_tax_id = ? WHERE id = ?";
        $dbs->query( $update_sql, $offset_account_id, $offset_tax_id,
            $form->{id} );

        my @sources =
          map { $_->{source} } grep { $_->{source} } @{ $data->{lines} };

        if (@sources) {
            my $placeholders = join( ", ", ("?") x @sources );

            my ($any_pending) = $dbs->query(
"SELECT bool_or(pending) FROM bank_transactions WHERE transaction_id IN ($placeholders)",
                @sources
            )->list;

            if ($any_pending) {
                $dbs->query(
                    "UPDATE acc_trans SET approved = false WHERE trans_id = ?",
                    $form->{id}
                );
            }
        }
    }

    if ( $data->{files} && ref $data->{files} eq 'ARRAY' ) {
        $form->{files}  = $data->{files};
        $form->{client} = $c->param('client');
        FM->upload_files( $dbs, $c, $form, 'gl' );
    }

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
        department   => $form->{department},
        offset_accno => $offset_accno,
        lines        => []
    };

    # Add file information to response if files were uploaded
    if ( $form->{files} && ref $form->{files} eq 'ARRAY' ) {
        $response_json->{files} = $form->{files};
    }

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

    my $status_code = $id ? 200 : 201;    # 200 for update, 201 for create

    return ( $status_code, $response_json );
};
$api->post(
    '/import/:type' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $type   = $c->param('type');
        return unless my $form = $c->check_perms("import.$type");

        # Get request body as JSON
        my $json = $c->req->json;

        if ( $type eq 'gl' ) {

            # Check if JSON payload is an array
            unless ( ref $json eq 'ARRAY' ) {
                $c->render(
                    json => { error => "Expected JSON array of transactions" },
                    status => 400
                );
                return;
            }

            my $dbs                 = $c->dbs($client);
            my $success_count       = 0;
            my $failed_count        = 0;
            my @failed_transactions = ();
            my @added_transactions  = ();

            # Process each transaction in the array
            foreach my $transaction (@$json) {

                # Set the form object for api_gl_transaction
                $transaction->{form} = $form;

                my $dbh = $form->dbconnect_noauto( $c->slconfig );

                # Call api_gl_transaction for each item in the array
                my ( $status_code, $response_json ) =
                  $c->api_gl_transaction( $dbs, $transaction, $dbh );

                if ( $status_code >= 200 && $status_code < 300 ) {
                    $success_count++;
                    push @added_transactions, $response_json;
                }
                else {
                    $failed_count++;
                    push @failed_transactions,
                      {
                        transaction => $transaction,
                        error => $response_json->{message} || "Unknown error"
                      };
                }
            }

            my $status_code = 200;
            if ( $failed_count > 0 && $success_count > 0 ) {
                $status_code = 207;    # Partial success
            }
            elsif ( $failed_count > 0 && $success_count == 0 ) {
                $status_code = 400;    # Complete failure
            }

            $c->render(
                json => {
                    success => $success_count > 0 ? 1 : 0,
                    added   => \@added_transactions,
                    failed  => \@failed_transactions,
                    counts  => {
                        success => $success_count,
                        failed  => $failed_count
                    }
                },
                status => $status_code
            );
        }
        else {
            $c->render(
                json   => { error => "Import type '$type' is not supported" },
                status => 400
            );
        }
    }
);

$api->delete(
    '/gl/transactions/:id' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("gl.add");
        my $client = $c->param('client');
        my $id     = $c->param('id');

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
        $form->{id} = $id;

        # Delete the transaction
        GL->delete_transaction( $c->slconfig, $form );
        FM->delete_files( $dbs, $c, $form );

        # Delete the entry from the gl table
        $dbs->query( "DELETE FROM gl WHERE id = ?", $id );
        $dbs->query(
"UPDATE bank_transactions SET reference_id = null, rule_id = null, module = null WHERE reference_id = ?",
            $id
        );

        $c->render( status => 204, data => '' );
    }
);

#########################
####                 ####
####      Chart      ####
####                 ####
#########################
### ROUTE TO BE REMOVED AND REPLACED WITH GET LINKS

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

###############################
####                       ####
####    System Settings    ####
####                       ####
###############################

$api->get(
    '/system/currencies' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.currencies");
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
        my $c = shift;
        return unless my $form = $c->check_perms("system.currencies");
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

        $form->{curr} = $curr;
        $form->{prec} = $prec;
        AM->save_currency( $c->slconfig, $form );

        return $c->render(
            status => 201,
            json   => { message => 'Currency created successfully' }
        );
    }
);

$api->delete(
    '/system/currencies/:curr' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.currencies");
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
        $form->{curr} = $curr;

        # Call the delete method from AM module
        AM->delete_currency( $c->slconfig, $form );

        # Return no content (204)
        return $c->render( status => 204, data => '' );
    }
);

# Suggested exchange rate (foreign -> CHF) from Swiss BAZG monthly average.
# Base currency must be CHF. Requires gl.transaction, customer.transaction or vendor.transaction.
$api->get(
    '/get_exchange_rate' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("gl.transaction, customer.transaction, vendor.transaction");
        my $client   = $c->param('client');
        my $currency = $c->param('currency');
        my $transdate = $c->param('transdate');

        unless ( $currency && $transdate ) {
            return $c->render(
                status => 400,
                json   => { message => "Missing required parameters: currency and transdate" }
            );
        }

        my $dbs = $c->dbs($client);
        my $base_row = $dbs->query("SELECT curr FROM curr WHERE rn = 1")->hash;
        unless ( $base_row && uc( $base_row->{curr} // '' ) eq 'CHF' ) {
            return $c->render(
                status => 400,
                json   => { message => "Exchange rate is only available when base currency is CHF" }
            );
        }

        my $curr_uc = uc($currency);
        if ( $curr_uc eq 'CHF' ) {
            return $c->render(
                status => 400,
                json   => { message => "Currency must not be CHF when base is CHF" }
            );
        }

        my ( $y, $m ) = ( $transdate =~ /^(\d{4})-(\d{2})/ );
        unless ( $y && $m ) {
            return $c->render(
                status => 400,
                json   => { message => "transdate must be in YYYY-MM-DD format" }
            );
        }

        my $url = "https://www.backend-rates.bazg.admin.ch/api/xmlavgmonth?j=$y&m=$m";
        my $ua  = Mojo::UserAgent->new;
        my $tx  = $ua->get($url);
        unless ( $tx->res->is_success ) {
            return $c->render(
                status => 502,
                json   => { message => "Failed to fetch exchange rate from provider" }
            );
        }
        my $xml = $tx->res->body;
        unless ( defined $xml && $xml ne '' ) {
            return $c->render(
                status => 502,
                json   => { message => "Empty response from exchange rate provider" }
            );
        }

        my $curr_lc = lc($curr_uc);
        unless ( $xml =~ /<devise\s+code="\Q$curr_lc\E"/ ) {
            return $c->render(
                status => 404,
                json   => { message => "Exchange rate not found for currency: $currency" }
            );
        }

        my ($kurs) = $xml =~ /<devise\s+code="\Q$curr_lc\E"[^>]*>.*?<kurs>([\d.]+)<\/kurs>/s;
        my ($waehrung) = $xml =~ /<devise\s+code="\Q$curr_lc\E"[^>]*>.*?<waehrung>([^<]*)<\/waehrung>/s;
        unless ( defined $kurs && $kurs ne '' && $kurs != 0 ) {
            return $c->render(
                status => 502,
                json   => { message => "Invalid or missing rate data for currency: $currency" }
            );
        }
        my $multiplier = 1;
        $multiplier = $1 if defined $waehrung && $waehrung =~ /^(\d+)/;
        $multiplier = 1 if $multiplier < 1;
        my $rate = $kurs / $multiplier;

        $c->render( json => { exchange_rate => $rate, currency => $curr_uc, transdate => $transdate } );
    }
);

$api->get(
    '/system/languages' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.messages");
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);

        my $languages;
        eval {
            $languages = $dbs->query(
                "SELECT code, description FROM language ORDER BY code")->hashes;
        };

        if ($@) {
            return $c->render(
                status => 500,
                json   =>
                  { error => { message => 'Failed to retrieve languages' } }
            );
        }

        $c->render( json => $languages );
    }
);

$api->post(
    '/system/languages' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.messages");
        my $client = $c->param('client');

        my $params = $c->req->json;
        my $code   = ref($params) eq 'HASH' ? $params->{code} : undef;
        my $description =
          ref($params) eq 'HASH' ? $params->{description} : undef;
        $code        = '' unless defined $code;
        $description = '' unless defined $description;

        if ( length($code) < 1 || length($code) > 6 ) {
            return $c->render(
                status => 400,
                json   => {
                    error =>
                      { message => 'code must be between 1 and 6 characters' }
                }
            );
        }

        my $dbs = $c->dbs($client);

        eval {
            $dbs->query(
                "INSERT INTO language (code, description) VALUES (?, ?) "
                  . "ON CONFLICT (code) DO UPDATE SET description = EXCLUDED.description",
                $code, $description
            );
        };

        if ($@) {
            return $c->render(
                status => 500,
                json   => { error => { message => 'Failed to save language' } }
            );
        }

        return $c->render(
            status => 201,
            json   => { message => 'Language saved successfully' }
        );
    }
);

$api->get(
    '/system/messages' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.messages");
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);
        my $params = $c->req->params->to_hash;

        my @where;
        my @binds;
        if ( defined $params->{message_type} && $params->{message_type} ne '' )
        {
            push @where, "message_type = ?";
            push @binds, $params->{message_type};
        }
        if ( defined $params->{language_code}
            && $params->{language_code} ne '' )
        {
            push @where, "language_code = ?";
            push @binds, $params->{language_code};
        }
        if ( defined $params->{trans_id} && $params->{trans_id} =~ /^\d+$/ ) {
            push @where, "trans_id = ?";
            push @binds, $params->{trans_id};
        }

        my $sql =
"SELECT id, message_type, language_code, content, trans_id FROM messages";
        $sql .= " WHERE " . join( " AND ", @where ) if @where;
        $sql .= " ORDER BY id";

        my $messages;
        eval {
            $messages =
                @binds
              ? $dbs->query( $sql, @binds )->hashes
              : $dbs->query($sql)->hashes;
        };

        if ($@) {
            return $c->render(
                status => 500,
                json   =>
                  { error => { message => 'Failed to retrieve messages' } }
            );
        }

        $c->render( json => $messages );
    }
);

$api->post(
    '/system/messages' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.messages");
        my $client = $c->param('client');

        my $params = $c->req->json;
        $params = {} unless ref($params) eq 'HASH';

        my $id            = $params->{id};
        my $message_type  = $params->{message_type}  // '';
        my $language_code = $params->{language_code} // '';
        my $content       = $params->{content};
        my $trans_id      = $params->{trans_id};

        $content  = '' unless defined $content;
        $trans_id = undef if defined $trans_id && $trans_id eq '';

        if ( length($message_type) < 1 || length($message_type) > 255 ) {
            return $c->render(
                status => 400,
                json   => {
                    error => {
                        message =>
                          'message_type must be between 1 and 255 characters'
                    }
                }
            );
        }

        my $dbs = $c->dbs($client);

        if ( defined $id && $id =~ /^\d+$/ ) {
            my $exists =
              $dbs->query( "SELECT 1 FROM messages WHERE id = ?", $id )->array;
            if ( $exists && $exists->[0] ) {
                eval {
                    $dbs->query(
"UPDATE messages SET message_type = ?, language_code = ?, content = ?, trans_id = ? WHERE id = ?",
                        $message_type, $language_code, $content, $trans_id,
                        $id );
                };
                if ($@) {
                    return $c->render(
                        status => 500,
                        json   => {
                            error => { message => 'Failed to update message' }
                        }
                    );
                }
                return $c->render(
                    status => 200,
                    json   => { message => 'Message updated successfully' }
                );
            }
        }

        eval {
            $dbs->query(
"INSERT INTO messages (message_type, language_code, content, trans_id) VALUES (?, ?, ?, ?)",
                $message_type, $language_code, $content, $trans_id );
        };

        if ($@) {
            return $c->render(
                status => 500,
                json   => { error => { message => 'Failed to create message' } }
            );
        }

        return $c->render(
            status => 201,
            json   => { message => 'Message created successfully' }
        );
    }
);

$api->get(
    '/system/companydefaults' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        return unless my $form = $c->check_perms("system.defaults");
        my $dbs = $c->dbs($client);

        $form = $c->get_defaults();

        # Query to check if linetaxamount is greater than 0 in any row
        my $lock_linetax_query = $dbs->query(
"SELECT EXISTS (SELECT 1 FROM acc_trans WHERE linetaxamount <> 0) AS locklinetax"
        );
        my $lock_linetax_result = $lock_linetax_query->hash;
        $form->{locklinetax} = $lock_linetax_result->{locklinetax} ? 1 : 0;
        use JSON;

  # Helper function to convert various boolean representations to proper boolean
        sub to_boolean {
            my $value = shift;
            return JSON::true
              if ( $value
                && ( $value eq "checked" || $value eq "1" || $value == 1 ) );
            return JSON::false;
        }

        my $all_accounts = $c->get_accounts($client);

        # Build the restructured response
        my %restructured_response = (
            company_info => {
                name    => $form->{company} || "",
                address => {
                    complete    => $form->{address}     || "",
                    street      => $form->{street}      || "",
                    post_office => $form->{post_office} || "",
                    line1       => $form->{address1}    || "",
                    line2       => $form->{address2}    || "",
                    city        => $form->{city}        || "",
                    state       => $form->{state}       || "",
                    zip         => $form->{zip}         || "",
                    country     => $form->{country}     || ""
                },
                contact => {
                    phone   => $form->{tel}            || "",
                    fax     => $form->{fax}            || "",
                    email   => $form->{companyemail}   || "",
                    website => $form->{companywebsite} || ""
                },
                business_number => $form->{businessnumber} || "",
                reference_url   => $form->{referenceurl}   || ""
            },

            settings => {

                # Financial Settings
                precision          => $form->{precision}        || "",
                annual_interest    => $form->{annualinterest}   || "",
                late_payment_fee   => $form->{latepaymentfee}   || "",
                restocking_charge  => $form->{restockingcharge} || "",
                round_change       => $form->{roundchange}      || "",
                weight_unit        => $form->{weightunit}       || "",
                clearing_account   => $form->{clearing}         || "",
                transition_account => $form->{transition}       || "",

                # System Settings (converted to proper booleans)
                reporting_method_cash =>
                  to_boolean( $form->{method} eq 'cash' ),
                check_inventory      => to_boolean( $form->{checkinventory} ),
                force_warehouse      => to_boolean( $form->{forcewarehouse} ),
                hide_closed_accounts => to_boolean( $form->{hideaccounts} ),
                line_tax             => to_boolean( $form->{linetax} ),
                sort_names_by_number => to_boolean( $form->{namesbynumber} ),
                xe_latex             => to_boolean( $form->{xelatex} ),
                type_of_contact      => $form->{typeofcontact} || "",
                paymentfile          => $form->{paymentfile}   || 0,
                term_days            => $form->{term_days}     || 0

            },

            account_defaults => {
                inventory_account_id    => $form->{inventory_accno_id} || undef,
                income_account_id       => $form->{income_accno_id}    || undef,
                expense_account_id      => $form->{expense_accno_id}   || undef,
                fx_gain_loss_account_id => $form->{fxgainloss_accno_id}
                  || undef,
                cash_over_short_account_id => $form->{cashovershort_accno_id}
                  || undef,
                ar_account_id  => $form->{ar_accno_id} || undef,
                ap_account_id  => $form->{ap_accno_id} || undef,
                ar_payment_id  => $form->{AR_paid}     || undef,
                ap_payment_id  => $form->{AP_paid}     || undef
            },

            number_sequences => {
                gl_reference => {
                    pattern => $form->{glnumber} || "",
                    locked  => to_boolean( $form->{lock_glnumber} )
                },
                sales_invoice => {
                    pattern => $form->{sinumber} || "",
                    locked  => to_boolean( $form->{lock_sinumber} )
                },
                sales_order => {
                    pattern => $form->{sonumber} || "",
                    locked  => to_boolean( $form->{lock_sonumber} )
                },
                vendor_invoice => {
                    pattern => $form->{vinumber} || "",
                    locked  => JSON::false    # No lock field found for vinumber
                },
                batch => {
                    pattern => $form->{batchnumber} || "",
                    locked  => JSON::false # No lock field found for batchnumber
                },
                voucher => {
                    pattern => $form->{vouchernumber} || "",
                    locked  =>
                      JSON::false    # No lock field found for vouchernumber
                },
                purchase_order => {
                    pattern => $form->{ponumber} || "",
                    locked  => to_boolean( $form->{lock_ponumber} )
                },
                sales_quotation => {
                    pattern => $form->{sqnumber} || "",
                    locked  => to_boolean( $form->{lock_sqnumber} )
                },
                rfq => {
                    pattern => $form->{rfqnumber} || "",
                    locked  => to_boolean( $form->{lock_rfqnumber} )
                },
                customer => {
                    pattern => $form->{customernumber} || "",
                    locked  => to_boolean( $form->{lock_customernumber} )
                },
                vendor => {
                    pattern => $form->{vendornumber} || "",
                    locked  => to_boolean( $form->{lock_vendornumber} )
                },
                employee => {
                    pattern => $form->{employeenumber} || "",
                    locked  => to_boolean( $form->{lock_employeenumber} )
                },
                part => {
                    pattern => $form->{partnumber} || "",
                    locked  => JSON::false  # No lock field found for partnumber
                },
                project => {
                    pattern => $form->{projectnumber} || "",
                    locked  =>
                      JSON::false    # No lock field found for projectnumber
                }
            },

            all_accounts => $all_accounts->{all}
        );

        # Check if per-DB SMTP is configured (password stored in connection_keys)
        my $smtp_key = $dbs->query(
            "SELECT fldvalue FROM connection_keys WHERE fldname = 'smtp_password'"
        )->hash;
        my $smtp_host = $form->{smtp_host} || '';
        $restructured_response{smtp} = {
            host     => $smtp_host,
            port     => $form->{smtp_port}     || '',
            username => $form->{smtp_username} || '',
            from_name => $form->{smtp_from_name} || '',
            ssl      => $form->{smtp_ssl}      || '',
            sasl     => $form->{smtp_sasl}     || '',
            active   => ( $smtp_key && $smtp_host ) ? JSON::true : JSON::false,
        };

        $c->render( json => \%restructured_response );
    }
);
$api->post(
    '/system/companydefaults' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.defaults");
        my $client = $c->param('client');

        my $json_data = $c->req->json;
        my $mapped_data = {};

        if ( $json_data->{company_info} ) {
            $mapped_data->{company} = $json_data->{company_info}->{name};
            $mapped_data->{businessnumber} =
              $json_data->{company_info}->{business_number};
            $mapped_data->{referenceurl} =
              $json_data->{company_info}->{reference_url};

            if ( $json_data->{company_info}->{address} ) {
                $mapped_data->{street} =
                  $json_data->{company_info}->{address}->{street};
                $mapped_data->{post_office} =
                  $json_data->{company_info}->{address}->{post_office};
                $mapped_data->{address} =
                  $json_data->{company_info}->{address}->{address};
                $mapped_data->{address1} =
                  $json_data->{company_info}->{address}->{line1};
                $mapped_data->{address2} =
                  $json_data->{company_info}->{address}->{line2};
                $mapped_data->{city} =
                  $json_data->{company_info}->{address}->{city};
                $mapped_data->{state} =
                  $json_data->{company_info}->{address}->{state};
                $mapped_data->{zip} =
                  $json_data->{company_info}->{address}->{zip};
                $mapped_data->{country} =
                  $json_data->{company_info}->{address}->{country};
            }

            if ( $json_data->{company_info}->{contact} ) {
                $mapped_data->{tel} =
                  $json_data->{company_info}->{contact}->{phone};
                $mapped_data->{fax} =
                  $json_data->{company_info}->{contact}->{fax};
                $mapped_data->{companyemail} =
                  $json_data->{company_info}->{contact}->{email};
                $mapped_data->{companywebsite} =
                  $json_data->{company_info}->{contact}->{website};
            }
        }

        if ( $json_data->{settings} ) {
            $mapped_data->{precision} = $json_data->{settings}->{precision};
            $mapped_data->{annualinterest} =
              $json_data->{settings}->{annual_interest};
            $mapped_data->{latepaymentfee} =
              $json_data->{settings}->{late_payment_fee};
            $mapped_data->{restockingcharge} =
              $json_data->{settings}->{restocking_charge};
            $mapped_data->{roundchange} =
              $json_data->{settings}->{round_change};
            $mapped_data->{weightunit} = $json_data->{settings}->{weight_unit};
            $mapped_data->{clearing} =
              $json_data->{settings}->{clearing_account};
            $mapped_data->{transition} =
              $json_data->{settings}->{transition_account};
            $mapped_data->{method} =
              $json_data->{settings}->{reporting_method_cash};
            $mapped_data->{checkinventory} =
              $json_data->{settings}->{check_inventory};
            $mapped_data->{forcewarehouse} =
              $json_data->{settings}->{force_warehouse};
            $mapped_data->{hideaccounts} =
              $json_data->{settings}->{hide_closed_accounts};
            $mapped_data->{linetax} = $json_data->{settings}->{line_tax};
            $mapped_data->{namesbynumber} =
              $json_data->{settings}->{sort_names_by_number};
            $mapped_data->{xelatex} = $json_data->{settings}->{xe_latex};
            $mapped_data->{typeofcontact} =
              $json_data->{settings}->{type_of_contact};
            $mapped_data->{paymentfile} = $json_data->{settings}->{paymentfile};
            $mapped_data->{term_days}   = $json_data->{settings}->{term_days};
        }

 # Map account defaults (these appear to be ID values only in the old structure)
        if ( $json_data->{account_defaults} ) {
            $mapped_data->{IC} =
              $json_data->{account_defaults}->{inventory_account_id};
            $mapped_data->{IC_income} =
              $json_data->{account_defaults}->{income_account_id};
            $mapped_data->{IC_expense} =
              $json_data->{account_defaults}->{expense_account_id};
            $mapped_data->{fxgainloss} =
              $json_data->{account_defaults}->{fx_gain_loss_account_id};
            $mapped_data->{cashovershort} =
              $json_data->{account_defaults}->{cash_over_short_account_id};
            $mapped_data->{AR} =
              $json_data->{account_defaults}->{ar_account_id};
            $mapped_data->{AP} =
              $json_data->{account_defaults}->{ap_account_id};
            $mapped_data->{AR_paid} =
              $json_data->{account_defaults}->{ar_payment_id};
            $mapped_data->{AP_paid} =
              $json_data->{account_defaults}->{ap_payment_id};
        }

        # Map number sequences
        if ( $json_data->{number_sequences} ) {
            my $sequences = $json_data->{number_sequences};

            # Map patterns
            $mapped_data->{glnumber} = $sequences->{gl_reference}->{pattern};
            $mapped_data->{sinumber} = $sequences->{sales_invoice}->{pattern};
            $mapped_data->{sonumber} = $sequences->{sales_order}->{pattern};
            $mapped_data->{vinumber} = $sequences->{vendor_invoice}->{pattern};
            $mapped_data->{batchnumber}   = $sequences->{batch}->{pattern};
            $mapped_data->{vouchernumber} = $sequences->{voucher}->{pattern};
            $mapped_data->{ponumber} = $sequences->{purchase_order}->{pattern};
            $mapped_data->{sqnumber} = $sequences->{sales_quotation}->{pattern};
            $mapped_data->{rfqnumber}      = $sequences->{rfq}->{pattern};
            $mapped_data->{partnumber}     = $sequences->{part}->{pattern};
            $mapped_data->{projectnumber}  = $sequences->{project}->{pattern};
            $mapped_data->{employeenumber} = $sequences->{employee}->{pattern};
            $mapped_data->{customernumber} = $sequences->{customer}->{pattern};
            $mapped_data->{vendornumber}   = $sequences->{vendor}->{pattern};

            # Map locked flags
            $mapped_data->{lock_glnumber} =
              $sequences->{gl_reference}->{locked};
            $mapped_data->{lock_sinumber} =
              $sequences->{sales_invoice}->{locked};
            $mapped_data->{lock_sonumber} = $sequences->{sales_order}->{locked};
            $mapped_data->{lock_ponumber} =
              $sequences->{purchase_order}->{locked};
            $mapped_data->{lock_sqnumber} =
              $sequences->{sales_quotation}->{locked};
            $mapped_data->{lock_rfqnumber} = $sequences->{rfq}->{locked};
            $mapped_data->{lock_employeenumber} =
              $sequences->{employee}->{locked};
            $mapped_data->{lock_customernumber} =
              $sequences->{customer}->{locked};
            $mapped_data->{lock_vendornumber} = $sequences->{vendor}->{locked};
        }

        # Handle SMTP settings
        my $smtp_data = $json_data->{smtp} // {};

        if ( $smtp_data->{host} || $smtp_data->{username} ) {
            $mapped_data->{smtp_host}      = $smtp_data->{host}      // '';
            $mapped_data->{smtp_port}      = $smtp_data->{port}      // '';
            $mapped_data->{smtp_username}  = $smtp_data->{username}  // '';
            $mapped_data->{smtp_from_name} = $smtp_data->{from_name} // '';
            $mapped_data->{smtp_ssl}       = $smtp_data->{ssl}       // '';
            $mapped_data->{smtp_sasl}      = $smtp_data->{sasl}      // '';
        }

        if ( my $err = _test_and_save_smtp_password( $c, $client, $smtp_data ) ) {
            return $c->render( status => $err->{status}, json => $err );
        }

        # Transfer mapped data to form object
        foreach my $key ( keys %$mapped_data ) {
            $form->{$key} = $mapped_data->{$key};
        }

        $form->{optional} =
"company street post_office address address1 address2 city state zip country tel fax companyemail companywebsite yearend weightunit businessnumber closedto revtrans audittrail method cdt namesbynumber xelatex typeofcontact roundchange referenceurl annualinterest latepaymentfee restockingcharge checkinventory hideaccounts linetax forcewarehouse glnumber sinumber sonumber vinumber batchnumber vouchernumber ponumber sqnumber rfqnumber partnumber projectnumber employeenumber customernumber vendornumber lock_glnumber lock_sinumber lock_sonumber lock_ponumber lock_sqnumber lock_rfqnumber lock_employeenumber lock_customernumber lock_vendornumber clearing transition paymentfile term_days AR_paid AP_paid smtp_host smtp_port smtp_username smtp_from_name smtp_ssl smtp_sasl";

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

sub format_date {
    my ($date) = @_;

    if ( $date && $date =~ /^(\d{4})(\d{2})(\d{2})$/ ) {
        return "$1-$2-$3";
    }

    return $date;    # return original if not matched
}

sub _aes_encrypt {
    use IPC::Open2;
    my ( $data, $key ) = @_;
    return undef unless defined $data && defined $key;

    local $ENV{OPENSSL_PASS} = $key;
    my $pid = open2(
        my $chld_out, my $chld_in,
        'openssl', 'enc', '-aes-256-cbc', '-a', '-salt',
        '-pass', 'env:OPENSSL_PASS', '-pbkdf2'
    );
    print $chld_in $data;
    close $chld_in;
    my $encrypted = do { local $/; <$chld_out> };
    waitpid( $pid, 0 );
    return undef if ( $? >> 8 ) != 0;
    chomp($encrypted) if $encrypted;
    return $encrypted;
}

sub _aes_decrypt {
    use IPC::Open2;
    my ( $data, $key ) = @_;
    return undef unless defined $data && defined $key;

    # openssl base64 decoder requires a trailing newline
    $data .= "\n" unless $data =~ /\n$/;

    local $ENV{OPENSSL_PASS} = $key;
    my $pid = open2(
        my $chld_out, my $chld_in,
        'openssl', 'enc', '-aes-256-cbc', '-d', '-a',
        '-pass', 'env:OPENSSL_PASS', '-pbkdf2'
    );
    print $chld_in $data;
    close $chld_in;
    my $decrypted = do { local $/; <$chld_out> };
    waitpid( $pid, 0 );
    return undef if ( $? >> 8 ) != 0;
    chomp($decrypted) if $decrypted;
    return $decrypted;
}

# Tests an SMTP connection and, if successful, encrypts and stores the password
# in connection_keys. Returns undef on success, or a hashref with status/message
# on failure. Only runs when host, username, and password are all provided.
sub _test_and_save_smtp_password {
    use Email::Sender::Transport::SMTP;
    use Email::Stuffer;
    my ( $c, $client, $smtp_data ) = @_;

    return undef
      unless $smtp_data->{host}
      && $smtp_data->{username}
      && $smtp_data->{password};

    # Get the current user's email directly to avoid get_user_profile's render side-effect
    my $user_email = do {
        my $sessionkey = $c->req->headers->header('Authorization');
        my $row = eval {
            $c->central_dbs->query(
                "SELECT p.email FROM session s LEFT JOIN profile p ON s.profile_id = p.id WHERE s.sessionkey = ?",
                $sessionkey
            )->hash;
        };
        ( $row && $row->{email} ) ? $row->{email} : $smtp_data->{username};
    };

    my $from_name = $smtp_data->{from_name} || $ENV{PRODUCT_NAME} || '';
    my $from = $from_name
      ? "$from_name <$smtp_data->{username}>"
      : $smtp_data->{username};

    my $test_ok = eval {
        my $transport = Email::Sender::Transport::SMTP->new(
            host          => $smtp_data->{host},
            port          => $smtp_data->{port} || 587,
            ssl           => $smtp_data->{ssl}  || 'starttls',
            sasl_username => $smtp_data->{username},
            sasl_password => $smtp_data->{password},
            sasl          => $smtp_data->{sasl} // 1,
            timeout       => 15,
        );
        Email::Stuffer
          ->from($from)
          ->to($user_email)
          ->subject('SMTP Connection Test')
          ->text_body('This is a test email to confirm your SMTP settings are working correctly.')
          ->transport($transport)
          ->send_or_die;
        1;
    };
    if ( !$test_ok || $@ ) {
        my $err = $@ || 'Unknown error';
        $err =~ s/ at \/.*? line \d+\.?\s*$//s;
        return { status => 422, error => 'error',
            message => "SMTP connection test failed: $err" };
    }

    my $aes_key = $ENV{aes_key};
    return { status => 500, error => 'error', message => 'Encryption key not found' }
      unless $aes_key;

    my $enc_password = _aes_encrypt( $smtp_data->{password}, $aes_key );
    return { status => 500, error => 'error', message => 'Failed to encrypt SMTP password' }
      unless $enc_password;

    my $dbs = $c->dbs($client);
    $dbs->query("DELETE FROM connection_keys WHERE fldname = 'smtp_password'");
    $dbs->insert( 'connection_keys',
        { fldname => 'smtp_password', fldvalue => encode_json( { password => $enc_password } ) } );

    return undef;
}

$api->get(
    '/system/audit' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        return unless my $form = $c->check_perms("system.audit");
        my $defaults = $c->get_defaults;
        $form->{closedto}   = $defaults->{closedto}   || 0;
        $form->{revtrans}   = $defaults->{revtrans}   || 0;
        $form->{audittrail} = $defaults->{audittrail} || 0;

       # Format closedto as yyyy-mm-dd if it exists and is in the 8-digit format
        my $formatted_closedto = format_date( $form->{closedto} );

        $c->render(
            json => {
                closedto   => $formatted_closedto,
                revtrans   => $form->{revtrans},
                audittrail => $form->{audittrail}
            }
        );
    }
);

$api->get(
    '/system/yearend' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        return unless my $form = $c->check_perms("system.yearend");

        my $all_accounts = $c->get_accounts($client);

        # Filter accounts with category 'Q' and charttype 'A'
        my @yearend_accounts =
          grep { $_->{category} eq 'Q' && $_->{charttype} eq 'A' }
          @{ $all_accounts->{all} };

        $c->render( json => \@yearend_accounts );
    }
);
$api->post(
    '/system/yearend' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        return unless my $form = $c->check_perms("system.yearend");
        my $dbs = $c->dbs($client);

        # Get JSON data from request
        my $json_data = $c->req->json;

        # Map JSON data to form
        $form->{todate}      = $json_data->{todate};
        $form->{accno}       = $json_data->{accno};
        $form->{description} = $json_data->{description}
          if $json_data->{description};
        $form->{notes}     = $json_data->{notes}     if $json_data->{notes};
        $form->{reference} = $json_data->{reference} if $json_data->{reference};
        $form->{method}    = $json_data->{method} || 'accrual';

        # Validate required fields
        unless ( $form->{todate} ) {
            return $c->render(
                json => {
                    status  => 'error',
                    message => 'Year-end date missing!'
                }
            );
        }

        unless ( $form->{accno} ) {
            return $c->render(
                json => {
                    status  => 'error',
                    message => 'Retained earnings account missing!'
                }
            );
        }

        # Get year-end statement data
        RP->yearend_statement( $c->slconfig, $form );

        # Set transaction date
        $form->{transdate} = $form->{todate};

        my $earnings = 0;
        my $ok       = 0;
        $form->{rowcount} = 1;

        # Process Income accounts (create debits to zero them out)
        for my $accno ( keys %{ $form->{I} } ) {
            if ( $form->{I}{$accno}{charttype} eq "A" ) {
                $form->{"debit_$form->{rowcount}"} = $form->{I}{$accno}{amount};
                $earnings += $form->{I}{$accno}{amount};
                $form->{"accno_$form->{rowcount}"} = $accno;
                $form->{rowcount}++;
                $ok = 1;
            }
        }

        # Process Expense accounts (create credits to zero them out)
        for my $accno ( keys %{ $form->{E} } ) {
            if ( $form->{E}{$accno}{charttype} eq "A" ) {
                $form->{"credit_$form->{rowcount}"} =
                  $form->{E}{$accno}{amount} * -1;
                $earnings += $form->{E}{$accno}{amount};
                $form->{"accno_$form->{rowcount}"} = $accno;
                $form->{rowcount}++;
                $ok = 1;
            }
        }

        # Create retained earnings entry
        if ( $earnings > 0 ) {

            # Profit: Credit retained earnings
            $form->{"credit_$form->{rowcount}"} = $earnings;
            $form->{"accno_$form->{rowcount}"}  = $form->{accno};
        }
        else {
            # Loss: Debit retained earnings
            $form->{"debit_$form->{rowcount}"} = $earnings * -1;
            $form->{"accno_$form->{rowcount}"} = $form->{accno};
        }

        # Check if there's anything to post
        unless ( $ok && $earnings ) {
            return $c->render(
                json => {
                    status  => 'error',
                    message => 'Nothing to post for year-end!'
                }
            );
        }

        # Post the year-end transaction
        if ( AM->post_yearend( $c->slconfig, $form ) ) {
            $dbs->query("DELETE FROM defaults WHERE fldname = 'closedto'");
            $form->{todate} =~ /^(\d{4})-(\d{2})-(\d{2})$/;
            my $closedto = "$1$2$3";
            $dbs->query(
"INSERT INTO defaults (fldname, fldvalue) VALUES ('closedto', '$closedto')"
            );
            $c->render(
                json => {
                    status    => 'success',
                    message   => 'Year-end posted successfully!',
                    reference => $form->{reference},
                    trans_id  => $form->{id},
                    earnings  => $earnings,
                    entries   => $form->{rowcount} - 1
                }
            );
        }
        else {
            $c->render(
                json => {
                    status  => 'error',
                    message => 'Year-end posting failed!'
                }
            );
        }
    }
);
$api->post(
    '/system/audit' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        return unless my $form = $c->check_perms("system.audit");

        my $closedto   = $c->req->json->{closedto}   || 0;
        my $revtrans   = $c->req->json->{revtrans}   || 0;
        my $audittrail = $c->req->json->{audittrail} || '';

        # Convert closedto from yyyy-mm-dd to yyyymmdd format if needed
        if ( $closedto && $closedto =~ /^(\d{4})-(\d{2})-(\d{2})$/ ) {
            $closedto = "$1$2$3";
        }

        $form->{closedto}   = $closedto;
        $form->{revtrans}   = $revtrans * 1;
        $form->{audittrail} = $audittrail * 1;

        my $result = AM->closebooks( $c->slconfig, $form );

        $c->render(
            json => {
                status  => 'success',
                message => 'Audit settings updated successfully',
                data    => {
                    closedto   => $closedto,
                    revtrans   => $revtrans,
                    audittrail => $audittrail
                }
            }
        );

    }
);

# Auto-seeds chart_categories from header accounts and assigns each bookable
# account to its direct parent's category, if no categories exist yet.
# Called from GET /system/chart/accounts so that existing datasets without
# categories get populated on first access. Remove this call once all
# datasets have been migrated.
helper seed_chart_categories_if_empty => sub {
    my ( $c, $dbs ) = @_;

    my $cat_count =
      $dbs->query("SELECT COUNT(*) FROM chart_categories")->array->[0];
    return if $cat_count > 0;

    $c->app->log->info("Seeding chart categories from header accounts");

    $dbs->query(q{
        INSERT INTO chart_categories (accno, description)
        SELECT accno, description
        FROM chart
        WHERE charttype = 'H'
        ORDER BY accno
    });

    $dbs->query(q{
        INSERT INTO chart_category_links (chart_id, category_id)
        SELECT c.id, cc.id
        FROM chart c
        JOIN chart parent ON parent.id = c.parent_id
        JOIN chart_categories cc ON cc.accno = parent.accno
        ON CONFLICT (chart_id, category_id) DO NOTHING
    });
};

$api->get(
    '/system/chart/accounts' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.chart.list");
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);

        # Auto-seed categories for datasets that predate this feature
        $c->seed_chart_categories_if_empty($dbs);

        my $result = CA->all_accounts( $c->slconfig, $form );
        if ($result) {
            # Fetch all category assignments in one query and index by chart_id
            my $links = $dbs->query(
                q{SELECT ccl.chart_id,
                         cc.id          AS category_id,
                         cc.accno       AS category_accno,
                         cc.description AS category_description
                  FROM chart_category_links ccl
                  JOIN chart_categories cc ON cc.id = ccl.category_id}
            )->hashes;

            my %cats_by_chart;
            for my $row (@$links) {
                push @{ $cats_by_chart{ $row->{chart_id} } }, {
                    id          => $row->{category_id},
                    accno       => $row->{category_accno},
                    description => $row->{category_description},
                };
            }

            # Attach categories array to each account
            for my $account ( @{ $form->{CA} } ) {
                $account->{categories} =
                  $cats_by_chart{ $account->{id} } // [];
            }

            $c->render( json => $form->{CA} );
        }
        else {
            $c->render(
                status => 500,
                json   => {
                    status  => 'error',
                    message => 'Failed to get accounts'
                }
            );
        }
    }
);

$api->get(
    '/system/chart/accounts/:id' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.chart.list");
        my $client = $c->param('client');
        my $id     = $c->param('id');
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

        my $result = AM->get_account( $c->slconfig, $form );

        $form->{has_transactions} = $transactions->rows > 0 ? \1 : \0;
        $form->{has_defaults}     = $defaults->rows > 0     ? \1 : \0;
        $form->{has_parts}        = $parts->rows > 0        ? \1 : \0;
        if ($result) {
            # Attach category assignments for this account
            my $cats = $dbs->query(
                q{SELECT cc.id, cc.accno, cc.description
                  FROM chart_category_links ccl
                  JOIN chart_categories cc ON cc.id = ccl.category_id
                  WHERE ccl.chart_id = ?
                  ORDER BY cc.accno},
                $id
            )->hashes;
            $form->{categories} = $cats;

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
        my $c = shift;
        return unless my $form = $c->check_perms("system.chart.add");
        my $client     = $c->param('client');
        my $id         = $c->param("id");
        my $params     = $c->req->json;
        my $dbs        = $c->dbs($client);

        # Extract category_ids before copying params into $form
        my $category_ids = $params->{category_ids};
        delete $params->{category_ids} if exists $params->{category_ids};

        for ( keys %$params ) { $form->{$_} = $params->{$_} if $params->{$_} }
        $form->{id} = $id // undef;

        my $result = AM->save_account( $c->slconfig, $form );

        if ($result) {
            # $form->{id} is set by AM->save_account after insert
            my $chart_id = $form->{id};

            if ( defined $category_ids && ref $category_ids eq 'ARRAY' ) {
                # Replace all category assignments for this account
                $dbs->query(
                    "DELETE FROM chart_category_links WHERE chart_id = ?",
                    $chart_id );

                for my $cat_id (@$category_ids) {
                    $dbs->query(
                        q{INSERT INTO chart_category_links (chart_id, category_id)
                          VALUES (?, ?)
                          ON CONFLICT (chart_id, category_id) DO NOTHING},
                        $chart_id, $cat_id
                    );
                }
            }

            # Return the account with its current categories
            my $cats = $dbs->query(
                q{SELECT cc.id, cc.accno, cc.description
                  FROM chart_category_links ccl
                  JOIN chart_categories cc ON cc.id = ccl.category_id
                  WHERE ccl.chart_id = ?
                  ORDER BY cc.accno},
                $chart_id
            )->hashes;
            $form->{categories} = $cats;

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
        my $c = shift;
        return unless my $form = $c->check_perms("system.chart.add");
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

        $form->{id} = $id;

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
##################################
####                          ####
####  CHART CATEGORIES        ####
####                          ####
##################################

$api->get(
    '/system/chart/categories' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.chart.list");
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);

        $c->seed_chart_categories_if_empty($dbs);

        my $categories = $dbs->query(
            q{SELECT id, accno, description
              FROM chart_categories
              ORDER BY accno}
        )->hashes;

        my $link_rows = $dbs->query(
            q{SELECT ccl.category_id,
                     c.id          AS chart_id,
                     c.accno       AS chart_accno,
                     c.description AS chart_description
              FROM chart_category_links ccl
              JOIN chart c ON c.id = ccl.chart_id
              ORDER BY ccl.category_id, c.accno}
        )->hashes;

        my %charts_by_category;
        for my $row (@$link_rows) {
            push @{ $charts_by_category{ $row->{category_id} } }, {
                id          => $row->{chart_id} + 0,
                accno       => $row->{chart_accno},
                description => $row->{chart_description},
            };
        }

        for my $cat (@$categories) {
            $cat->{charts} = $charts_by_category{ $cat->{id} } // [];
        }

        $c->render( json => $categories );
    }
);

$api->post(
    '/system/chart/categories' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.chart.add");
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);
        my $params = $c->req->json;

        unless ( $params->{accno} && $params->{description} ) {
            return $c->render(
                status => 400,
                json   => { error => 'accno and description are required' }
            );
        }

        $dbs->query(
            q{INSERT INTO chart_categories (accno, description)
              VALUES (?, ?)},
            $params->{accno},
            $params->{description},
        );

        my $id = $dbs->last_insert_id( undef, undef, 'chart_categories', 'id' );
        my $cat = $dbs->query(
            "SELECT id, accno, description FROM chart_categories WHERE id = ?",
            $id
        )->hash;

        $c->render( json => $cat );
    }
);

$api->post(
    '/system/chart/categories/:id' => sub {
        my $c   = shift;
        return unless my $form = $c->check_perms("system.chart.add");
        my $client = $c->param('client');
        my $id     = $c->param('id');
        my $dbs    = $c->dbs($client);
        my $params = $c->req->json;

        my $existing = $dbs->query(
            "SELECT id FROM chart_categories WHERE id = ?", $id )->hash;
        unless ($existing) {
            return $c->render(
                status => 404,
                json   => { error => 'Category not found' }
            );
        }

        my @fields;
        my @values;
        for my $f (qw(accno description)) {
            if ( exists $params->{$f} ) {
                push @fields, "$f = ?";
                push @values, $params->{$f};
            }
        }

        if (@fields) {
            $dbs->query(
                "UPDATE chart_categories SET " . join( ', ', @fields ) .
                " WHERE id = ?",
                @values, $id
            );
        }

        my $cat = $dbs->query(
            "SELECT id, accno, description FROM chart_categories WHERE id = ?",
            $id
        )->hash;

        $c->render( json => $cat );
    }
);

$api->delete(
    '/system/chart/categories/:id' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.chart.add");
        my $client = $c->param('client');
        my $id     = $c->param('id');
        my $dbs    = $c->dbs($client);

        my $existing = $dbs->query(
            "SELECT id FROM chart_categories WHERE id = ?", $id )->hash;
        unless ($existing) {
            return $c->render(
                status => 404,
                json   => { error => 'Category not found' }
            );
        }

        # chart_category_links will cascade-delete due to ON DELETE CASCADE
        $dbs->query( "DELETE FROM chart_categories WHERE id = ?", $id );

        $c->render( json => { success => 1, message => 'Category deleted' } );
    }
);

# Replace all category assignments for a single account
$api->post(
    '/system/chart/accounts/:id/categories' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.chart.add");
        my $client     = $c->param('client');
        my $chart_id   = $c->param('id');
        my $dbs        = $c->dbs($client);
        my $params     = $c->req->json;

        unless ( $params->{category_ids} && ref $params->{category_ids} eq 'ARRAY' ) {
            return $c->render(
                status => 400,
                json   => { error => 'category_ids array is required' }
            );
        }

        my $account = $dbs->query(
            "SELECT id FROM chart WHERE id = ?", $chart_id )->hash;
        unless ($account) {
            return $c->render(
                status => 404,
                json   => { error => 'Account not found' }
            );
        }

        # Replace all assignments atomically
        $dbs->query(
            "DELETE FROM chart_category_links WHERE chart_id = ?", $chart_id );

        for my $cat_id ( @{ $params->{category_ids} } ) {
            $dbs->query(
                q{INSERT INTO chart_category_links (chart_id, category_id)
                  VALUES (?, ?)
                  ON CONFLICT (chart_id, category_id) DO NOTHING},
                $chart_id, $cat_id
            );
        }

        my $cats = $dbs->query(
            q{SELECT cc.id, cc.accno, cc.description
              FROM chart_category_links ccl
              JOIN chart_categories cc ON cc.id = ccl.category_id
              WHERE ccl.chart_id = ?
              ORDER BY cc.accno},
            $chart_id
        )->hashes;

        $c->render( json => { chart_id => $chart_id + 0, categories => $cats } );
    }
);

$api->get(
    '/system/chart/gifi' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.chart.gifi");
        my $client = $c->param('client');

        my $result = AM->gifi_accounts( $c->slconfig, $form );
        if ($result) {
            $c->render( json => $form->{ALL} );
        }
        else {
            $c->render(
                status => 500,
                json   => {
                    status  => 'error',
                    message => 'Failed to get accounts'
                }
            );
        }
    }
);
$api->get(
    '/system/chart/gifi/:accno' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.chart.gifi");

        my $client = $c->param('client');
        my $accno  = $c->param('accno');
        $form->{accno} = $accno;
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        my $result = AM->get_gifi( $c->slconfig, $form );
        if ($result) {
            $c->render( json => {%$form} );

        }
        else {
            $c->render(
                status => 500,
                json   => {
                    status  => 'error',
                    message => 'Failed to get accounts'
                }
            );
        }
    }
);

$api->post(
    '/system/chart/gifi/:accno' => { accno => undef } => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.chart.gifi");

        my $client = $c->param('client');
        my $accno  = $c->param("accno");
        my $params = $c->req->json;
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        for ( keys %$params ) { $form->{$_} = $params->{$_} if $params->{$_} }
        $form->{accno} = $accno          // undef;
        $form->{id}    = $c->param('id') // undef;
        my $result = AM->save_gifi( $c->slconfig, $form );

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
    '/system/chart/gifi/:accno' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.chart.gifi");
        my $client = $c->param('client');

        my $accno  = $c->param("accno");
        my $params = $c->req->json;
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        $form->{id} = $accno;

        my $result = AM->delete_gifi( $c->slconfig, $form );

        $c->render( status => 204, data => '' );

    }
);

### Bank Accounts
# Get all bank accounts
$api->get(
    '/system/bank/accounts' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.bank");
        my $client = $c->param('client');

        my $result = AM->bank_accounts( $c->slconfig, $form );

        if ($result) {
            $c->render( json => $form->{ALL} );
        }
        else {
            $c->render(
                status => 500,
                json   => {
                    status  => 'error',
                    message => 'Failed to get bank accounts'
                }
            );
        }
    }
);

# Get specific bank account by id
$api->get(
    '/system/bank/accounts/:id' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.bank");
        my $client = $c->param('client');
        my $id     = $c->param('id');
        my $dbs    = $c->dbs($client);

        # Check for related records (similar to chart accounts)
        my $transactions =
          $dbs->query( "SELECT * FROM acc_trans WHERE chart_id = ?", $id );

        $form->{id} = $id;
        my $result = AM->get_bank( $c->slconfig, $form );

        $form->{has_transactions} = $transactions->rows > 0 ? \1 : \0;

        if ($result) {
            $c->render( json => {%$form} );
        }
        else {
            $c->render(
                status => 500,
                json   => {
                    status  => 'error',
                    message => 'Failed to get bank account'
                }
            );
        }
    }
);

# Create or update bank account
$api->post(
    '/system/bank/accounts/:id' => { id => undef } => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.bank");
        my $client = $c->param('client');
        my $id     = $c->param("id");
        my $params = $c->req->json;

        # Copy parameters from request to form
        for ( keys %$params ) {
            $form->{$_} = $params->{$_} if defined $params->{$_};
        }

        if ( $params->{check_number} ) {
            my ($accno) = split /--/, $form->{account};
            $form->{"check_$accno"} = $params->{check_number};
        }
        if ( $params->{receipt_number} ) {
            my ($accno) = split /--/, $form->{account};
            $form->{"receipt_$accno"} = $params->{receipt_number};
        }

        $form->{id} = $id // undef;

        my $result = AM->save_bank( $c->slconfig, $form );

        if ($result) {
            $c->render( json => {%$form} );
        }
        else {
            $c->render(
                status => 500,
                json   => {
                    status  => 'error',
                    message => 'Failed to save bank account'
                }
            );
        }
    }
);
############################
####                    ####
####       Taxes        ####
####                    ####
############################
$api->get(
    '/system/taxes' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.taxes");
        my $client = $c->param('client');

        AM->taxes( $c->slconfig, $form );

        $c->render( json => $form->{taxrates} );
    }
);

$api->post(
    '/system/taxes' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.taxes");
        my $client = $c->param('client');

        my $data = $c->req->json;

# If taxes is provided as an array, convert to the format expected by AM->save_taxes
        if ( ref $data->{taxes} eq 'ARRAY' && @{ $data->{taxes} } ) {
            my @tax_accounts;
            my $i = 1;

            foreach my $tax ( @{ $data->{taxes} } ) {
                if ( $tax->{chart_id} ) {
                    push @tax_accounts, $tax->{chart_id} . "_" . $i;
                    $form->{"taxrate_$i"}   = $tax->{rate}      || 0;
                    $form->{"taxnumber_$i"} = $tax->{taxnumber} || '';
                    $form->{"validto_$i"}   = $tax->{validto}   || '';

                    # Handle closed status for charts
                    if ( defined $tax->{closed} ) {
                        $form->{ "closed_" . $tax->{chart_id} } =
                          $tax->{closed} ? 1 : 0;
                    }

                    $i++;
                }
            }

            $form->{taxaccounts} = join( ' ', @tax_accounts );
        }

        my $result = AM->save_taxes( $c->slconfig, $form );

        if ($result) {
            $c->render(
                json => {
                    status  => 'success',
                    message => 'Tax information saved successfully'
                }
            );
        }
        else {
            $c->render(
                status => 500,
                json   => {
                    status  => 'error',
                    message => 'Failed to save tax'
                }
            );
        }
    }
);

############################
####                    ####
####     Departments    ####
####                    ####
############################
$api->get(
    '/system/departments' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.departments");
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);

        my $query = "SELECT * FROM department ORDER BY rn";

        my $departments = $dbs->query($query)->hashes;

        # Ensure departments is an array reference, even if empty
        return [] unless $departments && @$departments;

        # Check for transactions for each department
        foreach my $dept (@$departments) {
            my $txn_count = $dbs->query(
"SELECT COUNT(*) AS count FROM dpt_trans WHERE department_id = ?",
                $dept->{id}
            )->hash->{count};

            $dept->{transactions} = $txn_count > 0 ? 1 : 0;
        }

        $c->render( json => $departments );
    }
);
$api->post(
    '/system/departments' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.departments");
        my $client = $c->param('client');

        my $data = $c->req->json;
        for my $key ( keys %$data ) {
            $form->{$key} = $data->{$key} if defined $data->{$key};
        }
        AM->save_department( $c->slconfig, $form );
        if ( $form->{id} ) {
            $form->{id} = $form->{id};
            my $dbs = $c->dbs($client);
            warn( $form->{id} );
            warn( $form->{detail} );
            $dbs->query( "UPDATE department SET detail = ? where id = ?",
                $data->{detail}, $form->{id} );
        }

        $c->render( json => $form->{ALL} );
    }
);

$api->delete(
    '/system/departments/:id' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.departments");
        my $client = $c->param('client');
        my $id     = $c->param('id');

        return $c->render(
            status => 400,
            json   => { error => "Missing department ID" }
        ) unless $id;

        my $dbs = $c->dbs($client);

        # Check if the department has any transactions
        my $txn_count = $dbs->query(
            "SELECT COUNT(*) AS count FROM dpt_trans WHERE department_id = ?",
            $id )->hash->{count};

        if ( $txn_count > 0 ) {
            return $c->render(
                status => 409,    # HTTP 409 Conflict
                json   => {
                    error =>
"Department cannot be deleted because it has associated transactions"
                }
            );
        }

        $form->{id} = $id;

        # Call the delete method from AM module
        AM->delete_department( $c->slconfig, $form );

        # Return no content (204 No Content) on success
        return $c->rendered(204);
    }
);

############################
####                    ####
####     Projects       ####
####                    ####
############################
$api->get(
    '/projects' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.projects");
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);

        PE->projects( $c->slconfig, $form );
        $c->render( json => $form->{all_project} );

    }
);
$api->get(
    '/projects/:id' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.projects");
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);
        my $id     = $c->param('id');
        $form->{id} = $id;

        PE->get_project( $c->slconfig, $form );

        $c->render( json => {%$form} );

    }
);
$api->post(
    '/projects/:id' => { id => undef } => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("system.projects");
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);
        my $data   = $c->req->json;
        my $id     = $c->param('id');
        for ( keys %$data ) { $form->{$_} = $data->{$_} if $data->{$_} }

        PE->save_project( $c->slconfig, $form );

        if ( defined $data->{moco_project_id} ) {
            my $project =
              $dbs->query( "SELECT external_info FROM project WHERE id = ?",
                $form->{id} )->hash;

            my $info = {};
            if ( $project && $project->{external_info} ) {
                $info = eval { decode_json( $project->{external_info} ) } || {};
            }

            $info->{moco_id} = $data->{moco_project_id};

            my $info_json = encode_json($info);
            $dbs->query( "UPDATE project SET external_info = ? WHERE id = ?",
                $info_json, $form->{id} );

            $form->{external_info} = $info;
        }

        $c->render( json => {%$form} );

    }
);

##########################
####                  ####
#### Goods & Services ####
####                  ####
##########################

$api->get(    # to be replaced with get_links
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
$api->get(
    '/ic/items' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("items.search.allitems");
        my $client = $c->param('client');
        my $params = $c->req->params->to_hash;
        my $search = $params->{searchitems};

        # Return a 400 response if search parameter is not defined
        return $c->render(
            json   => { error => "searchitem is required." },
            status => 400
        ) unless defined $search;

        my %permissions = (
            allitems => "items.search.allitems",
            part     => "items.search.parts",
            service  => "items.search.services",
        );

        return unless $form = $c->check_perms( $permissions{$search} );

        $form->{searchitems}  = $params->{searchitems};
        $form->{partnumber}   = $params->{partnumber};
        $form->{description}  = $params->{description};
        $form->{serialnumber} = $params->{serialnumber};
        $form->{lot}          = $params->{lot};
        $form->{make}         = $params->{make};
        $form->{model}        = $params->{model};
        $form->{drawing}      = $params->{drawing};
        $form->{toolnumber}   = $params->{toolnumber};
        $form->{microfiche}   = $params->{microfiche};
        $form->{barcode}      = $params->{barcode};
        $form->{summary}      = 1;
        $form->{sold}         = $params->{sold};
        $form->{ordered}      = $params->{ordered};
        $form->{bought}       = $params->{bought};
        $form->{onorder}      = $params->{onorder};
        $form->{rfq}          = $params->{rfq};

        $form->{summary} = 0;
        $form->{open}    = 1;

        IC->all_parts( $c->slconfig, $form );
        warn( Dumper $form );
        my @results = $form->{parts};

        # Render the filtered JSON response
        $c->render( json => @results );
    }
);
$api->get(
    '/ic/items/:id' => sub {
        my $c = shift;
        return
          unless my $form =
          ( $c->check_perms('items.part') || $c->check_perms('items.service') );
        my $client = $c->param('client');
        my $id     = $c->param('id');

        $form->{id} = $id;
        IC->get_part( $c->slconfig, $form );

        # Render the form object as JSON
        $c->render( json => {%$form} );
    }
);
$api->post(
    '/ic/items/:id' => { id => undef } => sub {
        my $c = shift;
        return
          unless my $form =
          ( $c->check_perms('items.part') || $c->check_perms('items.service') );

        my $client = $c->param('client');
        my $id     = $c->param('id');
        my $data   = $c->req->json;
        my $dbs    = $c->dbs($client);
        $form->{id} = $id;

        if (   ( !$id )
            && $data->{partnumber}
            && $data->{partnumber} ne '' )
        {
            my $existing =
              $dbs->query( "SELECT * FROM parts WHERE partnumber = ?",
                $data->{partnumber} )->hash;
            if ($existing) {
                return $c->render(
                    status => 409,
                    json   => { error => "Part number already exists" }
                );
            }
        }

        # Map all non-array fields from $data to $form
        foreach my $key ( keys %$data ) {
            next
              if $key eq 'makeModelLines'
              || $key eq 'customerLines'
              || $key eq 'vendorLines';
            $form->{$key} = $data->{$key};
        }

        # Process make/model lines into keys like make_1, model_1, etc.
        if ( exists $data->{makeModelLines}
            && ref $data->{makeModelLines} eq 'ARRAY' )
        {
            my $i = 1;
            foreach my $line ( @{ $data->{makeModelLines} } ) {
                $form->{"make_$i"}  = $line->{make}  // '';
                $form->{"model_$i"} = $line->{model} // '';
                $i++;
            }
            $form->{makemodel_rows} = scalar @{ $data->{makeModelLines} };
        }

        # Process customer lines into keys like customer_1, pricebreak_1, etc.
        if ( exists $data->{customerLines}
            && ref $data->{customerLines} eq 'ARRAY' )
        {
            my $i = 1;
            foreach my $line ( @{ $data->{customerLines} } ) {
                $form->{"customer_$i"}      = $line->{customer}         // '';
                $form->{"pricebreak_$i"}    = $line->{priceBreak}       // '';
                $form->{"customerprice_$i"} = $line->{customerPrice}    // '';
                $form->{"customercurr_$i"}  = $line->{customerCurrency} // '';
                $form->{"validfrom_$i"}     = $line->{validFrom}        // '';
                $form->{"validto_$i"}       = $line->{validTo}          // '';
                $i++;
            }
            $form->{customer_rows} = scalar @{ $data->{customerLines} };
        }

        # Process vendor lines into keys like vendor_1, partnumber_1, etc.
        if ( exists $data->{vendorLines}
            && ref $data->{vendorLines} eq 'ARRAY' )
        {
            my $i = 1;
            foreach my $line ( @{ $data->{vendorLines} } ) {
                $form->{"vendor_$i"}     = $line->{vendor}           // '';
                $form->{"partnumber_$i"} = $line->{vendorPartNumber} // '';
                $form->{"lastcost_$i"}   = $line->{vendorCost}       // '';
                $form->{"vendorcurr_$i"} = $line->{vendorCurrency}   // '';
                $form->{"leadtime_$i"}   = $line->{vendorLeadtime}   // '';
                $i++;
            }
            $form->{vendor_rows} = scalar @{ $data->{vendorLines} };
        }
        $form->{id} = $id;
        IC->save( $c->slconfig, $form );
        $c->render( json => {%$form} );
    }
);

###############################
####                       ####
####      Templates        ####
####                       ####
###############################
$api->get(
    '/system/templates' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms('system.templates');
        my $client        = $c->param('client');
        my $templates_dir = "templates/$client/";

        # Open the directory, return error if not found or not accessible
        opendir( my $dh, $templates_dir )
          or return $c->render(
            json   => { error => "Directory '$templates_dir' not found" },
            status => 404
          );

        # Filter out directories; only include files
        my @templates = grep { -f "$templates_dir/$_" } readdir($dh);
        closedir($dh);

        # Render the list as JSON
        $c->render( json => { templates => \@templates } );
    }
);
$api->get(
    '/system/template' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms('system.templates');
        my $client   = $c->param('client');
        my $template = $c->param('id');

        return $c->render(
            json   => { error => "Invalid template name" },
            status => 400
        ) if $template =~ /\.\./;

        my $file = "templates/$client/$template";

        unless ( -e $file && -f $file ) {
            return $c->render(
                json   => { error => "Template not found" },
                status => 404
            );
        }

        if ( $file =~ /\.pdf$/i ) {
            my $timestamp = time();
            my ( $name, $ext ) = $template =~ /^(.*?)\.([^.]+)$/;
            my $new_filename = "${name}_${timestamp}.$ext";

            $c->res->headers->content_type('application/pdf');
            $c->res->headers->content_disposition(
                "inline; filename=$new_filename");
            $c->res->headers->cache_control(
                'no-cache, no-store, must-revalidate');
            $c->res->headers->expires(0);
            $c->reply->asset( Mojo::Asset::File->new( path => $file ) );
            return;
        }

        elsif ( $file =~ /\.(png|jpe?g|gif|webp|bmp|svg)$/i ) {
            my %mime_types = (
                png  => 'image/png',
                jpg  => 'image/jpeg',
                jpeg => 'image/jpeg',
                gif  => 'image/gif',
                webp => 'image/webp',
                bmp  => 'image/bmp',
                svg  => 'image/svg+xml'
            );
            my ($ext) = $file =~ /\.(\w+)$/;
            my $content_type =
              $mime_types{ lc $ext } || 'application/octet-stream';

            my $timestamp    = time();
            my ($name)       = $template =~ /^(.*?)\.([^.]+)$/;
            my $new_filename = "${name}_${timestamp}.$ext";

            $c->res->headers->content_type($content_type);
            $c->res->headers->content_disposition(
                "inline; filename=$new_filename");
            $c->res->headers->cache_control(
                'no-cache, no-store, must-revalidate');
            $c->res->headers->expires(0);
            $c->reply->asset( Mojo::Asset::File->new( path => $file ) );
            return;
        }

        else {
            open my $fh, '<',
              $file
              or return $c->render(
                json   => { error => "Cannot open template" },
                status => 500
              );
            local $/ = undef;
            my $content = <$fh>;
            close $fh;
            $c->render( text => $content );
        }
    }
);

$api->post(
    '/system/template' => sub {
        my $c = shift;
        return unless $c->check_perms('system.templates');
        my $client   = $c->param('client');
        my $template = $c->param('id');
        my $content  = $c->req->json->{content};

        # Ensure that new content is provided
        return $c->render(
            json   => { error => "Content not provided" },
            status => 400
        ) unless defined $content;

        # Basic sanitization to prevent directory traversal
        return $c->render(
            json   => { error => "Invalid template name" },
            status => 400
        ) if $template =~ /\.\./;

        my $file = "templates/$client/$template";

        # Ensure that the file exists and is a regular file
        unless ( -e $file && -f $file ) {
            return $c->render(
                json   => { error => "Template not found" },
                status => 404
            );
        }

        # Open the file for writing (this will overwrite the file)
        open my $fh, '>',
          $file
          or return $c->render(
            json   => { error => "Cannot write to template" },
            status => 500
          );
        print $fh $content;
        close $fh;

        $c->render( json => { success => "Template updated" } );
    }
);
$api->post(
    '/system/template/upload' => sub {
        my $c = shift;
        return unless $c->check_perms('system.templates');
        my $client = $c->param('client');
        my $template_id =
          $c->param('id');    # Optional - only provided for replacements
        my $filename = $c->param('name');    # Optional - alternative filename

        # Get uploaded file
        my $upload = $c->req->upload('file');

        unless ($upload) {
            return $c->render(
                json   => { error => "No file uploaded" },
                status => 400
            );
        }

        # Generate safe filename
        my $original_name = $upload->filename;

        # Use provided name, original filename, or template_id
        my $target_filename = $filename || $original_name;

        # For replacements, use the existing filename
        if ($template_id) {
            $target_filename = $template_id;
        }

        # Basic sanitization to prevent directory traversal
        $target_filename =~ s{[^\w\.-]}{}g;

        # Ensure client directory exists
        my $client_dir = "templates/$client";
        unless ( -d $client_dir ) {
            mkdir $client_dir
              or return $c->render(
                json   => { error => "Cannot create client directory" },
                status => 500
              );
        }

        my $target_path = "$client_dir/$target_filename";

        # If replacing, verify the file exists and check content type
        if ( $template_id && -e $target_path ) {

            # Check file type match for replacements
            my $existing_ext = ( $target_path   =~ /\.([^.]+)$/ )[0] || '';
            my $new_ext      = ( $original_name =~ /\.([^.]+)$/ )[0] || '';

            # Simplistic content type checking
            my $content_type = $upload->headers->content_type;

            # For PDFs
            if ( $existing_ext eq 'pdf'
                && !( $content_type eq 'application/pdf' || $new_ext eq 'pdf' )
              )
            {
                return $c->render(
                    json =>
                      { error => "Cannot replace PDF with another file type" },
                    status => 400
                );
            }

            # For images
            if (
                $existing_ext =~ /^(png|jpg|jpeg|gif|webp|bmp|svg)$/
                && !(
                       $content_type =~ /^image\//
                    || $new_ext =~ /^(png|jpg|jpeg|gif|webp|bmp|svg)$/
                )
              )
            {
                return $c->render(
                    json => {
                        error => "Cannot replace image with another file type"
                    },
                    status => 400
                );
            }

            # For HTML/TEX
            if ( $existing_ext =~ /^(html|tex)$/ && $new_ext ne $existing_ext )
            {
                return $c->render(
                    json => {
                        error =>
                          "Cannot replace $existing_ext with another file type"
                    },
                    status => 400
                );
            }
        }

        # Move the file to target location
        $upload->move_to($target_path);

        # For new files, update the templates list if needed
        # This depends on how your application manages template listings

        $c->render(
            json => {
                success => "Template uploaded successfully",
                name    => $target_filename
            }
        );
    }
);

# GET route: Check if a template exists
$api->get(
    '/system/template/check' => sub {
        my $c = shift;
        return unless $c->check_perms('system.templates');

        my $client   = $c->param('client');
        my $filename = $c->param('checkExists');

        # Basic sanitization to prevent directory traversal
        $filename =~ s{[^\w\.-]}{}g;

        my $file_path = "templates/$client/$filename";
        my $exists    = -e $file_path ? 1 : 0;

        $c->render( json => { exists => $exists } );
    }
);

###############################
####                       ####
####        LINKS          ####
####                       ####
###############################

helper get_defaults => sub {
    my $c      = shift;
    my $client = shift // $c->param('client');
    my $dbs    = $c->dbs($client);
    return {} unless $dbs;
    my $defaults = $dbs->query("SELECT * FROM defaults")->hashes;

    return {} unless ( $defaults && @$defaults );

    # Transform the array of hashrefs into a hashref keyed by fldname
    my %defaults_hash = map { $_->{fldname} => $_->{fldvalue} } @$defaults;

    return \%defaults_hash;
};

# Map JSON email "type" (e.g. invoice, reminder1) to messages.message_type.
helper email_send_type_to_message_type => sub {
    my ( $c, $type ) = @_;
    return undef if !defined $type || $type eq '';
    return "reminder_$1" if $type =~ /^reminder([1-3])$/;
    return 'invoice_send';
};

# Resolve body text: non-empty override wins, else VC row, else default rows (language, then any).
helper resolve_email_message_template => sub {
    my ( $c, $dbs, $vc_trans_id, $language_code, $message_type, $override ) = @_;
    if ( defined $override && $override =~ /\S/ ) {
        return $override;
    }
    return '' if !$message_type;
    my $template = $dbs->query(
        "SELECT content FROM messages WHERE trans_id = ? AND message_type = ?",
        $vc_trans_id, $message_type
    )->hash;
    if ( $template && defined $template->{content} && $template->{content} =~ /\S/ ) {
        return $template->{content};
    }
    if ( $language_code && $language_code =~ /\S/ ) {
        $template = $dbs->query(
"SELECT content FROM messages WHERE trans_id IS NULL AND message_type = ? AND language_code = ? ORDER BY id LIMIT 1",
            $message_type, $language_code
        )->hash;
    }
    else {
        $template = $dbs->query(
"SELECT content FROM messages WHERE trans_id IS NULL AND message_type = ? ORDER BY id LIMIT 1",
            $message_type
        )->hash;
    }
    return ( $template && defined $template->{content} )
      ? ( $template->{content} // '' )
      : '';
};

# Minimum document transdate for batch APIs: transdate > (closedto + 1 day).
# Returns undef when closedto is unset or unparseable (no extra filter).
helper batch_transdate_exclusive_min => sub {
    my ($c) = @_;
    my $defaults = $c->get_defaults;
    my $raw      = $defaults->{closedto};
    return undef unless defined $raw && $raw ne '';
    my $ymd = format_date($raw);
    return undef unless $ymd && $ymd =~ /^(\d{4})-(\d{2})-(\d{2})$/;
    my $dt = eval {
        DateTime->new(
            year  => int($1),
            month => int($2),
            day   => int($3),
        );
    };
    return undef unless $dt;
    $dt->add( days => 1 );
    return $dt->ymd;
};

# Reject YYYY-MM-DD on/before the same cutoff as batch search (closedto + 1 day).
# Returns undef if allowed or if no cutoff; otherwise an error message.
helper batch_date_must_be_after_closed_period => sub {
    my ( $c, $ymd ) = @_;
    return 'Invalid date format.'
      unless defined $ymd && $ymd =~ /^\d{4}-\d{2}-\d{2}$/;
    my $cutoff = $c->batch_transdate_exclusive_min;
    return undef unless $cutoff;
    return 'Date is in or before the closed period.' if $ymd le $cutoff;
    return undef;
};

# Same link-token rules as batch_build_create_links for ap_record / expense_accounts.
helper batch_ap_allowed_chart_maps => sub {
    my ( $c, $dbs ) = @_;
    my $charts = $dbs->query(
        q{SELECT id, accno, link FROM chart WHERE COALESCE(closed, false) = false}
    )->hashes;
    my $link_has = sub {
        my ( $link, $token ) = @_;
        return 0 unless defined $link && $link ne '';
        for my $t ( split /:/, $link ) {
            return 1 if $t eq $token;
        }
        return 0;
    };
    my ( %record, %expense );
    for my $row (@$charts) {
        $record{ $row->{id} } = 1 if $link_has->( $row->{link}, 'AP' );
        $expense{ $row->{id} } = 1
          if $link_has->( $row->{link}, 'AP_amount' );
    }
    return ( \%record, \%expense );
};

# One payable-side chart for the AP document (same filter idea as GET /batch/search AP lines).
helper batch_ap_payable_chart_id => sub {
    my ( $c, $dbs, $trans_id ) = @_;
    my $rows = $dbs->query(
        q{SELECT DISTINCT ac.chart_id
            FROM acc_trans ac
            JOIN chart c ON c.id = ac.chart_id
           WHERE ac.trans_id = ?
             AND ac.fx_transaction = '0'
             AND (':' || COALESCE(c.link, '') || ':') LIKE '%:AP:%'
             AND c.link NOT LIKE '%AP_amount%'
             AND c.link NOT LIKE '%AP_paid%'
             AND c.link NOT LIKE '%AP_discount%'},
        $trans_id
    )->arrays;
    return ( undef, 'No AP record (payable) account line found on this transaction.' )
      unless $rows && @$rows;
    return ( undef,
        'Multiple distinct AP record accounts on this transaction.' )
      if @$rows > 1;
    return ( $rows->[0][0], undef );
};

# Resolve chart id from JSON chart_id and/or accno against an allowed-id set ($kind = record|expense).
helper batch_ap_resolve_update_chart => sub {
    my ( $c, $dbs, $chart_id_raw, $accno_raw, $allowed_ids, $kind ) = @_;
    my $has_cid =
      defined $chart_id_raw && $chart_id_raw ne '';
    my $has_acc = defined $accno_raw && $accno_raw ne '';
    if ( $has_cid && $has_acc ) {
        my $row = $dbs->query(
            q{SELECT id, accno FROM chart
               WHERE id = ? AND COALESCE(closed, false) = false},
            $chart_id_raw + 0
        )->hash;
        return ( undef, "Invalid $kind chart_id." ) unless $row;
        return ( undef, "${kind}_accno does not match ${kind}_chart_id." )
          if $row->{accno} ne $accno_raw;
        return ( undef, "Not an allowed AP $kind account." )
          unless $allowed_ids->{ $row->{id} };
        return ( $row->{id} + 0, undef );
    }
    if ($has_cid) {
        my $cid = $chart_id_raw + 0;
        return ( undef, "Invalid $kind chart_id." )
          unless $allowed_ids->{$cid};
        return ( $cid, undef );
    }
    if ($has_acc) {
        my $row = $dbs->query(
            q{SELECT id FROM chart
               WHERE accno = ? AND COALESCE(closed, false) = false},
            $accno_raw
        )->hash;
        return ( undef, "Unknown $kind account accno." ) unless $row;
        return ( undef, "Not an allowed AP $kind account." )
          unless $allowed_ids->{ $row->{id} };
        return ( $row->{id} + 0, undef );
    }
    return ( undef, "Missing ${kind} chart_id or accno." );
};

# Chart ids allowed for GL acc_trans lines (same rules as batch gl_accounts picklist).
helper batch_gl_chart_allowed_ids => sub {
    my ( $c, $dbs ) = @_;
    my $rows = $dbs->query(
        q{SELECT id FROM chart
           WHERE charttype <> 'H'
             AND COALESCE(allow_gl, true) = true
             AND COALESCE(closed, false) = false}
    )->hashes;
    my %h = map { $_->{id} => 1 } @$rows;
    return \%h;
};

helper batch_gl_resolve_update_chart => sub {
    my ( $c, $dbs, $chart_id_raw, $accno_raw, $allowed_ids ) = @_;
    my $has_cid =
      defined $chart_id_raw && $chart_id_raw ne '';
    my $has_acc = defined $accno_raw && $accno_raw ne '';
    if ( $has_cid && $has_acc ) {
        my $row = $dbs->query(
            q{SELECT id, accno FROM chart
               WHERE id = ? AND COALESCE(closed, false) = false},
            $chart_id_raw + 0
        )->hash;
        return ( undef, 'Invalid chart_id.' ) unless $row;
        return ( undef, 'accno does not match chart_id.' )
          if $row->{accno} ne $accno_raw;
        return ( undef, 'Not an allowed GL account.' )
          unless $allowed_ids->{ $row->{id} };
        return ( $row->{id} + 0, undef );
    }
    if ($has_cid) {
        my $cid = $chart_id_raw + 0;
        return ( undef, 'Invalid chart_id.' ) unless $allowed_ids->{$cid};
        return ( $cid, undef );
    }
    if ($has_acc) {
        my $row = $dbs->query(
            q{SELECT id FROM chart
               WHERE accno = ? AND COALESCE(closed, false) = false},
            $accno_raw
        )->hash;
        return ( undef, 'Unknown account accno.' ) unless $row;
        return ( undef, 'Not an allowed GL account.' )
          unless $allowed_ids->{ $row->{id} };
        return ( $row->{id} + 0, undef );
    }
    return ( undef, 'Missing chart_id or accno.' );
};

# Reference data for batch UIs. $param: empty/0/false => undef; 1/all/true => full set;
# or comma-separated keys (see valid keys per module in helper body).
helper batch_build_create_links => sub {
    my ( $c, $client, $module, $param ) = @_;
    return undef
      unless defined $param;
    my $p = $param;
    $p =~ s/^\s+|\s+$//g;
    return undef
      if $p eq ''
      || $p eq '0'
      || lc($p) eq 'false';

    my $dbs = $c->dbs($client);
    return undef unless $dbs;

    my $link_has = sub {
        my ( $link, $token ) = @_;
        return 0 unless defined $link && $link ne '';
        for my $t ( split /:/, $link ) {
            return 1 if $t eq $token;
        }
        return 0;
    };
    my $acc_label = sub {
        my ($row) = @_;
        return $row->{accno} . '--' . ( $row->{description} // '' );
    };

    my %valid_ar = map { $_ => 1 }
      qw(customers ar_record_accounts ar_payment_accounts items departments projects);
    my %valid_ap = map { $_ => 1 }
      qw(vendors ap_record_accounts ap_payment_accounts expense_accounts expense_tax_accounts departments projects);
    my %valid_gl = map { $_ => 1 }
      qw(gl_accounts departments projects currencies);

    my %syn = (
        customer         => 'customers',
        customers        => 'customers',
        ar_record        => 'ar_record_accounts',
        ar_record_account => 'ar_record_accounts',
        ar_payment       => 'ar_payment_accounts',
        ar_payment_account => 'ar_payment_accounts',
        vendor           => 'vendors',
        vendors          => 'vendors',
        ap_record        => 'ap_record_accounts',
        ap_record_account => 'ap_record_accounts',
        ap_payment       => 'ap_payment_accounts',
        ap_payment_account => 'ap_payment_accounts',
        expense          => 'expense_accounts',
        expense_account  => 'expense_accounts',
        expense_tax      => 'expense_tax_accounts',
        expense_tax_account => 'expense_tax_accounts',
        tax              => 'expense_tax_accounts',
        gl_account       => 'gl_accounts',
        gl_accounts      => 'gl_accounts',
        account          => 'gl_accounts',
        currency         => 'currencies',
        currencies       => 'currencies',
        department       => 'departments',
        departments      => 'departments',
        project          => 'projects',
        projects         => 'projects',
        item             => 'items',
        items            => 'items',
    );

    my @want_tokens =
        ( $p eq '1' || lc($p) eq 'all' || lc($p) eq 'true' )
      ? ('__ALL__')
      : ( split /\s*,\s*/, lc $p );

    my %want;
    if ( $want_tokens[0] eq '__ALL__' ) {
        if ( $module eq 'ar' ) {
            %want = map { $_ => 1 } keys %valid_ar;
        }
        elsif ( $module eq 'ap' ) {
            %want = map { $_ => 1 } keys %valid_ap;
        }
        else {
            %want = map { $_ => 1 } keys %valid_gl;
        }
    }
    else {
        for my $t (@want_tokens) {
            my $k = $syn{$t} // $t;
            if ( $module eq 'ar' && $valid_ar{$k} ) {
                $want{$k} = 1;
            }
            elsif ( $module eq 'ap' && $valid_ap{$k} ) {
                $want{$k} = 1;
            }
            elsif ( $module eq 'gl' && $valid_gl{$k} ) {
                $want{$k} = 1;
            }
        }
    }

    return undef unless %want;

    my $out = {};

    if ( $module eq 'ar' ) {
        if ( $want{customers} ) {
            $out->{customers} = $c->get_vc( 'customer', $client );
        }
        if ( $want{items} ) {
            $out->{items} = $dbs->query(
                q{SELECT id, partnumber, description, unit, sellprice, assembly, obsolete
                  FROM parts ORDER BY partnumber}
            )->hashes;
        }
        if ( $want{departments} ) {
            $out->{departments} = $c->get_departments( 'P', $client );
        }
        if ( $want{projects} ) {
            $out->{projects} = $c->get_projects($client);
        }
        if ( $want{ar_record_accounts} || $want{ar_payment_accounts} ) {
            my $charts = $dbs->query(
                q{SELECT id, accno, description, link, charttype
                  FROM chart
                  WHERE COALESCE(closed, false) = false}
            )->hashes;
            if ( $want{ar_record_accounts} ) {
                my @acc = grep { $link_has->( $_->{link}, 'AR' ) } @$charts;
                $_->{label} = $acc_label->($_) for @acc;
                $out->{ar_record_accounts} = \@acc;
            }
            if ( $want{ar_payment_accounts} ) {
                my @acc = grep { $link_has->( $_->{link}, 'AR_paid' ) } @$charts;
                $_->{label} = $acc_label->($_) for @acc;
                $out->{ar_payment_accounts} = \@acc;
            }
        }
    }
    elsif ( $module eq 'ap' ) {
        if ( $want{vendors} ) {
            $out->{vendors} = $c->get_vc( 'vendor', $client );
        }
        if ( $want{departments} ) {
            $out->{departments} = $c->get_departments( undef, $client );
        }
        if ( $want{projects} ) {
            $out->{projects} = $c->get_projects($client);
        }
        if (   $want{ap_record_accounts}
            || $want{ap_payment_accounts}
            || $want{expense_accounts}
            || $want{expense_tax_accounts} )
        {
            my $charts = $dbs->query(
                q{SELECT id, accno, description, link, charttype
                  FROM chart
                  WHERE COALESCE(closed, false) = false}
            )->hashes;
            if ( $want{ap_record_accounts} ) {
                my @acc = grep { $link_has->( $_->{link}, 'AP' ) } @$charts;
                $_->{label} = $acc_label->($_) for @acc;
                $out->{ap_record_accounts} = \@acc;
            }
            if ( $want{ap_payment_accounts} ) {
                my @acc = grep { $link_has->( $_->{link}, 'AP_paid' ) } @$charts;
                $_->{label} = $acc_label->($_) for @acc;
                $out->{ap_payment_accounts} = \@acc;
            }
            if ( $want{expense_accounts} ) {
                my @acc =
                  grep { $link_has->( $_->{link}, 'AP_amount' ) }
                  @$charts;
                $_->{label} = $acc_label->($_) for @acc;
                $out->{expense_accounts} = \@acc;
            }
            if ( $want{expense_tax_accounts} ) {
                my @from_link =
                  grep { $link_has->( $_->{link}, 'AP_tax' ) } @$charts;
                my $from_vt = eval {
                    $dbs->query(
                        q{SELECT DISTINCT c.id, c.accno, c.description, c.link, c.charttype
                          FROM chart c
                          JOIN vendortax vt ON vt.chart_id = c.id
                          WHERE COALESCE(c.closed, false) = false}
                    )->hashes;
                };
                $from_vt = [] if $@ || !$from_vt;
                my %seen;
                my @merged;
                for my $row ( @from_link, @$from_vt ) {
                    next if $seen{ $row->{id} }++;
                    $row->{label} = $acc_label->($row);
                    push @merged, $row;
                }
                @merged = sort { $a->{accno} cmp $b->{accno} } @merged;
                $out->{expense_tax_accounts} = \@merged;
            }
        }
        # Vendor batch UIs always need the expense account picklist (same set as
        # sections=expense_accounts), even when /batch/create_links sections omit it.
        if ( !$out->{expense_accounts} ) {
            my $charts = $dbs->query(
                q{SELECT id, accno, description, link, charttype
                  FROM chart
                  WHERE COALESCE(closed, false) = false}
            )->hashes;
            my @acc =
              grep { $link_has->( $_->{link}, 'AP_amount' ) }
              @$charts;
            $_->{label} = $acc_label->($_) for @acc;
            $out->{expense_accounts} = \@acc;
        }
        # Vendor batch UIs always need department and project picklists.
        if ( !$out->{departments} ) {
            $out->{departments} = $c->get_departments( undef, $client );
        }
        if ( !$out->{projects} ) {
            $out->{projects} = $c->get_projects($client);
        }
    }
    else {
        if ( $want{gl_accounts} ) {
            $out->{gl_accounts} = $dbs->query(
                q{SELECT id, accno, description, link, charttype, category
                  FROM chart
                  WHERE charttype <> 'H'
                    AND COALESCE(allow_gl, true) = true
                    AND COALESCE(closed, false) = false
                  ORDER BY accno}
            )->hashes;
            $_->{label} = $acc_label->($_) for @{ $out->{gl_accounts} };
        }
        if ( $want{departments} ) {
            $out->{departments} = $c->get_departments( undef, $client );
        }
        if ( $want{projects} ) {
            $out->{projects} = $c->get_projects($client);
        }
        if ( $want{currencies} ) {
            my $cur;
            eval {
                $cur = $dbs->query("SELECT * FROM curr ORDER BY rn")->hashes;
            };
            $out->{currencies} = $cur // [];
        }
        # GL batch UIs need department and project picklists even when sections omits them.
        if ( !$out->{departments} ) {
            $out->{departments} = $c->get_departments( undef, $client );
        }
        if ( !$out->{projects} ) {
            $out->{projects} = $c->get_projects($client);
        }
    }

    return $out;
};

helper get_projects => sub {
    my $c        = shift;
    my $client   = shift // $c->param('client');
    my $dbs      = $c->dbs($client);
    my $projects = $dbs->query("SELECT * FROM project")->hashes;

    # Return an empty array ref if no projects are found
    return [] unless ( $projects && @$projects );

 # Add a 'value' property to each project that concatenates projectnumber and id
    for my $project (@$projects) {
        $project->{value} = $project->{projectnumber} . '--' . $project->{id};
    }

    return $projects;
};

helper get_departments => sub {
    my ( $c, $role, $client ) = @_;
    $client = $client // $c->param('client');
    my $dbs = $c->dbs($client);

    my $query = "SELECT * FROM department";

    my @bind_params;
    if ( defined $role && ( $role eq 'C' || $role eq 'P' ) ) {
        $query .= " WHERE role = ?";
        push @bind_params, $role;
    }

    my $departments = $dbs->query( $query, @bind_params )->hashes;

    return [] unless ( $departments && @$departments );

   # Add a 'value' property to each project that concatenates description and id
    for my $department (@$departments) {
        $department->{value} =
          $department->{description} . '--' . $department->{id};
    }

    return $departments // [];
};

helper get_vc => sub {
    my ( $c, $vc, $client ) = @_;
    $client = $client // $c->param('client');
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
          $item->{name} . " -- " . $item->{$number};
    }
    return $form->{all_vc};
};

helper get_currencies => sub {
    my ( $c, $client ) = @_;
    $client = $client // $c->param('client');

    my $dbs = $c->dbs($client);

    my $currencies;
    eval {
        $currencies = $dbs->query("SELECT * FROM curr ORDER BY rn")->hashes;
    };

    if ($@) {
        return $c->render(
            status => 500,
            json => { error => { message => 'Failed to retrieve currencies' } }
        );
    }

    return $currencies;
};

helper get_roles => sub {
    my $c      = shift;
    my $client = $c->param('client');
    my $dbs    = $c->dbs($client);
    my $roles  = $dbs->query("SELECT id, description FROM acsapirole");

    my $data = $roles->hashes;
    $data = [$data]
      unless ref $data eq 'ARRAY';
    return $data;
};

helper get_gifi => sub {
    my $c      = shift;
    my $client = $c->param('client');
    my $form   = Form->new;
    $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

    my $result = AM->gifi_accounts( $c->slconfig, $form );
    if ($result) {
        return $form->{ALL};
    }
    else {
        return [];
    }
};

helper get_accounts => sub {
    my ( $c, $client ) = @_;
    $client = $client // $c->param('client');
    my $form   = Form->new;
    my $module = $c->param('module') || '';
    $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

    # Fetch all accounts
    my $result   = CA->all_accounts( $c->slconfig, $form );
    my $accounts = $form->{CA};

    # Add a label property to all accounts (format: accno--description)
    foreach my $acc (@$accounts) {
        $acc->{label} = $acc->{accno} . '--' . $acc->{description};
    }

    # Mapping for the 4 types of accounts
    my %filter_mapping = (
        inventory      => 'IC',
        income         => 'AR_amount:IC_sale',
        service_income => 'AR_amount:IC_income',
        cogs           => 'AP_amount:IC_cogs',
        expense        => 'AP_amount:IC_expense',
        payment        => 'AR_paid|AP_paid',
        all            => ''
    );

    my $link_matches_filter = sub {
        my ( $link, $filter_str ) = @_;
        return 0 unless defined $link;
        return 1 if $filter_str eq '';
        if ( index( $filter_str, ':' ) >= 0 ) {
            my %have = map { $_ => 1 } grep { length $_ } split /:/, $link;
            for my $tok ( grep { length $_ } split /:/, $filter_str ) {
                return 0 unless $have{$tok};
            }
            return 1;
        }
        return $link =~ /\Q$filter_str\E/;
    };

    # Create a hash to store filtered accounts for each type
    my %filtered_accounts;
    foreach my $type ( keys %filter_mapping ) {
        my $filter_str = $filter_mapping{$type};
        my @filtered;
        if ( $type eq 'payment' ) {
            @filtered = grep {
                defined $_->{link}
                  && ( $_->{link} =~ /\bAR_paid\b/
                    || $_->{link} =~ /\bAP_paid\b/ )
            } @$accounts;
        }
        else {
            @filtered =
              grep { $link_matches_filter->( $_->{link}, $filter_str ) }
              @$accounts;
        }
        $filtered_accounts{$type} = \@filtered;
    }

    # Apply module-specific modifications:
    if ( $module eq 'gl' ) {

# For 'gl', we only want the 'all' accounts, but filter out accounts with charttype 'H'
        my @all_filtered =
          grep { $_->{charttype} ne 'H' } @{ $filtered_accounts{'all'} };
        return { all => \@all_filtered };
    }
    elsif ( $module eq 'gl_report' ) {

     # For 'gl_report', return only the 'all' accounts without further filtering
        return { all => $filtered_accounts{'all'} };
    }
    else {
        # For any other module, return the complete set of filtered accounts.
        return \%filtered_accounts;
    }
};

# Available modules: customer, vendor, goodsservices, gl_report, projects, incomestatement, employees
helper lock_number => sub {
    my $c      = shift;
    my $dbs    = shift;
    my $module = shift;

    my $lock =
      $dbs->query( "SELECT 1 FROM defaults WHERE fldname = 'lock_' || ?",
        $module )->hash;
    if ($lock) {
        return 1;
    }
    else {
        return 0;
    }
};
helper get_items => sub {
    my $c     = shift;
    my $dbs   = shift;
    my $parts = $dbs->query("SELECT * FROM parts")->hashes;

    foreach my $part (@$parts) {
        $part->{label} = $part->{partnumber} . '--' . $part->{description};
        my $taxaccounts = $dbs->query( "
            SELECT chart.accno 
            FROM partstax 
            JOIN chart ON partstax.chart_id = chart.id 
            WHERE partstax.parts_id = ?",
            $part->{id} )->arrays;

        # Add tax accounts as an array of accnos
        $part->{taxaccounts} = [ map { $_->[0] } @$taxaccounts ];
    }
    return $parts;
};
$api->get(
    '/create_links/:module' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);
        my $module = $c->param('module');

        # List of valid modules
        my @valid_modules =
          qw(customer vendor Vendor Customer ic gl chart gl_report projects incomestatement employees reminder import alltaxes tax_report payments payments_report import_bank);

        # Return empty JSON object if module not valid
        return $c->render( json => {} )
          unless grep { $_ eq $module } @valid_modules;

        my $tax_accounts = $dbs->query(
            "SELECT t.*, c.description, c.accno, c.link,
                CONCAT(c.accno, '--', c.description) AS label
         FROM tax t
         JOIN chart c ON (c.id = t.chart_id)
         ORDER BY c.accno"
        )->hashes;
        
        my $languages = $dbs->query("SELECT * FROM language")->hashes;

        my $accounts           = $c->get_accounts($client);
        my $currencies         = $c->get_currencies($client);
        my $customers          = $c->get_vc( 'customer', $client );
        my $vendors            = $c->get_vc( 'vendor',   $client );
        my $projects           = $c->get_projects($client);
        my $gifi               = $c->get_gifi($client);
        my $defaults           = $c->get_defaults($client);
        my $parts              = $c->get_items( $dbs, $client );
        my $formatted_closedto = $defaults->{closedto};
        my $paymentfile        = $defaults->{paymentfile};

        if (   $formatted_closedto
            && $formatted_closedto =~ /^(\d{4})(\d{2})(\d{2})$/ )
        {
            $formatted_closedto = "$1-$2-$3";
        }

        my $line_tax = $defaults->{linetax} ? 1 : 0;

        my $connection = $dbs->query("SELECT * FROM connections")->hash;

        if ($connection) {
            $connection = {
                type  => $connection->{type},
                error => $connection->{error},
            };
        }
        else {
            $connection = { type => 'local', };
        }

        my $response;

        #----------------
        # Chart
        #----------------
        if ( $module eq 'chart' ) {
            return unless $c->check_perms('system.chart');
            $response = { gifi => $gifi, };
        }

        #----------------
        # CUSTOMER module
        #----------------
        elsif ( lc($module) eq 'customer' ) {
            return unless $c->check_perms('customer');

            my $lock        = $c->lock_number( $dbs, 'sinumber' );
            my $role        = 'P';
            my $departments = $c->get_departments($role);

            $response = {
                currencies   => $currencies,
                accounts     => $accounts,
                tax_accounts => $tax_accounts,
                customers    => $customers,
                vendors      => $vendors,
                linetax      => $line_tax,
                departments  => $departments,
                projects     => $projects,
                locknumber   => $lock,
                revtrans     => $defaults->{revtrans},
                closedto     => $formatted_closedto,
                connection   => $connection,
                record       => $defaults->{ar_accno_id},
                payment => $defaults->{AR_paid},
                term_days    => $defaults->{term_days} || 0,
                languages    => $languages
            };
        }

        #-------------
        # VENDOR module
        #-------------
        elsif ( lc($module) eq 'vendor' ) {
            return unless my $form = $c->check_perms('customer');

            my $lock        = $c->lock_number( $dbs, 'vinumber' );
            my $role        = undef;
            my $departments = $c->get_departments($role);

            my $stations      = [];
            my $user_stations = [];
            if ($ai_plugin) {
                $stations      = $c->get_stations($form);
                $user_stations = $c->get_user_stations($form);
            }

            $response = {
                currencies    => $currencies,
                accounts      => $accounts,
                tax_accounts  => $tax_accounts,
                customers     => $customers,
                vendors       => $vendors,
                linetax       => $line_tax,
                departments   => $departments,
                projects      => $projects,
                locknumber    => $lock,
                revtrans      => $defaults->{revtrans},
                closedto      => $formatted_closedto,
                connection    => $connection,
                record        => $defaults->{ap_accno_id},
                payment       => $defaults->{AP_paid},
                stations      => $stations,
                user_stations => $user_stations,
                paymentfile   => $paymentfile,
                term_days     => $defaults->{term_days} || 0,
                languages     => $languages
            };
        }

        #-------------------
        # GOODSSERVICES module
        #-------------------
        elsif ( $module eq 'ic' ) {
            return unless $c->check_perms('items');
            my $role        = undef;
            my $departments = $c->get_departments($role);

            $response = {
                currencies   => $currencies,
                accounts     => $accounts,
                tax_accounts => $tax_accounts,
                customers    => $customers,
                vendors      => $vendors,
                linetax      => $line_tax,
                departments  => $departments,
                projects     => $projects,
                defaults     => $defaults
            };
        }

        #--------------
        # Reminder module
        #--------------
        elsif ( $module eq 'reminder' ) {
            return unless $c->check_perms('customer.reminder');
            my $departments = $c->get_departments('P');
            $response = {
                customers   => $customers,
                departments => $departments,
            };
        }

        #--------------
        # GL_REPORT module
        #--------------
        elsif ( $module eq 'gl_report' ) {
            return unless $c->check_perms('gl.transactions');
            my $role        = undef;
            my $departments = $c->get_departments($role);

            $response = {
                currencies   => $currencies,
                accounts     => $accounts,
                tax_accounts => $tax_accounts,
                customers    => $customers,
                vendors      => $vendors,
                linetax      => $line_tax,
                departments  => $departments,
                projects     => $projects,
            };
        }

        elsif ( $module eq 'gl' ) {
            return unless $c->check_perms('gl.add');
            my $role        = undef;
            my $departments = $c->get_departments($role);
            my $lock        = $c->lock_number( $dbs, 'glnumber' );

            $response = {
                currencies   => $currencies,
                accounts     => $accounts,
                tax_accounts => $tax_accounts,
                customers    => $customers,
                vendors      => $vendors,
                linetax      => $line_tax,
                departments  => $departments,
                projects     => $projects,
                locknumber   => $lock,
                revtrans     => $defaults->{revtrans},
                closedto     => $formatted_closedto,
                connection   => $connection,
            };
        }

        #--------------
        # PROJECTS module
        #--------------
        elsif ( $module eq 'projects' ) {
            return unless $c->check_perms('system.projects');
            my $role        = undef;
            my $departments = $c->get_departments($role);

            $response = {
                currencies   => $currencies,
                accounts     => $accounts,
                tax_accounts => $tax_accounts,
                customers    => $customers,
                vendors      => $vendors,
                linetax      => $line_tax,
                departments  => $departments,
                projects     => $projects,
            };
        }

        #---------------------
        # INCOMESTATEMENT module
        #---------------------
        elsif ( $module eq 'incomestatement' ) {
            return unless $c->check_perms('reports.income');
            my $role        = undef;
            my $departments = $c->get_departments($role);

            $response = {
                currencies   => $currencies,
                accounts     => $accounts,
                tax_accounts => $tax_accounts,
                customers    => $customers,
                vendors      => $vendors,
                linetax      => $line_tax,
                departments  => $departments,
                projects     => $projects,
            };
        }

        #---------------
        # EMPLOYEES module
        #---------------
        elsif ( $module eq 'employees' ) {
            return unless $c->check_perms('system.user.employees');
            my $role        = undef;
            my $departments = $c->get_departments($role);

            $response = {
                currencies   => $currencies,
                accounts     => $accounts,
                tax_accounts => $tax_accounts,
                customers    => $customers,
                vendors      => $vendors,
                linetax      => $line_tax,
                departments  => $departments,
                projects     => $projects,
            };
        }

        #---------------
        # Import
        #---------------
        elsif ( $module eq 'import' ) {
            return unless $c->check_perms('import.gl');
            my $role        = undef;
            my $departments = $c->get_departments($role);

            $response = {
                currencies   => $currencies,
                accounts     => $accounts,
                tax_accounts => $tax_accounts,
                customers    => $customers,
                vendors      => $vendors,
                departments  => $departments,
                projects     => $projects,
                closedto     => $formatted_closedto,
                parts        => $parts,
            };
        }

        elsif ( $module eq 'alltaxes' ) {
            return unless $c->check_perms('reports.alltaxes');
            my $role        = undef;
            my $departments = $c->get_departments($role);
            $response = { departments => $departments, };
        }
        elsif ( $module eq 'tax_report' ) {
            return
              unless $c->check_perms('vendor.taxreport,customer.taxreport');
            my $role        = undef;
            my $departments = $c->get_departments($role);
            $response = {
                departments  => $departments,
                tax_accounts => $tax_accounts,
            };
        }
        elsif ( $module eq 'payments' ) {
            return unless $c->check_perms('cash.receipts,cash.payments');
            my $role        = undef;
            my $departments = $c->get_departments($role);
            $response = {
                customers   => $customers,
                vendors     => $vendors,
                accounts    => $accounts,
                departments => $departments,
                currencies  => $currencies,
                closedto    => $formatted_closedto,
            };
        }
        elsif ( $module eq 'payments_report' ) {
            return
              unless $c->check_perms('cash.report.customer,cash.report.vendor');
            my $role        = undef;
            my $departments = $c->get_departments($role);
            $response = {
                departments => $departments,
                accounts    => $accounts,
                customers   => $customers,
                vendors     => $vendors
            };
        }
        elsif ( $module eq 'import_bank' ) {
            return unless $c->check_perms('import.bank');
            my $accounts         = $accounts->{all};
            my $defaults         = $c->get_defaults();
            my $clearing_account = $defaults->{clearing};
            my $bank_accounts    = $accounts->{payment};
            $response = {
                payment_accounts => $bank_accounts,
                clearing_account => $clearing_account
            };
        }

        # If we got here, it means we have a valid module and passed checks
        $c->render( json => $response );
    }
);
$api->get(
    '/last_transactions/:module' => sub {
        my $c       = shift;
        my $module  = $c->param('module');
        my $client  = $c->param('client');
        my $invoice = $c->param('invoice');
        my $dbs     = $c->dbs($client);

        my $sql;
        if ( $module eq 'gl' ) {
            return unless $c->check_perms('gl.transaction');
            $sql = qq{
                SELECT
        gl.*,
        d.description  AS department,
        COALESCE(a.amount, 0) AS amount
        FROM gl
        LEFT JOIN (
        SELECT
            trans_id,
            SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) AS amount
        FROM acc_trans
        GROUP BY trans_id
        ) AS a
        ON a.trans_id = gl.id
        LEFT JOIN department AS d
        ON d.id = gl.department_id
        ORDER BY gl.transdate DESC, gl.id DESC
        LIMIT 5; 
        }
        }
        elsif ( $module eq 'ar' || $module eq 'ap' ) {
            my $db    = $module;
            my $vc    = $module eq 'ar' ? 'customer'    : 'vendor';
            my $vc_id = $module eq 'ar' ? 'customer_id' : 'vendor_id';
            if ( !$invoice ) {
                $invoice = 'true';
            }
            if ( $module eq 'ar' ) {
                return unless $c->check_perms('customer.transactions');
            }
            elsif ( $module eq 'ap' ) {
                return unless $c->check_perms('vendor.transactions');
            }
            $sql = qq{
                SELECT db.*, vc.name FROM $db db
                LEFT JOIN $vc vc on db.$vc_id = vc.id
                WHERE db.invoice = $invoice
                ORDER BY db.id DESC
                LIMIT 5;
                }
        }
        elsif ( $module eq 'yearend' ) {
            return unless $c->check_perms('system.yearend');
            $sql = qq{
                SELECT
        gl.*,
        d.description  AS department,
        COALESCE(a.amount, 0) AS amount
        FROM yearend y
        JOIN gl ON gl.id = y.trans_id
        LEFT JOIN (
        SELECT
            trans_id,
            SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) AS amount
        FROM acc_trans
        GROUP BY trans_id
        ) AS a
        ON a.trans_id = gl.id
        LEFT JOIN department AS d
        ON d.id = gl.department_id
        ORDER BY y.transdate DESC, gl.id DESC
        LIMIT 5;
            }
        }
        elsif ( $module eq 'oe' ) {
            my $vc      = $c->param('vc');
            my $oe_type = $c->param('oe_type');
            return unless $c->check_perms("$vc.$oe_type");
            my $quotation = $oe_type eq 'quotation' ? 'true'  : 'false';
            my $vc_id     = $vc eq 'customer' ? 'customer_id' : 'vendor_id';
            $sql = qq{
                SELECT oe.*, vc.name FROM oe oe
                JOIN $vc vc on oe.$vc_id = vc.id
                WHERE oe.quotation = $quotation
                ORDER BY oe.id DESC
                LIMIT 5;
                }
        }

        my $transactions = $dbs->query($sql)->hashes;
        $c->render( json => $transactions );
    }
);

$api->get(
    '/next_number/:module' => sub {
        my $c      = shift;
        my $module = $c->param('module');
        my $client = $c->param('client');
        my $form   = new Form;
        my $number;
        if ( $module eq 'gl' ) {
            return unless $form = $c->check_perms('gl.add,gl.import');
            $number = $form->update_defaults( $c->slconfig, 'glnumber' );
        }
        elsif ( $module eq 'ar' ) {
            return
              unless $form = $c->check_perms(
'customer.transaction,customer.creditinvoicecustomer.import,customer.invoice'
              );
            $number = $form->update_defaults( $c->slconfig, 'sinumber' );
        }
        elsif ( $module eq 'ap' ) {
            return
              unless $form = $c->check_perms(
'vendor.transaction,vendor.debitinvoice,vendor.import,vendor.invoice'
              );
            $number = $form->update_defaults( $c->slconfig, 'vinumber' );
        }
        elsif ( $module eq 'customer' ) {
            return
              unless $form = $c->check_perms('customer.add,customer.import');
            $number = $form->update_defaults( $c->slconfig, 'customernumber' );
        }
        elsif ( $module eq 'vendor' ) {
            return unless $form = $c->check_perms('vendor.add,vendor.import');
            $number = $form->update_defaults( $c->slconfig, 'vendornumber' );
        }
        elsif ( $module eq 'customer_order' ) {
            return unless $form = $c->check_perms('customer.order');
            $number = $form->update_defaults( $c->slconfig, 'sonumber' );
        }
        elsif ( $module eq 'customer_quotation' ) {
            return unless $form = $c->check_perms('customer.quotation');
            $number = $form->update_defaults( $c->slconfig, 'quonumber' );
        }
        elsif ( $module eq 'vendor_order' ) {
            return unless $form = $c->check_perms('vendor.order');
            $number = $form->update_defaults( $c->slconfig, 'ponumber' );
        }
        elsif ( $module eq 'vendor_quotation' ) {
            return unless $form = $c->check_perms('vendor.quotation');
            $number = $form->update_defaults( $c->slconfig, 'rfqnumber' );
        }
        $c->render( json => { number => $number } );
    }
);
###############################
####                       ####
####         ARAP          ####
####                       ####
###############################

$api->get(
    '/arap/batch/:vc/:type' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $vc     = $c->param('vc');
        return unless $c->check_perms("$vc.batch");

        my $dbs = $c->dbs($client);

        # Get query parameters
        my $params        = $c->req->params->to_hash;
        my $open          = $params->{open}       // 1;
        my $closed        = $params->{closed}     // 0;
        my $onhold        = $params->{onhold}     // 0;
        my $emailed       = $params->{emailed}    // 0;
        my $notemailed    = $params->{notemailed} // 1;
        my $transdatefrom = $params->{transdatefrom};
        my $transdateto   = $params->{transdateto};
        my $invnumber     = $params->{invnumber};
        my $description   = $params->{description};
        my $customer_id   = $params->{customer_id};

        my $query = q{
            SELECT 
                a.id, vc.name,
                vc.customernumber AS vcnumber,
                a.invnumber, a.transdate,
                a.ordnumber, a.quonumber, a.invoice,
                'ar' AS tablename, '' AS spoolfile, a.description, a.amount,
                'customer' AS vc,
                ad.city, vc.email, 'customer' AS db,
                vc.id AS vc_id,
                a.shippingpoint, a.shipvia, a.waybill, a.terms,
                a.duedate, a.notes, a.intnotes,
                a.amount AS netamount, a.paid,
                c.id as contact_id, c.firstname, c.lastname, c.salutation,
                c.contacttitle, c.occupation, c.phone as contactphone,
                c.fax as contactfax, c.email as contactemail,
                s.emailed
            FROM ar a
            JOIN customer vc ON (a.customer_id = vc.id)
            JOIN address ad ON (ad.trans_id = vc.id)
            LEFT JOIN contact c ON vc.id = c.trans_id
            LEFT JOIN status s ON s.trans_id = a.id AND s.formname = 'invoice'
            WHERE a.invoice = '1'
            AND a.amount > 0
            AND a.approved = '1'
        };

        # Add filters based on parameters
        if ($onhold) {
            $query .= " AND a.onhold = '1'";
        }
        else {
            if ( $open && !$closed ) {
                $query .= " AND a.amount != a.paid";
            }
            elsif ( $closed && !$open ) {
                $query .= " AND a.amount = a.paid";
            }
        }

        # Email status filters
        if ( $emailed && !$notemailed ) {
            $query .= " AND s.emailed = '1'";
        }
        elsif ( $notemailed && !$emailed ) {
            $query .= " AND (s.emailed IS NULL OR s.emailed = '0')";
        }

        # Date range filters
        if ($transdatefrom) {
            $query .= " AND a.transdate >= '$transdatefrom'";
        }
        if ($transdateto) {
            $query .= " AND a.transdate <= '$transdateto'";
        }

        # Invoice number filter
        if ($invnumber) {
            $invnumber = $dbs->quote("%$invnumber%");
            $query .= " AND a.invnumber ILIKE $invnumber";
        }

        # Description filter
        if ($description) {
            $description = $dbs->quote("%$description%");
            $query .= " AND a.description ILIKE $description";
        }

        # Customer ID filter
        if ($customer_id) {
            $query .= " AND a.customer_id = $customer_id";
        }

        $query .= " ORDER BY a.transdate DESC";

        my $results = $dbs->query($query)->hashes;

        $c->render( json => $results );
    }
);
$api->get(
    '/arap/transactions/:vc' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $vc     = $c->param('vc');
        return unless my $form = $c->check_perms("$vc.transactions");
        my $data = $c->req->params->to_hash;

        unless ( $vc eq 'vendor' || $vc eq 'customer' ) {
            return $c->render(
                json => {
                    error => 'Invalid type. Must be either vendor or customer.'
                },
                status => 400
            );
        }

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

        # Handle entity-specific fields (single id or multiple: comma-separated / repeated param)
        if ( defined $data->{"vc_id"} && $data->{"vc_id"} ne '' ) {
            my $vc_ids = $data->{"vc_id"};
            $vc_ids = [ $vc_ids ] unless ref $vc_ids eq 'ARRAY';
            $vc_ids = [ split( /\s*,\s*/, $vc_ids->[0] ) ] if @$vc_ids == 1 && $vc_ids->[0] =~ /,/;
            $vc_ids = [ grep { /\S/ } map { ref $_ ? $_ : $_ } @$vc_ids ];
            $form->{"${vc}_id"} = @$vc_ids == 1 ? $vc_ids->[0] : $vc_ids;
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
            $totals->{amount}    += $transaction->{amount}    || 0;
            $totals->{netamount} += $transaction->{netamount} || 0;
            $totals->{paid}      += $transaction->{paid}      || 0;
            $transaction->{paymentdiff} =
              $transaction->{amount} - $transaction->{paid};
            $totals->{paymentdiff} += $transaction->{paymentdiff} || 0;
            $totals->{tax}         += $transaction->{tax}         || 0;
        }
        my $dbs = $c->dbs($client);
        eval {
            # Fetch files for all transactions in a single operation
            FM->get_files_for_transactions(
                $dbs,
                {
                    api_url => $base_url,
                    client  => $client
                },
                $form->{transactions}
            );
        };
        if ($@) {
            $c->app->log->error("Error getting files for transactions: $@");
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

$api->get(
    '/arap/overview/:vc' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $vc     = $c->param('vc');
        return unless my $form = $c->check_perms("$vc.overview");
        my $dbs    = $c->dbs($client);
        my $params = $c->req->params->to_hash;

        unless ( $vc eq 'vendor' || $vc eq 'customer' ) {
            return $c->render(
                status => 400,
                json   => {
                    error => 'Invalid type. Must be either vendor or customer.'
                }
            );
        }

        my $table = ( $vc eq 'customer' ) ? 'ar' : 'ap';

        my $query = qq|
            SELECT
                a.id,
                a.invnumber AS invnum,
                a.${vc}_id AS vc_id,
                vc.name AS vc_name,
                a.transdate,
                a.duedate,
                a.amount AS totalamount,
                a.paid AS amountpaid,
                a.description,
                a.invoice
            FROM $table a
            JOIN $vc vc ON (a.${vc}_id = vc.id)
            WHERE a.approved = '1'
        |;

        my @binds;

        if ( $params->{transdatefrom} ) {
            $query .= " AND a.transdate >= ?";
            push @binds, $params->{transdatefrom};
        }
        if ( $params->{transdateto} ) {
            $query .= " AND a.transdate <= ?";
            push @binds, $params->{transdateto};
        }
        if ( $params->{"${vc}_id"} ) {
            my $vc_ids = $params->{"${vc}_id"};
            $vc_ids = [ $vc_ids ] unless ref $vc_ids eq 'ARRAY';
            $vc_ids = [ split( /\s*,\s*/, $vc_ids->[0] ) ] if @$vc_ids == 1 && $vc_ids->[0] =~ /,/;
            $vc_ids = [ grep { /\S/ } map { ref $_ ? $_ : $_ } @$vc_ids ];
            if (@$vc_ids) {
                $query .= " AND a.${vc}_id IN (" . join( ", ", ("?") x @$vc_ids ) . ")";
                push @binds, @$vc_ids;
            }
        }
        if ( $params->{$vc} ) {
            $query .= " AND lower(vc.name) LIKE lower(?)";
            push @binds, "%" . $params->{$vc} . "%";
        }
        if ( $params->{invnumber} ) {
            $query .= " AND lower(a.invnumber) LIKE lower(?)";
            push @binds, "%" . $params->{invnumber} . "%";
        }
        if ( $params->{description} ) {
            $query .= " AND lower(a.description) LIKE lower(?)";
            push @binds, "%" . $params->{description} . "%";
        }

        $query .= " ORDER BY a.transdate DESC";

        my $rows = $dbs->query( $query, @binds )->hashes;

        my $summary = {
            transactions => {
                open     => { no => 0, amount => 0, transactions => [] },
                closed   => { no => 0, amount => 0, transactions => [] },
                overdue  => { no => 0, amount => 0, transactions => [] },
                overpaid => { no => 0, amount => 0, transactions => [] },
            }
        };

        my ( $sec, $min, $hour, $mday, $mon, $year ) = localtime();
        my $today = sprintf( "%04d-%02d-%02d", $year + 1900, $mon + 1, $mday );

        foreach my $r (@$rows) {
            my $amount           = $r->{totalamount} // 0;
            my $paid             = $r->{amountpaid}  // 0;
            my $status           = 'open';
            my $remaining_amount = 0;

            if ( abs($paid) > abs($amount) ) {
                $status = 'overpaid';

                # For overpaid, the amount is the excess paid
                $remaining_amount = abs($paid) - abs($amount);
            }
            elsif ( abs($paid) == abs($amount) ) {
                $status = 'closed';

                # For closed, show the total original amount
                $remaining_amount = abs($amount);
            }
            else {
                # For open/overdue, the amount is the remaining balance
                $remaining_amount = abs($amount) - abs($paid);

                if ( $r->{duedate} && $r->{duedate} lt $today ) {
                    $status = 'overdue';
                }
                else {
                    $status = 'open';
                }
            }

            $summary->{transactions}->{$status}->{no}++;
            $summary->{transactions}->{$status}->{amount} += $remaining_amount;

            $r->{status} = $status;

            $r->{remaining_amount} = $remaining_amount;

            push @{ $summary->{transactions}->{$status}->{transactions} }, $r;
        }

        $c->render( json => $summary );
    }
);

$api->get(
    '/arap/reminder/customer' => sub {
        my $c          = shift;
        my $client     = $c->param('client');
        my $department = $c->param('department');
        my $customer   = $c->param('customer');
        return unless my $form = $c->check_perms("customer.reminder");
        $form->{vc} = 'customer';
        if ($department) {
            $form->{department} = "a--$department";
        }
        if ($customer) {
            $form->{customer} = "a--$customer";
        }
        RP->reminder( $c->slconfig, $form );
        return $c->render( json => { transactions => $form->{AG} } );
    }
);
$api->post(
    '/arap/reminder/customer' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        return unless my $form = $c->check_perms("customer.reminder");
        my $dbs  = $c->dbs($client);
        my $data = $c->req->json;

        # Expect an array reference for the items
        my $items = $data->{items};
        unless ( ref $items eq 'ARRAY' ) {
            return $c->render(
                json => { error => "Invalid data: expected an array of items" }
            );
        }

        $form->{vc} = "customer";

        foreach my $item (@$items) {
            my $id    = $item->{id};
            my $level = $item->{level};

# Delete any existing status for the given transaction where the formname begins with "reminder_"
            my $delete_query = qq|
                DELETE FROM status
                WHERE trans_id = ?
                AND formname LIKE 'reminder_%'
            |;
            $dbs->query( $delete_query, $id );

            # If a valid level is provided, insert a new status record
            if ( defined $level && $level =~ /^\d+$/ && $level > 0 ) {
                my $insert_query = qq|
                    INSERT INTO status (trans_id, formname)
                    VALUES (?, ?)
                |;
                $dbs->query( $insert_query, $id, "reminder$level" );
            }
        }

        # Commit the transaction if the DB handle supports it
        $dbs->commit if $dbs->can("commit");

        return $c->render( json => { transactions => $form->{AG} } );
    }
);

# Used to fetch & load information in other forms AR/AP
# REPLACE WITH GET LINKS
$api->get(
    '/arap/list/:vc' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $vc     = $c->param('vc');

        return
          unless my $form = $c->check_perms(
"$vc.transaction,$vc.invoice,$vc.invoice_return,$vc.transaction_return"
          );

        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

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
        my $dbs    = $c->dbs($client);
        my $vc     = $c->param('vc');
        return
          unless my $form = $c->check_perms(
"$vc.transaction,$vc.invoice,$vc.invoice_return,$vc.transaction_return"
          );
        my $id = $c->param('id');

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

        my $bank_accounts =
          $dbs->query( "SELECT * FROM bank_account WHERE trans_id = ?", $id )
          ->hashes;
        $form->{bank_accounts} = $bank_accounts;

        my $lc = $form->{language_code} // '';
        $form->{email_message} = $c->resolve_email_message_template(
            $dbs, $id, $lc, 'invoice_send', undef );
        for my $lvl ( 1 .. 3 ) {
            $form->{"reminder_${lvl}_email_message"} =
              $c->resolve_email_message_template( $dbs, $id, $lc,
                "reminder_$lvl", undef );
        }

        # Render the form object as JSON
        $c->render( json => {%$form} );
    }
);

# Used for Customer/Vendor Forms

$api->get(
    '/bank/:vc' => sub {
        my $c  = shift;
        my $vc = $c->param('vc');
        return unless my $form = $c->check_perms("$vc.add");
        my $client   = $c->param('client');
        my $trans_id = $c->param('trans_id');

        unless ($trans_id) {
            return $c->render(
                status => 400,
                json   => { message => "trans_id parameter is required" }
            );
        }

        my $dbs = $c->dbs($client);
        return unless $dbs;

        # Query bank accounts with address information
        my $results = $dbs->query(
            q{
                SELECT 
                    ba.id,
                    ba.trans_id,
                    ba.name,
                    ba.iban,
                    ba.bic,
                    ba.address_id,
                    ba.dcn,
                    ba.rvc,
                    ba.membernumber,
                    ba.clearingnumber,
                    ba.qriban,
                    ba.strdbkginf,
                    ba.invdescriptionqr,
                    ba.is_primary,
                    ba.created_at,
                    ba.updated_at,
                    a.address1,
                    a.address2,
                    a.city,
                    a.state,
                    a.zipcode,
                    a.country
                FROM bank_account ba
                LEFT JOIN address a ON ba.address_id = a.id
                WHERE ba.trans_id = ?
                ORDER BY ba.is_primary DESC, ba.id ASC
            },
            $trans_id
        )->hashes;

        $c->render( json => $results );
    }
);
$api->post(
    '/vc/:vc/bank' => sub {
        my $c  = shift;
        my $vc = $c->param('vc');
        return unless my $form = $c->check_perms("$vc.add");
        my $client = $c->param('client');
        my $params = $c->req->json;

        unless ( $params->{trans_id} ) {
            return $c->render(
                status => 400,
                json   => { message => "trans_id is required" }
            );
        }

        my $dbs = $c->dbs($client);
        return unless $dbs;

        my $bank_id    = $params->{id};
        my $trans_id   = $params->{trans_id};
        my $is_primary = $params->{is_primary} // 0;
        my $address_id = $params->{address_id};

        eval {
            # Handle address if provided
            if (   $params->{address1}
                || $params->{address2}
                || $params->{city}
                || $params->{state}
                || $params->{zipcode}
                || $params->{country} )
            {
                if ($address_id) {

                    # Update existing address
                    $dbs->query(
                        q{
                            UPDATE address 
                            SET address1 = ?, address2 = ?, city = ?, 
                                state = ?, zipcode = ?, country = ?
                            WHERE id = ?
                        },
                        $params->{address1}, $params->{address2},
                        $params->{city},     $params->{state},
                        $params->{zipcode},  $params->{country},
                        $address_id
                    );
                }
                else {
                    # Insert new address
                    my $result = $dbs->query(
                        q{
                            INSERT INTO address 
                                (trans_id, address1, address2, city, state, zipcode, country)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            RETURNING id
                        },
                        $trans_id,           $params->{address1},
                        $params->{address2}, $params->{city},
                        $params->{state},    $params->{zipcode},
                        $params->{country}
                    )->hash;
                    $address_id = $result->{id};
                }
            }

            # If this account is being set as primary, unset all others
            if ($is_primary) {
                $dbs->query(
                    q{
                        UPDATE bank_account 
                        SET is_primary = FALSE 
                        WHERE trans_id = ? AND id != ?
                    },
                    $trans_id, $bank_id // 0
                );
            }

            # Update or Insert bank account
            if ($bank_id) {

                # Update existing bank account
                $dbs->query(
                    q{
                        UPDATE bank_account 
                        SET name = ?, iban = ?, bic = ?, address_id = ?,
                            dcn = ?, rvc = ?, membernumber = ?, 
                            clearingnumber = ?, qriban = ?, strdbkginf = ?,
                            invdescriptionqr = ?, is_primary = ?,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    },
                    $params->{name},
                    $params->{iban},
                    $params->{bic},
                    $address_id,
                    $params->{dcn},
                    $params->{rvc},
                    $params->{membernumber},
                    $params->{clearingnumber},
                    $params->{qriban},
                    $params->{strdbkginf},
                    $params->{invdescriptionqr},
                    $is_primary,
                    $bank_id
                );

                $c->render(
                    json => {
                        success => 1,
                        message => "Bank account updated successfully",
                        id      => $bank_id
                    }
                );
            }
            else {
                # Insert new bank account
                my $result = $dbs->query(
                    q{
                        INSERT INTO bank_account 
                            (trans_id, name, iban, bic, address_id, dcn, rvc,
                             membernumber, clearingnumber, qriban, strdbkginf,
                             invdescriptionqr, is_primary, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        RETURNING id
                    },
                    $trans_id,
                    $params->{name},
                    $params->{iban},
                    $params->{bic},
                    $address_id,
                    $params->{dcn},
                    $params->{rvc},
                    $params->{membernumber},
                    $params->{clearingnumber},
                    $params->{qriban},
                    $params->{strdbkginf},
                    $params->{invdescriptionqr},
                    $is_primary
                )->hash;

                $c->render(
                    json => {
                        success => 1,
                        message => "Bank account created successfully",
                        id      => $result->{id}
                    }
                );
            }
        };
        if ($@) {
            $c->render(
                status => 500,
                json   => {
                    success => 0,
                    message => "Failed to save bank account",
                    error   => "$@"
                }
            );
        }
    }
);

$api->get(
    '/arap/:vc/' => sub {
        my $c  = shift;
        my $vc = $c->param('vc');
        return unless my $form = $c->check_perms("$vc.search");
        my $client = $c->param('client');
        my $params = $c->req->params->to_hash;

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
        my $c  = shift;
        my $id = $c->param('id');
        my $vc = $c->param('vc');
        return unless my $form = $c->check_perms("$vc.add");
        my $client = $c->param('client');

        my $dbs = $c->dbs($client);
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

        my $lc = $form->{language_code} // '';
        $form->{message} = $c->resolve_email_message_template(
            $dbs, $id, $lc, 'invoice_send', undef );
        for my $lvl ( 1 .. 3 ) {
            $form->{"reminder_${lvl}_message"} =
              $c->resolve_email_message_template( $dbs, $id, $lc,
                "reminder_$lvl", undef );
        }

        # Render the filtered JSON response
        $c->render( json => {%$form} );
    }
);

$api->post(
    '/arap/:vc/' => sub {
        my $c      = shift;
        my $vc     = $c->param('vc');
        my $client = $c->param('client');
        return unless my $form = $c->check_perms("$vc.add");

        my $params = $c->req->json;

        $form->{db} = lc($vc);
        for ( keys %$params ) { $form->{$_} = $params->{$_} if $params->{$_} }
        $form->{message} = $params->{message} if exists $params->{message};
        for my $k (qw(reminder_1_message reminder_2_message reminder_3_message)) {
            $form->{$k} = $params->{$k} if exists $params->{$k};
        }
        $form->{ $vc =~ /^vendor$/i ? 'vendornumber' : 'customernumber' } =
          $params->{vcnumber};
        CT->save( $c->slconfig, $form );

        # Render the filtered JSON response
        $c->render( json => {%$form} );
    }
);

$api->post(
    '/import/invoice/:vc/' => sub {
        my $c  = shift;
        my $vc = $c->param('vc');
        return unless my $form = $c->check_perms("$vc.invoice");
        my $client = $c->param('client');

        my $transactions = $c->req->json;
        unless ( ref($transactions) eq 'ARRAY' ) {
            return $c->render(
                status => 400,
                json   => { message => "Expected a JSON array of invoices" }
            );
        }

        my @results;
        foreach my $transaction (@$transactions) {
            return unless my $form = $c->check_perms("$vc.invoice");
            my $new_invoice_id = $c->process_invoice( $transaction, $form );
            push @results,
              {
                id      => $new_invoice_id,
                success => defined($new_invoice_id),
                error   => defined($new_invoice_id)
                ? undef
                : "Failed to process invoice"
              };
        }

        $c->render( json => \@results );
    }
);

$api->post(
    '/import/transaction/:vc/' => sub {
        my $c      = shift;
        my $vc     = $c->param('vc');
        my $client = $c->param('client');

        my $transactions = $c->req->json;
        unless ( ref($transactions) eq 'ARRAY' ) {
            return $c->render(
                status => 400,
                json   => { message => "Expected a JSON array of transactions" }
            );
        }

        my @results;
        foreach my $transaction (@$transactions) {
            return unless my $form = $c->check_perms("$vc.transaction");
            my $result =
              $c->process_transaction( $transaction, $form, $client );

            # Check if process_transaction returned an error
            if ( ref($result) eq 'HASH' && exists $result->{error} ) {
                push @results,
                  {
                    id         => undef,
                    success    => 0,
                    error      => $result->{message},
                    error_type => $result->{error}
                  };
            }
            else {
                push @results,
                  {
                    id      => $result,
                    success => 1,
                    error   => undef
                  };
            }
        }

        $c->render( json => \@results );
    }
);

$api->post(
    '/import/arap/:vc/' => sub {
        my $c  = shift;
        my $vc = $c->param('vc');
        return unless my $form = $c->check_perms("$vc.add");
        my $client = $c->param('client');

        my $transactions = $c->req->json;
        unless ( ref($transactions) eq 'ARRAY' ) {
            return $c->render(
                status => 400,
                json   => { message => "Expected a JSON array of transactions" }
            );
        }

        my @results;
        foreach my $transaction (@$transactions) {
            $form           = new Form;
            $form->{db}     = $vc;
            $form->{client} = $client;

            # Copy transaction data to form
            for my $key ( keys %$transaction ) {
                $form->{$key} = $transaction->{$key};
            }

            # Set vcnumber from transaction data
            $form->{ $vc =~ /^vendor$/i ? 'vendornumber' : 'customernumber' } =
              $transaction->{vcnumber};

            # Save the transaction
            CT->save( $c->slconfig, $form );

            push @results,
              {
                id      => $form->{id},
                success => !$form->{error},
                error   => $form->{error}
              };
        }

        $c->render( json => \@results );
    }
);

$api->get(
    '/:vc/history/' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $vc     = $c->param('vc');
        return unless my $form = $c->check_perms("$vc.history");

        $form->{db} = $vc;

        $form->{transdatefrom} = $c->param('transdatefrom')
          // '';    # Start date (YYYY-MM-DD)
        $form->{transdateto} = $c->param('transdateto')
          // '';    # End date (YYYY-MM-DD)
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
        my $c      = shift;
        my $client = $c->param('client');
        my $data   = $c->req->json;
        my $id     = $c->param('id');
        my $vc     = $c->param('vc');
        return unless my $form = $c->check_perms("$vc.transaction");
        my $transaction_type = $vc eq 'vendor' ? 'AP'      : 'AR';
        my $vc_field    = $vc eq 'vendor' ? 'vendornumber' : 'customernumber';
        my $vc_id_field = $vc eq 'vendor' ? 'vendor_id'    : 'customer_id';

        # Initialize required variables
        my $dbs = $c->dbs($client);
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        my $ml       = 1;
        my %myconfig = ();
        $form->{id} = $id;
        $form->{vc} = $vc;
        $form->create_links( $transaction_type, $c->slconfig, $vc );

# Calculate total amount before applying multiplier to determine if it's negative
        my $total_amount   = 0;
        my @sorted_entries = sort { $a->{id} <=> $b->{id} }
          @{ $form->{acc_trans}{"${transaction_type}_amount"} };

        foreach my $entry (@sorted_entries) {
            $total_amount += $entry->{amount};
        }

        # Determine transaction type (normal, credit_note, debit_note)
        my $is_negative = ( $total_amount < 0 );
        my $doc_type;
        my $amount_multiplier;

        if ( $transaction_type eq 'AR' ) {
            if ($is_negative) {
                $doc_type          = "credit_note";
                $amount_multiplier = 1;
            }
            else {
                $doc_type          = "transaction";
                $amount_multiplier = -1;
            }
        }
        else {    # AP
            if ($is_negative) {
                $doc_type          = "transaction";
                $amount_multiplier = 1;
            }
            else {
                $doc_type          = "debit_note";
                $amount_multiplier = -1;
            }
        }

        my @line_items;

        # For each transaction item
        for my $entry (@sorted_entries) {
            push @line_items,
              {
                accno       => $entry->{accno},
                description => $entry->{memo} || '',
                amount      => $amount_multiplier * ( -$entry->{amount} ),
                taxAccount  => $entry->{tax_accno},
                taxAmount   => $entry->{linetaxamount},
                project     => $entry->{project_id},
              };
        }

        # Create payments array
        my @payments;

        warn Dumper $form->{acc_trans}{"${transaction_type}_paid"};

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
                    account      => "$payment->{accno}"
                  };
            }
        }

        # Process tax information
        my @taxes;
        if ( $form->{acc_trans}{"${transaction_type}_tax"} ) {
            if ( $transaction_type eq 'AP' ) {
                $amount_multiplier = -1;
            }
            else {
                $amount_multiplier = 1;
            }
            if ( $doc_type eq 'debit_note' ) {
                $amount_multiplier = 1;
            }
            elsif ( $doc_type eq 'credit_note' ) {
                $amount_multiplier = -1;
            }
            @taxes = map {
                {
                    accno  => $_->{accno},
                    amount => $amount_multiplier * $_->{amount},
                    rate   => $_->{rate}
                }
            } @{ $form->{acc_trans}{"${transaction_type}_tax"} };
        }

        my $files = FM->get_files( $dbs, $c, $form );
        my $station_id;
        my $transfer_history;
        my $payment_file;
        my $payment_amount;
        if ( $vc eq 'vendor' && $ai_plugin ) {
            my $station_info = $c->invoice_station_info( $form->{id} );
            $station_id       = $station_info->{station_id};
            $transfer_history = $station_info->{transfer_history};
            $payment_file =
              $dbs->query( "SELECT * FROM payments WHERE transaction_id = ?",
                $form->{id} )->hash;
            my $ai_processing =
              $dbs->query( "SELECT * FROM ai_processing WHERE reference_id = ?",
                $form->{id} )->hash;
            if ( $payment_file || $ai_processing ) {
                $payment_file = 1;
            }
            my $ap_row =
              $dbs->query( "SELECT external_info FROM ap WHERE id = ?",
                $form->{id} )->hash;
            if ( $ap_row && $ap_row->{external_info} ) {
                my $info =
                  eval { decode_json( $ap_row->{external_info} ) } || {};
                $payment_amount = $info->{payment_amount}
                  if defined $info->{payment_amount};
            }
        }

        # Create the transformed data structure
        my $json_data = {
            $vc_field        => $form->{$vc_field},
            shippingPoint    => $form->{shippingpoint},
            shipVia          => $form->{shipvia},
            wayBill          => $form->{waybill},
            description      => $form->{description},
            notes            => $form->{notes},
            intnotes         => $form->{intnotes},
            invNumber        => $form->{invnumber},
            ordNumber        => $form->{ordnumber},
            invDate          => $form->{transdate},
            executionDate    => $form->{executiondate},
            dueDate          => $form->{duedate},
            poNumber         => $form->{ponumber},
            currency         => $form->{currency},
            exchangerate     => $form->{exchangerate},
            department_id    => $form->{department_id},
            id               => $form->{id},
            pending          => $form->{approved} ? '0' : '1',
            dcn              => $form->{dcn},
            recordAccount    => $form->{acc_trans}{$transaction_type}[0],
            paymentmethod_id => $form->{paymentmethod_id},
            $vc_id_field     => $form->{$vc_id_field},
            vc_bank_id       => $form->{vc_bank_id},
            lineitems        => \@line_items,
            payments         => \@payments,
            type             => $doc_type,
            files            => $files,
            station_id       => $station_id       ? $station_id       : undef,
            history          => $transfer_history ? $transfer_history : undef,
            payment_file     => $payment_file
            ? $payment_file
            : $form->{paymentfile},
            payment_amount => $payment_amount,
        };

        # Add tax information if present
        if (@taxes) {
            $json_data->{taxes}       = \@taxes;
            $json_data->{taxincluded} = $form->{taxincluded};
        }

        # Render the structured response in JSON format
        $c->render( json => $json_data );
    }
);

helper process_transaction => sub {
    my ( $c, $data, $form, $client, $system ) = @_;

    if ( !$client ) {
        $client = $c->param('client');
    }
    my $vc = $data->{vc} || $c->param('vc');
    $vc = $data->{vc} if $data->{vc};
    my $id  = $c->param('id');
    my $dbs = $c->dbs($client);

    $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

    $form->{type}   = $data->{type};
    $form->{vc}     = $vc eq 'vendor' ? 'vendor' : 'customer';
    $form->{client} = $client;

    # Basic transaction details
    $form->{id}            = $id if $id;
    $form->{invnumber}     = $data->{invNumber}   || '';
    $form->{description}   = $data->{description} || '';
    $form->{transdate}     = $data->{invDate};
    $form->{executiondate} = $data->{executionDate} || undef;
    $form->{duedate}       = $data->{dueDate};
    $form->{exchangerate}  = $data->{exchangerate} || 1;
    $form->{department}    = $data->{department}   || '';
    $form->{pending}       = $data->{pending} eq '0' ? undef : 1;

    # Handle vendor/customer specific fields
    if ( $vc eq 'vendor' ) {
        $form->{vendor_id} = $data->{vendor_id};
        $form->{vendor}    = $data->{vendor};
        $form->{AP}        = $data->{recordAccount};
    }
    else {
        $form->{customer_id} = $data->{customer_id};
        $form->{customer}    = $data->{customer};
        $form->{AR}          = $data->{recordAccount};
    }

    # Currency and other details
    $form->{currency}  = $data->{curr};
    $form->{notes}     = $data->{notes}     || '';
    $form->{intnotes}  = $data->{intnotes}  || '';
    $form->{ordnumber} = $data->{ordNumber} || '';
    $form->{ponumber}  = $data->{poNumber}  || '';
    $form->{dcn}       = $data->{dcn}       || '';

    # Line items
    my $total_amount = 0;
    $form->{rowcount} = scalar @{ $data->{lines} };
    my %line_tax_accounts;
    my %tax_totals;

    for my $i ( 1 .. $form->{rowcount} ) {
        my $line   = $data->{lines}[ $i - 1 ];
        my $amount = $line->{amount};
        $total_amount += $amount;

        $form->{"amount_$i"}        = $amount;
        $form->{"description_$i"}   = $line->{description};
        $form->{"tax_$i"}           = $line->{taxAccount};
        $form->{"linetaxamount_$i"} = $line->{taxAmount};
        $form->{ $form->{vc} eq 'vendor' ? "AP_amount_$i" : "AR_amount_$i" } =
          $line->{account};

        if ( $line->{taxAccount} && !$line->{taxAmount} ) {
            my $tax_amount = calc_line_tax( $dbs, $form->{transdate}, $amount,
                $line->{taxAccount} );
            $form->{"linetaxamount_$i"} = $tax_amount;
        }

        # Collect tax account information from line items
        if ( $line->{taxAccount} ) {
            $line_tax_accounts{ $line->{taxAccount} } = 1;

            # Accumulate tax totals per account
            $tax_totals{ $line->{taxAccount} } +=
              $form->{"linetaxamount_$i"} || 0;
        }

        # Project number if exists
        if ( $line->{project} ) {
            $form->{"projectnumber_$i"} = $line->{project};
        }
    }

    # Payments
    $form->{paidaccounts} = 0;
    for my $payment ( @{ $data->{payments} } ) {
        $form->{paidaccounts}++;
        my $i = $form->{paidaccounts};

        $form->{"datepaid_$i"}     = $payment->{date};
        $form->{"source_$i"}       = $payment->{source} || '';
        $form->{"memo_$i"}         = $payment->{memo}   || '';
        $form->{"paid_$i"}         = $payment->{amount};
        $form->{"exchangerate_$i"} = $payment->{exchangerate} || '';

        $form->{ $form->{vc} eq 'vendor' ? "AP_paid_$i" : "AR_paid_$i" } =
          $payment->{account} . "--";

        if ( my $accno = $payment->{account} ) {
            $dbs->query( "SELECT id FROM chart WHERE accno = ?", $accno )
              ->into( my $id );
            $form->{"paymentmethod_$i"} = "0--$id" if defined $id;
        }
    }

    # Taxes
    my @taxaccounts;
    if (%line_tax_accounts) {

        @taxaccounts = keys %line_tax_accounts;
        for my $accno (@taxaccounts) {
            $form->{"tax_$accno"}       = $tax_totals{$accno};
            $form->{"calctax_${accno}"} = 1;
            $total_amount += $tax_totals{$accno};
        }
        $form->{taxaccounts} = join( ' ', @taxaccounts );
    }
    elsif ( $data->{taxes} && ref( $data->{taxes} ) eq 'ARRAY' ) {

        for my $tax ( @{ $data->{taxes} } ) {
            push @taxaccounts, $tax->{accno};
            $form->{"tax_$tax->{accno}"} = $tax->{amount};
            my $accno = $tax->{accno};
            $form->{"calctax_${accno}"} = 1;
            $total_amount += $tax->{amount};
        }
        $form->{taxaccounts} = join( ' ', @taxaccounts );
    }
    $form->{taxincluded} = $data->{taxincluded} ? 1 : 0;
    unless ($system) {
        if ( $vc eq 'vendor' && $ai_plugin ) {
            my $access = $c->verify_station_access($form);
            unless ( $access == 1 ) {
                return
                  $access;   # this will return the error object from the helper
            }
        }

    }

    my $default_curr_result = $dbs->query("SELECT curr FROM curr WHERE rn = 1");
    my $default_curr_row    = $default_curr_result->hash;
    $form->{defaultcurrency} =
      $default_curr_row ? $default_curr_row->{curr} : $form->{currency};

    # Swiss QR: ar.paymentmethod_id must be bank.id (see IS.pm invoice_details). With no
    # payment rows, AA reads paymentmethod_0 — set it from the API so the column is stored.
    if ( $data->{paymentmethod_id} && !$form->{paidaccounts} ) {
        my $pm = $data->{paymentmethod_id} + 0;
        $form->{paymentmethod_0} = "0--$pm" if $pm;
    }   
    
    # Post the transaction
    eval { AA->post_transaction( $c->slconfig, $form ); } or do {

        my $error = $@;
        return {
            error   => 'post_transaction_failed',
            message => "Failed to post transaction: $error"
        };
    };

    if ( $data->{files} && ref $data->{files} eq 'ARRAY' ) {
        $form->{files}  = $data->{files};
        $form->{client} = $client;
        my $upload_result = FM->upload_files( $dbs, $c, $form, $vc );
        if ( ref($upload_result) ne 'HASH' || !$upload_result->{success} ) {
            my $upload_error =
              ref($upload_result) eq 'HASH' && $upload_result->{error}
              ? $upload_result->{error}
              : 'Unknown upload failure';
            return {
                error   => 'file_upload_failed',
                message => "Failed to upload attachment: $upload_error"
            };
        }
    }

    if ( $data->{vc_bank_id} ) {
        if ( $vc eq 'vendor' ) {
            $dbs->query( "UPDATE ap SET vc_bank_id = ? WHERE id = ?",
                $data->{vc_bank_id}, $form->{id} );
        }
        else {
            $dbs->query( "UPDATE ar SET vc_bank_id = ? WHERE id = ?",
                $data->{vc_bank_id}, $form->{id} );
        }
    }

    my $payment_amount = $data->{payment_amount} || 0;

    if ( $ai_plugin && $vc eq 'vendor' ) {
        if ( $data->{payment_file} ) {
            $c->add_payment( $form->{id}, $dbs, $payment_amount );
        }
    }

    return $form->{id};
};

$api->post(
    '/arap/transaction/:vc/:id' => { id => undef } => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $data;
        my $content_type = $c->req->headers->content_type || '';

        if ( $content_type =~ m!multipart/form-data!i ) {
            $data = handle_multipart_request($c);
        }
        else {
            $data = $c->req->json;
            if ( ref $data->{files} eq 'ARRAY' ) {
                $data->{files} = $c->decode_base64_files( $data->{files} );
            }
        }

        my $vc = $c->param('vc');
        return unless my $form = $c->check_perms("$vc.transaction");

        my $result = $c->process_transaction( $data, $form, $client );

        if ( ref($result) eq 'HASH' && exists $result->{error} ) {
            my $status = 400;
            if ( $result->{error} eq 'access_denied' ) {
                $status = 403;
            }
            elsif ( $result->{error} eq 'amount_exceeded' ) {
                $status = 400;
            }
            elsif ( $result->{error} eq 'no_amount_rules' ) {
                $status = 400;
            }
            elsif ( $result->{error} eq 'post_transaction_failed' ) {
                $status = 500;
            }

            return $c->render(
                status => $status,
                json   => $result
            );
        }

        $c->render( json => { id => $result } );
    }
);
$api->delete(
    'arap/transaction/:vc/:id' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $id     = $c->param('id');
        my $vc     = $c->param('vc');
        return unless my $form = $c->check_perms("$vc.transaction");
        $form->{id}               = $id;
        $form->{vc}               = $vc;
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        AA->delete_transaction( $c->slconfig, $form );
        $c->render( status => 204, data => '' );
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

        return unless my $form = $c->check_perms("$vc");
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
        my $ml     = 1;
        my $qty_ml = 1;

        # Create payments array
        my @payments;

        # For AR-paid or AP-paid, the key is the same pattern:
        #   AR_paid or AP_paid in the acc_trans hash.
        my $paid_key = $arap_key . '_paid';
        if ( $vc eq 'customer' ) { $ml = -1; }

        if ( $form->{type} eq 'invoice' ) {
            return unless $c->check_perms("$vc.invoice");
        }
        else { return unless $c->check_perms("$vc.invoice.return"); }
        if (
            $form->{type}
            && (   $form->{type} eq 'credit_invoice'
                || $form->{type} eq 'debit_invoice' )
          )
        {
            $ml = $ml * -1;
        }
        if ( $form->{type} eq 'credit_invoice' ) {
            $qty_ml = -1;
        }

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

      # Build line items
      # (The same structure should come out of invoice_details whether AR or AP)
        my @lines;
        if ( ref $form->{invoice_details} eq 'ARRAY' ) {
            @lines = map {
                {
                    id          => $_->{id},
                    partnumber  => $_->{partnumber},
                    description => $_->{description},
                    qty         => $_->{qty} * $qty_ml,
                    onhand      => $_->{onhand},
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
                    project          => $_->{project_id} || '',
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
                    amount => abs($_->{amount}),
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

        my $files = FM->get_files( $dbs, $c, $form );

        # Build JSON response
        my $json_data = {

            # Dynamic fields for vendor or customer
            $vc_field    => $form->{$vc_field},
            $vc_id_field => $form->{$vc_id_field},

            shippingPoint    => $form->{shippingpoint},
            shipVia          => $form->{shipvia},
            wayBill          => $form->{waybill},
            description      => $form->{invdescription},
            dcn              => $form->{dcn},
            notes            => $form->{notes},
            intnotes         => $form->{intnotes},
            invNumber        => $form->{invnumber},
            ordNumber        => $form->{ordnumber},
            invDate          => $form->{transdate},
            dueDate          => $form->{duedate},
            poNumber         => $form->{ponumber},
            recordAccount    => $form->{acc_trans}{$arap_key}[0]{accno},
            type             => $form->{type},
            currency         => $form->{currency},
            exchangerate     => $form->{"$form->{currency}"},
            id               => $form->{id},
            department_id    => $form->{department_id},
            rounding         => $form->{rounding} + 0,
            files            => $files,
            lines            => \@lines,
            payments         => \@payments,
            paymentmethod_id => $form->{"paymentmethod_id"},
        };

        if (@taxes) {
            $json_data->{taxes}       = \@taxes;
            $json_data->{taxincluded} = $form->{taxincluded};
        }

        my $shipto;
        foreach my $item (
            qw(name address1 address2 city state zipcode country contact phone fax email)
          )
        {
            $json_data->{shipto}->{$item} = $form->{"shipto$item"};
        }

        $c->render( json => $json_data );
    }
);

helper process_invoice => sub {
    my ( $c, $data, $form, $client ) = @_;

    if ( $c->param('client') ) {
        $client = $c->param('client');
    }
    my $dbs = $c->dbs($client);
    my $id  = $c->param('id') || $data->{id};
    my $vc  = $c->param('vc');
    $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

    $vc = $data->{vc} if $data->{vc};
    $form->{vc} = $vc;

    # Determine if this should be AR or AP
    my $invoice_type = ( $vc eq 'vendor' ) ? 'AP' : 'AR';

    # Configure DB connection
    my $dbs = $c->dbs($client);

    # Set the ID if provided; otherwise it will post as a new invoice
    $form->{id} = $id if $id;

    # Basic invoice details common to both AR and AP
    $form->{invnumber}   = $data->{invNumber}   || '';
    $form->{description} = $data->{description} || '';

    $form->{type}         = $data->{type};
    $form->{transdate}    = $data->{invDate};
    $form->{duedate}      = $data->{dueDate};
    $form->{currency}     = $data->{currency};
    $form->{exchangerate} = $data->{exchangerate} || 1;
    $form->{notes}        = $data->{notes}        || '';
    $form->{intnotes}     = $data->{intnotes}     || '';
    $form->{till}         = $data->{till}         || '';
    $form->{department}   = $data->{department}   || '';
    $form->{dcn}          = $data->{dcn}          || '';
    $form->{rounding}     = $data->{rounding}     || 0;

    # Set up AR or AP account from JSON
    # for AR, it's $form->{AR}, for AP, it's $form->{AP}.
    if ( $invoice_type eq 'AR' ) {

        # AR fields
        $form->{AR}          = "$data->{recordAccount}--A";
        $form->{customer_id} = $data->{customer_id};
    }
    else {
        # AP fields
        $form->{AP}        = "$data->{recordAccount}--A";
        $form->{vendor_id} = $data->{vendor_id};
    }

    # Additional invoice details
    $form->{ordnumber}     = $data->{ordNumber}     || '';
    $form->{ponumber}      = $data->{poNumber}      || '';
    $form->{shippingpoint} = $data->{shippingPoint} || '';
    $form->{shipvia}       = $data->{shipVia}       || '';
    $form->{waybill}       = $data->{wayBill}       || '';

    my $shipto;
    foreach my $item (
        qw(name address1 address2 city state zipcode country contact phone fax email)
      )
    {
        $form->{"shipto$item"} = $data->{shipto}->{$item};
    }

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
        $form->{"volume_$i"}           = $line->{volume}           || '';
        $form->{"weight_$i"}           = $line->{weight}           || '';
        $form->{"netweight_$i"}        = $line->{netweight}        || '';
        $form->{"cost_$i"}             = $line->{cost}             || '';
        $form->{"projectnumber_$i"}    = $line->{project}          || '';
        $form->{"project_id_$i"}       = $line->{project_id}       || '';
    }

    # Build payments
    $form->{paidaccounts} = 0;
    for my $payment ( @{ $data->{payments} } ) {
        $form->{paidaccounts}++;
        my $i = $form->{paidaccounts};

        $form->{"datepaid_$i"}     = $payment->{date};
        $form->{"source_$i"}       = $payment->{source} || '';
        $form->{"memo_$i"}         = $payment->{memo}   || '';
        $form->{"paid_$i"}         = $payment->{amount};
        $form->{"exchangerate_$i"} = $payment->{exchangerate} || 1;

        $form->{ $form->{vc} eq 'vendor' ? "AP_paid_$i" : "AR_paid_$i" } =
          $payment->{account} . "--";

        if ( my $accno = $payment->{account} ) {
            $dbs->query( "SELECT id FROM chart WHERE accno = ?", $accno )
              ->into( my $chart_id );
            $form->{"paymentmethod_$i"} = "0--$chart_id" if defined $chart_id;
        }
    }

    # Taxes
    $form->{taxincluded} = 0;
    if ( $data->{taxes} && ref( $data->{taxes} ) eq 'ARRAY' ) {
        my @taxaccounts;
        for my $tax ( @{ $data->{taxes} } ) {
            push @taxaccounts, $tax->{accno};

            $form->{"$tax->{accno}_rate"} = $tax->{rate};
            if ( defined $tax->{amount} ) {
                $form->{"tax_$tax->{accno}"} = $tax->{amount};
            }
        }
        $form->{taxaccounts} = join( ' ', @taxaccounts );
        $form->{taxincluded} = $data->{taxincluded};
    }
    else {
        # No valid taxes object, query from database
        my $transdate = $data->{invDate};

        my $taxes = $dbs->query(
            q{
            SELECT c.accno, t.rate, t.chart_id
            FROM tax t
            JOIN chart c ON c.id = t.chart_id
            WHERE t.validto IS NULL 
               OR t.validto >= ?
            ORDER BY t.chart_id, t.id DESC
        },
            $transdate
        )->hashes;

        if (@$taxes) {
            my @taxaccounts;
            my %seen_charts;

            for my $tax (@$taxes) {

                # Only use the first (most recent) rate for each chart_id
                next if $seen_charts{ $tax->{chart_id} };
                $seen_charts{ $tax->{chart_id} } = 1;

                push @taxaccounts, $tax->{accno};
                $form->{"$tax->{accno}_rate"} = $tax->{rate};
            }

            $form->{taxaccounts} = join( ' ', @taxaccounts );
            $form->{taxincluded} = $data->{taxincluded} // 0;
        }
    }

    # Other defaults
    $form->{employee_id}   = undef;
    $form->{language_code} = '';
    $form->{precision}     = $data->{selectedCurrency}->{prec} || 2;

    # Finally, post invoice to LedgerSMB
    if ( $invoice_type eq 'AR' ) {
        IS->post_invoice( $c->slconfig, $form );
    }
    else {
        IR->post_invoice( $c->slconfig, $form );
    }

    if ( $ai_plugin && $invoice_type eq 'AR' && $form->{id} ) {
        eval { $c->sync_moco_invoice_payments( $client, $form->{id} ); };
    }

    if ( $data->{files} && ref $data->{files} eq 'ARRAY' ) {
        $form->{files}  = $c->decode_base64_files( $data->{files} );
        $form->{client} = $client;
        my $upload_result = FM->upload_files( $dbs, $c, $form, $vc );
        if ( ref($upload_result) ne 'HASH' || !$upload_result->{success} ) {
            my $upload_error =
              ref($upload_result) eq 'HASH' && $upload_result->{error}
              ? $upload_result->{error}
              : 'Unknown upload failure';
            die "file_upload_failed: $upload_error";
        }
    }

# generate and store the invoice PDF using the correct template for this document type
    $c->generate_invoice_pdf( $client, $form->{id}, $vc, $form->{type}, 'tex' );

    return $form->{id};
};

helper generate_invoice_pdf => sub {
    my ( $c, $client, $invoice_id, $vc, $template, $format ) = @_;

    $template = 'invoice';
    $format   = 'tex';

    my $dbs = $c->dbs($client);
    $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

    my $form = Form->new;
    $form->{vc} = $vc;
    if ( $vc eq 'vendor' ) {
        $template = 'vendor_invoice';
    }

    $form->{id} = $invoice_id;

    build_invoice( $c, $client, $form, $dbs );
    if ( $form->{type} eq 'credit_invoice' ) {
        $template = 'credit_invoice';
    }

    $form->{lastpage}          = 0;
    $form->{sumcarriedforward} = 0;
    $form->{templates}         = "templates/$client";
    $form->{IN}                = "$template.$format";

    my $userspath = "tmp";
    my $defaults  = $c->get_defaults($client);

# get the transdate from the invoice for folder structure
# accept both yyyy-mm-dd (ISO) and dd-mm-yyyy (display format from build_invoice)
    my $transdate = $form->{invdate} || $form->{transdate};
    my ( $year, $month );
    if ( $transdate && $transdate =~ /^(\d{4})-(\d{2})-\d{2}$/ ) {
        ( $year, $month ) = ( $1, $2 );
    }
    elsif ( $transdate && $transdate =~ /^(\d{1,2})-(\d{1,2})-(\d{4})$/ ) {
        ( $year, $month ) = ( $3, sprintf( "%02d", $2 ) );
    }
    else {
        my @lt = localtime;
        $year  = $lt[5] + 1900;
        $month = sprintf( "%02d", $lt[4] + 1 );
    }

    # create storage directory: files/$client/invoices/$year/$month/
    my $storage_dir = "files/$client/invoices/$year/$month";
    eval { make_path($storage_dir); };
    if ($@) {
        $c->app->log->error(
            "Could not create invoice storage directory '$storage_dir': $@");
        return undef;
    }

    # generate unique filename using invnumber and template type
    my $safe_invnumber = $form->{invnumber} || $invoice_id;
    $safe_invnumber =~ s/[^a-zA-Z0-9_.-]+/_/g;
    my $safe_template = $template;
    $safe_template =~ s/[^a-zA-Z0-9_.-]+/_/g;
    my $filename = "${safe_invnumber}_${safe_template}.pdf";
    my $pdf_path = "$storage_dir/$filename";

    if ( $format eq 'tex' ) {
        $form->{OUT}    = ">tmp/invoice_${invoice_id}.pdf";
        $form->{format} = "pdf";
        $form->{media}  = "screen";
        $form->{copies} = 1;

        my $dvipdf  = "";
        my $xelatex = $defaults->{xelatex};
        $form->parse_template( $c->slconfig, $userspath, $dvipdf, $xelatex );

        my $temp_pdf = "tmp/invoice_${invoice_id}.pdf";
        if ( -f $temp_pdf ) {
            require File::Copy;
            File::Copy::move( $temp_pdf, $pdf_path )
              or do {
                $c->app->log->error("Failed to move PDF to storage: $!");
                return undef;
              };
        }
        else {
            $c->app->log->error("PDF generation failed - temp file not found");
            return undef;
        }
    }
    elsif ( $format eq 'html' ) {
        $form->{OUT} = ">tmp/invoice_${invoice_id}.html";
        $form->parse_template( $c->slconfig, $userspath );

        ( my $file_path = $form->{OUT} ) =~ s/^>//;

        open my $fh, '<', $file_path or do {
            $c->app->log->error("Cannot open $file_path: $!");
            return undef;
        };
        { local $/; $form->{html_content} = <$fh> }
        close $fh;
        unlink $file_path;

        my $pdf = html_to_pdf( $form->{html_content} );
        unless ($pdf) {
            $c->app->log->error("Failed to convert HTML to PDF");
            return undef;
        }

        open my $out_fh, '>', $pdf_path or do {
            $c->app->log->error("Cannot write to $pdf_path: $!");
            return undef;
        };
        binmode $out_fh;
        print $out_fh $pdf;
        close $out_fh;
    }
    else {
        $c->app->log->error("Unsupported format for PDF generation: $format");
        return undef;
    }

    $c->app->log->info("Generated invoice PDF: $pdf_path");
    return $pdf_path;
};

helper get_invoice_pdf => sub {
    my ( $c, $client, $invoice_id, $vc, $template, $format ) = @_;

    $template ||= 'invoice';
    $format   ||= 'tex';

    my $dbs = $c->dbs($client);

    # get invoice details to determine folder path
    my $arap = $vc eq 'vendor' ? 'ap' : 'ar';
    my $invoice =
      $dbs->query( "SELECT invnumber, transdate FROM $arap WHERE id = ?",
        $invoice_id )->hash;

    return undef unless $invoice;

    my $transdate = $invoice->{transdate};
    my ( $year, $month );
    if ( $transdate && $transdate =~ /^(\d{4})-(\d{2})-\d{2}$/ ) {
        ( $year, $month ) = ( $1, $2 );
    }
    else {
        my @lt = localtime;
        $year  = $lt[5] + 1900;
        $month = sprintf( "%02d", $lt[4] + 1 );
    }

    my $safe_invnumber = $invoice->{invnumber} || $invoice_id;
    $safe_invnumber =~ s/[^a-zA-Z0-9_.-]+/_/g;
    my $safe_template = $template;
    $safe_template =~ s/[^a-zA-Z0-9_.-]+/_/g;
    my $filename = "${safe_invnumber}_${safe_template}.pdf";
    my $pdf_path = "files/$client/invoices/$year/$month/$filename";

    # check if file already exists
    if ( -f $pdf_path ) {
        $c->app->log->info("Returning existing invoice PDF: $pdf_path");
        return $pdf_path;
    }

    # generate if it doesn't exist
    return $c->generate_invoice_pdf( $client, $invoice_id, $vc, $template,
        $format );
};

$api->post(
    '/arap/invoice/:vc/:id' => { id => undef } => sub {
        my $c      = shift;
        my $vc     = $c->param('vc');
        my $id     = $c->param('id');
        my $client = $c->param('client');

        my $data;
        my $content_type = $c->req->headers->content_type || '';

        if ( $content_type =~ m!multipart/form-data!i ) {
            $data = handle_multipart_request($c);
            $data->{vc} = $vc;
        }
        else {
            $data = $c->req->json;
            $data->{vc} = $vc;
        }

        my $form;
        if ( $data->{vc} eq 'customer' ) {
            if ( $data->{type} eq 'credit_invoice' ) {
                $form = $c->check_perms("customer.invoice_return");
            }
            else {
                $form = $c->check_perms("customer.invoice");
            }
        }
        else {
            if ( $data->{type} eq 'debit_invoice' ) {
                $form = $c->check_perms("vendor.invoice_return");
            }
            else {
                $form = $c->check_perms("vendor.invoice");
            }
        }
        my $new_invoice_id = $c->process_invoice( $data, $form, $client );

        # Return the newly posted or updated invoice ID
        $c->render( json => { id => $new_invoice_id } );
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

$api->get(
    '/arap/payment/:vc/:id' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $id     = $c->param('id');
        my $vc     = $c->param('vc');

        my $table;
        if ( $vc eq 'customer' ) {
            $table = 'ar';
        }
        elsif ( $vc eq 'vendor' ) {
            $table = 'ap';
        }
        else {
            return $c->render(
                json => {
                    error =>
                      "Invalid vc parameter. Must be 'customer' or 'vendor'."
                },
                status => 400
            );
        }

        return unless my $form = $c->check_perms("$vc.invoice");

        my $dbs = $c->dbs($client);
        my $row = $dbs->query(
            "SELECT netamount, paid, datepaid FROM $table WHERE id = ?", $id )
          ->hash;

        if ( !$row ) {
            return $c->render(
                json   => { error => "Invoice with ID $id not found." },
                status => 404
            );
        }

        $c->render(
            json => {
                netamount  => $row->{netamount} + 0,
                paid       => $row->{paid} + 0,
                datepaid   => $row->{datepaid},
                difference => ( $row->{netamount} - $row->{paid} ) + 0,
            }
        );
    }
);

$api->get(
    '/invoice/consolidate' => sub {
        my $c      = shift;
        my $client = $c->param('client');

        return unless my $form = $c->check_perms("customer.consolidate");
        $form->{sort} ||= "transdate";
        IS->consolidate( $c->slconfig, $form );
        if ( $form->{closedto} && $form->{closedto} ne '' ) {

            # Loop through all currencies
            foreach my $curr ( keys %{ $form->{all_transactions} } ) {

                # Loop through all account numbers
                foreach
                  my $accno ( keys %{ $form->{all_transactions}->{$curr} } )
                {
                    # Loop through all customers
                    foreach my $customer (
                        keys %{ $form->{all_transactions}->{$curr}->{$accno} } )
                    {
                        # Filter out transactions with dates <= closedto
                        my @filtered_transactions =
                          grep { $_->{transdate} gt $form->{closedto} }
                          @{ $form->{all_transactions}->{$curr}->{$accno}
                              ->{$customer} };

                        # Replace with filtered list
                        $form->{all_transactions}->{$curr}->{$accno}
                          ->{$customer} = \@filtered_transactions;

                        # Remove empty customer entries
                        if ( !@filtered_transactions ) {
                            delete $form->{all_transactions}->{$curr}->{$accno}
                              ->{$customer};
                        }
                    }

                    # Remove empty account number entries
                    if ( !keys %{ $form->{all_transactions}->{$curr}->{$accno} }
                      )
                    {
                        delete $form->{all_transactions}->{$curr}->{$accno};
                    }
                }

                # Remove empty currency entries
                if ( !keys %{ $form->{all_transactions}->{$curr} } ) {
                    delete $form->{all_transactions}->{$curr};
                }
            }
        }

        $c->render( json => $form->{all_transactions} );
    }
);
$api->post(
    '/invoice/consolidate' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $json   = $c->req->json;

        my $form = $c->check_perms("customer.consolidate");
        return $c->render(
            json   => { error => "Permission denied" },
            status => 403
        ) unless $form;

        # Ensure 'ids' is a space-separated string
        if ( ref $json->{ids} eq 'ARRAY' ) {
            $form->{ids} = join( ' ', @{ $json->{ids} } );

            # Set ndx_<id> values for each ID
            foreach my $id ( @{ $json->{ids} } ) {
                $form->{"ndx_$id"} = 1;    # Mark the ID as selected
            }
        }
        else {
            return $c->render(
                json   => { error => "Invalid input: 'ids' must be an array" },
                status => 400
            );
        }

        my $result = IS->consolidate_invoices( $c->slconfig, $form );

        # Render the result
        if ($result) {
            $c->render( json => { success => 1 } );
        }
        else {
            $c->render(
                json   => { error => "Failed to consolidate invoices" },
                status => 500
            );
        }
    }
);

$api->get(
    '/taxreport/:vc' => sub {
        my $c  = shift;
        my $vc = $c->param('vc');

        # Validate vc parameter
        unless ( $vc eq 'customer' || $vc eq 'vendor' ) {
            return $c->render(
                json   => { error => "Invalid vc parameter" },
                status => 400
            );
        }
        my $form;
        if ( $vc eq 'customer' ) {
            return unless $form = $c->check_perms("customer.taxreport");
        }
        else {
            return unless $form = $c->check_perms("vendor.taxreport");
        }

        # Core parameters
        $form->{db}         = $vc eq 'customer' ? 'ar' : 'ap';
        $form->{fromdate}   = $c->param('fromdate');
        $form->{todate}     = $c->param('todate');
        $form->{reportcode} = $c->param('reportcode');
        $form->{summary}    = $c->param('summary') ? 1 : 0;
        $form->{method}     = $c->param('method') || 'accrual';

        # Account filtering
        $form->{taxaccounts}      = $c->param('taxaccounts');
        $form->{gifi_taxaccounts} = $c->param('gifi_taxaccounts');
        $form->{department}       = $c->param('department');

        # Set individual account flags if taxaccounts provided
        if ( $form->{taxaccounts} ) {
            for my $account ( split / /, $form->{taxaccounts} ) {
                $form->{"accno_$account"} = 1;
            }
        }

        # Set individual GIFI flags if gifi_taxaccounts provided
        if ( $form->{gifi_taxaccounts} ) {
            for my $gifi ( split / /, $form->{gifi_taxaccounts} ) {
                $form->{"gifi_$gifi"} = 1;
            }
        }

        # Alternative date parameters
        $form->{year}     = $c->param('year');
        $form->{month}    = $c->param('month');
        $form->{interval} = $c->param('interval');

        RP->tax_report( $c->slconfig, $form );

        # Return results
        $c->render( json => $form->{TR} || [] );
    }
);
$api->get(
    '/open_invoices/:vc' => sub {
        my $c  = shift;
        my $vc = $c->param('vc');

        my $form;
        if ( $vc eq 'customer' ) {
            return unless $form = $c->check_perms("cash.receipts");
        }
        else {
            return unless $form = $c->check_perms("cash.payments");
        }

        # Set required parameters
        $form->{vc}       = $vc;
        $form->{fromdate} = $c->param('fromdate');
        $form->{todate}   = $c->param('todate');

        # Set additional parameters that get_openinvoices expects
        $form->{"${vc}_id"}    = $c->param("${vc}_id");
        $form->{currency}      = $c->param('currency');
        $form->{duedatefrom}   = $c->param('duedatefrom');
        $form->{duedateto}     = $c->param('duedateto');
        $form->{department}    = $c->param('department');
        $form->{paymentmethod} = $c->param('paymentmethod');
        $form->{payment}       = $c->param('payment');
        $form->{datepaid}      = $c->param('datepaid');

        # Set ARAP table name based on vc type
        if ( $vc eq 'customer' ) {
            $form->{arap} = 'ar';
            $form->{ARAP} = 'AR';
        }
        elsif ( $vc eq 'vendor' ) {
            $form->{arap}     = 'ap';
            $form->{ARAP}     = 'AP';
            $form->{business} = $c->param('business');
        }
        else {
            return $c->render(
                json => {
                    error => 'Invalid vc parameter. Must be customer or vendor'
                },
                status => 400
            );
        }
        CP->get_openinvoices( $c->slconfig, $form );
        $c->render( json => $form->{PR} || [] );

    }
);
$api->post(
    '/open_invoices/:vc' => sub {
        my $c      = shift;
        my $vc     = $c->param('vc');
        my $client = $c->param('client') || die "Missing client parameter";
        my $json   = $c->req->json;
        my $form;

        # Check permissions
        if ( $vc eq 'customer' ) {
            return unless $form = $c->check_perms("cash.receipts");
        }
        else {
            return unless $form = $c->check_perms("cash.payments");
        }

        # Validate required JSON fields
        unless ( $json->{account}
            && $json->{date}
            && $json->{payments}
            && $json->{method} )
        {
            return $c->render(
                json => {
                    error =>
                      'Missing required fields: account, date, payments, method'
                },
                status => 400
            );
        }

        # Validate method
        unless ( $json->{method} eq 'individual' || $json->{method} eq 'group' )
        {
            return $c->render(
                json => {
                    error => 'Invalid method. Must be "individual" or "group"'
                },
                status => 400
            );
        }

        # Prepare common form data using the existing form object
        $form->{vc}            = $vc;
        $form->{datepaid}      = $json->{date};
        $form->{currency}      = $json->{currency} || $form->{defaultcurrency};
        $form->{exchangerate}  = $json->{exchangerate}  || 1;
        $form->{paymentmethod} = $json->{paymentmethod} || '';
        $form->{source}        = $json->{source}        || '';
        $form->{memo}          = $json->{memo}          || '';
        $form->{type}          = $vc eq 'customer' ? 'receipt' : 'payment';
        $form->{formname}      = $vc eq 'customer' ? 'receipt' : 'payment';
        $form->{payment}       = 'payment';

        # Set ARAP table name and payment account based on vc type
        if ( $vc eq 'customer' ) {
            $form->{arap}    = 'ar';
            $form->{ARAP}    = 'AR';
            $form->{AR_paid} = $json->{account};
        }
        elsif ( $vc eq 'vendor' ) {
            $form->{arap}    = 'ap';
            $form->{ARAP}    = 'AP';
            $form->{AP_paid} = $json->{account};
        }

        my $method          = $json->{method};
        my $total_processed = 0;
        my $total_amount    = 0;
        my @results;

        if ( $method eq 'individual' ) {

            # Handle individual payments using the existing form object
            my $payments = $json->{payments};
            $form->{rowcount} = scalar @$payments;

            for my $i ( 0 .. $#$payments ) {
                my $row_num = $i + 1;            # 1-based indexing
                my $payment = $payments->[$i];

                # Validate required payment fields
                unless ( $payment->{id} && defined $payment->{paid} ) {
                    return $c->render(
                        json => {
                            error =>
"Payment $row_num missing required fields: id, paid"
                        },
                        status => 400
                    );
                }

                # Set payment row data
                $form->{"checked_$row_num"} = 1;              # Mark as selected
                $form->{"id_$row_num"}      = $payment->{id};
                $form->{"paid_$row_num"}    = $payment->{paid};

                # Add to total amount
                $total_amount += $payment->{paid};
            }

            # Override source/memo with individual payment data if provided
            if ( $payments->[0]->{source} || $payments->[0]->{memo} ) {
                $form->{source} = $payments->[0]->{source} || $form->{source};
                $form->{memo}   = $payments->[0]->{memo}   || $form->{memo};
            }

            # Set total payment amount
            $form->{amount} = $total_amount;

            # Call the payment posting routine
            my $result = CP->post_payment( $c->slconfig, $form );

            if ($result) {
                $total_processed = scalar @$payments;

              # regenerate PDFs for all paid invoices to reflect updated balance
                for my $payment (@$payments) {
                    $c->generate_invoice_pdf( $client, $payment->{id}, $vc,
                        'invoice', 'tex' );
                }
            }
            else {
                return $c->render(
                    json   => { error => 'Payment posting failed' },
                    status => 500
                );
            }

        }
        elsif ( $method eq 'group' ) {

            # Handle group payments
            my $payments = $json->{payments};

            for my $payment_group (@$payments) {

                # Validate payment group structure
                unless ( $payment_group->{total_amount}
                    && $payment_group->{invoices} )
                {
                    return $c->render(
                        json => {
                            error =>
'Invalid payment group structure. Required: customer, total_amount, invoices'
                        },
                        status => 400
                    );
                }

           # Create a new form for this payment group, copying from the original
                my $group_form = new Form;
                $group_form->{"${vc}_id"} = $payment_group->{vc_id};

             # Copy all data from the original form (including permissions data)
                for my $key ( keys %$form ) {
                    $group_form->{$key} = $form->{$key};
                }

                # Override source and memo for this payment group if provided
                $group_form->{source} =
                  $payment_group->{source} || $form->{source};
                $group_form->{memo} = $payment_group->{memo} || $form->{memo};

                # Transform invoices into indexed format
                my $invoices = $payment_group->{invoices};
                $group_form->{rowcount} = scalar @$invoices;

                # Clear any existing row data from the copied form
                for my $key ( keys %$group_form ) {
                    if ( $key =~ /^(checked_|id_|paid_)\d+$/ ) {
                        delete $group_form->{$key};
                    }
                }

                for my $i ( 0 .. $#$invoices ) {
                    my $row_num = $i + 1;            # 1-based indexing
                    my $invoice = $invoices->[$i];

                    # Validate required invoice fields
                    unless ( $invoice->{id} && defined $invoice->{paid} ) {
                        return $c->render(
                            json => {
                                error =>
"Invoice in payment group for $payment_group->{customer} missing required fields: id, paid"
                            },
                            status => 400
                        );
                    }

                    # Set invoice row data
                    $group_form->{"checked_$row_num"} = 1;    # Mark as selected
                    $group_form->{"id_$row_num"}      = $invoice->{id};
                    $group_form->{"paid_$row_num"}    = $invoice->{paid};
                }

                # Set total payment amount for this group
                $group_form->{amount} = $payment_group->{total_amount};

                # Post payment for this group
                my $result = CP->post_payment( $c->slconfig, $group_form );

                if ($result) {
                    push @results,
                      {
                        customer       => $payment_group->{customer},
                        amount         => $payment_group->{total_amount},
                        invoices_count => scalar @$invoices,
                        success        => 1
                      };
                    $total_processed += scalar @$invoices;
                    $total_amount    += $payment_group->{total_amount};

              # regenerate PDFs for all paid invoices to reflect updated balance
                    for my $invoice (@$invoices) {
                        $c->generate_invoice_pdf( $client, $invoice->{id}, $vc,
                            'invoice', 'tex' );
                    }
                }
                else {
                    return $c->render(
                        json => {
                            error =>
"Payment posting failed for customer: $payment_group->{customer}"
                        },
                        status => 500
                    );
                }
            }
        }

        # Return success response
        my $response = {
            success            => 1,
            message            => 'Payment(s) posted successfully',
            method             => $method,
            total_amount       => $total_amount,
            payments_processed => $total_processed
        };

        # Add group-specific details
        if ( $method eq 'group' ) {
            $response->{payment_groups} = \@results;
        }

        $c->render( json => $response );
    }
);
$api->get(
    '/cash/report/:vc' => sub {
        my $c  = shift;
        my $vc = $c->param('vc');

        # Validate vc parameter
        unless ( $vc eq 'customer' || $vc eq 'vendor' ) {
            return $c->render(
                json   => { error => "Invalid vc parameter" },
                status => 400
            );
        }

        # Check permissions
        return unless my $form = $c->check_perms("cash.report.$vc");

        # Core parameters
        $form->{db} = $vc eq 'customer' ? 'ar' : 'ap';
        $form->{vc} = $vc;

        # Date parameters
        $form->{fromdate} = $c->param('fromdate');
        $form->{todate}   = $c->param('todate');

        # Alternative date parameters
        $form->{year}     = $c->param('year');
        $form->{month}    = $c->param('month');
        $form->{interval} = $c->param('interval');

        # Payment account filtering (key parameter for the subroutine)
        $form->{paymentaccounts} = $c->param('paymentaccounts');

        # Department filtering
        $form->{department_id} = $c->param('department_id');

        # Search filters
        $form->{description} = $c->param('description') || '';
        $form->{source}      = $c->param('source')      || '';
        $form->{memo}        = $c->param('memo')        || '';

        # Customer/Vendor filtering
        $form->{$vc} = $c->param('vc_name') || '';

        # Call the payments report function
        RP->payments( $c->slconfig, $form );

        # Build response with accounts and their transactions
        my @response = ();

        if ( $form->{PR} && ref $form->{PR} eq 'ARRAY' ) {
            foreach my $account ( @{ $form->{PR} } ) {
                my $account_data = {
                    id           => $account->{id},
                    accno        => $account->{accno},
                    description  => $account->{description},
                    translation  => $account->{translation},
                    transactions => $form->{ $account->{id} } || []
                };
                push @response, $account_data;
            }
        }

        # Return results
        $c->render( json => \@response );
    }
);

###############################
####                       ####
####    Order  Entry       ####
####                       ####
###############################

$api->get(
    '/oe/:type/:vc' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $type   = $c->param('type');
        my $vc     = $c->param('vc');
        return unless my $form = $c->check_perms("$vc.transactions");
        my $data = $c->req->params->to_hash;

        # Validate type parameter
        unless ( $type eq 'order' || $type eq 'quotation' ) {
            return $c->render(
                json => {
                    error => 'Invalid type. Must be either order or quotation.'
                },
                status => 400
            );
        }

        # Validate vc parameter
        unless ( $vc eq 'vendor' || $vc eq 'customer' ) {
            return $c->render(
                json => {
                    error => 'Invalid vc. Must be either vendor or customer.'
                },
                status => 400
            );
        }

        # Map internal type based on type and vc combination
        my $internal_type;
        if ( $type eq 'order' ) {
            $internal_type = $vc eq 'customer' ? 'ship_order' : 'receive_order';
        }
        elsif ( $type eq 'quotation' ) {
            $internal_type = "${vc}_quotation";
        }

        $form->{type}             = $internal_type;
        $form->{vc}               = $vc;
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        # Define available filters for OE transactions
        my @date_filters = qw(transdatefrom transdateto);
        my @text_filters =
          qw(ordnumber quonumber ponumber shipvia waybill notes description memo);
        my @entity_filters  = qw(department);
        my @boolean_filters = qw(open closed);

        # Apply the predefined values from $data
        for my $key ( keys %$data ) {
            $form->{$key} = $data->{$key} if defined $data->{$key};
        }

        # Additional validation for date fields if they're not empty
        for my $filter (@date_filters) {
            next unless $form->{$filter};
            if (   $filter =~ /^transdate/
                && $form->{$filter} !~ /^\d{4}-\d{2}-\d{2}$/ )
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

        # Call OE transactions subroutine
        OE->transactions( $c->slconfig, $form );

        # Check if results exist
        if (  !defined $form->{OE}
            || ref $form->{OE} ne 'ARRAY'
            || !@{ $form->{OE} } )
        {
            return $c->render(
                status => 404,
                json   => { message => "No orders found" }
            );
        }

        # Calculate totals for specific fields
        my $totals = {
            amount    => 0,
            netamount => 0,
        };

        foreach my $order ( @{ $form->{OE} } ) {
            $totals->{amount}    += $order->{amount}    || 0;
            $totals->{netamount} += $order->{netamount} || 0;
        }

        my $dbs = $c->dbs($client);

        # Return both orders and totals
        return $c->render(
            json => {
                orders => $form->{OE},
                totals => $totals
            }
        );
    }
);

$api->get(
    '/oe/:type/:vc/:id' => sub {
        my $c       = shift;
        my $vc      = $c->param('vc');
        my $oe_type = $c->param('type');
        my $id      = $c->param('id');

        my $form = $c->check_perms("$vc.$oe_type");
        $form->{vc} = $vc;
        $form->{id} = $id;
        OE->retrieve( $c->slconfig, $form );

        my $arap_key = $vc eq 'vendor'   ? 'AP' : 'AR';
        my $ml       = $vc eq 'customer' ? -1   : 1;

        # Create payments array
        my @payments;
        my $paid_key = $arap_key . '_paid';

        if ( defined $form->{acc_trans}{$paid_key}
            && ref $form->{acc_trans}{$paid_key} eq 'ARRAY' )
        {
            for my $payment_entry ( @{ $form->{acc_trans}{$paid_key} } ) {
                push @payments,
                  {
                    date         => $payment_entry->{transdate},
                    source       => $payment_entry->{source},
                    memo         => $payment_entry->{memo},
                    amount       => $payment_entry->{amount} * $ml,
                    exchangerate => $payment_entry->{exchangerate},
                    account      => $payment_entry->{accno}
                  };
            }
        }

      # Build line items (using form_details from the dump, not invoice_details)
        my @lines;
        if ( ref $form->{form_details} eq 'ARRAY' ) {
            @lines = map {
                {
                    id          => $_->{id},
                    partnumber  => $_->{partnumber},
                    description => $_->{description},
                    qty         => $_->{qty},
                    onhand      => $_->{onhand},
                    unit        => $_->{unit},
                    price => $_->{sellprice} > 0 ? $_->{sellprice} : $_->{sell},
                    discount         => $_->{discount} * 100,
                    taxaccounts      => [ split ' ', $_->{taxaccounts} || '' ],
                    lineitemdetail   => $_->{lineitemdetail},
                    itemnotes        => $_->{itemnotes},
                    ordernumber      => $_->{ordernumber},
                    serialnumber     => $_->{serialnumber},
                    customerponumber => $_->{customerponumber},
                    project_id       => $_->{project_id} || '',
                    cost             => $_->{cost},
                    costvendor       => $_->{costvendor},
                    costvendorid     => $_->{costvendorid},
                    package          => $_->{package},
                    volume           => $_->{volume},
                    weight           => $_->{weight},
                    netweight        => $_->{netweight},
                    sku              => $_->{sku},
                    make             => $_->{make},
                    model            => $_->{model},
                }
            } @{ $form->{form_details} };
        }

        # Process tax information (if tax data exists in acc_trans)
        my @taxes;
        my $tax_key = $arap_key . '_tax';
        if ( $form->{acc_trans}{$tax_key} ) {
            @taxes = map {
                {
                    accno  => $_->{accno},
                    amount => $_->{amount},
                    rate   => $_->{rate},
                }
            } @{ $form->{acc_trans}{$tax_key} };
        }

        # For the vc_field and vc_id_field
        my ( $vc_field, $vc_id_field ) =
          $vc eq 'vendor'
          ? ( 'vendornumber', 'vendor_id' )
          : ( 'customernumber', 'customer_id' );

        # Get files if FM module is available
        my $files = [];

       # my $files = FM->get_files( $dbs, $c, $form ) if defined &FM::get_files;

        # Build JSON response
        my $json_data = {

            # Dynamic fields for vendor or customer
            $vc_field    => $form->{$vc_field},
            $vc_id_field => $form->{$vc_id_field},

            # Use correct field names from the dump
            customer      => $form->{customer},       # For display name
            shippingpoint => $form->{shippingpoint},
            shipvia       => $form->{shipvia},
            waybill       => $form->{waybill},
            description   => $form->{description},
            notes         => $form->{notes},
            intnotes      => $form->{intnotes},
            ordnumber     => $form->{ordnumber},      # Not invnumber for orders
            transdate     => $form->{transdate},
            reqdate       => $form->{reqdate},
            ponumber      => $form->{ponumber},
            quonumber     => $form->{quonumber},
            type          => $oe_type,         # Use the type from URL parameter
            currency      => $form->{currency},
            exchangerate  => $form->{"$form->{currency}"},
            id            => $form->{id},
            department_id => $form->{department_id},
            invtotal      => $form->{invtotal},
            taxincluded   => $form->{taxincluded},
            terms         => $form->{terms},
            closed        => $form->{closed},
            files         => $files,
            lines         => \@lines,
            payments      => \@payments,
        };

        # Add taxes if they exist
        if (@taxes) {
            $json_data->{taxes} = \@taxes;
        }

        # Add shipping information
        my $shipto = {};
        foreach my $item (
            qw(name address1 address2 city state zipcode country contact phone fax email)
          )
        {
            $shipto->{$item} = $form->{"shipto$item"};
        }
        $json_data->{shipto} = $shipto;

        $c->render( json => $json_data );
    }
);

sub process_order {
    my ( $c, $data, $form, $client ) = @_;

    if ( $c->param('client') ) {
        $client = $c->param('client');
    }
    my $dbs        = $c->dbs($client);
    my $id         = $c->param('id');
    my $vc         = $c->param('vc');
    my $order_type = $c->param('type') || 'quotation';
    $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

    $vc = $data->{vc} if $data->{vc};
    $form->{vc} = $vc;

    if ( $order_type eq 'order' ) {
        $form->{type} =
          ( $vc eq 'customer' ) ? 'sales_order' : 'purchase_order';
    }
    else {
        $form->{type} = ( $vc eq 'customer' ) ? 'quotation' : 'rfq';
    }

    # Set the ID if provided
    $form->{id} = $id if $id;

    # Basic order details
    $form->{ordnumber}    = $data->{number}      || '';
    $form->{quonumber}    = $data->{number}      || '';
    $form->{description}  = $data->{description} || '';
    $form->{transdate}    = $data->{date};
    $form->{reqdate}      = $data->{requiredBy};
    $form->{currency}     = $data->{currency};
    $form->{curr}         = $data->{currency};
    $form->{exchangerate} = $data->{exchangerate} || 1;
    $form->{notes}        = $data->{notes}        || '';
    $form->{intnotes}     = $data->{intnotes}     || '';
    $form->{till}         = $data->{till}         || '';
    $form->{department}   = $data->{department}   || '';
    $form->{ponumber}     = $data->{ponumber}     || '';
    $form->{terms}        = $data->{terms}        || 0;
    $form->{closed}       = $data->{closed}       || 0;
    $form->{backorder}    = $data->{backorder}    || 0;

    # Set customer/vendor ID
    if ( $vc eq 'customer' ) {
        $form->{customer_id} = $data->{customer_id};
        $form->{customer}    = $data->{customer} || '';
    }
    else {
        $form->{vendor_id} =
          $data->{selectedVendor}->{id} || $data->{vendor_id};
        $form->{vendor} = $data->{vendor} || '';
    }

    # Shipping information
    $form->{shippingpoint} = $data->{shippingPoint} || '';
    $form->{shipvia}       = $data->{shipVia}       || '';
    $form->{waybill}       = $data->{wayBill}       || '';

    # Ship-to address
    foreach my $item (
        qw(name address1 address2 city state zipcode country contact phone fax email)
      )
    {
        $form->{"shipto$item"} = $data->{shipto}->{$item} || '';
    }

    # Build line items
    $form->{rowcount} = scalar @{ $data->{lines} || [] };
    for my $i ( 1 .. $form->{rowcount} ) {
        my $line = $data->{lines}[ $i - 1 ];

        $form->{"id_$i"}          = $line->{number}      || $line->{parts_id};
        $form->{"description_$i"} = $line->{description} || '';
        $form->{"qty_$i"}         = $line->{qty}         || 0;
        $form->{"ship_$i"}        = $line->{ship}        || 0;
        $form->{"sellprice_$i"}   = $line->{price}       || 0;
        $form->{"discount_$i"}    = $line->{discount}    || 0;
        $form->{"unit_$i"}        = $line->{unit}        || '';
        $form->{"lineitemdetail_$i"} = $line->{lineitemdetail} || 0;
        $form->{"reqdate_$i"} = $line->{deliverydate} || $line->{reqdate} || '';
        $form->{"itemnotes_$i"}        = $line->{itemnotes}        || '';
        $form->{"ordernumber_$i"}      = $line->{ordernumber}      || '';
        $form->{"serialnumber_$i"}     = $line->{serialnumber}     || '';
        $form->{"customerponumber_$i"} = $line->{customerponumber} || '';
        $form->{"costvendor_$i"}       = $line->{costvendor}       || '';
        $form->{"package_$i"}          = $line->{package}          || '';
        $form->{"volume_$i"}           = $line->{volume}           || 0;
        $form->{"netweight_$i"}        = $line->{netweight}        || 0;
        $form->{"grossweight_$i"} =
          $line->{grossweight} || $line->{weight} || 0;
        $form->{"cost_$i"}          = $line->{cost}        || 0;
        $form->{"projectnumber_$i"} = $line->{project}     || '';
        $form->{"project_id_$i"}    = $line->{project_id}  || '';
        $form->{"taxaccounts_$i"}   = $line->{taxaccounts} || '';
    }

    # Build payments
    $form->{paidaccounts} = scalar @{ $data->{payments} || [] };
    for my $payment_idx ( 0 .. $form->{paidaccounts} - 1 ) {
        my $payment = $data->{payments}[$payment_idx];
        my $i       = $payment_idx + 1;

        $form->{"datepaid_$i"}     = $payment->{date};
        $form->{"source_$i"}       = $payment->{source}       || '';
        $form->{"memo_$i"}         = $payment->{memo}         || '';
        $form->{"paid_$i"}         = $payment->{amount}       || 0;
        $form->{"exchangerate_$i"} = $payment->{exchangerate} || 1;

        # Set payment account based on vc type
        my $payment_field = ( $vc eq 'vendor' ) ? "AP_paid_$i" : "AR_paid_$i";
        $form->{$payment_field} = $payment->{account} . "--"
          if $payment->{account};

        # Set payment method if account number provided
        if ( my $accno = $payment->{account} ) {
            my $account_id =
              $dbs->query( "SELECT id FROM chart WHERE accno = ?", $accno )
              ->into( my $id );
            $form->{"payment_$i"} = "0--$id" if defined $id;
        }
    }

    # Taxes
    $form->{taxincluded} = $data->{taxincluded} || 0;
    if ( $data->{taxes} && ref( $data->{taxes} ) eq 'ARRAY' ) {
        my @taxaccounts;
        for my $tax ( @{ $data->{taxes} } ) {
            push @taxaccounts, $tax->{accno};
            $form->{"$tax->{accno}_rate"} = $tax->{rate} || 0;
        }
        $form->{taxaccounts} = join( ' ', @taxaccounts );
    }
    else {
        # Query taxes from database if not provided
        my $transdate = $data->{date} || $data->{transdate};

        my $taxes = $dbs->query(
            q{
            SELECT c.accno, t.rate, t.chart_id
            FROM tax t
            JOIN chart c ON c.id = t.chart_id
            WHERE t.validto IS NULL 
               OR t.validto >= ?
            ORDER BY t.chart_id, t.id DESC
            },
            $transdate
        )->hashes;

        if (@$taxes) {
            my @taxaccounts;
            my %seen_charts;

            for my $tax (@$taxes) {

                # Only use the first (most recent) rate for each chart_id
                next if $seen_charts{ $tax->{chart_id} };
                $seen_charts{ $tax->{chart_id} } = 1;

                push @taxaccounts, $tax->{accno};
                $form->{"$tax->{accno}_rate"} = $tax->{rate} || 0;
            }

            $form->{taxaccounts} = join( ' ', @taxaccounts );
        }
    }

    # Employee and language settings
    $form->{employee}      = $data->{employee}      || '';
    $form->{employee_id}   = $data->{employee_id}   || '';
    $form->{language_code} = $data->{language_code} || '';
    $form->{precision} =
      $data->{selectedCurrency}->{prec} || $data->{precision} || 2;

    # Department and warehouse
    $form->{department_id} = $data->{department_id} || '';
    $form->{warehouse}     = $data->{warehouse}     || '';
    $form->{warehouse_id}  = $data->{warehouse_id}  || '';

    # Save the order
    OE->save( $c->slconfig, $form );

    # Handle file uploads
    if ( $data->{files} && ref $data->{files} eq 'ARRAY' ) {
        $form->{files}  = $c->decode_base64_files( $data->{files} );
        $form->{client} = $client;
        FM->upload_files( $dbs, $c, $form, $vc );
    }

    return $form->{id};
}

$api->post(
    '/oe/:type/:vc/:id' => { id => undef } => sub {
        my $c      = shift;
        my $vc     = $c->param('vc')   || 'customer';
        my $type   = $c->param('type') || 'quotation';
        my $id     = $c->param('id');
        my $client = $c->param('client');

        my $data;
        my $content_type = $c->req->headers->content_type || '';

        if ( $content_type =~ m!multipart/form-data!i ) {
            $data         = handle_multipart_request($c);
            $data->{vc}   = $vc;
            $data->{type} = $type;
        }
        else {
            $data         = $c->req->json;
            $data->{vc}   = $vc;
            $data->{type} = $type;
        }

        my $form;
        if ( $type eq 'quotation' ) {
            $form = $c->check_perms("$vc.quotation");
        }
        else {
            $form = $c->check_perms("$vc.order");
        }
        my $new_order_id = process_order( $c, $data, $form, $client );

        # Return the newly posted or updated invoice ID
        $c->render( json => { id => $new_order_id } );
    }
);

$api->delete(
    '/oe/:type/:vc/:id' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $id     = $c->param('id');
        my $vc     = $c->param('vc');
        my $type   = $c->param('type');
        my $form   = new Form;

        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
        if ( $type eq 'quotation' ) {
            return unless $c->check_perms("$vc.quotation");
        }
        else {
            return unless $c->check_perms("$vc.order");
        }
        $form->{id} = $id;
        OE->delete( $c->slconfig, $form );

        $c->render( status => 204, data => '' );
    }
);

sub build_oe {
    my ( $c, $client, $form, $dbs ) = @_;
    my $template = $c->param("template");
    my $format   = $c->param("format");

    # Extract parameters
    my $client = $c->param('client') || die "Missing client parameter";
    my $vc     = $c->param('vc')     || die "Missing vc parameter";
    my $id     = $c->param('id')     || die "Missing invoice id";
    my $type   = $c->param('type')   || die "Missing type parameter";
    my $dbs    = $c->dbs($client);

    return unless my $form = $c->check_perms("$type.$vc");
    $form->{vc} = $vc;
    $form->{id} = $id;

    # Build invoice and letterhead data
    OE->retrieve( $c->slconfig, $form );
    my $i = 1;
    for my $item ( @{ $form->{form_details} || [] } ) {
        for my $key ( keys %$item ) {
            $form->{"${key}_$i"} = $item->{$key};
        }
        $i++;
    }
    $form->{rowcount} = $i;

    # Process tax data
    my $taxes_query = $dbs->query(
        q{
            SELECT c.accno, c.description, t.taxnumber, t.rate, t.chart_id
            FROM tax t
            JOIN chart c ON c.id = t.chart_id
            WHERE t.validto IS NULL 
               OR t.validto >= ?
            ORDER BY t.chart_id, t.id DESC
        },
        $form->{transdate}
    )->hashes;

    my %taxaccounts;
    my %taxbase;
    my $tax      = 0;
    my $taxrate  = 0;
    my $myconfig = $c->get_defaults();    # Assuming this method exists

    if (@$taxes_query) {
        my @taxaccounts_list;
        my %seen_charts;

        for my $tax_item (@$taxes_query) {

            # Only use the first (most recent) rate for each chart_id
            next if $seen_charts{ $tax_item->{chart_id} };
            $seen_charts{ $tax_item->{chart_id} } = 1;

            push @taxaccounts_list, $tax_item->{accno};
            $form->{"$tax_item->{accno}_rate"} = $tax_item->{rate};
            $form->{"$tax_item->{accno}_description"} =
              $tax_item->{description};
            $form->{"$tax_item->{accno}_taxnumber"} = $tax_item->{taxnumber};

            # Initialize tax accounts hash for processing
            $taxaccounts{ $tax_item->{accno} } = 0;
            $taxbase{ $tax_item->{accno} }     = 0;
        }
        $form->{taxaccounts} = join( ' ', @taxaccounts_list );

        # Process tax calculations
        for ( sort keys %taxaccounts ) {
            $taxaccounts{$_} =
              $form->round_amount( $taxaccounts{$_}, $form->{precision} );
            $tax += $taxaccounts{$_};
            $form->{"${_}_taxbaseinclusive"} =
              $taxbase{$_} + $taxaccounts{$_};

            push(
                @{ $form->{taxdescription} },
                $form->string_replace( $form->{"${_}_description"}, "%", "" )
            );

            $taxrate += $form->{"${_}_rate"};

            push( @{ $form->{xml_taxrate} }, $form->{"${_}_rate"} * 100 );
            push(
                @{ $form->{taxrate} },
                $form->format_amount(
                    $myconfig,          $form->{"${_}_rate"} * 100,
                    $form->{precision}, '0.00'
                )
            );
            push( @{ $form->{taxnumber} }, $form->{"${_}_taxnumber"} );
        }
    }

    AA->company_details( $c->slconfig, $form );
    OE->order_details( $c->slconfig, $form );

    my @f =
      qw(email name address1 address2 city state zipcode country contact phone fax);
    my $fillshipto = 1;

    # check for shipto
    foreach my $item (@f) {
        if ( $form->{"shipto$item"} ) {
            $fillshipto = 0;
            last;
        }
    }

    if ($fillshipto) {
        $fillshipto = 0;
        $fillshipto = 1
          if $form->{formname} =~
          /(credit_invoice|purchase_order|request_quotation|bin_list)/;
        $fillshipto = 1
          if ( $form->{type} eq 'invoice' && $form->{vc} eq 'vendor' );

        $form->{shiptophone}   = $form->{tel};
        $form->{shiptofax}     = $form->{fax};
        $form->{shiptocontact} = $form->{employee};

        if ($fillshipto) {
            if ( $form->{warehouse} ) {
                $form->{shiptoname} = $form->{company};
                for (qw(address1 address2 city state zipcode country)) {
                    $form->{"shipto$_"} = $form->{"warehouse$_"};
                }
            }
            else {
                # fill in company address
                $form->{shiptoname}     = $form->{company};
                $form->{shiptoaddress1} = $form->{address};
            }
        }
        else {
            for (@f) { $form->{"shipto$_"} = $form->{$_} }
            for (qw(phone fax)) {
                $form->{"shipto$_"} = $form->{"$form->{vc}$_"};
            }
        }
    }
    return $form;
}

$api->get(
    "/print_oe/:type/:vc/:id" => sub {
        my $c        = shift;
        my $template = $c->param("template");
        my $format   = $c->param("format");

        # Extract parameters
        my $client = $c->param('client') || die "Missing client parameter";
        my $vc     = $c->param('vc')     || die "Missing vc parameter";
        my $id     = $c->param('id')     || die "Missing invoice id";
        my $type   = $c->param('type')   || die "Missing type parameter";
        my $dbs    = $c->dbs($client);

        return unless my $form = $c->check_perms("$type.$vc");
        $form                      = build_oe( $c, $client, $form, $dbs );
        $form->{lastpage}          = 0;
        $form->{sumcarriedforward} = 0;
        $form->{templates}         = "templates/$client";
        $form->{IN}                = "$template.$format";

        # Set input and output based on type
        if ( $format eq 'tex' ) {
            $form->{OUT}    = ">tmp/invoice.pdf";
            $form->{format} = "pdf";
            $form->{media}  = "screen";
            $form->{copies} = 1;
        }
        elsif ( $format eq 'html' ) {
            $form->{OUT} = ">tmp/invoice.html";
        }
        else {
            die "Unsupported format: $format";
        }

        my $userspath = "tmp";
        my $defaults  = $c->get_defaults();

        # Process based on format
        if ( $format eq 'tex' ) {
            my $dvipdf  = "";
            my $xelatex = $defaults->{xelatex};
            $form->parse_template( $c->slconfig, $userspath, $dvipdf,
                $xelatex );

            my $pdf_path = "tmp/invoice.pdf";

            # Read PDF file content
            open my $fh, '<', $pdf_path or die "Cannot open file $pdf_path: $!";
            binmode $fh;
            my $pdf_content = do { local $/; <$fh> };
            close $fh;
            unlink $pdf_path or warn "Could not delete $pdf_path: $!";

            # Return PDF as response
            $c->res->headers->content_type('application/pdf');
            $c->res->headers->content_disposition(
                "attachment; filename=\"$id.pdf\"");
            $c->render( data => $pdf_content );
        }
        elsif ( $format eq 'html' ) {
            $form->parse_template( $c->slconfig, $userspath );

            # Strip the '>' character from the output file path
            ( my $file_path = $form->{OUT} ) =~ s/^>//;

            # Read the HTML file content
            open my $fh, '<', $file_path or die "Cannot open $file_path: $!";
            my $html_content = do { local $/; <$fh> };
            close $fh;
            unlink $file_path or warn "Could not delete $file_path: $!";

            # Convert HTML to PDF
            my $pdf = html_to_pdf($html_content);
            unless ($pdf) {
                return $c->render(
                    status => 500,
                    text   => "Failed to generate PDF"
                );
            }
            $c->res->headers->content_type('application/pdf');
            $c->render( data => $pdf );
        }
    }
);

###############################
####                       ####
####    Bank Adjustments   ####
####                       ####
###############################
$api->get(
    '/bank_adjustments/transactions' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms('bank.adjustments');
        my $dbs              = $c->dbs( $c->param('client') );
        my $clearing_account = $c->get_defaults->{clearing};

        eval {
            # Get account description
            my $account_desc =
              $dbs->query( "SELECT description FROM chart WHERE accno = ?",
                $clearing_account )->list
              || 'Unknown Account';

            my $sql = q{
            -- Accounts Receivable transactions
            SELECT ac.transdate, ar.invnumber as reference, ar.curr, ac.amount, ac.source, ac.memo,
                   ar.id as trans_id, ar.invoice, ar.description, c.name as company, 'AR' as trans_type
            FROM acc_trans ac 
            INNER JOIN ar ON ar.id = ac.trans_id 
            LEFT JOIN customer c ON c.id = ar.customer_id
            WHERE ac.chart_id IN (SELECT id FROM chart WHERE accno=?)
            
            UNION ALL
            
            -- Accounts Payable transactions  
            SELECT ac.transdate, ap.invnumber as reference, ap.curr, ac.amount, ac.source, ac.memo,
                   ap.id as trans_id, ap.invoice, ap.description, v.name as company, 'AP' as trans_type
            FROM acc_trans ac 
            INNER JOIN ap ON ap.id = ac.trans_id 
            LEFT JOIN vendor v ON v.id = ap.vendor_id
            WHERE ac.chart_id IN (SELECT id FROM chart WHERE accno=?)
            
            UNION ALL
            
            -- General Ledger transactions
            SELECT ac.transdate, gl.reference as reference, gl.curr, ac.amount, ac.source, ac.memo,
                   gl.id as trans_id, NULL as invoice, gl.description, '' as company, 'GL' as trans_type
            FROM acc_trans ac 
            INNER JOIN gl ON gl.id = ac.trans_id
            WHERE ac.chart_id IN (SELECT id FROM chart WHERE accno=?)
            
            ORDER BY transdate, reference
        };

            my $results =
              $dbs->query( $sql, $clearing_account, $clearing_account,
                $clearing_account )->hashes;

            # Process results
            my ( $total_debit, $total_credit ) = ( 0, 0 );

            for my $row (@$results) {
                $row->{reference_display} = $row->{reference} || '';

                if ( $row->{amount} < 0 ) {
                    $row->{debit}  = abs( $row->{amount} );
                    $row->{credit} = 0;
                    $total_debit += abs( $row->{amount} );
                }
                else {
                    $row->{debit}  = 0;
                    $row->{credit} = $row->{amount};
                    $total_credit += $row->{amount};
                }
            }

            $c->render(
                json => {
                    success => 1,
                    data    => {
                        transactions => $results,
                        totals       => {
                            debit  => $total_debit,
                            credit => $total_credit
                        },
                        account_info => {
                            number      => $clearing_account,
                            description => $account_desc
                        },
                        summary => {
                            total_records          => scalar @$results,
                            total_debit_formatted  => $total_debit,
                            total_credit_formatted => $total_credit
                        }
                    }
                }
            );
        };

        if ($@) {
            $c->render(
                json => {
                    success => 0,
                    error   => "Database error: $@"
                },
                status => 500
            );
        }
    }
);
$api->get(
    '/bank_adjustments/transaction_detail' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms('bank.adjustments');
        my $dbs = $c->dbs( $c->param('client') );

        my $trans_id = $c->param('trans_id');
        my $accno    = $c->param('accno')    || $c->get_defaults->{clearing};
        my $fromdate = $c->param('fromdate') || '';
        my $todate   = $c->param('todate')   || '';
        my $arap     = $c->param('arap')     || '';

        return $c->render(
            json => { success => 0, error => 'Transaction ID required' } )
          unless $trans_id;

        eval {
            # Get GL transaction details
            my $gl_query = q{
            SELECT gl.reference, ac.transdate, c.accno, c.description as account_description, 
                   gl.description, ac.source, ac.memo, ac.fx_transaction, gl.curr,
                   CASE WHEN ac.amount < 0 THEN ABS(ac.amount) ELSE 0 END as debit,
                   CASE WHEN ac.amount > 0 THEN ac.amount ELSE 0 END as credit
            FROM acc_trans ac
            JOIN chart c ON (c.id = ac.chart_id)
            JOIN gl ON gl.id = ac.trans_id
            WHERE ac.trans_id = ?
            ORDER BY c.accno
        };

            my $gl_transactions = $dbs->query( $gl_query, $trans_id )->hashes;

            # Get chart accounts for GL selection
            my $chart_accounts = $dbs->query(
                q{
            SELECT id, accno || '--' || substr(description,1,30) as descrip
            FROM chart
            WHERE charttype='A' AND allow_gl
            ORDER BY accno
        }
            )->hashes;

            # Get the search amount and determine AR/AP based on debit/credit
            my ( $search_debit, $search_credit ) = $dbs->query(
                q{
            SELECT 
                CASE WHEN ac.amount < 0 THEN ABS(ac.amount) ELSE 0 END as debit,
                CASE WHEN ac.amount > 0 THEN ac.amount ELSE 0 END as credit
            FROM acc_trans ac
            JOIN gl ON gl.id = ac.trans_id
            WHERE ac.trans_id = ? AND ac.chart_id = (SELECT id FROM chart WHERE accno = ?)
            AND NOT COALESCE(fx_transaction, false)
        }, $trans_id, $accno
            )->list;

            my $search_amount =
              ( $search_debit || 0 ) + ( $search_credit || 0 );

            # Auto-determine AR/AP if not set
            if ( !$arap ) {
                $arap = $search_debit > 0 ? 'ap' : 'ar';
            }

            $c->render(
                json => {
                    success => 1,
                    data    => {
                        gl_transactions => $gl_transactions,
                        chart_accounts  => $chart_accounts,
                        trans_id        => $trans_id,
                        accno           => $accno,
                        search_amount   => $search_amount,
                        arap            => $arap,
                        fromdate        => $fromdate,
                        todate          => $todate
                    }
                }
            );
        };

        if ($@) {
            $c->render(
                json   => { success => 0, error => "Database error: $@" },
                status => 500
            );
        }
    }
);

# 2. Outstanding Transactions Route
$api->get(
    '/bank_adjustments/outstanding_transactions' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms('bank.adjustments');
        my $dbs = $c->dbs( $c->param('client') );

        my $arap          = $c->param('arap')          || 'ar';
        my $fromdate      = $c->param('fromdate')      || '';
        my $todate        = $c->param('todate')        || '';
        my $search_amount = $c->param('search_amount') || 0;
        my $iban          = $c->param('iban')          || '';

        eval {
            # Get outstanding AR/AP transactions
            my ( @bind, $where_clause );
            if ($fromdate) {
                $where_clause .= " AND aa.transdate >= ?";
                push @bind, $fromdate;
            }
            if ($todate) {
                $where_clause .= " AND aa.transdate <= ?";
                push @bind, $todate;
            }
            if ($iban) {
                $where_clause .= " AND b.iban = ?";
                push @bind, $iban;
            }

            my $vc          = $arap eq 'ar' ? 'customer'    : 'vendor';
            my $vc_id_field = $arap eq 'ar' ? 'customer_id' : 'vendor_id';

            my $transactions_query = qq{
            SELECT aa.id, aa.invnumber, aa.transdate, aa.description, aa.ordnumber, 
                   vc.name, aa.curr, aa.amount, aa.paid, aa.amount - aa.paid as due, 
                   aa.invoice, b.iban
            FROM $arap aa
            JOIN $vc vc ON (vc.id = aa.${vc_id_field})
            LEFT JOIN bank b ON (b.id = aa.${vc_id_field})
            WHERE aa.amount - aa.paid != 0
            $where_clause
            ORDER BY aa.transdate
        };

            my $outstanding_transactions =
              $dbs->query( $transactions_query, @bind )->hashes;

            # Mark transactions that match the search amount
            for my $trans (@$outstanding_transactions) {
                $trans->{auto_selected} =
                  ( abs( $trans->{fxdue} || $trans->{due} ) == $search_amount )
                  ? 1
                  : 0;
            }

            $c->render(
                json => {
                    success => 1,
                    data    => {
                        outstanding_transactions => $outstanding_transactions,
                        arap                     => $arap,
                        search_amount            => $search_amount,
                        iban                     => $iban
                    }
                }
            );
        };

        if ($@) {
            $c->render(
                json   => { success => 0, error => "Database error: $@" },
                status => 500
            );
        }
    }
);

# 3. Booking Confirmation Route
$api->post(
    '/bank_adjustments/book_selected' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms('bank.adjustments');
        my $dbs  = $c->dbs( $c->param('client') );
        my $data = $c->req->json;

        my $trans_id      = $data->{trans_id};
        my $accno         = $data->{accno};
        my $gl_account_id = $data->{gl_account_id};
        my $selected_ids  = $data->{selected_ids} || '';

        eval {
            # Get GL transaction details for display
            my $gl_query = q{
            SELECT gl.id, gl.reference, ac.transdate, c.id as acc_id, c.accno, 
                   c.description as account_description, gl.description, ac.source, ac.memo,
                   CASE WHEN ac.amount < 0 THEN ABS(ac.amount) ELSE 0 END as debit,
                   CASE WHEN ac.amount > 0 THEN ac.amount ELSE 0 END as credit
            FROM acc_trans ac
            JOIN gl ON gl.id = ac.trans_id
            JOIN chart c ON (c.id = ac.chart_id)
            WHERE ac.trans_id = ?
            ORDER BY c.accno
        };

            my $gl_details = $dbs->query( $gl_query, $trans_id )->hashes;

            # Get selected transactions details if any
            my $selected_transactions = [];
            if ($selected_ids) {
                my @ids = split( ',', $selected_ids );
                if (@ids) {
                    my $ids_placeholder = join( ',', ('?') x @ids );
                    my $selected_query  = qq{
                    SELECT id, 'ar' as module, invnumber, description, ordnumber, transdate, amount, invoice
                    FROM ar WHERE id IN ($ids_placeholder)
                    UNION ALL
                    SELECT id, 'ap' as module, invnumber, description, ordnumber, transdate, amount, invoice  
                    FROM ap WHERE id IN ($ids_placeholder)
                    ORDER BY id
                };
                    $selected_transactions =
                      $dbs->query( $selected_query, @ids, @ids )->hashes;
                }
            }

            # Get GL account details if selected
            my $gl_account_details = {};
            if ($gl_account_id) {
                $gl_account_details = $dbs->query(
                    "SELECT accno, description FROM chart WHERE id = ?",
                    $gl_account_id )->hash
                  || {};
            }

            $c->render(
                json => {
                    success => 1,
                    data    => {
                        gl_details            => $gl_details,
                        selected_transactions => $selected_transactions,
                        gl_account_details    => $gl_account_details,
                        trans_id              => $trans_id,
                        accno                 => $accno,
                        gl_account_id         => $gl_account_id,
                        selected_ids          => $selected_ids
                    }
                }
            );
        };

        if ($@) {
            $c->render(
                json   => { success => 0, error => "Database error: $@" },
                status => 500
            );
        }
    }
);
$api->post(
    '/bank_adjustments/process_adjustment' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms('bank.adjustments');
        my $dbs  = $c->dbs( $c->param('client') );
        my $data = $c->req->json;

        my $trans_id      = $data->{trans_id};
        my $gl_account_id = $data->{gl_account_id};
        my $accno         = $data->{accno};
        my $selected_ids  = $data->{selected_ids} || '';

        my $clearing_account   = $c->get_defaults->{clearing};
        my $transition_account = $c->get_defaults->{transition};

        eval {
            # Start transaction
            $dbs->begin;

            # Get clearing and transition account IDs
            my $clearing_accno_id =
              $dbs->query( "SELECT id FROM chart WHERE accno = ?",
                $clearing_account )->list;

            my $transition_accno_id =
              $dbs->query( "SELECT id FROM chart WHERE accno = ?",
                $transition_account )->list;

            # Simple GL account change (no AR/AP transactions selected)
            if ( $gl_account_id && !$selected_ids ) {
                $dbs->query(
"UPDATE acc_trans SET chart_id = ? WHERE chart_id = ? AND trans_id = ?",
                    $gl_account_id, $clearing_accno_id, $trans_id );

                $dbs->commit;
                $c->render(
                    json => {
                        success => 1,
                        message => 'GL account updated successfully',
                        type    => 'gl_updated'
                    }
                );
                return;
            }

            # Complex adjustment with AR/AP transactions
            if ($selected_ids) {
                my @ids = split( ',', $selected_ids );

                # Get GL transaction details
                my ( $gl_date, $curr, $fxrate ) = $dbs->query(
"SELECT transdate, curr, COALESCE(exchangerate, 1) FROM gl WHERE id = ?",
                    $trans_id
                )->list;

                $fxrate ||= 1;    # Default to 1 if null

                # Get the adjustment amount available from GL
                my $adjustment_available = $dbs->query(
"SELECT 0 - amount FROM acc_trans WHERE chart_id = ? AND trans_id = ? AND NOT COALESCE(fx_transaction, false)",
                    $clearing_accno_id, $trans_id
                  )->list
                  || 0;

                # Get AR/AP transactions to be adjusted
                my $ids_placeholder = join( ',', ('?') x @ids );
                my $query           = qq{
                SELECT id, 'ar' as tbl, invnumber, transdate, amount - paid as fxdue
                FROM ar
                WHERE id IN ($ids_placeholder)
                
                UNION ALL
                
                SELECT id, 'ap' as tbl, invnumber, transdate, amount - paid as fxdue
                FROM ap
                WHERE id IN ($ids_placeholder)
                
                ORDER BY id
            };

                my @rows = $dbs->query( $query, @ids, @ids )->hashes;

                my $adjustment_total = 0;
                my $arap
                  ; # Declare outside the loop so it's available for final GL adjustment

                # Process each selected AR/AP transaction
                for my $row (@rows) {
                    $arap = $row->{tbl};
                    my $ml =
                      ( $arap eq 'ap' ) ? 1 : -1;    # Multiplier for AP vs AR
                    my $ARAP = uc($arap);

                    # Determine payment date (later of GL date or AR/AP date)
                    my $arap_date = $row->{transdate} || '';
                    my $payment_date;

          # Compare dates properly using string comparison for YYYY-MM-DD format
                    if ( !$gl_date || !$arap_date ) {
                        $payment_date =
                          $gl_date || $arap_date || 'CURRENT_DATE';
                    }
                    elsif ( $gl_date ge $arap_date ) {
                        $payment_date = $gl_date;    # gl_date is later or equal
                    }
                    else {
                        $payment_date = $arap_date;    # arap_date is later
                    }

                    # Calculate amount to be adjusted
                    my $amount_to_be_adjusted;
                    if ( $adjustment_available * $ml < $row->{fxdue} ) {
                        $amount_to_be_adjusted = $adjustment_available;
                        $adjustment_available  = 0;
                    }
                    else {
                        $amount_to_be_adjusted = $row->{fxdue};
                        $adjustment_available -= $row->{fxdue};
                    }

                    # Calculate FX adjustment if needed
                    my $fx_amount_to_be_adjusted =
                      $amount_to_be_adjusted * $fxrate - $amount_to_be_adjusted;
                    my $payment_id = undef;

                    if ( $fxrate != 1 ) {
                        $payment_id = $dbs->query(
                            "SELECT COALESCE(MAX(id), 0) + 1 FROM payment")
                          ->list || 1;
                    }

                    # Get the AR/AP account ID
                    my $arap_accno_id = $dbs->query(
"SELECT chart_id FROM acc_trans WHERE trans_id = ? AND chart_id IN (SELECT id FROM chart WHERE link = ?) LIMIT 1",
                        $row->{id}, "${ARAP}"
                    )->list;

                    if ( $arap eq 'ap' ) {

                        # AP adjustments
                        $dbs->query(
"INSERT INTO acc_trans(trans_id, chart_id, transdate, amount, id) VALUES (?, ?, ?, ?, ?)",
                            $row->{id},    $transition_accno_id,
                            $payment_date, $amount_to_be_adjusted,
                            $payment_id
                        );

                        if ( $fx_amount_to_be_adjusted != 0 ) {
                            $dbs->query(
"INSERT INTO acc_trans(trans_id, chart_id, fx_transaction, transdate, amount) VALUES (?, ?, ?, ?, ?)",
                                $row->{id},
                                $transition_accno_id,
                                't',
                                $payment_date,
                                $fx_amount_to_be_adjusted
                            );
                        }

                        $dbs->query(
"INSERT INTO acc_trans(trans_id, chart_id, transdate, amount) VALUES (?, ?, ?, ?)",
                            $row->{id},
                            $arap_accno_id,
                            $payment_date,
                            ( $row->{fxdue} * -1 ) + (
                                ( $row->{fxdue} * $fxrate - $row->{fxdue} ) * -1
                            )
                        );
                    }
                    else {
                        # AR adjustments
                        $dbs->query(
"INSERT INTO acc_trans(trans_id, chart_id, transdate, amount, id) VALUES (?, ?, ?, ?, ?)",
                            $row->{id},
                            $transition_accno_id,
                            $payment_date,
                            $amount_to_be_adjusted * -1,
                            $payment_id
                        );

                        if ( $fx_amount_to_be_adjusted != 0 ) {
                            $dbs->query(
"INSERT INTO acc_trans(trans_id, chart_id, fx_transaction, transdate, amount) VALUES (?, ?, ?, ?, ?)",
                                $row->{id},
                                $transition_accno_id,
                                't',
                                $payment_date,
                                $fx_amount_to_be_adjusted * -1
                            );
                        }

                        $dbs->query(
"INSERT INTO acc_trans(trans_id, chart_id, transdate, amount) VALUES (?, ?, ?, ?)",
                            $row->{id},
                            $arap_accno_id,
                            $payment_date,
                            $row->{fxdue} +
                              ( $row->{fxdue} * $fxrate - $row->{fxdue} )
                        );
                    }

                    # Insert payment record if payment_id was generated
                    if ($payment_id) {
                        $dbs->query(
"INSERT INTO payment (id, trans_id, exchangerate) VALUES (?, ?, ?)",
                            $payment_id, $row->{id}, $fxrate );
                    }

                    # Update AR/AP paid amounts and payment date
                    $dbs->query(
"UPDATE $arap SET paid = paid + ?, datepaid = ? WHERE id = ?",
                        $amount_to_be_adjusted + $fx_amount_to_be_adjusted,
                        $payment_date,
                        $row->{id}
                    );

                    $adjustment_total += $amount_to_be_adjusted;
                }

    # Update GL transaction - move clearing account amount to transition account
    # Apply AP/AR direction logic to adjustment total
                if ( $arap eq 'ap' ) {
                    $adjustment_total *= -1;
                }

                if ( $adjustment_total != 0 ) {

                    # Get the current clearing account amount
                    my $clearing_amount = $dbs->query(
"SELECT amount FROM acc_trans WHERE chart_id = ? AND trans_id = ? AND NOT COALESCE(fx_transaction, false)",
                        $clearing_accno_id, $trans_id
                    )->list;

                    if ( $adjustment_total == $clearing_amount ) {

    # Full adjustment - simply change the clearing account to transition account
                        $dbs->query(
"UPDATE acc_trans SET chart_id = ? WHERE chart_id = ? AND trans_id = ? AND NOT COALESCE(fx_transaction, false)",
                            $transition_accno_id, $clearing_accno_id,
                            $trans_id );
                    }
                    else {
                       # Partial adjustment - reduce clearing and add transition
                        $dbs->query(
"UPDATE acc_trans SET amount = amount - ? WHERE chart_id = ? AND trans_id = ? AND NOT COALESCE(fx_transaction, false)",
                            $adjustment_total, $clearing_accno_id, $trans_id );

                        $dbs->query(
"INSERT INTO acc_trans (trans_id, chart_id, amount, transdate) VALUES (?, ?, ?, ?)",
                            $trans_id, $transition_accno_id, $adjustment_total,
                            $gl_date );
                    }

                    # Add FX transaction for transition account if needed
                    my $fx_adjustment =
                      $adjustment_total * $fxrate - $adjustment_total;
                    if ( $fx_adjustment != 0 ) {
                        $dbs->query(
"INSERT INTO acc_trans (trans_id, chart_id, amount, transdate, fx_transaction) VALUES (?, ?, ?, ?, ?)",
                            $trans_id,
                            $transition_accno_id,
                            $fx_adjustment,
                            $gl_date,
                            't'
                        );
                    }
                }
                $dbs->commit;
                $c->render(
                    json => {
                        success => 1,
                        message => 'Adjustment processed successfully',
                        type    => 'adjustment_complete'
                    }
                );
            }
        };

        if ($@) {
            $dbs->rollback;
            $c->render(
                json =>
                  { success => 0, error => "Error processing adjustment: $@" },
                status => 500
            );
        }
    }
);
###############################
####                       ####
####        Reports        ####
####                       ####
###############################

$api->get(
    '/reports/trial_balance' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms('reports.trial');
        my $client = $c->param('client');

        my $datefrom = $c->param('fromdate');
        my $dateto   = $c->param('todate');

        $form->{fromdate} = $datefrom || '';
        $form->{todate}   = $dateto   || '';

        RP->trial_balance( $c->slconfig, $form );

        $c->render( json => $form->{TB} );

    }
);
$api->get(
    '/reports/transactions' => sub {
        my $c = shift;
        return
          unless my $form = ( $c->check_perms('reports.trial')
              || $c->check_perms('reports.income') );
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);

        $form->{fromdate}      = $c->param('fromdate')   || '';
        $form->{todate}        = $c->param('todate')     || '';
        $form->{accno}         = $c->param('accno')      || '';
        $form->{department}    = $c->param('department') || '';
        $form->{projectnumber} = $c->param('project')    || '';
        $form->{accounttype}   = 'standard';

        # Query the chart table to get the current account record.
        my $chart_sql =
          'SELECT accno, charttype, description FROM chart WHERE accno = ?';
        my $result = $dbs->query( $chart_sql, $form->{accno} );
        my $heading_row =
          $result->hash;    # use the 'hash' method instead of fetchrow_hashref

        my $response = {};

        if ( $heading_row->{charttype} eq 'A' ) {

            # For an account type "A", process transactions normally.
            CA->all_transactions( $c->slconfig, $form );
            $response->{transactions} = $form->{CA};
            $response->{accno}        = $form->{accno};
            $response->{description}  = $form->{description};
        }
        else {
            # If it's a heading ("H"), fetch its child accounts.
            my @child_accnos;
            my $child_sql =
'SELECT accno, charttype FROM chart WHERE accno > ? ORDER BY accno';
            my $child_result = $dbs->query( $child_sql, $heading_row->{accno} );
            while ( my $row = $child_result->hash )
            {    # iterate using the 'hash' method
                last if $row->{charttype} eq 'H';
                push @child_accnos, $row->{accno};
            }

            my @combined_transactions;

            foreach my $child (@child_accnos) {
                $form->{accno} = $child;
                CA->all_transactions( $c->slconfig, $form );
                push @combined_transactions, @{ $form->{CA} || [] };
            }

            # Build the response using the heading's details.
            $response->{transactions} = \@combined_transactions;
            $response->{accno}        = $heading_row->{accno};
            $response->{description}  = $heading_row->{description};
        }
        eval {
            # Fetch files for all transactions in a single operation
            FM->get_files_for_transactions(
                $dbs,
                {
                    api_url => $base_url,
                    client  => $client
                },
                $response->{transactions}
            );
        };
        if ($@) {
            $c->app->log->error("Error getting files for transactions: $@");
        }

        $c->render( json => $response );
    }
);

$api->get(
    '/reports/income_statement' => sub {
        my $c = shift;
        return unless $c->check_perms('reports.income');

        my $client = $c->param('client');
        my $params = $c->req->params->to_hash;

        my $form   = Form->new;
        my $locale = Locale->new;

        # Get default currency from database
        my $currencies = $form->get_currencies( $c->slconfig );
        unless ($currencies) {
            return $c->render(
                status => 400,
                json => { error => 'No currencies configured in the database' }
            );
        }
        my $default_currency = substr( $currencies, 0, 3 );

        $form->{currency}        = $params->{currency} || $default_currency;
        $form->{defaultcurrency} = $default_currency;
        $form->{decimalplaces}   = $params->{decimalplaces} // "2";
        $form->{method}          = $params->{method}        // "accrual";
        $form->{includeperiod}   = $params->{includeperiod} // "year";
        $form->{previousyear}    = $params->{previousyear}  // "0";
        $form->{accounttype}     = $params->{accounttype}   // "standard";
        $form->{l_accno}         = $params->{l_accno}       // 0;
        $form->{usetemplate}     = $params->{usetemplate}   // '';
        $form->{heading_level}   = $params->{heading_level} // '';

        # Parse periods first — indexed: periods[N][label]=..., periods[N][fromdate]=...
        # We need these before determining the common date range below.
        my $periods = [];
        for my $key ( keys %$params ) {
            if ( $key =~ /^periods\[(\d+)\]\[(\w+)\]$/ ) {
                my ( $index, $field ) = ( $1, $2 );
                $periods->[$index]{$field} = $params->{$key};
            }
        }

        # Shared date range for department/project comparison mode.
        # Prefer explicit top-level fromdate/todate; fall back to the first
        # period's dates (the front-end may only send dates inside periods[]).
        my $common_fromdate = ( $params->{fromdate} && $params->{fromdate} ne '' )
                            ? $params->{fromdate}
                            : ( $periods->[0]{fromdate} // "" );
        my $common_todate   = ( $params->{todate} && $params->{todate} ne '' )
                            ? $params->{todate}
                            : ( $periods->[0]{todate} // "" );

        $form->{fromdate} = $common_fromdate;
        $form->{todate}   = $common_todate;

        # Parse departments — supports indexed (departments[0]=Name--ID),
        # repeated params, or single (department=Name--ID)
        my @departments;
        {
            my %dept_idx;
            for my $key ( keys %$params ) {
                if ( $key =~ /^departments\[(\d+)\]$/ ) {
                    $dept_idx{$1} = $params->{$key};
                }
            }
            if (%dept_idx) {
                @departments =
                  map { $dept_idx{$_} } sort { $a <=> $b } keys %dept_idx;
            }
            elsif ( exists $params->{department} ) {
                my $d = $params->{department};
                @departments = ref $d eq 'ARRAY' ? @$d : ($d);
            }
            @departments = grep { /\S/ } @departments;
        }

        # Parse projectnumbers — supports indexed (projectnumbers[0]=Name--ID),
        # repeated params, or single (projectnumber=Name--ID)
        my @projectnumbers;
        {
            my %proj_idx;
            for my $key ( keys %$params ) {
                if ( $key =~ /^projectnumbers\[(\d+)\]$/ ) {
                    $proj_idx{$1} = $params->{$key};
                }
            }
            if (%proj_idx) {
                @projectnumbers =
                  map { $proj_idx{$_} } sort { $a <=> $b } keys %proj_idx;
            }
            elsif ( exists $params->{projectnumber} ) {
                my $p = $params->{projectnumber};
                @projectnumbers = ref $p eq 'ARRAY' ? @$p : ($p);
            }
            @projectnumbers = grep { /\S/ } @projectnumbers;
        }

        # Validate: at most one dimension may have multiple items
        my $multi_count = ( scalar(@$periods)      > 1 ? 1 : 0 )
                        + ( scalar(@departments)   > 1 ? 1 : 0 )
                        + ( scalar(@projectnumbers) > 1 ? 1 : 0 );
        if ( $multi_count > 1 ) {
            return $c->render(
                status => 400,
                json   => {
                    error =>
                      'Only one comparison dimension is allowed at a time: multiple periods, departments, or projects'
                }
            );
        }

        if ( scalar(@departments) > 1 ) {
            # Department comparison: each department becomes a column keyed by
            # its description looked up from the database.
            my %labels = _lookup_comparison_labels(
                $c->dbs($client), 'department', @departments );
            $form->{comparison_mode} = 'department';
            $periods = [
                map {
                    {   label      => $labels{$_},
                        department => $_,
                        fromdate   => $common_fromdate,
                        todate     => $common_todate,
                    }
                } @departments
            ];
            $form->{department}    = "";
            $form->{projectnumber} = @projectnumbers ? $projectnumbers[0] : "";
        }
        elsif ( scalar(@projectnumbers) > 1 ) {
            # Project comparison: each project becomes a column keyed by its
            # description looked up from the database.
            my %labels = _lookup_comparison_labels(
                $c->dbs($client), 'project', @projectnumbers );
            $form->{comparison_mode} = 'project';
            $periods = [
                map {
                    {   label         => $labels{$_},
                        projectnumber => $_,
                        fromdate      => $common_fromdate,
                        todate        => $common_todate,
                    }
                } @projectnumbers
            ];
            $form->{department}    = @departments ? $departments[0] : "";
            $form->{projectnumber} = "";
        }
        else {
            # Period comparison (default): single dept/project filter, multiple date ranges
            $form->{comparison_mode} = 'period';
            $form->{department}    = @departments    ? $departments[0]    : "";
            $form->{projectnumber} = @projectnumbers ? $projectnumbers[0] : "";
        }

        $form->{periods} = $periods;

        RP->income_statement_periods( $c->slconfig, $form, $locale );

        if ( $form->{usetemplate} eq 'Y' ) {
            my $account_map = {
                I => { ml => 1 },
                E => { ml => -1 },
            };

            my $myconfig = $c->slconfig;
            my $timeperiod =
              $locale->date( \%$myconfig, $form->{fromdate},
                $form->{longformat} )
              . ' '
              . $locale->text('To') . ' '
              . $locale->date( \%myconfig, $form->{todate},
                $form->{longformat} );

            build_income_statement( $form, $locale, $account_map, $myconfig,
                $timeperiod );

            my $logo_base64 = get_image_base64(
                $c->app->home->rel_file("templates/$client/logo.png") );

            my $template_data = {
                company           => $form->{company} || '',
                address           => $form->{address} || '',
                department        => $form->{department},
                projectnumber     => $form->{projectnumber},
                currency          => $form->{currency},
                periods           => $form->{_periods},
                income_data       => $form->{income_data},
                expense_data      => $form->{expense_data},
                income_hierarchy  => $form->{income_hierarchy},
                expense_hierarchy => $form->{expense_hierarchy},
                formatted_totals  => $form->{formatted_totals},
                logo              => $logo_base64,
                heading_level     => $form->{heading_level},
            };

            my $html_content = $c->render_to_string(
                template => "$client/income_statement",
                %$template_data
            );

            my $pdf = html_to_pdf($html_content);
            unless ($pdf) {
                return $c->render(
                    status => 500,
                    text   => "Failed to generate PDF"
                );
            }

            $c->res->headers->content_type('application/pdf');
            $c->render( data => $pdf );
            return;
        }

        $c->render( json => {%$form} );
    }
);

sub html_to_pdf {
    my ($html_content) = @_;

    # Check if required modules are available
    eval {
        require PDF::WebKit;
        require File::Temp;
        PDF::WebKit->import();
        1;
    } or do {
        warn "PDF::WebKit or File::Temp module not found: $@";
        return 0;
    };

    # Write HTML to temporary file with UTF-8 encoding
    my ( $fh, $filename ) =
      File::Temp::tempfile( SUFFIX => '.html', UNLINK => 1 );

    binmode( $fh, ':encoding(UTF-8)' );
    print $fh $html_content;
    close $fh;

    my $kit;
    eval {
        # Use the minimal approach that worked in debug
        $kit = PDF::WebKit->new($filename);
        1;
    } or do {
        warn "Failed to initialize PDF::WebKit: $@";
        return 0;
    };

    my $pdf;
    eval {
        $pdf = $kit->to_pdf;
        1;
    } or do {
        warn "Failed to generate PDF: $@";
        return 0;
    };

    # Check if PDF was generated successfully with reasonable size
    if ( defined $pdf && length($pdf) > 1000 ) {
        return $pdf;
    }
    else {
        warn "Generated PDF appears to be empty or too small: "
          . ( defined $pdf ? length($pdf) . " bytes" : "undefined" );
        return 0;
    }
}

sub get_image_base64 {
    my ($logo_path) = @_;

    # Read the logo file
    open my $fh, '<:raw', $logo_path or return '';
    my $logo_data = do { local $/; <$fh> };
    close $fh;

    # Convert to base64
    use MIME::Base64;
    my $base64 = encode_base64( $logo_data, '' );

    # Determine MIME type based on file extension
    my $mime_type = 'image/png';    # default
    if ( $logo_path =~ /\.jpe?g$/i ) {
        $mime_type = 'image/jpeg';
    }
    elsif ( $logo_path =~ /\.gif$/i ) {
        $mime_type = 'image/gif';
    }
    elsif ( $logo_path =~ /\.svg$/i ) {
        $mime_type = 'image/svg+xml';
    }

    return "data:$mime_type;base64,$base64";
}

#----------------------------------------------------------------
# Subroutine: build_report
#
# Now accepts required objects/variables as parameters.
#----------------------------------------------------------------
sub build_income_statement {
    my ( $form, $locale, $account_map, $myconfig, $timeperiod ) = @_;

    my @periods = map { $_->{label} } @{ $form->{periods} };

    my ( %income_data,      %expense_data );
    my ( %total_income,     %total_expense );
    my ( %income_hierarchy, %expense_hierarchy );
    my $data_key = '';

    foreach my $accno ( sort { $a <=> $b } keys %{ $form->{$data_key} } ) {
        foreach my $period (@periods) {
            next unless exists $form->{$data_key}{$accno}{$period};
            my ($cat) = keys %{ $form->{$data_key}{$accno}{$period} };
            next unless $cat =~ /^(I|E)$/;

            my $data         = $form->{$data_key}{$accno}{$period}{$cat};
            my $charttype    = $data->{charttype};
            my $description  = $data->{description};
            my $amount       = $data->{amount};
            my $ml           = $account_map->{$cat}{ml} // 1;
            my $parent_accno = $data->{parent_accno};

            my $formatted_amount = $form->format_amount(
                $myconfig,
                $amount * $ml,
                $form->{decimalplaces}, ''
            );

            my $label =
              $charttype eq "A"
              ? ( $form->{l_accno} ? "$accno - $description" : $description )
              : $description;

            my $target_data  = $cat eq 'I' ? \%income_data  : \%expense_data;
            my $target_total = $cat eq 'I' ? \%total_income : \%total_expense;
            my $target_hierarchy =
              $cat eq 'I' ? \%income_hierarchy : \%expense_hierarchy;

            $target_data->{$accno}{label} ||= $label;
            $target_data->{$accno}{charttype}        = $charttype;
            $target_data->{$accno}{parent_accno}     = $parent_accno;
            $target_data->{$accno}{amounts}{$period} = $formatted_amount;

            next if $charttype eq 'H';
            $target_total->{$period} += $amount * $ml;
        }
    }

    # Build hierarchy for income and expense
    foreach my $cat (
        [ 'I', \%income_data,  \%income_hierarchy ],
        [ 'E', \%expense_data, \%expense_hierarchy ]
      )
    {
        my ( $c, $data, $hierarchy ) = @$cat;
        my @root_accounts;

        foreach my $accno ( sort { $a <=> $b } keys %$data ) {
            my $parent = $data->{$accno}{parent_accno};
            if ( !$parent || !exists $data->{$parent} ) {
                push @root_accounts, $accno;
            }
        }

        foreach my $accno ( keys %$data ) {
            my $parent = $data->{$accno}{parent_accno};
            if ( $parent && exists $data->{$parent} ) {
                $data->{$parent}{children}{$accno} = 1;
            }
        }

        foreach my $root (@root_accounts) {
            $hierarchy->{$root} = 1;
            _calculate_levels( $data, $root, 0 );
        }
    }

    # Format totals
    my %formatted_totals;
    foreach my $period (@periods) {
        $formatted_totals{income}{$period} = $form->format_amount(
            $myconfig,
            $total_income{$period} || 0,
            $form->{decimalplaces}, ''
        );
        $formatted_totals{expense}{$period} = $form->format_amount(
            $myconfig,
            $total_expense{$period} || 0,
            $form->{decimalplaces}, ''
        );
        $formatted_totals{profit}{$period} = $form->format_amount(
            $myconfig,
            ( $total_income{$period} || 0 ) - ( $total_expense{$period} || 0 ),
            $form->{decimalplaces},
            ''
        );
    }

    $form->{income_data}       = \%income_data;
    $form->{expense_data}      = \%expense_data;
    $form->{income_hierarchy}  = \%income_hierarchy;
    $form->{expense_hierarchy} = \%expense_hierarchy;
    $form->{formatted_totals}  = \%formatted_totals;
    $form->{period}            = join( " / ", @periods );
    $form->{_periods}          = \@periods;
    $form->{timeperiod}        = $timeperiod;

    return 1;
}

sub build_balance_sheet {
    my ( $form, $locale, $myconfig, $timeperiod, $report_type ) = @_;

    # Extract period labels from the defined periods
    my @periods = map { $_->{label} } @{ $form->{periods} };
    my ( %balance_data, %category_totals, %hierarchy );
    my $data_key = '';

    # First, collect all data and calculate raw category totals
    foreach my $accno ( sort { $a <=> $b } keys %{ $form->{$data_key} } ) {
        foreach my $period (@periods) {
            next unless exists $form->{$data_key}{$accno}{$period};
            my @cats = keys %{ $form->{$data_key}{$accno}{$period} };
            next unless @cats == 1;
            my $cat = $cats[0];
            next unless $cat =~ /^(A|L|Q)$/;

            my $data      = $form->{$data_key}{$accno}{$period}{$cat};
            my $charttype = $data->{charttype};

            # Skip non-heading accounts if heading_only is true
            if ( $form->{heading_only} && $charttype ne 'H' ) {
                next;
            }

            my $description  = $data->{description};
            my $amount       = $data->{amount};
            my $parent_accno = $data->{parent_accno};

            # Flip the sign for Assets right after reading
            if ( $cat eq 'A' ) {
                $amount = -$amount;
            }

            # Determine the multiplier for summation based on category
            my $ml;
            if ( $cat eq 'A' ) {
                $ml = 1;    # Assets contribute positively after sign flip
            }
            elsif ( $cat eq 'L' || $cat eq 'Q' ) {
                $ml = -1;    # Liabilities & Equity contribute negatively
            }

            # Calculate the value contributing to the category total sum
            my $signed_amount = $amount * $ml;

            # Format the amount for display
            my $formatted_amount = $form->format_amount( $myconfig, $amount,
                $form->{decimalplaces}, '' );

            my $label = "";
            if ( $charttype eq "A" ) {
                $label =
                  $form->{l_accno} ? "$accno - $description" : $description;
            }
            else {
                $label = $description;
            }

            # Store account data
            if ( !exists $balance_data{$cat}{$accno} ) {
                $balance_data{$cat}{$accno} = {
                    label        => $label,
                    charttype    => $charttype,
                    parent_accno => $parent_accno,
                    amounts      => {},
                    children     => {},
                    level        => 0                # Will be calculated later
                };
            }

            $balance_data{$cat}{$accno}{amounts}{$period} = $formatted_amount;
            next if $charttype eq 'H';  # skip headings to avoid double counting
                # Add the correctly signed amount to totals
            $category_totals{$cat}{$period} += $signed_amount;
        }
    }

    # Build hierarchical structure for each category
    foreach my $cat (qw(A L Q)) {
        next unless exists $balance_data{$cat};

        # Find root accounts (accounts with no parent or parent not in our data)
        my @root_accounts = ();
        foreach my $accno ( sort { $a <=> $b } keys %{ $balance_data{$cat} } ) {
            my $parent = $balance_data{$cat}{$accno}{parent_accno};
            if ( !$parent || !exists $balance_data{$cat}{$parent} ) {
                push @root_accounts, $accno;
            }
        }

        # Build parent-child relationships
        foreach my $accno ( keys %{ $balance_data{$cat} } ) {
            my $parent = $balance_data{$cat}{$accno}{parent_accno};
            if ( $parent && exists $balance_data{$cat}{$parent} ) {
                $balance_data{$cat}{$parent}{children}{$accno} = 1;
            }
        }

        # Calculate levels and store hierarchy
        $hierarchy{$cat} = {};
        foreach my $root_accno (@root_accounts) {
            $hierarchy{$cat}{$root_accno} = 1;
            _calculate_levels( $balance_data{$cat}, $root_accno, 0 );
        }
    }

    # If heading_only is true, find max level headings and convert them to 'A'
    if ( $form->{heading_only} ) {
        foreach my $cat (qw(A L Q)) {
            next unless exists $balance_data{$cat};

            # Find the maximum level among heading accounts
            my $max_level = -1;
            foreach my $accno ( keys %{ $balance_data{$cat} } ) {
                if ( $balance_data{$cat}{$accno}{charttype} eq 'H' ) {
                    my $level = $balance_data{$cat}{$accno}{level};
                    $max_level = $level if $level > $max_level;
                }
            }

            # Convert max level headings from 'H' to 'A' and recalculate totals
            if ( $max_level >= 0 ) {
                foreach my $accno ( keys %{ $balance_data{$cat} } ) {
                    if (   $balance_data{$cat}{$accno}{charttype} eq 'H'
                        && $balance_data{$cat}{$accno}{level} == $max_level )
                    {

                        # Change charttype to 'A'
                        $balance_data{$cat}{$accno}{charttype} = 'A';

                        # Update label format for 'A' type
                        my $description = $balance_data{$cat}{$accno}{label};
                        $balance_data{$cat}{$accno}{label} =
                          $form->{l_accno}
                          ? "$accno - $description"
                          : $description;

                        # Now add these amounts to category totals
                        foreach my $period (@periods) {
                            if (
                                exists $balance_data{$cat}{$accno}{amounts}
                                {$period} )
                            {
                                my $formatted =
                                  $balance_data{$cat}{$accno}{amounts}{$period};

                                # Parse the formatted amount back to numeric
                                my $amount =
                                  $form->parse_amount( $myconfig, $formatted );

                                # Determine the multiplier
                                my $ml;
                                if ( $cat eq 'A' ) {
                                    $ml = 1;
                                }
                                elsif ( $cat eq 'L' || $cat eq 'Q' ) {
                                    $ml = -1;
                                }

                                my $signed_amount = $amount * $ml;
                                $category_totals{$cat}{$period} +=
                                  $signed_amount;
                            }
                        }
                    }
                }
            }
        }
    }

    # Calculate final totals
    my %net_totals;
    my %current_earnings;

    foreach my $period (@periods) {

        # Get the raw summed totals for each category for this period
        my $raw_assets   = $category_totals{'A'}{$period} || 0;
        my $raw_liabs    = $category_totals{'L'}{$period} || 0;
        my $raw_equity_q = $category_totals{'Q'}{$period} || 0;

        # Core Calculation Logic
        my $total_assets      = $raw_assets;       # Should be positive
        my $total_liabilities = -$raw_liabs;       # Should now be positive
        my $recorded_equity   = -$raw_equity_q;    # Should now be positive

        # Equity = Assets - Liabilities
        my $calculated_total_equity = $total_assets - $total_liabilities;

        # Current Earnings = Calculated Total Equity - Recorded Equity
        my $current_earnings_amount =
          $calculated_total_equity - $recorded_equity;

        $net_totals{assets}{$period}           = $total_assets;
        $net_totals{liabilities}{$period}      = $total_liabilities;
        $net_totals{recorded_equity}{$period}  = $recorded_equity;
        $net_totals{total_equity}{$period}     = $calculated_total_equity;
        $net_totals{current_earnings}{$period} = $current_earnings_amount;
        $net_totals{total_liabilities_equity}{$period} =
          $total_liabilities + $calculated_total_equity;

        # Format current earnings for display
        $current_earnings{$period} =
          $form->format_amount( $myconfig, $current_earnings_amount,
            $form->{decimalplaces}, '' );
    }

    # Format net totals for display
    my %formatted_net_totals;
    foreach my $period (@periods) {
        $formatted_net_totals{assets}{$period} = $form->format_amount(
            $myconfig,
            $net_totals{assets}{$period},
            $form->{decimalplaces}, ''
        );
        $formatted_net_totals{liabilities}{$period} = $form->format_amount(
            $myconfig,
            $net_totals{liabilities}{$period},
            $form->{decimalplaces}, ''
        );
        $formatted_net_totals{total_equity}{$period} = $form->format_amount(
            $myconfig,
            $net_totals{total_equity}{$period},
            $form->{decimalplaces}, ''
        );
        $formatted_net_totals{total_liabilities_equity}{$period} =
          $form->format_amount(
            $myconfig,
            $net_totals{total_liabilities_equity}{$period},
            $form->{decimalplaces}, ''
          );
    }

    # Store data for template
    $form->{assets_data}           = $balance_data{'A'} || {};
    $form->{liabilities_data}      = $balance_data{'L'} || {};
    $form->{equity_data}           = $balance_data{'Q'} || {};
    $form->{assets_hierarchy}      = $hierarchy{'A'}    || {};
    $form->{liabilities_hierarchy} = $hierarchy{'L'}    || {};
    $form->{equity_hierarchy}      = $hierarchy{'Q'}    || {};
    $form->{current_earnings}      = \%current_earnings;
    $form->{net_totals}            = \%formatted_net_totals;
    $form->{period}                = join( " / ", @periods );
    $form->{_periods}              = \@periods;

    $form->{timeperiod} = $timeperiod;
    return 1;    # Indicate success
}

# Helper function to calculate account levels in hierarchy
# Look up human-readable descriptions for a list of "value--id" strings from
# either the 'department' or 'project' table.  Returns a hash mapping each
# original value to its display label (falls back to the text before '--').
sub _lookup_comparison_labels {
    my ( $dbs, $table, @values ) = @_;

    my %by_id;
    for my $val (@values) {
        my ( undef, $id ) = split /--/, $val;
        $by_id{$id} = $val if defined $id && $id =~ /^\d+$/;
    }

    if (%by_id) {
        my @ids  = keys %by_id;
        my $rows = $dbs->query(
            "SELECT id, description FROM $table WHERE id IN ("
              . join( ',', ('?') x @ids ) . ')',
            @ids
        )->hashes;
        for my $row (@$rows) {
            my $orig = $by_id{ $row->{id} };
            $by_id{ $row->{id} } = { orig => $orig, label => $row->{description} };
        }
    }

    my %labels;
    for my $val (@values) {
        my ( $fallback, $id ) = split /--/, $val;
        if ( defined $id && ref $by_id{$id} eq 'HASH' ) {
            $labels{$val} = $by_id{$id}{label} // $fallback // $val;
        }
        else {
            $labels{$val} = $fallback // $val;
        }
    }
    return %labels;
}

sub _calculate_levels {
    my ( $data, $accno, $level ) = @_;

    $data->{$accno}{level} = $level;

    foreach
      my $child_accno ( sort { $a <=> $b } keys %{ $data->{$accno}{children} } )
    {
        _calculate_levels( $data, $child_accno, $level + 1 );
    }
}

$api->get(
    '/reports/balance_sheet' => sub {
        my $c = shift;
        return unless $c->check_perms('reports.balance');
        my $client = $c->param('client');
        my $params = $c->req->params->to_hash;

        my $form   = Form->new;
        my $locale = Locale->new;

        # Get default currency from database
        my $currencies = $form->get_currencies( $c->slconfig );
        unless ($currencies) {
            return $c->render(
                status => 400,
                json => { error => 'No currencies configured in the database' }
            );
        }
        my $default_currency = substr( $currencies, 0, 3 );

        # Assign parameters
        $form->{currency}        = $params->{currency} || $default_currency;
        $form->{defaultcurrency} = $default_currency;
        $form->{decimalplaces}   = $params->{decimalplaces} // "2";
        $form->{includeperiod}   = $params->{includeperiod} // "year";
        $form->{previousyear}    = $params->{previousyear}  // "0";
        $form->{accounttype}     = $params->{accounttype}   // "standard";
        $form->{l_accno}         = $params->{l_accno}       // 0;
        $form->{usetemplate}     = $params->{usetemplate}   // '';
        $form->{heading_only}    = $params->{heading_only}  // 0;
        $form->{heading_level}   = $params->{heading_level} // '';

        # Parse periods first — indexed: periods[N][label]=..., periods[N][todate]=...
        # We need these before determining the common date range below.
        my $periods = [];
        for my $key ( keys %$params ) {
            if ( $key =~ /^periods\[(\d+)\]\[(\w+)\]$/ ) {
                my ( $index, $field ) = ( $1, $2 );
                $periods->[$index]{$field} = $params->{$key};
            }
        }

        # Shared todate for department/project comparison mode.
        # Prefer explicit top-level todate; fall back to the first period's todate.
        my $common_todate = ( $params->{todate} && $params->{todate} ne '' )
                          ? $params->{todate}
                          : ( $periods->[0]{todate} // "" );

        $form->{todate} = $common_todate;

        # Parse departments — supports indexed (departments[0]=Name--ID),
        # repeated params, or single (department=Name--ID)
        my @departments;
        {
            my %dept_idx;
            for my $key ( keys %$params ) {
                if ( $key =~ /^departments\[(\d+)\]$/ ) {
                    $dept_idx{$1} = $params->{$key};
                }
            }
            if (%dept_idx) {
                @departments =
                  map { $dept_idx{$_} } sort { $a <=> $b } keys %dept_idx;
            }
            elsif ( exists $params->{department} ) {
                my $d = $params->{department};
                @departments = ref $d eq 'ARRAY' ? @$d : ($d);
            }
            @departments = grep { /\S/ } @departments;
        }

        # Parse projectnumbers — supports indexed (projectnumbers[0]=Name--ID),
        # repeated params, or single (projectnumber=Name--ID)
        my @projectnumbers;
        {
            my %proj_idx;
            for my $key ( keys %$params ) {
                if ( $key =~ /^projectnumbers\[(\d+)\]$/ ) {
                    $proj_idx{$1} = $params->{$key};
                }
            }
            if (%proj_idx) {
                @projectnumbers =
                  map { $proj_idx{$_} } sort { $a <=> $b } keys %proj_idx;
            }
            elsif ( exists $params->{projectnumber} ) {
                my $p = $params->{projectnumber};
                @projectnumbers = ref $p eq 'ARRAY' ? @$p : ($p);
            }
            @projectnumbers = grep { /\S/ } @projectnumbers;
        }

        # Validate: at most one dimension may have multiple items
        my $multi_count = ( scalar(@$periods)       > 1 ? 1 : 0 )
                        + ( scalar(@departments)    > 1 ? 1 : 0 )
                        + ( scalar(@projectnumbers) > 1 ? 1 : 0 );
        if ( $multi_count > 1 ) {
            return $c->render(
                status => 400,
                json   => {
                    error =>
                      'Only one comparison dimension is allowed at a time: multiple periods, departments, or projects'
                }
            );
        }

        if ( scalar(@departments) > 1 ) {
            # Department comparison: each department becomes a column keyed by
            # its description looked up from the database.
            my %labels = _lookup_comparison_labels(
                $c->dbs($client), 'department', @departments );
            $form->{comparison_mode} = 'department';
            $periods = [
                map {
                    {   label      => $labels{$_},
                        department => $_,
                        todate     => $common_todate,
                    }
                } @departments
            ];
            $form->{department}    = "";
            $form->{projectnumber} = @projectnumbers ? $projectnumbers[0] : "";
        }
        elsif ( scalar(@projectnumbers) > 1 ) {
            # Project comparison: each project becomes a column keyed by its
            # description looked up from the database.
            my %labels = _lookup_comparison_labels(
                $c->dbs($client), 'project', @projectnumbers );
            $form->{comparison_mode} = 'project';
            $periods = [
                map {
                    {   label         => $labels{$_},
                        projectnumber => $_,
                        todate        => $common_todate,
                    }
                } @projectnumbers
            ];
            $form->{department}    = @departments ? $departments[0] : "";
            $form->{projectnumber} = "";
        }
        else {
            # Period comparison (default): single dept/project filter, multiple snapshots
            $form->{comparison_mode} = 'period';
            $form->{department}    = @departments    ? $departments[0]    : "";
            $form->{projectnumber} = @projectnumbers ? $projectnumbers[0] : "";
        }

        $form->{periods} = $periods;

        RP->balance_sheet_periods( $c->slconfig, $form, $locale );

        if ( $form->{usetemplate} eq 'Y' ) {

            my $myconfig   = $c->slconfig;
            my $timeperiod = "";
            if ( @{ $form->{periods} } == 1 ) {
                $timeperiod = $locale->date( \%myconfig, $form->{todate},
                    $form->{longformat} );
            }
            else {
                $timeperiod =
                  join( " / ", map { $_->{label} } @{ $form->{periods} } );
            }

            # Build report data
            build_balance_sheet( $form, $locale, $myconfig,
                $timeperiod, 'balance_sheet' );

            my $logo_base64 = get_image_base64(
                $c->app->home->rel_file("templates/$client/logo.png") );

            # Prepare template data
            my $template_data = {
                company               => $form->{company} || '',
                address               => $form->{address} || '',
                timeperiod            => $timeperiod,
                department            => $form->{department},
                projectnumber         => $form->{projectnumber},
                currency              => $form->{currency},
                periods               => $form->{periods},
                assets_data           => $form->{assets_data},
                liabilities_data      => $form->{liabilities_data},
                equity_data           => $form->{equity_data},
                assets_hierarchy      => $form->{assets_hierarchy},
                liabilities_hierarchy => $form->{liabilities_hierarchy},
                equity_hierarchy      => $form->{equity_hierarchy},
                current_earnings      => $form->{current_earnings},
                net_totals            => $form->{net_totals},
                logo                  => $logo_base64,
                heading_level         => $form->{heading_level},
            };

            # Render using Mojolicious template
            my $html_content = $c->render_to_string(
                template => "$client/balance_sheet",
                %$template_data
            );
            my $pdf = html_to_pdf($html_content);
            unless ($pdf) {
                return $c->render(
                    status => 500,
                    text   => "Failed to generate PDF"
                );
            }

            $c->res->headers->content_type('application/pdf');
            $c->render( data => $pdf );
            return;
        }

        $c->render( json => {%$form} );
    }
);
$api->get(
    '/reports/all_taxes' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        return unless my $form = $c->check_perms("reports.alltaxes");

        $form->{fromdate}   = $c->param('fromdate')   // '';
        $form->{todate}     = $c->param('todate')     // '';
        $form->{department} = $c->param('department') // '';

        my $dbs = $c->dbs($client);
        $form->{dbs} = $c->dbs($client);
        my $rows = RP->alltaxes($form);

        # Get all tax data and chart data in separate queries
        my $tax_lookup   = {};
        my $chart_lookup = {};

        # Get all charts
        my $chart_results = $dbs->select( 'chart', [ 'id', 'accno' ] );
        while ( my $chart_row = $chart_results->hash ) {
            $chart_lookup->{ $chart_row->{id} } = $chart_row->{accno};
        }

        # Get all taxes
        my $tax_results = $dbs->select( 'tax', '*' );
        while ( my $tax_row = $tax_results->hash ) {
            my $accno = $chart_lookup->{ $tax_row->{chart_id} };
            if ($accno) {
                push @{ $tax_lookup->{$accno} }, $tax_row;
            }
        }

        # Sort tax records by validto date (most recent first, nulls first)
        foreach my $accno ( keys %$tax_lookup ) {
            $tax_lookup->{$accno} = [
                sort {
                    # Handle nulls - nulls (no expiry) should come first
                    return -1
                      if !defined( $a->{validto} ) && defined( $b->{validto} );
                    return 1
                      if defined( $a->{validto} ) && !defined( $b->{validto} );
                    return 0
                      if !defined( $a->{validto} ) && !defined( $b->{validto} );

                    # For non-nulls, sort by date descending (most recent first)
                    return $b->{validto} cmp $a->{validto};
                } @{ $tax_lookup->{$accno} }
            ];
        }

        # Function to find the right tax for a given account and date
        my $find_tax = sub {
            my ( $account_number, $trans_date ) = @_;
            return undef unless $tax_lookup->{$account_number};

            # Find the most recent tax that's valid for this date
            foreach my $tax ( @{ $tax_lookup->{$account_number} } ) {

                # Tax is valid if validto is null or >= trans_date
                if ( !$tax->{validto} || $tax->{validto} ge $trans_date ) {
                    return {
                        tax_id    => $tax->{id},
                        rate      => $tax->{rate} * 100,
                        taxnumber => $tax->{taxnumber}
                    };
                }
            }
            return undef;
        };

        # Add address field and tax information to each row
        foreach my $row (@$rows) {
            my $address = '';
            if ( $row->{vc_id} ) {
                my $addr_data = $dbs->select(
                    'address',
                    [ 'city', 'state', 'zipcode', 'country' ],
                    { trans_id => $row->{vc_id} }
                )->hash;

                if ($addr_data) {

                    # Build address as: "City, State Zipcode, Country"
                    my $address_line = '';
                    if ( $addr_data->{city} && $addr_data->{city} ne '' ) {
                        $address_line .= $addr_data->{city};
                    }
                    if ( $addr_data->{state} && $addr_data->{state} ne '' ) {
                        $address_line .=
                          ( $address_line ? ', ' : '' ) . $addr_data->{state};
                    }
                    if ( $addr_data->{zipcode} && $addr_data->{zipcode} ne '' )
                    {
                        $address_line .= (
                            $addr_data->{state} && $addr_data->{state} ne ''
                            ? ' '
                            : ( $address_line ? ', ' : '' )
                        ) . $addr_data->{zipcode};
                    }
                    if ( $addr_data->{country} && $addr_data->{country} ne '' )
                    {
                        $address_line .=
                          ( $address_line ? ', ' : '' ) . $addr_data->{country};
                    }
                    $address = $address_line;
                }
            }
            $row->{address} = $address;

           # Extract account number from the account field (before the first --)
            my $account_number = '';
            if ( $row->{account} && $row->{account} =~ /^([^-]+)--/ ) {
                $account_number = $1;
            }

            # Get tax information using our lookup
            if ( $account_number && $row->{transdate} ) {
                my $tax_data =
                  $find_tax->( $account_number, $row->{transdate} );

                if ($tax_data) {
                    $row->{tax_rate}  = $tax_data->{rate};
                    $row->{tax_id}    = $tax_data->{tax_id};
                    $row->{taxnumber} = $tax_data->{taxnumber};
                }
                else {
                    # Set default values if no tax found
                    $row->{tax_rate}  = undef;
                    $row->{tax_id}    = undef;
                    $row->{taxnumber} = undef;
                }
            }
            else {
               # Set default values if account number or transdate not available
                $row->{tax_rate}  = undef;
                $row->{tax_id}    = undef;
                $row->{taxnumber} = undef;
            }
        }
        $rows = FM->get_files_for_transactions(
            $dbs,
            {
                api_url => $base_url,
                client  => $client
            },
            $rows
        );

        $c->render( json => $rows );
    }
);

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
        return unless my $form = $c->check_perms('cash.recon');
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
        return unless my $form = $c->check_perms('cash.recon');
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        # Initialize form and load parameters
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
        return unless my $form = $c->check_perms('cash.recon');

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

# Display dates for TeX templates (invoice, ar/ap transaction, etc.).
# Form::format_date (SL/Form.pm) takes a pattern and yyyymmdd; DB values are usually yyyy-mm-dd.
sub template_display_date {
    my ( $form, $date ) = @_;
    return '' unless defined $date && $date ne '';
    my $yyyymmdd = $date;
    $yyyymmdd =~ s/-//g;
    return $date unless $yyyymmdd =~ /^\d{8}$/;
    return $form->format_date( 'dd.mm.yyyy', $yyyymmdd );
}

sub build_letterhead {
    my ($c) = @_;
    my $client = $c->param('client');

    my $dbs = $c->dbs($client);

    my @defkeys = qw(
        company address tel fax companyemail companywebsite
        address1 address2 city state zip zipcode country
        businessnumber iban bic
    );
    my $placeholders = join ',', ('?') x @defkeys;
    my $results      = $dbs->query(
        "SELECT fldname, fldvalue FROM defaults WHERE fldname IN ($placeholders)",
        @defkeys
    )->hashes;

    my %letterhead = map { $_->{fldname} => $_->{fldvalue} } @$results;

    # NEO footer / QR creditor address (match IS.pm invoice_details: company zip is defaults "zip")
    $letterhead{companyaddress1} = $letterhead{address1}  // '';
    $letterhead{companyaddress2} = $letterhead{address2}  // '';
    $letterhead{companycity}     = $letterhead{city}      // '';
    $letterhead{companyzip}      = $letterhead{zip}       // $letterhead{zipcode} // '';
    $letterhead{companycountry}  = $letterhead{country}  // '';
    $letterhead{companystate}    = $letterhead{state}    // '';

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
        typeofcontact => $contact_row->{typeofcontact} // 'company',
        firstname       => $contact_row->{firstname}    // '',
        lastname        => $contact_row->{lastname}     // '',
        salutation      => $contact_row->{salutation}   // '',
        contacttitle    => $contact_row->{contacttitle}  // '',
        (
            $vc eq 'customer'
            ? (
                customerphone     => $phone,
                customerfax       => $fax,
                customertaxnumber => $vc_row->{taxnumber} // '',
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
    my ( $c, $client, $form, $dbs ) = @_;

    my $invoice_type = $form->{vc} eq 'vendor' ? 'AP' : 'AR';
    my $arap_key     = $invoice_type;

    my $arap = "ar";
    if ( $form->{vc} eq 'vendor' ) {
        $arap = "ap";
    }

    my $config = $c->slconfig;
    $config->{dbconnect} = "dbi:Pg:dbname=$client";

    if ( $invoice_type eq 'AR' ) {
        IS->retrieve_invoice( $c->slconfig, $form );
    }
    else {
        IR->retrieve_invoice( $c->slconfig, $form );
    }
    AA->company_details( $c->slconfig, $form );
    my $taxes__query = $dbs->query(
        q{
            SELECT c.accno, c.description, t.taxnumber, t.rate, t.chart_id
            FROM tax t
            JOIN chart c ON c.id = t.chart_id
            WHERE t.validto IS NULL 
               OR t.validto >= ?
            ORDER BY t.chart_id, t.id DESC
        },
        $form->{invdate}
    )->hashes;

    if (@$taxes__query) {
        my @taxaccounts;
        my %seen_charts;
        for my $tax (@$taxes__query) {

            # Only use the first (most recent) rate for each chart_id
            next if $seen_charts{ $tax->{chart_id} };
            $seen_charts{ $tax->{chart_id} } = 1;
            push @taxaccounts, $tax->{accno};
            $form->{"$tax->{accno}_rate"}        = $tax->{rate};
            $form->{"$tax->{accno}_description"} = $tax->{description};
            $form->{"$tax->{accno}_taxnumber"}   = $tax->{taxnumber};
        }
        $form->{taxaccounts} = join( ' ', @taxaccounts );
    }
    my $ln = 1;
    for my $l ( @{ $form->{invoice_details} } ) {

        $form->{"id_$ln"}           = $l->{id};
        $form->{"qty_$ln"}          = $l->{qty}            // 0;
        $form->{"sellprice_$ln"}    = $l->{sellprice}      // 0;
        $form->{"fxsellprice_$ln"}  = $l->{fxsellprice}    // 0;
        $form->{"discount_$ln"}     = $l->{discount} * 100 // 0;
        $form->{"discountrate_$ln"} = $l->{discountrate}   // 0;
        $form->{"taxaccounts_$ln"}  = $l->{taxaccounts}    // '';
        $form->{"partnumber_$ln"}   = $l->{partnumber}     // '';
        $form->{"description_$ln"}  = $l->{description}    // '';
        $form->{"unit_$ln"}         = $l->{unit}           // '';
        $form->{"deliverydate_$ln"} = $l->{deliverydate}   // '';
        $form->{"package_$ln"}      = $l->{package}        // '';
        $form->{"assembly_$ln"}     = $l->{assembly}       // 0;
        $form->{"kit_$ln"}          = $l->{kit}            // '';
        $form->{"pricematrix_$ln"}  = $l->{pricematrix}    // '';
        $form->{"itemnotes_$ln"}    = $l->{itemnotes}      // '';

        $ln++;
    }
    $form->{rowcount} = $ln;

    if ( $invoice_type eq 'AR' ) {
        IS->invoice_details( $c->slconfig, $form );
    }
    else {
        IR->invoice_details( $c->slconfig, $form );
    }

    # NEO / TeX: dd.mm.yyyy via Form::format_date (same rules as template_display_date)
    for my $field (qw(invdate transdate duedate)) {
        if ( $form->{$field} ) {
            $form->{$field} = template_display_date( $form, $form->{$field} );
        }
    }
    for my $i ( 1 .. $form->{rowcount} - 1 ) {
        if ( $form->{"deliverydate_$i"} ) {
            $form->{"deliverydate_$i"} =
              template_display_date( $form, $form->{"deliverydate_$i"} );
        }
    }

    my $credit_remaining = $dbs->query(
        qq|SELECT SUM(a.amount - a.paid)
          FROM $arap a
          WHERE a.amount != a.paid
          AND $form->{vc}_id = $form->{"$form->{vc}_id"}|
    )->hash;
    my $credit = -$credit_remaining->{sum};
    my $credit_before =
      $credit + $form->parse_amount( $c->slconfig, $form->{subtotal} );
    $credit        = sprintf( "%.2f", $credit );
    $credit_before = sprintf( "%.2f", $credit_before );

    # small epsilon value to handle floating-point precision issues
    my $epsilon = 1e-10;
    if ( abs($credit) < $epsilon ) {
        $credit = 0;
    }
    if ( abs($credit_before) < $epsilon ) {
        $credit_before = 0;
    }

    # Format the credit values
    my $display_credit = $form->format_amount( $c->slconfig, abs $credit );
    $display_credit = "($display_credit)" if $credit > 0;
    $display_credit = "0"                 if $credit == 0;

    my $display_credit_before =
      $form->format_amount( $c->slconfig, abs $credit_before );
    $display_credit_before = "($display_credit_before)" if $credit_before > 0;
    $display_credit_before = "0"                        if $credit_before == 0;

    my @f =
      qw(email name address1 address2 city state zipcode country contact phone fax);

    my $fillshipto = 1;

    # check for shipto
    foreach my $item (@f) {
        if ( $form->{"shipto$item"} ) {
            $fillshipto = 0;
            last;
        }
    }

    if ($fillshipto) {
        $fillshipto = 0;
        $fillshipto = 1
          if $form->{formname} =~
          /(credit_invoice|purchase_order|request_quotation|bin_list)/;
        $fillshipto = 1
          if ( $form->{type} eq 'invoice' && $form->{vc} eq 'vendor' );

        $form->{shiptophone}   = $form->{tel};
        $form->{shiptofax}     = $form->{fax};
        $form->{shiptocontact} = $form->{employee};

        if ($fillshipto) {
            if ( $form->{warehouse} ) {
                $form->{shiptoname} = $form->{company};
                for (qw(address1 address2 city state zipcode country)) {
                    $form->{"shipto$_"} = $form->{"warehouse$_"};
                }
            }
            else {
                # fill in company address
                $form->{shiptoname}     = $form->{company};
                $form->{shiptoaddress1} = $form->{address};
            }
        }
        else {
            for (@f) { $form->{"shipto$_"} = $form->{$_} }
            for (qw(phone fax)) {
                $form->{"shipto$_"} = $form->{"$form->{vc}$_"};
            }
        }
    }

    $form->{credit}                = $credit;
    $form->{display_credit}        = $display_credit;
    $form->{display_credit_before} = $display_credit_before;
    $form->{credit_before}         = $credit_before;

    my $format = $c->param("format") || 'tex';
    if ( $format eq 'tex' ) {

        my @escape_fields = qw(
          invnumber ordnumber quonumber cusordnumber donumber
          name address1 address2 address3 address4
          city state zipcode country
          contact phone fax email
          shiptoname shiptoaddress1 shiptoaddress2 shiptoaddress3 shiptoaddress4
          shiptocity shiptostate shiptozipcode shiptocountry
          shiptocontact shiptophone shiptofax shiptoemail
          notes intnotes
          username employee
          shippingpoint shipvia waybill
        );

        foreach my $key ( keys %$form ) {
            if ( $key =~
/^(description|itemnotes|unit|partnumber|projectnumber|serialnumber|bin|reqdate|transdate|invdate|orddate|quodate)_\d+$/
              )
            {
                push @escape_fields, $key;
            }
        }

        for my $field (
            qw(description itemnotes unit partnumber projectnumber serialnumber bin reqdate transdate invdate orddate quodate ordernumber customerponumber package netweight grossweight)
          )
        {
            if ( ref( $form->{$field} ) eq 'ARRAY' ) {
                for my $i ( 0 .. $#{ $form->{$field} } ) {

                    next unless defined $form->{$field}[$i];

                    my $temp_form =
                      { value => $form->{$field}[$i], format => $format };
                    bless $temp_form, 'Form';
                    $temp_form->format_string('value');
                    $form->{$field}[$i] = $temp_form->{value};
                }
            }
        }

        @escape_fields = grep { defined $form->{$_} } @escape_fields;
        $form->format_string(@escape_fields);
    }

    return $form;
}
$api->get(
    "/print_invoice/" => sub {
        my $c        = shift;
        my $template = $c->param("template") || 'invoice';
        my $format   = $c->param("format")   || 'tex';

        my $client = $c->param('client') || die "Missing client parameter";
        my $vc     = $c->param('vc')     || die "Missing vc parameter";
        my $id     = $c->param('id')     || die "Missing invoice id";

        return unless $c->check_perms("$vc.transaction");

        # get invoice info for the filename
        my $dbs  = $c->dbs($client);
        my $arap = $vc eq 'vendor' ? 'ap' : 'ar';
        my $invoice =
          $dbs->query( "SELECT invnumber FROM $arap WHERE id = ?", $id )->hash;

        unless ($invoice) {
            return $c->render(
                status => 404,
                json   => { error => "Invoice not found" }
            );
        }

        # use the helper to get (or generate) the PDF
        my $pdf_path =
          $c->get_invoice_pdf( $client, $id, $vc, $template, $format );

        unless ( $pdf_path && -f $pdf_path ) {
            return $c->render(
                status => 500,
                json   => { error => "Failed to generate invoice PDF" }
            );
        }

        # read and return the PDF
        open my $fh, '<', $pdf_path or do {
            return $c->render(
                status => 500,
                json   => { error => "Cannot read PDF file" }
            );
        };
        binmode $fh;
        my $pdf_content = do { local $/; <$fh> };
        close $fh;

        my $filename = $invoice->{invnumber} || $id;
        $filename =~ s/[^a-zA-Z0-9_.-]+/_/g;

        $c->res->headers->content_type('application/pdf');
        $c->res->headers->content_disposition(
            "attachment; filename=\"${filename}.pdf\"");
        $c->render( data => $pdf_content );
    }
);

# Swiss QR / eBill placeholders (NEO content_qrinvoice*.tex), aligned with SL/IS.pm invoice_details.
sub transaction_append_swiss_qr_template_fields {
    my ( $form, $myconfig, $transaction, $open_amount_num, $bank_qr ) = @_;
    $bank_qr ||= {};

    my $iq = substr( $transaction->{invnumber} // '', 0, 24 );
    $iq = $form->string_replace( $iq, "%", "" );
    $iq = $form->string_replace( $iq, "/", "" );
    $iq =~ s/\\//g;
    $transaction->{invnumberqr} = $iq;

    my $raw_desc = $bank_qr->{invdescriptionqr} // $transaction->{invdescription} // '';
    my $idq = $form->format_line($raw_desc);
    $idq = $form->string_replace( $idq, "%", "" );
    $idq = $form->string_abbreviate( $idq, 55 );
    $transaction->{invdescriptionqr}  = $idq;
    $transaction->{invdescriptionqr2} = $idq;

    my $qrb = $bank_qr->{qriban} // '';
    $transaction->{qriban} = $qrb;
    my $qrbqr = $qrb;
    $qrbqr =~ s/\s//g;
    $qrbqr = $form->string_replace( $qrbqr, "%", "" );
    $transaction->{qribanqr} = $qrbqr;

    for my $spec (
        [qw(companyqr company 70)],
        [qw(companyaddress1qr companyaddress1 70)],
        [qw(companyzipqr companyzip 16)],
        [qw(companycityqr companycity 35)],
        [qw(nameqr name 70)],
        [qw(address1qr address1 70)],
        [qw(zipcodeqr zipcode 16)],
        [qw(cityqr city 35)],
      )
    {
        my ( $to, $from, $len ) = @$spec;
        my $s = substr( $transaction->{$from} // '', 0, $len );
        $s = $form->string_replace( $s, "%", "" );
        $transaction->{$to} = $s;
    }

    for my $fld (qw(dcn rvc)) {
        my $v = $bank_qr->{$fld} // '';
        $transaction->{$fld} = $form->format_dcn($v);
    }

    my $str = $bank_qr->{strdbkginf} // '';
    $str = $form->format_line($str);
    $str = substr( $str, 0, 85 );
    $str = $form->string_replace( $str, "%", "" );
    $transaction->{strdbkginf}        = $str;
    $transaction->{strdbkginfqr}      = $str;
    $transaction->{strdbkginfline1qr} = substr( $str, 0,  50 );
    $transaction->{strdbkginfline2qr} = substr( $str, 50, 35 );

    my $fmt_amt = sprintf( "%.2f", 0 + $open_amount_num );
    my ( $whole, $decimal ) = split /\./, $fmt_amt;
    $decimal = substr( "${decimal}00", 0, 2 );
    $transaction->{integer_out_amount} = $whole;
    $transaction->{out_decimal}        = $decimal;

    my $qr_nf = { numberformat => '1,000.00' };
    my $ft = $form->format_amount( $qr_nf, $open_amount_num, 2 );
    $ft =~ s/,/ /g;
    $transaction->{total} = $ft;

    if (   defined $transaction->{businessnumber}
        && $transaction->{businessnumber} ne '' )
    {
        my @nums = $transaction->{businessnumber} =~ /(\d+)/g;
        $transaction->{businessnumberqr} = join '', @nums;
    }
    else {
        $transaction->{businessnumberqr} = '';
    }

    return;
}

sub build_transaction {
    my ( $c, $client, $vc, $id ) = @_;

    # Determine transaction type and corresponding field names.
    my $transaction_type = $vc eq 'vendor' ? 'AP'           : 'AR';
    my $vc_field         = $vc eq 'vendor' ? 'vendornumber' : 'customernumber';
    my $vc_id_field      = $vc eq 'vendor' ? 'vendor_id'    : 'customer_id';

    # Establish database connection.
    my $dbs = $c->dbs($client);
    $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

    my $letterhead = build_letterhead($c);

    # AR transactions use -1 as a multiplier for amounts.
    my $amount_multiplier = $transaction_type eq 'AR' ? -1 : 1;

    # Initialize form object.
    my $form = Form->new;
    $form->{id} = $id;
    $form->{vc} = $vc;

    # Prepare the form with transaction links/info.
    $form->create_links( $transaction_type, $c->slconfig, $vc );

    if ( $form->{transdate} && $form->{duedate} ) {
        $form->{terms} =
          $form->datediff( $c->slconfig, $form->{transdate}, $form->{duedate} );
    }
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

            push @paymentdate,
              template_display_date( $form, $pay->{transdate} // '' );
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
    # Same shape as invoice printing (IS.pm): templates (e.g. NEO) use <%foreach tax%>,
    # <%tax%>, <%taxrate%>, <%taxdescription%>, <%taxnumber%>, <%taxbase%>, <%taxbaseinclusive%>.
    my (
        @tax, @taxaccno, @taxamount, @taxrate, @taxdescription,
        @taxnumber, @taxbase, @taxbaseinclusive
    );
    my $taxtotal = 0;

    my $tax_bucket = $form->{acc_trans}{ "${transaction_type}_tax" };
    my @tax_rows;
    if ( $tax_bucket && ref($tax_bucket) eq 'ARRAY' ) {
        @tax_rows = @$tax_bucket;
    }
    if ( !@tax_rows ) {
        @tax_rows = @{
            $dbs->query(
                q{
            SELECT c.accno, c.description, ac.amount, ac.memo
            FROM acc_trans ac
            JOIN chart c ON c.id = ac.chart_id
            WHERE ac.trans_id = ?
              AND ac.fx_transaction = '0'
              AND EXISTS (SELECT 1 FROM tax t WHERE t.chart_id = ac.chart_id)
            ORDER BY ac.id
        },
                $id
            )->hashes
        };
    }

    my $taxes_meta = $dbs->query(
        q{
            SELECT c.accno, c.description, t.taxnumber, t.rate, t.chart_id
            FROM tax t
            JOIN chart c ON c.id = t.chart_id
            WHERE t.validto IS NULL
               OR t.validto >= ?
            ORDER BY t.chart_id, t.id DESC
        },
        $form->{transdate}
    )->hashes;

    my %taxmeta_by_accno;
    if ( ref($taxes_meta) eq 'ARRAY' ) {
        for my $row (@$taxes_meta) {
            next if $taxmeta_by_accno{ $row->{accno} };
            $taxmeta_by_accno{ $row->{accno} } = $row;
        }
    }

    my $prec = $form->{precision} // 2;
    for my $tax (@tax_rows) {
        my $t_amt = abs( $amount_multiplier * $tax->{amount} );
        $taxtotal += $t_amt;

        my $accno       = $tax->{accno}       // '';
        my $meta        = $taxmeta_by_accno{$accno};
        my $rate        = $meta->{rate} // 0;
        my $desc        = $meta->{description} // $tax->{description} // '';
        my $txnum       = $meta->{taxnumber} // '';
        my $abs_tax     = $t_amt;
        my $base_num    = 0;
        my $incl_num    = $abs_tax;
        if ( $rate > 0 ) {
            $base_num = $form->round_amount( $abs_tax / $rate, $prec );
            $incl_num = $form->round_amount( $base_num + $abs_tax, $prec );
        }

        my $rate_pct = $form->format_amount(
            $c->slconfig, $rate * 100,
            $prec, '0.00'
        );
        my $fmt_tax = $form->format_amount( $c->slconfig, $abs_tax );
        my $desc_fmt = $form->string_replace( $desc, "%", "" );

        push @taxaccno, $accno;
        push @taxamount,      $fmt_tax;
        push @tax,            $fmt_tax;
        push @taxrate,        $rate_pct;
        push @taxdescription, $desc_fmt;
        push @taxnumber,      $txnum;
        push @taxbase,
          $form->format_amount( $c->slconfig, $base_num );
        push @taxbaseinclusive,
          $form->format_amount( $c->slconfig, $incl_num );
    }

    my $num2text;
    if ( $form->{language_code} ne "" ) {
        $num2text = new CP $form->{language_code};
    }
    else {
        $num2text = new CP $c->slconfig->{countrycode};
    }
    $num2text->init;

    # Gross document total vs balance due (matches IS.pm: invtotal = full amount, total = due).
    my $document_total_num = $subtotal + $taxtotal;
    my $amount_due_num     = $document_total_num - $payment_total;

    # Amount in words reflects balance due (what remains to pay).
    my $formatted_total = sprintf( "%.2f", $amount_due_num );
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
        typeofcontact => $vc_data->{typeofcontact}
          || 'company',
        firstname   => $vc_data->{firstname}   // '',
        lastname    => $vc_data->{lastname}    // '',
        salutation  => $vc_data->{salutation}  // '',
        contacttitle => $vc_data->{contacttitle} // '',
        contact => $vc_data->{contact}
          || '',
        email => $vc_data->{email}
          || '',
        vendortaxnumber => $vc_data->{vendortaxnumber}
          || '',
        customertaxnumber => $vc_data->{customertaxnumber}
          || '',
        (
            $vc eq 'customer'
            ? (
                customerphone   => $vc_data->{customerphone}   || '',
                customerfax     => $vc_data->{customerfax}     || '',
                customeremail   => $vc_data->{email}           // '',
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
        invdate   => template_display_date( $form, $form->{transdate} ),
        duedate   => template_display_date( $form, $form->{duedate} ),
        ponumber  => $form->{ponumber},
        ordnumber => $form->{ordnumber},
        employee  => $form->{employee} || '',
        # NEO content_header title; same field as SQL-Ledger a.description (not line memos).
        invdescription => $form->{description} // '',
        notes          => $form->{notes}      // '',
        intnotes       => $form->{intnotes}   // '',
        terms          => (
            defined $form->{terms} && $form->{terms} ne ''
            ? $form->{terms}
            : 0
        ),

        ## Line Items as parallel arrays
        item_id       => \@lineitem_ids,
        accno         => \@lineitem_accno,
        account       => \@lineitem_account,
        amount        => \@lineitem_amount,
        description   => \@lineitem_description,
        projectnumber => \@lineitem_projectnumber,

        ## Totals & Amount in Words
        subtotal    => $form->format_amount( $c->slconfig, $subtotal ),
        invtotal    => $form->format_amount( $c->slconfig, $document_total_num ),
        openamount  => $form->format_amount( $c->slconfig, $amount_due_num ),
        text_amount => $text_amount,
        decimal     => $decimal,
        currency    => $form->{currency},
        paid        => $form->format_amount( $c->slconfig, $payment_total ),

        ## Payments as parallel arrays
        paid_1         => $paid_1,
        paymentdate    => \@paymentdate,
        paymentaccount => \@paymentaccount,
        paymentsource  => \@paymentsource,
        paymentmemo    => \@paymentmemo,
        payment        => \@paymentamount,

        ## Tax Information as parallel arrays (invoice-compatible names)
        tax               => \@tax,
        taxaccno          => \@taxaccno,
        taxamount         => \@taxamount,
        taxrate           => \@taxrate,
        taxdescription    => \@taxdescription,
        taxnumber         => \@taxnumber,
        taxbase           => \@taxbase,
        taxbaseinclusive  => \@taxbaseinclusive,
    );

    # Include tax inclusion flag if applicable.
    if (@taxaccno) {
        $transaction{taxincluded} = $form->{taxincluded} ? 1 : 0;
    }

    # Pass through vendor/customer identifiers.
    $transaction{$vc_field}    = $form->{$vc_field};
    $transaction{$vc_id_field} = $form->{$vc_id_field};

    for my $fld (
        qw(company address tel fax companyemail companywebsite companyaddress1
           companyaddress2 companycity companyzip companycountry companystate
           businessnumber iban bic)
      )
    {
        $transaction{$fld} = $letterhead->{$fld} // '';
    }

    my $arap_tbl    = $transaction_type eq 'AR' ? 'ar' : 'ap';
    # Swiss QR / creditor data: same source as IS.pm invoice_details — `bank` row id = ar.paymentmethod_id.
    # (vc_bank_id / bank_account is unrelated to QR; do not load it before bank or it can mask paymentmethod_id.)
    my $ledger_bank = $dbs->query(
        "SELECT vc_bank_id, dcn, paymentmethod_id FROM $arap_tbl WHERE id = ?",
        $id
    )->hash // {};
    my $bank_id = $ledger_bank->{paymentmethod_id};
    $bank_id = defined $bank_id && $bank_id ne '' ? $bank_id + 0 : 0;
    if ( !$bank_id ) {
        my $pay_pm = $dbs->query(
            q{SELECT paymentmethod_id FROM payment WHERE trans_id = ? ORDER BY id DESC LIMIT 1},
            $id
        )->hash;
        if ( $pay_pm && defined $pay_pm->{paymentmethod_id} && $pay_pm->{paymentmethod_id} ne '' )
        {
            $bank_id = $pay_pm->{paymentmethod_id} + 0;
        }
    }
    my %bank_qr;
    if ($bank_id) {
        my $bk = $dbs->query(
            q{SELECT iban, bic, qriban, dcn, rvc, membernumber, clearingnumber, strdbkginf, invdescriptionqr
              FROM bank WHERE id = ?},
            $bank_id
        )->hash;
        %bank_qr = %$bk if $bk;
    }
    my $have_qriban = defined $bank_qr{qriban} && $bank_qr{qriban} ne '';
    if ( !$have_qriban && $ledger_bank->{vc_bank_id} ) {
        my $ba = $dbs->query(
            q{SELECT iban, bic, qriban, dcn, rvc, membernumber, clearingnumber, strdbkginf, invdescriptionqr
              FROM bank_account WHERE id = ?},
            $ledger_bank->{vc_bank_id}
        )->hash;
        %bank_qr = %$ba if $ba;
    }
    if ( $ledger_bank->{dcn} && !( $bank_qr{dcn} && $bank_qr{dcn} ne '' ) ) {
        $bank_qr{dcn} = $ledger_bank->{dcn};
    }

    for my $fld (qw(iban bic qriban membernumber clearingnumber)) {
        if ( defined $bank_qr{$fld} && $bank_qr{$fld} ne '' ) {
            $transaction{$fld} = $bank_qr{$fld};
        }
    }

    transaction_append_swiss_qr_template_fields(
        $form, $c->slconfig, \%transaction,
        $amount_due_num, \%bank_qr
    );

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

        # Merge company defaults (do not map raw address1/city onto customer fields)
        for my $fld (
            qw(company address tel fax companyemail companywebsite companyaddress1
               companyaddress2 companycity companyzip companycountry companystate
               businessnumber)
          )
        {
            $transaction_data->{$fld} = $letterhead->{$fld} // '';
        }
        # IBAN/BIC: invoices get these from AA->company_details (bank on AR/AP paid account);
        # transactions get them from build_transaction (bank row). Do not wipe with empty defaults.
        for my $fld (qw(iban bic)) {
            my $lh = $letterhead->{$fld} // '';
            my $tx = $transaction_data->{$fld} // '';
            $transaction_data->{$fld} = ( defined $lh && $lh ne '' ) ? $lh : $tx;
        }
        $transaction_data->{lastpage}          = 0;
        $transaction_data->{sumcarriedforward} = 0;
        $transaction_data->{templates}         = "templates/$client";
        $transaction_data->{IN}                = "$template.tex";
        $transaction_data->{OUT}               = ">tmp/transaction.pdf";
        $transaction_data->{format}            = "pdf";
        $transaction_data->{media}             = "screen";
        $transaction_data->{copies}            = 1;

        my $form      = new Form;
        my $user_path = "tmp";
        for my $k ( keys %$transaction_data ) {
            $form->{$k} = $transaction_data->{$k};
        }
        my $dvipdf    = "";
        my $xelatex   = "";
        my $userspath = "tmp";

        $form->parse_template( $c->slconfig, $userspath, $dvipdf, $xelatex )
          or die "parse_template failed!";

        my $pdf_path = "tmp/transaction.pdf";

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

#############################
####                     ####
####   File Management   ####
####                     ####
#############################
$api->post(
    '/connection/exchange-token' => sub {
        my $c = shift;

# Extract the state from the query parameters (format: "clientName|serviceType")
        my $state = $c->param('state');
        unless ($state) {
            return $c->render(
                json => { success => 0, message => 'State parameter missing' },
                status => 400
            );
        }
        my ( $client, $service_type ) = split( /\|/, $state );
        unless ( $client && $service_type ) {
            return $c->render(
                json =>
                  { success => 0, message => 'Invalid state parameter format' },
                status => 400
            );
        }

        # Get the authorization code from the JSON request body
        my $data = $c->req->json || {};
        my $code = $data->{code};
        unless ($code) {
            return $c->render(
                json => {
                    success => 0,
                    message =>
                      'Authorization code missing or user cancelled the request'
                },
                status => 400
            );
        }

        my $redirect_uri = "$front_end/connection"
          ;    # Make sure $front_end is appropriately defined
        my $ua = Mojo::UserAgent->new;

        # Define service configurations
        my %services = (
            dropbox => {
                url           => 'https://api.dropboxapi.com/oauth2/token',
                client_id     => $ENV{DROPBOX_KEY},
                client_secret => $ENV{DROPBOX_SECRET},
                type          => 'dropbox',
            },
            google_drive => {
                url           => 'https://oauth2.googleapis.com/token',
                client_id     => $ENV{GOOGLE_CLIENT_ID},
                client_secret => $ENV{GOOGLE_SECRET},
                type          => 'google_drive',
            },
            drive => {
                url           => 'https://oauth2.googleapis.com/token',
                client_id     => $ENV{GOOGLE_CLIENT_ID},
                client_secret => $ENV{GOOGLE_SECRET},
                type          => 'google_drive',
            },
        );

        # Check for unsupported service types
        my $service = $services{$service_type};
        unless ($service) {
            return $c->render(
                json => { success => 0, message => 'Unsupported service type' },
                status => 400
            );
        }

        # Perform token exchange API request
        my $res = $ua->post(
            $service->{url} => form => {
                code          => $code,
                grant_type    => 'authorization_code',
                client_id     => $service->{client_id},
                client_secret => $service->{client_secret},
                redirect_uri  => $redirect_uri,
            }
        )->result;
        if ( $res->is_success ) {
            my $token_data = $res->json;
            warn( Dumper $token_data );
            my $access_token = $token_data->{access_token};
            my $refresh_token =
              defined $token_data->{refresh_token}
              ? $token_data->{refresh_token}
              : '';
            my $token_expires_epoch =
              $token_data->{expires_in}
              ? time() + $token_data->{expires_in}
              : time();
            my $token_expires =
              strftime( '%Y-%m-%d %H:%M:%S', localtime($token_expires_epoch) );

  # Update the database connection using the formatted string without conversion
            my $dbs = $c->dbs($client);
            $dbs->query("DELETE FROM connections");
            $dbs->query(
                q{
            INSERT INTO connections
              (type, access_token, refresh_token, token_expires, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        },
                $service->{type}, $access_token, $refresh_token,
                $token_expires,   'active'
            );

            return $c->render(
                json => {
                    success => 1,
                    message => ucfirst( $service->{type} )
                      . ' successfully connected'
                }
            );
        }
        else {
            my $error_details = $res->json || { error => $res->message };
            warn( Dumper $res->json );
            return $c->render(
                json => {
                    success => 0,
                    message =>
                      "Error retrieving access token from $service_type",
                    error => $error_details,
                },
                status => 500
            );
        }
    }
);

$api->get(
    "/files/:id" => sub {
        my $c        = shift;
        my $module   = $c->param('module');
        my $client   = $c->param('client');
        my $dbs      = $c->dbs($client);
        my $filename = $c->param('id');
        my $file =
          $dbs->query( "SELECT path FROM files WHERE link = ?", $filename )
          ->hash;
        my $path = $c->app->home->rel_file( $file->{path} );
        if ( -e $path ) {
            $c->reply->file($path);
        }
        else {
            $c->reply->not_found;
        }

    }
);

$api->delete(
    "/files/:module/:id" => sub {
        my $c        = shift;
        my $module   = $c->param('module');
        my $client   = $c->param('client');
        my $dbs      = $c->dbs($client);
        my $form     = new Form;
        my $filename = $c->param('id');
        $form->{filename} = $filename;

        # Call your deletion subroutine (e.g., from FM module)
        my $result = FM->delete_file( $dbs, $c, $form );

        if ( $result->{success} ) {

            # Return 204 No Content for a successful deletion.
            return $c->render( status => 204, text => '' );
        }
        else {
            # Return error message with a proper status if needed.
            return $c->render(
                status => 500,
                json   => { error => $result->{error} }
            );
        }
    }
);
$api->post(
    '/invoice_status' => sub {
        my $c = shift;
        return unless my $form = $c->check_perms("customer.batch");
        my $json     = $c->req->json // {};
        my $invoices = $json->{invoices} || {};

        while ( my ( $inv_id, $state ) = each %{$invoices} ) {
            $form             = new Form;
            $form->{id}       = $inv_id;
            $form->{formname} = 'invoice';
            $form->{queued}   = '';
            $form->{printed}  = '';
            $form->{emailed} =
              $state eq 'sent'
              ? 'invoice'
              : '';

            $form->update_status( $c->slconfig );
        }

        $c->render( json => { success => 1 } );
    }
);

$api->post(
    "/send_email" => sub {
        my $c      = shift;
        my $client = $c->param('client');

        # Extract JSON data from request
        my $json = $c->req->json;

        # Extract parameters from JSON
        my $vc         = $json->{vc}         || die "Missing vc parameter";
        my $id         = $json->{id}         || die "Missing id parameter";
        my $type       = $json->{type}       || die "Missing type parameter";
        my $attachment = $json->{attachment} || '';    # tex, html or empty
        my $inline     = $json->{inline}     || 0;     # 0 or 1
        my $email      = $json->{email}      || die "Missing email parameter";
        my $cc         = $json->{cc}         || '';
        my $bcc = $json->{bcc} || '';
        my $message_override =
          exists $json->{message} ? $json->{message} : undef;

        my $dbs = $c->dbs($client);

        # Check permissions
        return unless my $form = $c->check_perms("$vc.transaction");
        $form->{vc} = $vc;
        $form->{id} = $id;

        # Build invoice data (needed for intnotes and status updates)
        build_invoice( $c, $client, $form, $dbs );

        my $msg_type = $c->email_send_type_to_message_type($type);
        my $vc_tid   = $form->{"${vc}_id"};
        my $message  = $c->resolve_email_message_template(
            $dbs, $vc_tid, $form->{language_code} // '', $msg_type,
            $message_override );

        # Replace any {variable} placeholders in message with form values
        my %seen;
        for my $key ( grep { !$seen{$_}++ } ( $message =~ /\{(\w+)\}/g ) ) {
            my $val = ( defined $form->{$key} && !ref $form->{$key} )
                ? $form->{$key}
                : '';
            # Escape only \ and $ so replacement is literal (no \Q which would escape . and space)
            $val =~ s/\\/\\\\/g;
            $val =~ s/\$/\\\$/g;
            $message =~ s/\Q{$key}\E/$val/g;
        }

        # Set up email attachments
        my @attachments = ();

# Process attachment if requested - use get_invoice_pdf to get cached or generate new
        if ($attachment) {
            my $pdf_path =
              $c->get_invoice_pdf( $client, $id, $vc, $type, $attachment );
            if ( $pdf_path && -f $pdf_path ) {
                push @attachments, $pdf_path;
            }
            else {
                return $c->render(
                    status => 500,
                    json   => { error => "Failed to generate PDF attachment" }
                );
            }
        }

        # Set up the email content
        my $subject = "Invoice $form->{invnumber}";

        # Add CC and BCC if provided
        my $to = $email;
        if ($cc) {
            $to .= ",$cc";
        }
        if ($bcc) {
            $to .= ",$bcc";
        }

        my $now    = scalar localtime;
        my $locale = Locale->new;

        # Send email with or without attachments
        my $status = $c->send_email_central( $to, $subject, $message,
            \@attachments, undef, $client );
        $cc  = $locale->text('Cc') . qq|: $cc\n|   if $cc;
        $bcc = $locale->text('Bcc') . qq|: $bcc\n| if $bcc;
        my $int_notes = qq| $form->{intnotes}\n\n|;
        $int_notes .=
            qq|[email]\n|
          . $locale->text('Date')
          . qq|: $now\n|
          . $locale->text('To')
          . qq|: $email\n${cc}${bcc}|
          . $locale->text('Subject')
          . qq|: $subject\n|;
        $int_notes .= qq|\n| . $locale->text('Message') . qq|:|;
        $int_notes .= ($message) ? $message : $locale->text('sent');
        $form->save_intnotes( $c->slconfig, 'ar' );

        if ( $form->{emailed} !~ /$type/ ) {
            $form->{emailed} .= " $type";
            $form->{emailed} =~ s/^ //;
            $form->{"$type\_emailed"} = 1;

            # save status
            $form->update_status( $c->slconfig );
        }

        if ( $status && $status->{status} == 200 ) {
            $c->render(
                json => { success => 1, message => $status->{message} } );
        }
        else {
            my $error_msg = $status ? $status->{error} : "Failed to send email";
            $c->render(
                json   => { success => 0, message => $error_msg },
                status => 500
            );
        }
    }
);
app->minion->add_task(
    bulk_pdf_generation => sub {
        my ( $job, $args ) = @_;

        my $client = $args->{client};
        my $c      = $job->app;

        my $dbs = $c->dbs($client);

        my $emails = $args->{emails};
        my $vc     = $args->{vc};
        my $attachment =
          $args->{attachment} || 'tex';    # Default to tex if not specified
        my $jobtype    = $args->{jobtype} || 'bulk_pdf';
        my $adminemail = $args->{adminemail};
        my $form       = $args->{form};
        my $config     = $args->{config};

        # Initialize results tracking
        my $results = {
            total     => scalar @$emails,
            success   => 0,
            failed    => 0,
            errors    => [],
            pdf_files => [],
            jobtype   => $jobtype,
            client    => $client
        };

        # Store initial progress in job notes
        $job->note( client           => $client );
        $job->note( total_emails     => scalar @$emails );
        $job->note( emails_processed => 0 );
        $job->note( progress_percent => 0 );
        $job->note( jobtype          => $jobtype );

        # Create a unique batch identifier for this job
        my $batch_id  = sprintf( "batch_%s_%s", $job->id, time() );
        my @pdf_files = ();

        # Process each email in the batch
        my $processed = 0;
        foreach my $item (@$emails) {
            my $id        = $item->{id}        || next;
            my $type      = $item->{type}      || next;
            my $email     = $item->{email}     || next;
            my $name      = $item->{name}      || next;
            my $invnumber = $item->{invnumber} || next;

            eval {
                # use get_invoice_pdf to get cached PDF or generate new one
                my $pdf_filename =
                  $c->get_invoice_pdf( $client, $id, $vc, $type, $attachment );

                # Verify PDF was created successfully
                if ( $pdf_filename && -e $pdf_filename && -s $pdf_filename > 0 )
                {

                    # Create a meaningful filename for the ZIP
                    my $display_name = sprintf(
                        "invoice_%s_%s.pdf",
                        $invnumber || $id,
                        $name ? $name =~ s/[^a-zA-Z0-9_-]/_/gr : "customer"
                    );

                    push @pdf_files,
                      {
                        file_path    => $pdf_filename,
                        display_name => $display_name,
                        invoice_id   => $id,
                        invoice_num  => $invnumber,
                        customer     => $name
                      };

                    $results->{success}++;
                    push @{ $results->{successes} },
                      {
                        id        => $id,
                        type      => $type,
                        name      => $name,
                        invnumber => $invnumber,
                        pdf_file  => $display_name
                      };

                    # Insert success record into job_status table
                    $dbs->insert(
                        'job_status',
                        {
                            job_id    => $job->id,
                            trans_id  => $id,
                            status    => 'success',
                            type      => $type,
                            name      => $name,
                            reference => $invnumber
                        }
                    );
                }
                else {
                    die "PDF file was not created or is empty";
                }
            };

            # Handle errors for this specific PDF
            if ($@) {
                my $error_message = "$@";
                $results->{failed}++;
                push @{ $results->{errors} },
                  {
                    id        => $id,
                    type      => $type,
                    email     => $email,
                    name      => $name,
                    invnumber => $invnumber,
                    error     => $error_message
                  };

                # Insert error record into job_status table
                $dbs->insert(
                    'job_status',
                    {
                        job_id        => $job->id,
                        trans_id      => $id,
                        status        => 'error',
                        type          => $type,
                        name          => $name,
                        reference     => $invnumber,
                        error_message => $error_message
                    }
                );
            }

            # Update progress after each PDF is processed
            $processed++;
            my $progress_percent =
              int( ( $processed / scalar(@$emails) ) * 100 );
            $job->note( emails_processed => $processed );
            $job->note( progress_percent => $progress_percent );
            $job->note( success_count    => $results->{success} );
            $job->note( failed_count     => $results->{failed} );
        }

        # Create ZIP file if we have any successful PDFs
        my $zip_file_path;
        if ( @pdf_files > 0 ) {
            require Archive::Zip;
            my $zip = Archive::Zip->new();

            $zip_file_path = "tmp/invoices_${batch_id}.zip";

            foreach my $pdf_info (@pdf_files) {
                my $member = $zip->addFile( $pdf_info->{file_path},
                    $pdf_info->{display_name} );
                unless ($member) {
                    warn "Failed to add $pdf_info->{file_path} to ZIP";
                }
            }

            # Write the ZIP file
            unless (
                $zip->writeToFileNamed($zip_file_path) == Archive::Zip::AZ_OK )
            {
                die "Failed to create ZIP file: $zip_file_path";
            }

            $results->{zip_file} = $zip_file_path;
            $job->note( zip_created => 1 );
            $job->note( zip_file    => $zip_file_path );
        }

        # Send completion email to admin with ZIP attachment
        if ( $adminemail && $zip_file_path && -e $zip_file_path ) {
            my $subject = "Bulk PDF Generation Job #" . $job->id . " Completed";
            my $result_message =
              "Bulk PDF generation job #" . $job->id . " completed.\n\n";
            $result_message .= "Results:\n";
            $result_message .= "- Total: $results->{total}\n";
            $result_message .= "- Successful: $results->{success}\n";
            $result_message .= "- Failed: $results->{failed}\n\n";

            if ( $results->{success} > 0 ) {
                $result_message .=
                  "Generated PDFs are attached in the ZIP file.\n\n";
            }

            if ( $results->{failed} > 0 ) {
                $result_message .= "Failed PDFs:\n";
                foreach my $error ( @{ $results->{errors} } ) {
                    $result_message .=
"ID: $error->{id}, Type: $error->{type}, Email: $error->{email}, Name: $error->{name}, Invnumber: $error->{invnumber}\n";
                    $result_message .= "Error: $error->{error}\n\n";
                }
            }

            # Send email with ZIP attachment
            $c->send_email_central( $adminemail, $subject, $result_message,
                [$zip_file_path], undef, $client );

            # Clean up ZIP file immediately after sending email
            unlink $zip_file_path if -e $zip_file_path;
        }

        # Clean up temporary PDF files
        foreach my $pdf_info (@pdf_files) {
            unlink $pdf_info->{file_path} if -e $pdf_info->{file_path};
        }

        # Update final progress status
        $job->note( progress_percent => 100 );
        $job->note( status           => 'completed' );

        # Store the results in Minion's built-in results storage
        $job->finish($results);
    }
);
$api->post(
    "/create_pdf_batch" => sub {
        my $c      = shift;
        my $client = $c->param('client');

        # Extract JSON data from request
        my $json = $c->req->json;

        # Extract common parameters
        my $vc = $json->{vc} || do {
            $c->render(
                json   => { success => 0, message => "Missing vc parameter" },
                status => 400
            );
            return;
        };

        my $attachment = $json->{attachment} || 'tex';        # Default to tex
        my $jobtype    = $json->{jobtype}    || 'bulk_pdf';
        my $adminemail = $json->{adminemail} || '';

        # Check permissions
        return unless my $form = $c->check_perms("$vc.transaction");
        my $config = $c->slconfig;

        # Extract email array (we still use this structure for consistency)
        my $emails = $json->{emails} || do {
            $c->render(
                json   => { success => 0, message => "Missing emails array" },
                status => 400
            );
            return;
        };

        # Validate emails array
        unless ( ref $emails eq 'ARRAY' && @$emails > 0 ) {
            $c->render(
                json => {
                    success => 0,
                    message => "Invalid emails format or empty array"
                },
                status => 400
            );
            return;
        }

        # Validate attachment type
        unless ( $attachment eq 'tex' || $attachment eq 'html' ) {
            $c->render(
                json => {
                    success => 0,
                    message =>
                      "Invalid attachment type. Must be 'tex' or 'html'"
                },
                status => 400
            );
            return;
        }

        # Queue the PDF generation job
        my $job_id = $c->minion->enqueue(
            bulk_pdf_generation => [
                {
                    client     => $client,
                    vc         => $vc,
                    attachment => $attachment,
                    emails     => $emails,
                    jobtype    => $jobtype,
                    adminemail => $adminemail,
                    form       => $form,
                    config     => $config
                }
            ] => {
                priority => 1,
                notes    => {
                    client           => $client,
                    total_emails     => scalar @$emails,
                    emails_processed => 0,
                    progress_percent => 0,
                    jobtype          => $jobtype,
                    status           => 'queued'
                }
            }
        );

        # Return job ID to client
        $c->render(
            json => {
                success => 1,
                message => "Bulk PDF generation job queued successfully",
                job_id  => $job_id,
                client  => $client
            }
        );
    }
);

app->minion->add_task(
    bulk_email => sub {
        my ( $job, $args ) = @_;

        my $client = $args->{client};
        my $c      = $job->app;

        my $dbs = $c->dbs($client);

        my $emails     = $args->{emails};
        my $vc         = $args->{vc};
        my $attachment    = $args->{attachment} || '';
        my $inline        = $args->{inline}     || 0;
        my $batch_message = exists $args->{message} ? $args->{message} : undef;
        my $jobtype       = $args->{jobtype}    || 'bulk_email';
        my $adminemail = $args->{adminemail};
        my $form       = $args->{form};
        my $config     = $args->{config};

        # Initialize results tracking
        my $results = {
            total   => scalar @$emails,
            success => 0,
            failed  => 0,
            errors  => [],
            jobtype => $jobtype,
            client  => $client
        };

        # Store initial progress in job notes
        $job->note( client           => $client );
        $job->note( total_emails     => scalar @$emails );
        $job->note( emails_processed => 0 );
        $job->note( progress_percent => 0 );
        $job->note( jobtype          => $jobtype );

        # Process each email in the batch
        my $processed = 0;
        foreach my $item (@$emails) {
            my $id        = $item->{id}        || next;
            my $type      = $item->{type}      || next;
            my $email     = $item->{email}     || next;
            my $name      = $item->{name}      || next;
            my $invnumber = $item->{invnumber} || next;
            my $cc        = $item->{cc}        || '';
            my $bcc       = $item->{bcc}       || '';

            # Create a form object for this email
            my $form = new Form;
            eval {
                $form->{vc} = $vc;
                $form->{id} = $id;

                # Build invoice data (needed for intnotes and status updates)
                build_invoice( $c, $client, $form, $dbs );

                my $item_override =
                  exists $item->{message} ? $item->{message} : undef;
                my $override =
                    ( defined $item_override && $item_override =~ /\S/ )
                  ? $item_override
                  : ( defined $batch_message && $batch_message =~ /\S/ )
                  ? $batch_message
                  : undef;
                my $msg_type = $c->email_send_type_to_message_type($type);
                my $message  = $c->resolve_email_message_template(
                    $dbs, $form->{"${vc}_id"}, $form->{language_code} // '',
                    $msg_type, $override );

                my %seen_ph;
                for my $key (
                    grep { !$seen_ph{$_}++ } ( $message =~ /\{(\w+)\}/g ) )
                {
                    my $val = ( defined $form->{$key} && !ref $form->{$key} )
                      ? $form->{$key}
                      : '';
                    $val =~ s/\\/\\\\/g;
                    $val =~ s/\$/\\\$/g;
                    $message =~ s/\Q{$key}\E/$val/g;
                }

                # Set up email content and attachments
                my @attachments = ();

             # Process attachment if requested - use get_invoice_pdf for caching
                if ($attachment) {
                    my $pdf_path =
                      $c->get_invoice_pdf( $client, $id, $vc, $type,
                        $attachment );
                    if ( $pdf_path && -f $pdf_path ) {
                        push @attachments, $pdf_path;
                    }
                    else {
                        die "Failed to generate PDF attachment";
                    }
                }

                # Set up the email content
                my $subject = "Invoice $form->{invnumber}";

                # Add CC and BCC if provided
                my $to = $email;
                $to .= ",$cc"  if $cc;
                $to .= ",$bcc" if $bcc;

                my $now    = scalar localtime;
                my $locale = Locale->new;

                # Send email with or without attachments
                my $status = $c->send_email_central( $to, $subject, $message,
                    \@attachments, undef, $client );

                # Update internal notes
                $cc  = $locale->text('Cc') . qq|: $cc\n|   if $cc;
                $bcc = $locale->text('Bcc') . qq|: $bcc\n| if $bcc;
                my $int_notes = qq|$form->{intnotes}\n|;
                $int_notes = qq|\n[email]\n|;
                $int_notes .= qq|Type: $type\n|;
                $int_notes .= $locale->text('Date') . qq|: $now\n|;
                $int_notes .= $locale->text('To') . qq|: $email\n${cc}${bcc}|;
                $int_notes .= $locale->text('Subject') . qq|: $subject\n|;
                $int_notes .= $locale->text('Message') . qq|:|;
                $int_notes .= ($message) ? $message : $locale->text('sent');

                $form->{intnotes} = $int_notes;
                $form->save_intnotes( $config, 'ar' );

                # Handle reminder processing
                if ( $type =~ /^reminder(\d+)$/ ) {
                    my $level = $1;

                    # Ensure the level doesn't exceed 3
                    $level = 3 if $level > 3;

                    # Delete existing reminder status records
                    my $delete_query = qq|
                        DELETE FROM status
                        WHERE trans_id = ?
                        AND formname LIKE 'reminder_%'
                    |;
                    $dbs->query( $delete_query, $id );

                    # Insert new status record with the appropriate level
                    if ( $level > 0 ) {
                        $level++;
                        $level = 3 if $level > 3;
                        my $insert_query = qq|
                            INSERT INTO status (trans_id, formname)
                            VALUES (?, ?)
                        |;
                        $dbs->query( $insert_query, $id, "reminder$level" );
                    }
                }

                # Update emailed status
                if ( $form->{emailed} !~ /$type/ ) {
                    $form->{emailed} .= " $type";
                    $form->{emailed} =~ s/^ //;
                    $form->{"$type\_emailed"} = 1;

                    # save status
                    $form->update_status($config);
                }

                # Track success
                if ( $status && $status->{status} == 200 ) {
                    $results->{success}++;
                    push @{ $results->{successes} },
                      {
                        id        => $id,
                        type      => $type,
                        email     => $email,
                        name      => $name,
                        invnumber => $invnumber,
                      };

                    # Insert success record into job_status table
                    $dbs->insert(
                        'job_status',
                        {
                            job_id    => $job->id,
                            trans_id  => $id,
                            status    => 'success',
                            type      => $type,
                            email     => $email,
                            name      => $name,
                            reference => $invnumber
                        }
                    );
                }
                else {
                    my $error_msg =
                      $status ? $status->{error} : "Failed to send email";
                    die $error_msg;
                }
            };

            # Handle errors for this specific email
            if ($@) {
                my $error_message = "$@";
                $results->{failed}++;
                push @{ $results->{errors} },
                  {
                    id        => $id,
                    type      => $type,
                    email     => $email,
                    name      => $name,
                    invnumber => $invnumber,
                    error     => $error_message
                  };

                # Insert error record into job_status table
                $dbs->insert(
                    'job_status',
                    {
                        job_id        => $job->id,
                        trans_id      => $id,
                        status        => 'error',
                        type          => $type,
                        email         => $email,
                        name          => $name,
                        reference     => $invnumber,
                        error_message => $error_message
                    }
                );
            }

            # Update progress after each email is processed
            $processed++;
            my $progress_percent =
              int( ( $processed / scalar(@$emails) ) * 100 );
            $job->note( emails_processed => $processed );
            $job->note( progress_percent => $progress_percent );
            $job->note( success_count    => $results->{success} );
            $job->note( failed_count     => $results->{failed} );
        }

        # Send completion email to admin
        if ($adminemail) {
            my $subject = "Bulk Email Job #" . $job->id . " Completed";
            my $result_message =
              "Bulk email job #" . $job->id . " completed.\n\n";
            $result_message .= "Results:\n";
            $result_message .= "- Total: $results->{total}\n";
            $result_message .= "- Successful: $results->{success}\n";
            $result_message .= "- Failed: $results->{failed}\n\n";

            if ( $results->{failed} > 0 ) {
                $result_message .= "Failed emails:\n";
                foreach my $error ( @{ $results->{errors} } ) {
                    $result_message .=
"ID: $error->{id}, Type: $error->{type}, Email: $error->{email}, Name: $error->{name}, Invnumber: $error->{invnumber}\n";
                    $result_message .= "Error: $error->{error}\n\n";
                }
            }

            $c->send_email_central( $adminemail, $subject, $result_message,
                [], undef, $client );
        }

        # Update final progress status
        $job->note( progress_percent => 100 );
        $job->note( status           => 'completed' );

        # Store the results in Minion's built-in results storage
        $job->finish($results);
    }
);

$api->post(
    "/create_email_batch" => sub {
        my $c      = shift;
        my $client = $c->param('client');

        # Extract JSON data from request
        my $json = $c->req->json;

        # Extract common parameters
        my $vc = $json->{vc} || do {
            $c->render(
                json   => { success => 0, message => "Missing vc parameter" },
                status => 400
            );
            return;
        };

        my $attachment = $json->{attachment} || '';
        my $inline     = $json->{inline}     || 0;
        my $message    = $json->{message}    || '';
        my $jobtype    = $json->{jobtype}    || 'bulk_email';
        my $adminemail = $json->{adminemail} || '';
        $vc = $json->{vc} || '';
        return unless my $form = $c->check_perms("$vc.transaction");
        my $config = $c->slconfig;

        # Extract email array
        my $emails = $json->{emails} || do {
            $c->render(
                json   => { success => 0, message => "Missing emails array" },
                status => 400
            );
            return;
        };

        # Validate emails array
        unless ( ref $emails eq 'ARRAY' && @$emails > 0 ) {
            $c->render(
                json => {
                    success => 0,
                    message => "Invalid emails format or empty array"
                },
                status => 400
            );
            return;
        }

        # Queue the job with client association
        my $job_id = $c->minion->enqueue(
            bulk_email => [
                {
                    client     => $client,
                    vc         => $vc,
                    attachment => $attachment,
                    inline     => $inline,
                    message    => $message,
                    emails     => $emails,
                    jobtype    => $jobtype,
                    adminemail => $adminemail,
                    form       => $form,
                    config     => $config
                }
            ] => {
                priority => 1,
                notes    => {
                    client           => $client,
                    total_emails     => scalar @$emails,
                    emails_processed => 0,
                    progress_percent => 0,
                    jobtype          => $jobtype,
                    status           => 'queued'
                }
            }
        );

        # Return job ID to client
        $c->render(
            json => {
                success => 1,
                message => "Bulk email job queued successfully",
                job_id  => $job_id,
                client  => $client
            }
        );
    }
);
$api->get(
    "/email_jobs" => sub {
        my $c      = shift;
        my $minion = $c->minion;
        my $client = $c->param('client');

        my $jobs = $minion->jobs();
        my @job_data;

        while ( my $info = $jobs->next ) {
            warn( Dumper $info );
            next
              unless defined $info->{notes}
              && defined $info->{notes}{client}
              && $info->{notes}{client} eq $client;

            my $notes = $info->{notes} // {};
            my $args =
              ( $info->{args} && @{ $info->{args} } ) ? $info->{args}[0] : {};

            # Get success and failed counts directly from the database
            my $dbs           = $c->dbs($client);
            my $success_count = $dbs->query(
"SELECT COUNT(*) FROM job_status WHERE job_id = ? AND status = 'success'",
                $info->{id}
            )->array->[0]
              || 0;

            my $failed_count = $dbs->query(
"SELECT COUNT(*) FROM job_status WHERE job_id = ? AND status = 'error'",
                $info->{id}
            )->array->[0]
              || 0;

            push @job_data,
              {
                id               => $info->{id},
                state            => $info->{state},
                created          => $info->{created},
                finished         => $info->{finished}          // '',
                total_emails     => $notes->{total_emails}     // 0,
                emails           => $args->{emails}            // [],
                emails_processed => $notes->{emails_processed} // 0,
                progress_percent => $notes->{progress_percent} // 0,
                success_count    => $success_count,
                failed_count     => $failed_count,
                jobtype          => $notes->{jobtype}   // '',
                status           => $notes->{status}    // $info->{state},
                adminemail       => $args->{adminemail} // '',
                attachment       => $args->{attachment} // ''
              };
        }

        $c->render( json => { success => 1, jobs => \@job_data } );
    }
);
$api->get(
    "/email_job_status/:job_id" => sub {
        my $c      = shift;
        my $job_id = $c->param('job_id');
        my $status =
          $c->param('status');  # Optional: 'success', 'error', or undef for all
        my $page     = $c->param('page')     || 1;
        my $per_page = $c->param('per_page') || 50;
        my $client   = $c->param('client');

        my $dbs = $c->dbs($client);

        # Build query based on parameters
        my $query =
          "SELECT *, reference AS invnumber FROM job_status WHERE job_id = ?";
        my @params = ($job_id);

        if ($status) {
            $query .= " AND status = ?";
            push @params, $status;
        }

        # Add order and pagination
        $query .= " ORDER BY created_at DESC LIMIT ? OFFSET ?";
        push @params, $per_page, ( $page - 1 ) * $per_page;

        # Execute query using DBIx::Simple
        my $results = $dbs->query( $query, @params )->hashes;

        # Get total count for pagination
        my $count_query  = "SELECT COUNT(*) FROM job_status WHERE job_id = ?";
        my @count_params = ($job_id);

        if ($status) {
            $count_query .= " AND status = ?";
            push @count_params, $status;
        }

        my $total = $dbs->query( $count_query, @count_params )->array->[0];

        $c->render(
            json => {
                success  => 1,
                total    => $total,
                page     => $page,
                per_page => $per_page,
                items    => $results
            }
        );
    }
);

$api->post(
    "/manage_email_job" => sub {
        my $c      = shift;
        my $minion = $c->minion;
        my $client = $c->param('client');
        my $job_id = $c->param('job_id');
        my $action = $c->param('action');

        # Validate params
        unless ( $job_id && $action ) {
            return $c->render(
                json => { success => 0, message => "Missing job_id or action" },
                status => 400
            );
        }

        # Get the job
        my $job = $minion->job($job_id);
        unless ($job) {
            return $c->render(
                json   => { success => 0, message => "Job not found" },
                status => 404
            );
        }

        # Verify job belongs to this client
        my $job_info = $job->info;
        unless ( defined $job_info->{notes}
            && defined $job_info->{notes}{client}
            && $job_info->{notes}{client} eq $client )
        {
            return $c->render(
                json =>
                  { success => 0, message => "Unauthorized access to job" },
                status => 403
            );
        }

        # Handle different actions
        if ( $action eq 'cancel' ) {

            # Cancel the job
            if ( $job_info->{state} eq 'active' ) {
                $job->fail( { error => "Cancelled by user" } );
            }
            else {
                $job->remove;
            }
            return $c->render( json =>
                  { success => 1, message => "Job cancelled successfully" } );
        }
        elsif ( $action eq 'restart' ) {

            # Only restart inactive jobs
            if ( $job_info->{state} eq 'active' ) {
                return $c->render(
                    json => {
                        success => 0,
                        message => "Cannot restart an active job"
                    },
                    status => 400
                );
            }

            # Retry the job with same parameters
            my $new_id = $job->retry;
            return $c->render(
                json => {
                    success    => 1,
                    message    => "Job restarted successfully",
                    new_job_id => $new_id
                }
            );
        }
        elsif ( $action eq 'delete' ) {

            # Remove the job from the queue
            $job->remove;
            return $c->render(
                json => { success => 1, message => "Job deleted successfully" }
            );
        }
        else {
            return $c->render(
                json => { success => 0, message => "Unknown action: $action" },
                status => 400
            );
        }
    }
);

$api->get(
    '/onboarding' => sub {
        my $c       = shift;
        my $client  = $c->param('client');
        my $profile = $c->get_user_profile();
        my $central = $c->central_dbs();

        my $dataset =
          $central->query( "SELECT id from dataset WHERE db_name = ?", $client )
          ->hash;
        my $access = $central->query(
"SELECT access_level FROM dataset_access WHERE profile_id = ? AND dataset_id = ?",
            $profile->{profile_id}, $dataset->{id}
        )->hash;

        unless (
            $access
            && (   $access->{access_level} eq 'admin'
                || $access->{access_level} eq 'owner' )
          )
        {
            return $c->render(
                json => { onboarding => 0, completed => [], incomplete => [] }
            );
        }

        my $dbs = $c->dbs($client);
        my $onboarding =
          $dbs->query("SELECT fldname, fldvalue FROM onboarding")->hashes;

        my @incomplete_items = ();
        my @completed_items  = ();

        foreach my $item (@$onboarding) {
            if ( $item->{fldvalue} ) {
                push @completed_items, $item->{fldname};
            }
            else {
                push @incomplete_items, $item->{fldname};
            }
        }

        my $onboarding_status = @incomplete_items ? 1 : 0;

        return $c->render(
            json => {
                onboarding => $onboarding_status,
                completed  => \@completed_items,
                incomplete => \@incomplete_items
            }
        );
    }
);
$api->post(
    '/onboarding' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);
        my $data   = $c->req->json;

        my $onboarding =
          $dbs->query( "SELECT * FROM onboarding WHERE fldname = ?",
            $data->{fldname} )->hash;

        unless ($onboarding) {
            return $c->render(
                status => 404,
                json   => {
                    success => 0,
                    message => "Onboarding item not found"
                }
            );
        }

        $dbs->query( "UPDATE onboarding SET fldvalue = ? WHERE fldname = ?",
            $data->{fldvalue}, $data->{fldname} );

        $c->render( json =>
              { success => 1, message => "Onboarding updated successfully" } );
    }
);

#########################
####                 ####
####  DASHBOARD      ####
####  WIDGETS        ####
####                 ####
#########################

$api->get(
    '/dashboard/widgets' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        return unless my $form = $c->check_perms("dashboard");
        my $dbs    = $c->dbs($client);
        my $params = $c->req->params->to_hash;

        # Default start date to January 1st of the current year when not provided
        unless ( $params->{transdatefrom} ) {
            my ($year) = (localtime)[5];
            $params->{transdatefrom} = sprintf( "%04d-01-01", $year + 1900 );
        }

        # Get widget config for the user (can be empty)
        my $widget_config =
          $dbs->query( "SELECT config FROM widget_config WHERE user_id = ?",
            $form->{profile_id} )->hash;

        my $config   = $widget_config ? $widget_config->{config} : {};
        my $response = { config => $config };

        if ( $c->has_perm( $form, 'customer.overview' ) ) {
            $response->{customer_overview} =
              $c->get_overview_widget_data( $dbs, 'customer', $params );
        }

        if ( $c->has_perm( $form, 'vendor.overview' ) ) {
            $response->{vendor_overview} =
              $c->get_overview_widget_data( $dbs, 'vendor', $params );
        }

        if ( $ai_plugin && $c->has_perm( $form, 'stations.get' ) ) {
            $response->{workflow_pending} =
              $c->get_workflow_pending_invoices( $dbs, $form, $client );
        }

        if ( $c->has_perm( $form, 'gl.transactions' ) ) {
            $response->{revenue} =
              $c->get_revenue_widget_data( $dbs, $params );

            $response->{pl} =
              $c->get_pl_widget_data( $dbs, $params );

            $response->{balance_sheet} =
              $c->get_balance_sheet_widget_data( $dbs, $params );

            my $bank_accounts = $dbs->query(
                "SELECT c.id, c.accno, c.description, c.closed,
                     bk.name, bk.iban
                     FROM chart c
                     LEFT JOIN bank bk ON (bk.id = c.id)
                     WHERE c.link LIKE '%_paid%'
                     ORDER BY 2"
            )->hashes;

            my @chart_ids = map { $_->{id} } @{$bank_accounts};

            if (@chart_ids) {
                my $id_placeholders = join( ", ", ("?") x scalar @chart_ids );

                # Build bind list: chart_ids first, then optional date_to, then optional date_from
                my @bank_binds     = @chart_ids;
                my $date_to_clause = '';
                if ( $params->{transdateto} ) {
                    $date_to_clause = " AND transdate <= ?";
                    push @bank_binds, $params->{transdateto};
                }

                my $date_from_clause = '';
                if ( $params->{transdatefrom} ) {
                    my $from_month = substr( $params->{transdatefrom}, 0, 7 );
                    $date_from_clause = " WHERE month >= ?";
                    push @bank_binds, $from_month;
                }

                # Cumulative running balance per account per month.
                # Inner query aggregates all history up to transdateto; outer query
                # trims the visible months to transdatefrom onwards.
                my $bank_query = qq|
                    SELECT chart_id, month, running_balance
                    FROM (
                        SELECT
                            chart_id,
                            TO_CHAR(transdate, 'YYYY-MM') AS month,
                            SUM(SUM(amount * -1)) OVER (
                                PARTITION BY chart_id
                                ORDER BY TO_CHAR(transdate, 'YYYY-MM')
                            ) AS running_balance
                        FROM acc_trans
                        WHERE chart_id IN ($id_placeholders)
                          AND approved = '1'
                          $date_to_clause
                        GROUP BY chart_id, TO_CHAR(transdate, 'YYYY-MM')
                    ) sub
                    $date_from_clause
                    ORDER BY chart_id, month
                |;

                my $balance_rows = $dbs->query( $bank_query, @bank_binds )->hashes;

                my %balance_by_account;
                for my $row ( @{$balance_rows} ) {
                    $balance_by_account{ $row->{chart_id} }{ $row->{month} } =
                      $row->{running_balance} + 0;
                }

                for my $account ( @{$bank_accounts} ) {
                    $account->{balance_by_month} =
                      $balance_by_account{ $account->{id} } // {};
                }
            }

            $response->{bank_accounts} = $bank_accounts;
        }

        $c->render( json => $response );
    }
);

# Helper to get overview data (reused from /arap/overview/:vc logic)
helper get_overview_data => sub {
    my ( $c, $dbs, $vc, $params ) = @_;
    $params //= {};

    my $table = ( $vc eq 'customer' ) ? 'ar' : 'ap';

    my $query = qq|
        SELECT
            a.id,
            a.invnumber AS invnum,
            a.${vc}_id AS vc_id,
            vc.name AS vc_name,
            a.transdate,
            a.duedate,
            a.amount AS totalamount,
            a.paid AS amountpaid,
            a.description,
            a.invoice
        FROM $table a
        JOIN $vc vc ON (a.${vc}_id = vc.id)
        WHERE a.approved = '1'
    |;

    my @binds;

    if ( $params->{transdatefrom} ) {
        $query .= " AND a.transdate >= ?";
        push @binds, $params->{transdatefrom};
    }
    if ( $params->{transdateto} ) {
        $query .= " AND a.transdate <= ?";
        push @binds, $params->{transdateto};
    }
    if ( $params->{"${vc}_id"} ) {
        my $vc_ids = $params->{"${vc}_id"};
        $vc_ids = [ $vc_ids ] unless ref $vc_ids eq 'ARRAY';
        $vc_ids = [ split( /\s*,\s*/, $vc_ids->[0] ) ] if @$vc_ids == 1 && $vc_ids->[0] =~ /,/;
        $vc_ids = [ grep { /\S/ } map { ref $_ ? $_ : $_ } @$vc_ids ];
        if (@$vc_ids) {
            $query .= " AND a.${vc}_id IN (" . join( ", ", ("?") x @$vc_ids ) . ")";
            push @binds, @$vc_ids;
        }
    }
    if ( $params->{$vc} ) {
        $query .= " AND lower(vc.name) LIKE lower(?)";
        push @binds, "%" . $params->{$vc} . "%";
    }
    if ( $params->{invnumber} ) {
        $query .= " AND lower(a.invnumber) LIKE lower(?)";
        push @binds, "%" . $params->{invnumber} . "%";
    }
    if ( $params->{description} ) {
        $query .= " AND lower(a.description) LIKE lower(?)";
        push @binds, "%" . $params->{description} . "%";
    }

    $query .= " ORDER BY a.transdate DESC";

    my $rows = $dbs->query( $query, @binds )->hashes;

    my $summary = {
        transactions => {
            open     => { no => 0, amount => 0, transactions => [] },
            closed   => { no => 0, amount => 0, transactions => [] },
            overdue  => { no => 0, amount => 0, transactions => [] },
            overpaid => { no => 0, amount => 0, transactions => [] },
        }
    };

    my ( $sec, $min, $hour, $mday, $mon, $year ) = localtime();
    my $today = sprintf( "%04d-%02d-%02d", $year + 1900, $mon + 1, $mday );

    foreach my $r (@$rows) {
        my $amount           = $r->{totalamount} // 0;
        my $paid             = $r->{amountpaid}  // 0;
        my $status           = 'open';
        my $remaining_amount = 0;

        if ( abs($paid) > abs($amount) ) {
            $status           = 'overpaid';
            $remaining_amount = abs($paid) - abs($amount);
        }
        elsif ( abs($paid) == abs($amount) ) {
            $status           = 'closed';
            $remaining_amount = abs($amount);
        }
        else {
            $remaining_amount = abs($amount) - abs($paid);

            if ( $r->{duedate} && $r->{duedate} lt $today ) {
                $status = 'overdue';
            }
            else {
                $status = 'open';
            }
        }

        $summary->{transactions}->{$status}->{no}++;
        $summary->{transactions}->{$status}->{amount} += $remaining_amount;

        $r->{status}           = $status;
        $r->{remaining_amount} = $remaining_amount;

        push @{ $summary->{transactions}->{$status}->{transactions} }, $r;
    }

    return $summary;
};

# Helper for the dashboard overview widget: returns pre-aggregated by_month + top10.
# Does NOT return raw transactions — the /arap/overview/:vc endpoint keeps that shape.
helper get_overview_widget_data => sub {
    my ( $c, $dbs, $vc, $params ) = @_;
    $params //= {};

    my $table = ( $vc eq 'customer' ) ? 'ar' : 'ap';

    my @binds;
    my $date_filter = '';
    if ( $params->{transdatefrom} ) {
        $date_filter .= " AND a.transdate >= ?";
        push @binds, $params->{transdatefrom};
    }
    if ( $params->{transdateto} ) {
        $date_filter .= " AND a.transdate <= ?";
        push @binds, $params->{transdateto};
    }

    # Monthly aggregation: bucket invoice amounts by month and current status.
    # Status is determined against today so the chart reflects the live state of each invoice.
    my $monthly_query = qq|
        SELECT
            TO_CHAR(a.transdate, 'YYYY-MM') AS month,
            CASE
                WHEN ABS(a.paid) > ABS(a.amount)                        THEN 'overpaid'
                WHEN ABS(a.paid) = ABS(a.amount)                        THEN 'closed'
                WHEN a.duedate IS NOT NULL AND a.duedate < CURRENT_DATE  THEN 'overdue'
                ELSE 'open'
            END AS status,
            SUM(a.amount) AS total_amount
        FROM $table a
        JOIN $vc vc ON (a.${vc}_id = vc.id)
        WHERE a.approved = '1'
        $date_filter
        GROUP BY TO_CHAR(a.transdate, 'YYYY-MM'), status
        ORDER BY month, status
    |;

    my $monthly_rows = $dbs->query( $monthly_query, @binds )->hashes;

    my %by_month;
    my %totals = ( open => 0, overdue => 0, closed => 0, overpaid => 0 );

    for my $row ( @{$monthly_rows} ) {
        my $m      = $row->{month};
        my $status = $row->{status};
        my $amt    = $row->{total_amount} + 0;

        $by_month{$m} //= { open => 0, overdue => 0, closed => 0, overpaid => 0 };
        $by_month{$m}{$status} += $amt;
        $totals{$status}       += $amt;
    }

    # Top 10 by total invoice amount over the date range
    my $top10_query = qq|
        SELECT
            a.${vc}_id AS vc_id,
            vc.name    AS vc_name,
            SUM(a.amount) AS amount
        FROM $table a
        JOIN $vc vc ON (a.${vc}_id = vc.id)
        WHERE a.approved = '1'
        $date_filter
        GROUP BY a.${vc}_id, vc.name
        ORDER BY amount DESC
        LIMIT 10
    |;

    my $top10_rows = $dbs->query( $top10_query, @binds )->hashes;

    my @top10 = map {
        {
            vc_id   => $_->{vc_id},
            vc_name => $_->{vc_name},
            amount  => $_->{amount} + 0,
        }
    } @{$top10_rows};

    return {
        totals   => \%totals,
        by_month => \%by_month,
        top10    => \@top10,
    };
};

# Helper for the revenue widget.
# Resolves the full account hierarchy under a chart_categories root accno
# (default '3' = revenue), then aggregates acc_trans by month for the
# current year and — for the same months — the previous year.
#
# Revenue amounts in acc_trans are stored as positive credits (category='I'),
# so SUM(amount) gives the correct positive revenue figure directly.
# fx_transaction rows are excluded because they represent exchange-rate
# adjustments, not actual revenue movements.
#
# Returns:
#   by_month  – { "YYYY-MM" => { ac => N, py => N }, ... }
#   ac_ytd    – sum of all ac values in the date range
#   py_ytd    – sum of all py values for the matched months
helper get_revenue_widget_data => sub {
    my ( $c, $dbs, $params ) = @_;
    $params //= {};

    my $category_accno = $params->{category_accno} // '3';

    # Resolve the full set of bookable (charttype='A') accounts that belong to
    # the given category, walking through any intermediate heading accounts.
    # A depth cap of 5 prevents runaway recursion on malformed data.
    my $leaf_query = qq|
        WITH RECURSIVE category_tree AS (
            SELECT
                c.id        AS chart_id,
                c.accno     AS chart_accno,
                c.charttype,
                1           AS depth
            FROM chart_categories cc
            JOIN chart_category_links ccl ON ccl.category_id = cc.id
            JOIN chart                 c   ON c.id = ccl.chart_id
            WHERE cc.accno = ?

            UNION ALL

            SELECT
                c2.id,
                c2.accno,
                c2.charttype,
                ct.depth + 1
            FROM category_tree ct
            JOIN chart_categories  cc2  ON cc2.accno = ct.chart_accno
            JOIN chart_category_links ccl2 ON ccl2.category_id = cc2.id
            JOIN chart             c2   ON c2.id = ccl2.chart_id
            WHERE ct.charttype = 'H'
              AND ct.depth < 5
        )
        SELECT DISTINCT chart_id
        FROM category_tree
        WHERE charttype = 'A'
    |;

    my $leaf_rows = $dbs->query( $leaf_query, $category_accno )->hashes;
    my @chart_ids = map { $_->{chart_id} } @{$leaf_rows};

    return { by_month => {}, ac_ytd => 0, py_ytd => 0 } unless @chart_ids;

    my $ids = join( ", ", ("?") x scalar @chart_ids );

    # Derive the current-year date window
    my $date_from = $params->{transdatefrom};
    my ($cy)      = $date_from =~ /^(\d{4})/;
    my $cy_end    = $params->{transdateto} // sprintf( "%04d-12-31", $cy );
    my $py        = $cy - 1;
    my $py_start  = sprintf( "%04d%s", $py, substr( $date_from, 4 ) );
    my $py_end    = sprintf( "%04d%s", $py, substr( $cy_end,    4 ) );

    # Query current-year monthly revenue
    my $cy_query = qq|
        SELECT
            TO_CHAR(at.transdate, 'YYYY-MM') AS month,
            SUM(at.amount)                   AS revenue
        FROM acc_trans at
        WHERE at.chart_id       IN ($ids)
          AND at.approved        = '1'
          AND at.fx_transaction  = 'f'
          AND at.transdate      >= ?
          AND at.transdate      <= ?
        GROUP BY TO_CHAR(at.transdate, 'YYYY-MM')
        ORDER BY month
    |;

    my $cy_rows = $dbs->query( $cy_query, @chart_ids, $date_from, $cy_end )->hashes;

    my %by_month;
    my $ac_ytd = 0;

    for my $row ( @{$cy_rows} ) {
        my $amt = $row->{revenue} + 0;
        $by_month{ $row->{month} }{ac} = $amt;
        $by_month{ $row->{month} }{py} = 0;
        $ac_ytd += $amt;
    }

    # Query previous-year monthly revenue for the same calendar months
    my $py_query = qq|
        SELECT
            TO_CHAR(at.transdate, 'YYYY-MM') AS month,
            SUM(at.amount)                   AS revenue
        FROM acc_trans at
        WHERE at.chart_id       IN ($ids)
          AND at.approved        = '1'
          AND at.fx_transaction  = 'f'
          AND at.transdate      >= ?
          AND at.transdate      <= ?
        GROUP BY TO_CHAR(at.transdate, 'YYYY-MM')
        ORDER BY month
    |;

    my $py_rows = $dbs->query( $py_query, @chart_ids, $py_start, $py_end )->hashes;

    my $py_ytd = 0;

    for my $row ( @{$py_rows} ) {
        my $amt = $row->{revenue} + 0;
        # Map the PY month ("2024-03") to the CY equivalent ("2025-03")
        # and only include it when there is corresponding CY data
        my $cy_month = sprintf( "%04d%s", $cy, substr( $row->{month}, 4 ) );
        if ( exists $by_month{$cy_month} ) {
            $by_month{$cy_month}{py} = $amt;
            $py_ytd += $amt;
        }
    }

    return {
        by_month => \%by_month,
        ac_ytd   => $ac_ytd,
        py_ytd   => $py_ytd,
    };
};

# ─────────────────────────────────────────────────────────────────────────────
# P&L widget helper
#
# Returns a pre-computed Profit & Loss summary for the requested date window
# (default: current year to date) plus the equivalent prior-year period.
#
# ACCOUNT RESOLUTION
# ──────────────────
# Chart accounts are resolved from chart_categories / chart_category_links.
# Because category 6 (Betriebsaufwand) mixes operating overhead (60-67),
# depreciation (68), and financial items (690, 695), we resolve each
# sub-category independently rather than using the parent '6' bucket.
# This lets us build EBITDA (excludes 68, 690, 695) and EBIT (includes 68)
# cleanly without post-processing.  690 and 695 are never queried, so they
# are automatically excluded from every P&L line.
#
# SIGN CONVENTION
# ───────────────
# SQL-Ledger stores journal entries with the double-entry sign rule:
#   credits → positive   (revenue accounts — category I — are credit-normal)
#   debits  → negative   (expense accounts — category E — are debit-normal)
#
# This means all the arithmetic below is plain addition:
#   DB1 = rev + mat  →  SUM(cat_3) + SUM(cat_4)
#                        positive  + negative   = margin
# No sign flip is ever needed; the signs already encode the direction.
#
# FX transactions (fx_transaction = 't') are exchange-rate adjustment entries
# that would distort revenue and margin figures — they are excluded.
#
# P&L LINES
# ──────────
#   Umsatz  = cat_3
#   DB 1    = cat_3 + cat_4                        (− Material & Drittleistungen)
#   DB 2    = cat_3 + cat_4 + cat_5                (− Personalaufwand)
#   EBITDA  = cat_3 + cat_4 + cat_5 + cat_60..67  (− Betriebsaufwand excl. Abschr.)
#   EBIT    = cat_3 + cat_4 + cat_5 + cat_60..68  (− incl. Abschreibungen)
#
# RESPONSE SHAPE
# ──────────────
#   by_month  – monthly breakdown for charting, CY and PY side-by-side
#   ytd       – aggregated year-to-date totals + margin % relative to Umsatz
#
# PY months are mapped to their CY equivalent key ("2024-03" → "2025-03")
# and are only included when a CY entry exists for that month (avoids showing
# prior-year data for months that haven't occurred in the current year yet).
# ─────────────────────────────────────────────────────────────────────────────
helper get_pl_widget_data => sub {
    my ( $c, $dbs, $params ) = @_;
    $params //= {};

    # Root category accnos to resolve.  60-67 = operating overhead,
    # 68 = depreciation.  690 / 695 (financial items) are intentionally absent.
    my @cats = qw(3 4 5 60 61 62 63 64 65 66 67 68);
    my $accno_placeholders = join( ", ", map {"?"} @cats );

    # One recursive CTE resolves leaf accounts for ALL categories in a single
    # database round-trip.  The root_category label is carried through every
    # level of the recursion so each acc_trans row is attributed back to the
    # top-level bucket it belongs to.  A DISTINCT dedup step (leaf_accounts)
    # prevents double-counting when the same account appears via multiple paths.
    my $sql = qq|
        WITH RECURSIVE category_tree AS (

            SELECT
                c.id      AS chart_id,
                c.accno   AS chart_accno,
                c.charttype,
                cc.accno  AS root_category,
                1         AS depth
            FROM chart_categories      cc
            JOIN chart_category_links  ccl ON ccl.category_id = cc.id
            JOIN chart                 c   ON c.id = ccl.chart_id
            WHERE cc.accno = ANY( ARRAY[$accno_placeholders] )

            UNION ALL

            SELECT
                c2.id,
                c2.accno,
                c2.charttype,
                ct.root_category,
                ct.depth + 1
            FROM category_tree         ct
            JOIN chart_categories      cc2  ON cc2.accno = ct.chart_accno
            JOIN chart_category_links  ccl2 ON ccl2.category_id = cc2.id
            JOIN chart                 c2   ON c2.id = ccl2.chart_id
            WHERE ct.charttype = 'H'
              AND ct.depth     < 5
        ),

        leaf_accounts AS (
            SELECT DISTINCT chart_id, root_category
            FROM  category_tree
            WHERE charttype = 'A'
        )

        SELECT
            la.root_category,
            TO_CHAR(at.transdate, 'YYYY-MM') AS month,
            SUM(at.amount)                   AS total
        FROM   leaf_accounts la
        JOIN   acc_trans at ON at.chart_id = la.chart_id
        WHERE  at.approved       = '1'
          AND  at.fx_transaction = 'f'
          AND  at.transdate     >= ?
          AND  at.transdate     <= ?
        GROUP  BY la.root_category, TO_CHAR(at.transdate, 'YYYY-MM')
        ORDER  BY la.root_category, month
    |;

    # ── Date window derivation ────────────────────────────────────────────────
    my $date_from = $params->{transdatefrom};
    my ($cy)      = $date_from =~ /^(\d{4})/;
    my $cy_end    = $params->{transdateto} // sprintf( "%04d-12-31", $cy );
    my $py        = $cy - 1;
    my $py_start  = sprintf( "%04d%s", $py, substr( $date_from, 4 ) );
    my $py_end    = sprintf( "%04d%s", $py, substr( $cy_end,    4 ) );

    my @base_binds = @cats;

    # ── Fetch CY and PY raw totals ────────────────────────────────────────────
    my $cy_rows = $dbs->query( $sql, @base_binds, $date_from, $cy_end )->hashes;
    my $py_rows = $dbs->query( $sql, @base_binds, $py_start,  $py_end )->hashes;

    my ( %cat_ac, %cat_py );

    for my $row ( @{$cy_rows} ) {
        $cat_ac{ $row->{root_category} }{ $row->{month} } += $row->{total} + 0;
    }
    for my $row ( @{$py_rows} ) {
        my $cy_month = sprintf( "%04d%s", $cy, substr( $row->{month}, 4 ) );
        $cat_py{ $row->{root_category} }{$cy_month} += $row->{total} + 0;
    }

    # Helper closures to read a category/month value safely
    my $ac  = sub { $cat_ac{ $_[0] }{ $_[1] } // 0 };
    my $py_ = sub { $cat_py{ $_[0] }{ $_[1] } // 0 };

    # ── Build by_month ────────────────────────────────────────────────────────
    # Only produce entries for months that have at least one CY data point
    my %all_cy_months;
    $all_cy_months{$_} = 1 for map { keys %$_ } values %cat_ac;

    my %by_month;
    for my $m ( sort keys %all_cy_months ) {

        my $u_ac = $ac->( '3', $m );
        my $u_py = $py_->( '3', $m );

        my $d1_ac = $u_ac + $ac->( '4', $m );
        my $d1_py = $u_py + $py_->( '4', $m );

        my $d2_ac = $d1_ac + $ac->( '5', $m );
        my $d2_py = $d1_py + $py_->( '5', $m );

        my $opex_ac = $ac->('60',$m) + $ac->('61',$m) + $ac->('62',$m)
                    + $ac->('63',$m) + $ac->('64',$m) + $ac->('65',$m)
                    + $ac->('66',$m) + $ac->('67',$m);
        my $opex_py = $py_->('60',$m) + $py_->('61',$m) + $py_->('62',$m)
                    + $py_->('63',$m) + $py_->('64',$m) + $py_->('65',$m)
                    + $py_->('66',$m) + $py_->('67',$m);

        my $eb_ac = $d2_ac + $opex_ac;
        my $eb_py = $d2_py + $opex_py;

        my $ei_ac = $eb_ac + $ac->( '68', $m );
        my $ei_py = $eb_py + $py_->( '68', $m );

        $by_month{$m} = {
            umsatz => { ac => $u_ac  + 0, py => $u_py  + 0 },
            db1    => { ac => $d1_ac + 0, py => $d1_py + 0 },
            db2    => { ac => $d2_ac + 0, py => $d2_py + 0 },
            ebitda => { ac => $eb_ac + 0, py => $eb_py + 0 },
            ebit   => { ac => $ei_ac + 0, py => $ei_py + 0 },
        };
    }

    # ── Compute YTD totals by summing all months ──────────────────────────────
    my %ytd = map { $_ => { ac => 0, py => 0 } }
              qw(umsatz db1 db2 ebitda ebit);

    for my $m ( keys %by_month ) {
        for my $line ( qw(umsatz db1 db2 ebitda ebit) ) {
            $ytd{$line}{ac} += $by_month{$m}{$line}{ac};
            $ytd{$line}{py} += $by_month{$m}{$line}{py};
        }
    }

    # Margin percentages (relative to Umsatz) — only for sub-total lines
    for my $line ( qw(db1 db2 ebitda ebit) ) {
        $ytd{$line}{ac_pct} =
            $ytd{umsatz}{ac} != 0
            ? sprintf( "%.1f", $ytd{$line}{ac} / $ytd{umsatz}{ac} * 100 ) + 0
            : 0;
        $ytd{$line}{py_pct} =
            $ytd{umsatz}{py} != 0
            ? sprintf( "%.1f", $ytd{$line}{py} / $ytd{umsatz}{py} * 100 ) + 0
            : 0;
    }

    return {
        by_month => \%by_month,
        ytd      => \%ytd,
    };
};

# ─────────────────────────────────────────────────────────────────────────────
# Balance-sheet widget helper
#
# Returns the month-end BALANCE (cumulative running total) for each asset and
# liability/equity category, suitable for a stacked-bar chart where assets
# appear as positive bars above zero and liabilities as negative bars below.
#
# ASSETS vs LIABILITIES
# ─────────────────────
# Asset categories     : 10 (Flüssige Mittel), 11 (Forderungen),
#                        13 (Aktive RAP), 14 (Finanzanlagen), 15 (Sachanlagen)
# Liability/equity cats: 20 (Verbindlichkeiten L&L), 21 (Kurzfr. verzinslich),
#                        22 (Übrige kurzfr.), 23 (Passive RAP),
#                        26 (Rückstellungen), 29 (Reserven & Übriges)
#
# SIGN CONVENTION  (same rule for every category — multiply acc_trans by -1)
# ───────────────────────────────────────────────────────────────────────────
# SQL-Ledger encodes debits as negative and credits as positive.
#
#   Assets are debit-normal  → stored negative  → × -1 → positive for chart
#   Liabilities are credit-normal → stored positive → × -1 → negative for chart
#
# Applying "amount × -1" uniformly gives:
#   •  positive values for every asset category  (bars above zero)
#   •  negative values for every liability/equity category (bars below zero)
#
# On a well-formed balance sheet the total assets and total liabilities sums
# cancel exactly to zero — a useful sanity check in the frontend.
#
# BALANCE vs FLOW
# ───────────────
# Unlike the P&L widget (which sums flows within a date range), the balance
# sheet shows a SNAPSHOT at the end of each month.  The cumulative running
# balance must therefore include ALL historical transactions up to that date,
# not only those within the requested window.
#
# Implementation:
#   inner query  – pulls the whole history up to transdateto (no start filter)
#   window func  – SUM … OVER (PARTITION BY category ORDER BY month) gives the
#                  cumulative balance at each month-end
#   outer filter – WHERE month >= transdatefrom trims the visible range
#
# RESPONSE SHAPE
# ──────────────
#   labels               – human-readable description per category accno
#   asset_categories     – ordered list of asset accnos (2-char chart_categories
#                          roots with chart.category = A)
#   liability_categories – ordered list of liability/equity accnos (2-char roots,
#                          chart.category L or Q)
#   by_month             – { "YYYY-MM": { assets: { "10": N, …, total: N },
#                                         liabilities: { "20": N, …, total: N } } }
#
# The totals inside assets/liabilities are included so the frontend can plot
# the overall balance envelope without iterating all sub-keys itself.
# ─────────────────────────────────────────────────────────────────────────────
helper get_balance_sheet_widget_data => sub {
    my ( $c, $dbs, $params ) = @_;
    $params //= {};

    # Top-level balance-sheet groups: every chart_categories row whose accno is
    # exactly two characters, scoped to balance-sheet chart categories (A/L/Q)
    # via the matching header row in chart.
    my $cat_rows = $dbs->query(
        q{
        SELECT cc.accno, cc.description, c.category
          FROM chart_categories cc
          JOIN chart c ON c.accno = cc.accno AND c.charttype = 'H'
         WHERE char_length(cc.accno) = 2
           AND c.category IN ('A', 'L', 'Q')
        }
    )->hashes;

    my @sorted = sort { $a->{accno} cmp $b->{accno} } @{$cat_rows};
    my @asset_cats =
      map { $_->{accno} } grep { $_->{category} eq 'A' } @sorted;
    my @liability_cats =
      map { $_->{accno} } grep { $_->{category} =~ /^[LQ]$/ } @sorted;
    my @all_cats = ( @asset_cats, @liability_cats );

    unless (@all_cats) {
        return {
            labels               => {},
            asset_categories     => [],
            liability_categories => [],
            by_month             => {},
        };
    }

    my $accno_ph = join( ", ", map {"?"} @all_cats );

    # ── Single recursive CTE resolves every leaf account for all categories ──
    # The running-balance window (SUM OVER ORDER BY month) accumulates the
    # entire history; the outer WHERE month >= ? clips to the display window.
    my $sql = qq|
        WITH RECURSIVE category_tree AS (

            SELECT
                c.id      AS chart_id,
                c.accno   AS chart_accno,
                c.charttype,
                cc.accno  AS root_category,
                1         AS depth
            FROM chart_categories      cc
            JOIN chart_category_links  ccl ON ccl.category_id = cc.id
            JOIN chart                 c   ON c.id = ccl.chart_id
            WHERE cc.accno = ANY( ARRAY[$accno_ph] )

            UNION ALL

            SELECT
                c2.id,
                c2.accno,
                c2.charttype,
                ct.root_category,
                ct.depth + 1
            FROM category_tree         ct
            JOIN chart_categories      cc2  ON cc2.accno = ct.chart_accno
            JOIN chart_category_links  ccl2 ON ccl2.category_id = cc2.id
            JOIN chart                 c2   ON c2.id = ccl2.chart_id
            WHERE ct.charttype = 'H'
              AND ct.depth     < 5
        ),

        leaf_accounts AS (
            SELECT DISTINCT chart_id, root_category
            FROM  category_tree
            WHERE charttype = 'A'
        ),

        monthly_movement AS (
            SELECT
                la.root_category,
                TO_CHAR(at.transdate, 'YYYY-MM') AS month,
                SUM(at.amount * -1)               AS net
            FROM   leaf_accounts la
            JOIN   acc_trans at ON at.chart_id = la.chart_id
            WHERE  at.approved       = '1'
              AND  at.fx_transaction = 'f'
              AND  at.transdate     <= ?
            GROUP  BY la.root_category, TO_CHAR(at.transdate, 'YYYY-MM')
        )

        SELECT
            root_category,
            month,
            SUM(net) OVER (
                PARTITION BY root_category
                ORDER BY month
            ) AS balance
        FROM  monthly_movement
        WHERE month >= ?
        ORDER BY root_category, month
    |;

    # ── Date window ──────────────────────────────────────────────────────────
    my $date_from  = $params->{transdatefrom};
    my $date_to    = $params->{transdateto} // do {
        my ($y) = (localtime)[5];
        sprintf( "%04d-12-31", $y + 1900 );
    };
    my $from_month = substr( $date_from, 0, 7 );

    my $rows = $dbs->query( $sql, @all_cats, $date_to, $from_month )->hashes;

    my %labels = map { $_->{accno} => $_->{description} } @sorted;

    # ── Organise raw balance data ────────────────────────────────────────────
    my %cat_by_month;
    for my $row ( @{$rows} ) {
        $cat_by_month{ $row->{root_category} }{ $row->{month} } =
          $row->{balance} + 0;
    }

    my %all_months;
    $all_months{$_} = 1 for map { keys %$_ } values %cat_by_month;

    my %by_month;
    for my $m ( sort keys %all_months ) {

        # Assets — positive values (debit-normal accounts × -1 already applied)
        my %assets;
        my $total_assets = 0;
        for my $cat (@asset_cats) {
            my $v = $cat_by_month{$cat}{$m} // 0;
            $assets{$cat}  = $v + 0;
            $total_assets += $v;
        }
        $assets{total} = $total_assets + 0;

        # Liabilities — negative values (credit-normal accounts × -1 already applied)
        my %liabilities;
        my $total_liabilities = 0;
        for my $cat (@liability_cats) {
            my $v = $cat_by_month{$cat}{$m} // 0;
            $liabilities{$cat}   = $v + 0;
            $total_liabilities  += $v;
        }
        $liabilities{total} = $total_liabilities + 0;

        $by_month{$m} = {
            assets      => \%assets,
            liabilities => \%liabilities,
        };
    }

    return {
        labels               => \%labels,
        asset_categories     => \@asset_cats,
        liability_categories => \@liability_cats,
        by_month             => \%by_month,
    };
};

$api->post(
    '/dashboard/widgets' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        return unless my $form = $c->check_perms("dashboard");
        my $dbs  = $c->dbs($client);
        my $data = $c->req->json;

        unless ( $data && ref($data) eq 'HASH' ) {
            return $c->render(
                status => 400,
                json   =>
                  { error => 'Invalid request body. Expected JSON object.' }
            );
        }

        # Check if config already exists for this user
        my $existing =
          $dbs->query( "SELECT id FROM widget_config WHERE user_id = ?",
            $form->{profile_id} )->hash;

        if ($existing) {

            # Update existing config
            $dbs->query(
                "UPDATE widget_config SET config = ? WHERE user_id = ?",
                encode_json( $data->{config} // {} ),
                $form->{profile_id}
            );
        }
        else {
            # Insert new config
            $dbs->query(
                "INSERT INTO widget_config (user_id, config) VALUES (?, ?)",
                $form->{profile_id}, encode_json( $data->{config} // {} ) );
        }

        $c->render(
            json => {
                success => 1,
                message => "Widget configuration saved successfully"
            }
        );
    }
);

app->start;
