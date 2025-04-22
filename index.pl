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
Dotenv->load;
app->config( hypnotoad => { listen => ['http://*:3000'] } );
my $base_url          = $ENV{BACKEND_URL};
my $front_end         = $ENV{FRONT_END_URL};
my $postgres_user     = $ENV{POSTGRES_USER};
my $postgres_password = $ENV{POSTGRES_PASSWORD};

$front_end = "http://localhost:9000";

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
'["dashboard", "customer", "customer.transaction", "customer.invoice", "customer.creditinvoice", "customer.addcustomer", "customer.transactions", "customer.search", "customer.history"
, "vendor", "vendor.transaction", "vendor.invoice", "vendor.debitinvoice", "vendor.addvendor", "vendor.transactions", "vendor.search", "vendor.history", "cash", "cash.recon", "gl", "gl.add", "gl.transactions"
, "items", "items.part", "items.service", "items.search.allitems", "items.search.parts", "items.search.services", "reports", "reports.trial", "reports.income", "system", "system.currencies", "system.projects"
, "system.departments", "system.defaults", "system.user.roles", "system.user.employees", "system.chart", "system.chart.list", "system.chart.add", "system.chart.gifi", "system.taxes", "customer.return", "vendor.add", "vendor.return", "customer.invoice.return", "customer.add", "system.templates", "system.test"]';

helper send_email_central => sub {
    use Email::Sender::Transport::SMTP;
    use Email::Stuffer;
    my ( $c, $to, $subject, $content, $attachments ) = @_;

    my $transport = Email::Sender::Transport::SMTP->new(
        host                 => $ENV{SMTP_HOST},
        port                 => $ENV{SMTP_PORT},
        ssl                  => $ENV{SMTP_SSL},
        sasl_username        => $ENV{SMTP_USERNAME},
        sasl_password        => $ENV{SMTP_PASSWORD},
        sasl                 => $ENV{SMTP_SASL},
    );

    # Create the Email::Stuffer object
    my $email_obj =
      Email::Stuffer->from("$ENV{SMTP_USERNAME}")->to($to)->subject($subject)
      ->text_body($content);

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
        "SELECT s.profile_id, p.email
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
    my $c       = shift;
    my $client  = $c->param('client');
    my $profile = $c->get_user_profile();
    my $dbs     = $c->central_dbs();

    my $dataset =
      $dbs->query( "SELECT id from dataset WHERE db_name = ?", $client )->hash;
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
            SELECT id
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

            # Check if the dataset (client) exists
            my $dataset =
              $central_dbs->query( 'SELECT id FROM dataset WHERE db_name = ?',
                $client )->hash;
            unless ($dataset) {
                return $c->render(
                    status => 400,
                    json   => { message => "Invalid client" }
                );
            }

            # Check if the user has access to the dataset
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

        my $session_key = $central_dbs->query(
'INSERT INTO session (profile_id, sessionkey) VALUES (?, encode(gen_random_bytes(32), ?)) RETURNING sessionkey',
            $login->{id}, 'hex'
        )->hash->{sessionkey};

        return $c->render(
            json => {
                sessionkey => $session_key
            }
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
            "SELECT r.acs
     FROM dataset_access da
     JOIN role r ON da.role_id = r.id
     WHERE da.profile_id = ? AND r.dataset_id = ?",
            $profile->{profile_id}, $dataset_id
        )->hashes;

        # Merge the ACS arrays from all roles into a single set
        my %acs_union;
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
        }
        my @merged_acs = keys %acs_union;

        $c->render( json => { acs => \@merged_acs } );
    }
);

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
                    "SELECT id, name, acs 
                     FROM role
                     WHERE dataset_id = ?",
                    $dataset->{id}
                )->hashes;
                $dataset->{roles}            = $roles;
                $dataset->{admin}            = 1;

                my $client_dbs = $c->dbs( $dataset->{db_name} );

                my $connections;
                eval {
                    $connections = $client_dbs->query(
                        "SELECT type, status, error, drive_id FROM connections")->hashes;
                    1
                      ; # Indicate success so we don't jump into the 'or do' block
                } or do {

                  # If the query fails for any reason (e.g. table doesn't exist)
                    $connections = [];
                };

                $dataset->{connections} = $connections;
            }
        }

        $c->render( json => $datasets );
    }
);
$api->get('get_drives' => sub {
    my $c = shift;
    return unless $c->is_admin();
    my $client = $c->param('client');
    my $dbs = $c->dbs($client);
    my $drives = FM->get_drives($dbs, $c);

    $c->render(json => $drives);
});
$api->post('select_drive' => sub { 
    my $c = shift;
    return unless $c->is_admin();
    my $drive_id = $c->req->json->{'drive_id'};
    my $client = $c->param('client');
    my $dbs = $c->dbs($client);
    $dbs->query("UPDATE connections SET drive_id = ? WHERE type = 'google_drive'", $drive_id);
       return $c->render(
        status => 200,
        json   => { success => 1, message => "Drive ID updated successfully for client '$client'." }
    );
});

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

            my $acs = defined $data->{acs} ? $data->{acs} : '[]';

            # Insert new record and return the new id
            my $sth = $dbs_central->query(
"INSERT INTO role (dataset_id, name, acs) VALUES (?, ?, ?::jsonb) RETURNING id",
                $dataset_id, $name, $acs );
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

            # Update role. Only name and acs are updated.
            # If acs is not provided, COALESCE keeps the current value.
            my $acs = $data->{acs};
            my $sql = "UPDATE role
                       SET name = COALESCE(?, name),
                           acs = COALESCE(?::jsonb, acs)
                       WHERE id = ? AND dataset_id = ?";
            $dbs_central->query( $sql, $name, $acs, $id, $dataset_id );

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
          grep     { /-chart\.sql$/ && -f $_ }
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

$central->get("connection_keys", sub {
    my $c = shift;
    $c->render(json => {
        DROPBOX_KEY      => $ENV{DROPBOX_KEY},
        GOOGLE_CLIENT_ID => $ENV{GOOGLE_CLIENT_ID},
        ALL_DRIVE       => $ENV{ALL_DRIVE} * 1,
    });
});

$central->post(
    'create_dataset' => sub {
        my $c         = shift;
        my $params    = $c->req->json;
        my $dataset   = $params->{dataset};
        my $company   = $params->{company};
        my $templates = $params->{templates};
        my $chart     = $params->{chart};

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

        # Template directory handling
        my $templates_dir   = "doc/templates/";
        my $destination_dir = "templates/$dataset";
        dircopy( "$templates_dir$templates", $destination_dir );
        rename( "$destination_dir/$templates", "$destination_dir/$dataset" );

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
            "${sql_dir}Pg-functions.sql", "${sql_dir}Pg-neoledger.sql"
        );
        foreach my $sql_file (@sql_files) {
            run_sql_file( $dataset, $sql_file );
        }

        # Load chart-specific SQL
        my $chart_file = "${sql_dir}${chart}-chart.sql";
        run_sql_file( $dataset, $chart_file );

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
        my $dataset_dbh = DBI->connect( "dbi:Pg:dbname=$dataset;host=localhost",
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
            $dataset_id, 'main', $neoledger_perms );
        my $role_id =
          $central_dbs->last_insert_id( undef, undef, 'role', 'id' );

        $central_dbs->query(
"INSERT INTO dataset_access(profile_id, dataset_id, access_level, role_id) VALUES (?,?, 'owner', ?)",
            $profile->{profile_id},
            $dataset_id, $role_id
        );

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

    # Split SQL content into individual statements
    my @statements = split( /;\s*/, $sql );
    foreach my $statement (@statements) {
        next if $statement =~ /^\s*$/;

        # Execute each statement inside an eval block to catch errors
        eval {
            $dbh->do($statement);
            1;
        } or do {
            my $error = $@ || 'Unknown error';

     # Log a trimmed version of the statement for context (first 100 characters)
            my $trimmed_statement = substr( $statement, 0, 100 );
            die
"Failed to execute SQL statement in file '$sql_file': $error\nStatement (truncated): $trimmed_statement...";
        };
    }

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
              "You've been invited to access dataset '$dataset->{db_name}'";
            $content = <<"EMAIL";
Hello,

You have been invited by $profile->{email} to access the dataset "$dataset->{db_name}" on Neo-Ledger.
Please log in at: $front_end/login

Thank you,
The Neo-Ledger Team
EMAIL
        }
        else {
            # For new users, send a signup invitation email
            $subject =
              "Invitation to join Neo-Ledger and access '$dataset->{db_name}'";
            $content = <<"EMAIL";
Hello,

You have been invited by $profile->{email} to access the dataset "$dataset->{db_name}" on Neo-Ledger.
If you already have an account, please log in at: $front_end/login.
If not, please sign up using the following link:
$front_end/signup?invite=$invite->{invite_code}

We look forward to having you onboard.

Best regards,
$dataset->{db_name}
EMAIL
        }

        # Use the provided email helper to send the email
        my $email_result =
          $c->send_email_central( $recipient_email, $subject, $content );
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
    $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";
    my $central_dbs = $c->central_dbs();

    # Validate the session and get the profile (user) record
    my $profile = $c->get_user_profile();
    unless ($profile) {
        $c->render(
            status => 401,
            json   => { message => "Invalid session key" }
        );
        return 0;
    }

    my $dataset =
      $central_dbs->query( "SELECT id from dataset WHERE db_name = ?", $client )
      ->hash;

    my $admin = $central_dbs->query(
        "SELECT 1 FROM dataset_access da
         WHERE da.profile_id = ? 
           AND da.access_level IN ('admin','owner') 
           AND da.dataset_id = ?
         LIMIT 1",
        $profile->{profile_id}, $dataset->{id}
    )->hash;
    my $form = new Form;
    $form->{api_url}      = $base_url;
    $form->{frontend_url} = $front_end;
    $form->{client}       = $c->param('client');
    return $form if $admin;

    # Fetch all roles for the given dataset
    my $role = $central_dbs->query(
        "SELECT r.acs
         FROM role r
         JOIN dataset_access da ON r.id = da.role_id
         WHERE da.profile_id = ? 
         AND da.dataset_id = ?",
        $profile->{profile_id}, $dataset->{id}
    )->hash;

    warn( Dumper $role );

    # Combine allowed permissions into a hash for faster lookup
    my %allowed;

    my $acs   = $role->{acs} // '[]';
    my $perms = ref($acs) eq 'ARRAY' ? $acs : decode_json($acs);

    $allowed{$_} = 1 for @$perms;

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
                $dbs, $c,
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
                $new_line{linetaxamount} = $line->{linetaxamount};

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

        my $response = {
            id            => $form->{id},
            reference     => $form->{reference},
            approved      => $form->{approved},
            ts            => $form->{ts},
            curr          => $form->{curr},
            description   => $form->{description},
            notes         => $form->{notes},
            department    => $form->{department},
            department_id => $form->{department_id},
            transdate     => $form->{transdate},
            ts            => $form->{ts},
            exchangeRate  => $form->{exchangerate},
            employeeId    => $form->{employee_id},
            lines         => \@lines,
            files         => $files
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
        }

        $data->{form} = $form;
        my $dbs = $c->dbs($client);
        api_gl_transaction( $c, $dbs, $data );
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
        api_gl_transaction( $c, $dbs, $data, $id );
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

sub api_gl_transaction {
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
    my $form = $data->{form};

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
    $form->{department}      = $data->{department};
    $form->{transdate}       = $transdate;
    $form->{defaultcurrency} = $default_currency;
    $form->{login}           = $data->{login};

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
        $form->{"projectnumber_$i"} = $line->{project};

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

    my $status_code =
      $c->param('id') ? 200 : 201;    # 200 for update, 201 for create

    $c->render(
        status => $status_code,
        json   => $response_json,
    );
}

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
$api->get(
    '/system/companydefaults' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        return unless my $form = $c->check_perms("system.defaults");

        my $dbs = $c->dbs($client);

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

        for (qw(cdt checkinventory hideaccounts linetax forcewarehouse xelatex))
        {
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
        my $c = shift;
        return unless my $form = $c->check_perms("system.defaults");
        my $client = $c->param('client');

        # Get form data from JSON request body
        my $json_data = $c->req->json;
        warn( Dumper $json_data );

        # Transfer JSON data to form object
        foreach my $key ( keys %$json_data ) {
            $form->{$key} = $json_data->{$key};
        }
        warn( Dumper $form );

        $form->{optional} =
"company address tel fax companyemail companywebsite yearend weightunit businessnumber closedto revtrans audittrail method cdt namesbynumber xelatex typeofcontact roundchange referenceurl annualinterest latepaymentfee restockingcharge checkinventory hideaccounts linetax forcewarehouse glnumber sinumber sonumber vinumber batchnumber vouchernumber ponumber sqnumber rfqnumber partnumber projectnumber employeenumber customernumber vendornumber lock_glnumber lock_sinumber lock_sonumber lock_ponumber lock_sqnumber lock_rfqnumber lock_employeenumber lock_customernumber lock_vendornumber";

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
        my $c = shift;
        return unless my $form = $c->check_perms("system.chart.list");
        my $client = $c->param('client');

        my $result = CA->all_accounts( $c->slconfig, $form );
        if ($result) {
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
        my $client = $c->param('client');
        my $id     = $c->param("id");
        my $params = $c->req->json;

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

        return unless my $form = $c->check_perms( $permissions{$search} );

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
    my $c        = shift;
    my $client   = $c->param('client');
    my $dbs      = $c->dbs($client);
    my $defaults = $dbs->query("SELECT * FROM defaults")->hashes;

    return {} unless ( $defaults && @$defaults );

    # Transform the array of hashrefs into a hashref keyed by fldname
    my %defaults_hash = map { $_->{fldname} => $_->{fldvalue} } @$defaults;

    return \%defaults_hash;
};

helper get_projects => sub {
    my $c        = shift;
    my $client   = $c->param('client');
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
    my ( $c, $role ) = @_;
    my $client = $c->param('client');
    my $dbs    = $c->dbs($client);

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
    my ( $c, $vc ) = @_;
    my $client = $c->param('client');
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
    my $c      = shift;
    my $client = $c->param('client');

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
    my ($c)    = @_;
    my $client = $c->param('client');
    my $form   = Form->new;
    my $module = $c->param('module');
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
        all            => ''
    );

    # Create a hash to store filtered accounts for each type
    my %filtered_accounts;
    foreach my $type ( keys %filter_mapping ) {
        my $filter_str = $filter_mapping{$type};
        my @filtered =
          grep { defined $_->{link} && $_->{link} =~ /\Q$filter_str\E/ }
          @$accounts;
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
$api->get(
    '/create_links/:module' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);
        my $module = $c->param('module');

        # List of valid modules
        my @valid_modules =
          qw(customer vendor ic gl chart gl_report projects incomestatement employees reminder);

        # Return empty JSON object if module not valid
        return $c->render( json => {} )
          unless grep { $_ eq $module } @valid_modules;

        my $tax_accounts = $dbs->query(
            "SELECT t.*, c.description, c.accno,
                CONCAT(c.accno, '--', c.description) AS label
         FROM tax t
         JOIN chart c ON (c.id = t.chart_id)
         ORDER BY c.accno"
        )->hashes;

        my $accounts   = $c->get_accounts;
        my $currencies = $c->get_currencies;
        my $customers  = $c->get_vc('customer');
        my $vendors    = $c->get_vc('vendor');
        my $projects   = $c->get_projects;
        my $gifi       = $c->get_gifi;
        my $defaults   = $c->get_defaults;
        warn( Dumper $defaults );

        my $line_tax = $defaults->{linetax} ? 1 : 0;

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
        elsif ( $module eq 'customer' ) {
            return unless $c->check_perms('customer');

            # Here, do module-specific parameter checks
            # E.g., return unless $c->check_params('customer_check');

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
            };
        }

        #-------------
        # VENDOR module
        #-------------
        elsif ( $module eq 'vendor' ) {
            return unless $c->check_perms('customer');

            # Module-specific checks
            # E.g., return unless $c->check_params('vendor_check');

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

        # If we got here, it means we have a valid module and passed checks
        $c->render( json => $response );
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
        my $dbs = $c->dbs($client);
        eval {
            # Fetch files for all transactions in a single operation
            FM->get_files_for_transactions(
                $dbs, $c,
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
        return
          unless my $form = $c->check_perms(
            "$vc.transaction,$vc.invoice,$vc.creditinvoice,$vc.debitinvoice");
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

        # Render the form object as JSON
        $c->render( json => {%$form} );
    }
);

# Used for Customer/Vendor Forms

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
        return unless my $form = $c->check_perms("$vc.add");

        my $params = $c->req->json;

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
        Dumper( warn $form );

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
                $doc_type          = "debit_note";
                $amount_multiplier = 1;
            }
            else {
                $doc_type          = "transaction";
                $amount_multiplier = 1;
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

        my $files = FM->get_files( $dbs, $c, $form );

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
            department_id => $form->{department_id},
            id            => $form->{id},
            recordAccount => $form->{acc_trans}{$transaction_type}[0],
            $vc_id_field  => $form->{$vc_id_field},
            lineitems     => \@line_items,
            payments      => \@payments,
            type          => $doc_type,
            files         => $files,
        };

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
        }

        my $vc = $c->param('vc');
        return unless my $form = $c->check_perms("$vc.transaction");
        my $dbs = $c->dbs($client);
        my $id  = $c->param('id');
        $c->slconfig->{dbconnect} = "dbi:Pg:dbname=$client";

        $form->{type} = $data->{type};
        $form->{vc}   = $vc eq 'vendor' ? 'vendor' : 'customer';

        # Basic transaction details
        $form->{id}           = $id if $id;
        $form->{invnumber}    = $data->{invNumber}   || '';
        $form->{description}  = $data->{description} || '';
        $form->{transdate}    = $data->{invDate};
        $form->{duedate}      = $data->{dueDate};
        $form->{exchangerate} = $data->{exchangerate} || 1;
        $form->{department}   = $data->{department}   || '';

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
                $form->{"projectnumber_$i"} = $line->{project};
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

        if ( $data->{files} && ref $data->{files} eq 'ARRAY' ) {
            $form->{files}  = $data->{files};
            $form->{client} = $c->param('client');
            FM->upload_files( $dbs, $c, $form, $vc );
        }

        $c->render( json => { id => $form->{id} } );
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
        warn( Dumper $form );
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

        my $files = FM->get_files( $dbs, $c, $form );

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
            department_id => $form->{department_id},
            files         => $files,
            lines         => \@lines,
            payments      => \@payments,
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

        warn Dumper($json_data);

        $c->render( json => $json_data );
    }
);
$api->post(
    '/arap/invoice/:vc/:id' => { id => undef } => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $id     = $c->param('id');
        my $vc     = $c->param('vc');

        my $data;
        my $content_type = $c->req->headers->content_type || '';

        if ( $content_type =~ m!multipart/form-data!i ) {
            $data = handle_multipart_request($c);
        }
        else {
            $data = $c->req->json;
        }

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
        $form->{currency}     = $data->{currency};
        $form->{exchangerate} = $data->{exchangerate} || 1;
        $form->{notes}        = $data->{notes}        || '';
        $form->{intnotes}     = $data->{intnotes}     || '';
        $form->{till}         = $data->{till}         || '';
        $form->{department}   = $data->{department}   || '';

        # Set up AR or AP account from JSON
        # for AR, it's $form->{AR}, for AP, it's $form->{AP}.
        if ( $invoice_type eq 'AR' ) {

            # AR fields
            $form->{AR}          = $data->{recordAccount};
            $form->{customer_id} = $data->{customer_id};
            $form->{customer}    = $data->{customer};
        }
        else {
            # AP fields
            $form->{AP}        = $data->{recordAccount};
            $form->{vendor_id} = $data->{selectedVendor}->{id};
            $form->{vendor}    = $data->{selectedVendor}->{name};
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
        $form->{employee_id}   = undef;
        $form->{language_code} = '';
        $form->{precision}     = $data->{selectedCurrency}->{prec} || 2;

        warn Dumper($form);

        # Finally, post invoice to LedgerSMB
        if ( $invoice_type eq 'AR' ) {
            IS->post_invoice( $c->slconfig, $form );
        }
        else {
            IR->post_invoice( $c->slconfig, $form );
        }

        if ( $data->{files} && ref $data->{files} eq 'ARRAY' ) {
            $form->{files}  = $data->{files};
            $form->{client} = $c->param('client');
            FM->upload_files( $dbs, $c, $form, $vc );
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

###############################
####                       ####
####        Reports        ####
####                       ####
###############################

$api->get(
    '/reports/trial_balance' => sub {
        my $c = shift;
        return unless $c->check_perms('reports.trial');
        my $client = $c->param('client');

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
        my $c = shift;
        return
          unless ( $c->check_perms('reports.trial')
            || $c->check_perms('reports.income') );
        my $client = $c->param('client');
        my $dbs    = $c->dbs($client);

        my $form = new Form;
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
                warn( $row->{accno} );
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
                $dbs, $c,
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
        warn Dumper $params;

        # Create the required objects
        my $form   = Form->new;
        my $locale = Locale->new;

        # Assign parameters with a defined-or operator
        $form->{department}      = $params->{department}      // "";
        $form->{projectnumber}   = $params->{projectnumber}   // "";
        $form->{fromdate}        = $params->{fromdate}        // "";
        $form->{todate}          = $params->{todate}          // "";
        $form->{frommonth}       = $params->{frommonth}       // "";
        $form->{fromyear}        = $params->{fromyear}        // "";
        $form->{interval}        = $params->{interval}        // "0";
        $form->{currency}        = $params->{currency}        // "PKR";
        $form->{defaultcurrency} = $params->{defaultcurrency} // "PKR";
        $form->{decimalplaces}   = $params->{decimalplaces}   // "2";
        $form->{method}          = $params->{method}          // "accrual";
        $form->{includeperiod}   = $params->{includeperiod}   // "year";
        $form->{previousyear}    = $params->{previousyear}    // "0";
        $form->{accounttype}     = $params->{accounttype}     // "standard";
        $form->{usetemplate}     = $params->{usetemplate}     // '';
        my $periods = [];

        foreach my $key ( keys %$params ) {
            if ( $key =~ /^periods\[(\d+)\]\[(\w+)\]$/ ) {
                my ( $index, $field ) = ( $1, $2 );
                $periods->[$index]{$field} = $params->{$key};
            }
        }

        $form->{periods} = $periods;

        # Process income statement report
        RP->income_statement_periods( $c->slconfig, $form, $locale );

        warn( Dumper $form );

        if ( $form->{usetemplate} eq 'Y' ) {

            # spacer configuration for formatting (if needed)
            my %spacer = (
                H => '',
                A => '&nbsp;&nbsp;&nbsp;'
            );
            my $account_map = {
                A => {
                    type  => 'asset',
                    ml    => 1,
                    label => $locale->text('Assets')
                },
                L => {
                    type  => 'liability',
                    ml    => 1,
                    label => $locale->text('Liabilities')
                },
                Q => {
                    type  => 'equity',
                    ml    => 1,
                    label => $locale->text('Equity')
                },
                I => {
                    type  => 'income',
                    ml    => 1,
                    label => $locale->text('Income')
                },
                E => {
                    type  => 'expense',
                    ml    => -1,
                    label => $locale->text('Expense')
                },
            };

            my $myconfig = $c->slconfig;
            my $timeperiod =
              $locale->date( \%myconfig, $form->{fromdate},
                $form->{longformat} )
              . qq| |
              . $locale->text('To') . qq| |
              . $locale->date( \%myconfig, $form->{todate},
                $form->{longformat} );
            my $userspath = "tmp";
            $form->{templates} = "templates/$client/";
            $form->{IN}        = "income_statement_new.html";
            $form->{OUT}       = ">tmp/income_statement.html";

            # Build the report; pass the objects and needed variables
            build_report( $form, $locale, $account_map, $myconfig,
                $timeperiod, 'income_statement' );
            $form->parse_template( \%$myconfig, $userspath );

            # Strip the '>' character from the output file path
            ( my $file_path = $form->{OUT} ) =~ s/^>//;

            # Open the file for reading
            open my $fh, '<', $file_path or die "Cannot open $file_path: $!";

            # Slurp the entire file into a scalar
            {
                local $/;    # Enable 'slurp' mode
                $form->{html_content} = <$fh>;
            }

            close $fh;
            unlink $file_path or warn "Could not delete $file_path: $!";
            my $pdf = html_to_pdf( $form->{html_content} );
            unless ($pdf) {
                $c->res->status(500);
                $c->render( text => "Failed to generate PDF" );
                return;
            }

            $c->res->headers->content_type('application/pdf');
            $c->render( data => $pdf );
            return;
        }

        warn Dumper $form;
        $c->render( json => {%$form} );
    }
);

sub html_to_pdf {
    my ($html_content) = @_;

    # Check if PDF::WebKit is available
    eval {
        require PDF::WebKit;
        PDF::WebKit->import();
        1;
    } or do {
        warn "PDF::WebKit module not found.";
        return 0;
    };

    my $kit;
    eval {
        $kit = PDF::WebKit->new( \$html_content, page_size => 'Letter' );
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

    # Check if $pdf was generated successfully
    return defined $pdf ? $pdf : 0;
}

#----------------------------------------------------------------
# Subroutine: build_report
#
# Now accepts required objects/variables as parameters.
#----------------------------------------------------------------

sub build_report {
    my ( $form, $locale, $account_map, $myconfig, $timeperiod, $report_type ) =
      @_;

    # Extract period labels from the defined periods
    my @periods = map { $_->{label} } @{ $form->{periods} };

    # Build header row for period columns
    my $period_headers_html = "";
    foreach my $p ( @{ $form->{periods} } ) {
        $period_headers_html .= qq|<th>$p->{label}</th>|;
    }
    $form->{period_headers_html} = $period_headers_html;

    if ( $report_type eq 'income_statement' ) {

        # --- INCOME STATEMENT  ---
        my ( %income_data,  %expense_data );
        my ( %total_income, %total_expense );
        my $data_key = '';

        foreach my $accno ( sort { $a <=> $b } keys %{ $form->{$data_key} } ) {
            foreach my $period (@periods) {
                next unless exists $form->{$data_key}{$accno}{$period};
                my ($cat) = keys %{ $form->{$data_key}{$accno}{$period} };
                next unless $cat =~ /^(I|E)$/;
                my $data        = $form->{$data_key}{$accno}{$period}{$cat};
                my $charttype   = $data->{charttype};
                my $description = $data->{description};
                my $amount      = $data->{amount};
                my $ml          = $account_map->{$cat}{ml} // 1;
                my $formatted_amount = $form->format_amount(
                    $myconfig,
                    $amount * $ml,
                    $form->{decimalplaces}, ''
                );
                my $label = "";

                if ( $charttype eq "A" ) {
                    $label =
                      $form->{l_accno} ? "$accno - $description" : $description;
                }
                elsif ( $charttype eq "H" ) {
                    $label =
                        $form->{br}
                      . $form->{bold}
                      . $description
                      . $form->{endbold};
                }
                if ( $cat eq 'I' ) {
                    $income_data{$accno}{label} ||= $label;
                    $income_data{$accno}{amounts}{$period} = $formatted_amount;
                    $total_income{$period} +=
                      ( $charttype eq "H" ? 0 : $amount * $ml );
                }
                elsif ( $cat eq 'E' ) {
                    $expense_data{$accno}{label} ||= $label;
                    $expense_data{$accno}{amounts}{$period} = $formatted_amount;
                    $total_expense{$period} +=
                      ( $charttype eq "H" ? 0 : $amount * $ml );
                }
            }
        }
        my $income_rows_html = "";
        foreach my $accno ( sort { $a <=> $b } keys %income_data ) {
            my $row =
              qq|<tr><td width="4"></td><td>$income_data{$accno}{label}</td>|;
            foreach my $period (@periods) {
                my $amt =
                  exists $income_data{$accno}{amounts}{$period}
                  ? $income_data{$accno}{amounts}{$period}
                  : "";
                $row .= qq|<td align="right">$amt</td>|;
            }
            $row              .= "</tr>\n";
            $income_rows_html .= $row;
        }
        my $expense_rows_html = "";
        foreach my $accno ( sort { $a <=> $b } keys %expense_data ) {
            my $row =
              qq|<tr><td width="4"></td><td>$expense_data{$accno}{label}</td>|;
            foreach my $period (@periods) {
                my $amt =
                  exists $expense_data{$accno}{amounts}{$period}
                  ? $expense_data{$accno}{amounts}{$period}
                  : "";
                $row .= qq|<td align="right">$amt</td>|;
            }
            $row               .= "</tr>\n";
            $expense_rows_html .= $row;
        }
        my $total_income_html =
          qq|<tr valign="top"><td> </td><th align="left">TOTAL INCOME</th>|;
        my $total_expense_html =
          qq|<tr valign="top"><td> </td><th align="left">TOTAL EXPENSES</th>|;
        my $total_profit_html =
qq|<tr valign="top"><th align="left" colspan="2">INCOME / (LOSS)</th>|;
        foreach my $period (@periods) {
            my $inc = $form->format_amount(
                $myconfig,
                $total_income{$period} || 0,
                $form->{decimalplaces}, ''
            );
            my $exp = $form->format_amount(
                $myconfig,
                $total_expense{$period} || 0,
                $form->{decimalplaces}, ''
            );
            my $profit = $form->format_amount(
                $myconfig,
                ( $total_income{$period}    || 0 ) -
                  ( $total_expense{$period} || 0 ),
                $form->{decimalplaces},
                ''
            );
            $total_income_html .=
              qq|<td align="right">$inc<hr noshade size="2"></td>|;
            $total_expense_html .=
              qq|<td align="right">$exp<hr noshade size="2"></td>|;
            $total_profit_html .=
              qq|<td align="right">$profit<hr noshade size="2"></td>|;
        }
        $total_income_html  .= "</tr>\n";
        $total_expense_html .= "</tr>\n";
        $total_profit_html  .= "</tr>\n";
        $form->{income_rows}        = $income_rows_html;
        $form->{expense_rows}       = $expense_rows_html;
        $form->{total_income_html}  = $total_income_html;
        $form->{total_expense_html} = $total_expense_html;
        $form->{total_profit_html}  = $total_profit_html;
        $form->{period}             = join( " / ", @periods );
        $form->{_periods}           = \@periods;

        # --- END INCOME STATEMENT CODE ---

    }
    elsif ( $report_type eq 'balance_sheet' ) {

        my ( %balance_data, %category_totals );
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
                next if $charttype eq "H";

                my $description = $data->{description};
                my $amount      = $data->{amount};

                # Flip the sign for Assets right after reading
                if ( $cat eq 'A' ) {
                    $amount = -$amount;
                }

                # Determine the multiplier for summation based on category
                # This ensures A=L+E balancing works correctly later
                my $ml;
                if ( $cat eq 'A' ) {

                    # Assets contribute positively after sign flip
                    $ml = 1;
                }
                elsif ( $cat eq 'L' || $cat eq 'Q' ) {

                  # Liabilities & Equity contribute negatively
                  # Force -1 for this calculation, ignore account_map->{ml} here
                    $ml = -1;
                }
                else {
                    # Should not happen, but default
                    $ml = 1;
                }

                # Calculate the value contributing to the category total sum
                my $signed_amount = $amount * $ml;

              # Format the amount for display. Use the sign-corrected $amount.
              # format_amount should handle negative display (e.g., parentheses)
                my $formatted_amount = $form->format_amount(
                    $myconfig,
                    $amount,    # Display the corrected amount
                    $form->{decimalplaces}, ''
                );

                my $label = "";
                if ( $charttype eq "A" ) {
                    $label =
                      $form->{l_accno} ? "$accno - $description" : $description;
                }
                else {
                    $label = $description;
                }

                $balance_data{$cat}{$accno}{label} ||= $label;
                $balance_data{$cat}{$accno}{amounts}{$period} =
                  $formatted_amount;

                # Add the correctly signed amount to totals
                $category_totals{$cat}{$period} += $signed_amount;
            }
        }

        # --- Build HTML rows  ---
        my ( $assets_rows_html, $liabilities_rows_html, $equity_rows_html ) =
          ( "", "", "" );
        for my $cat (qw(A L Q)) {
            next unless exists $balance_data{$cat};
            foreach
              my $accno ( sort { $a <=> $b } keys %{ $balance_data{$cat} } )
            {
                my $row =
qq|<tr><td width="4"></td><td>$balance_data{$cat}{$accno}{label}</td>|;
                foreach my $period (@periods) {
                    my $amt =
                      exists $balance_data{$cat}{$accno}{amounts}{$period}
                      ? $balance_data{$cat}{$accno}{amounts}{$period}
                      : "";
                    $row .= qq|<td align="right">$amt</td>|;
                }
                $row .= "</tr>\n";
                if    ( $cat eq 'A' ) { $assets_rows_html      .= $row; }
                elsif ( $cat eq 'L' ) { $liabilities_rows_html .= $row; }
                elsif ( $cat eq 'Q' ) { $equity_rows_html      .= $row; }
            }
        }

        # --- End Build HTML rows ---

        # --- Calculate final totals  ---
        my %net_totals;
        my $current_earnings_html =
qq|<tr valign="top"><td width="4"></td><th align="left">Current Earnings</th>|;

        foreach my $period (@periods) {

          # Get the raw summed totals for each category for this period
          # With the ml fix, these should now be: Assets(+), Liabs(-), Equity(-)
            my $raw_assets   = $category_totals{'A'}{$period} || 0;
            my $raw_liabs    = $category_totals{'L'}{$period} || 0;
            my $raw_equity_q = $category_totals{'Q'}{$period} || 0;

            # --- Core Calculation Logic ---
            my $total_assets      = $raw_assets;       # Should be positive
            my $total_liabilities = -$raw_liabs;       # Should now be positive
            my $recorded_equity   = -$raw_equity_q;    # Should now be positive

            # Equity = Assets - Liabilities
            my $calculated_total_equity = $total_assets - $total_liabilities;

            # Current Earnings = Calculated Total Equity - Recorded Equity
            my $current_earnings = $calculated_total_equity - $recorded_equity;

            # --- End Core Calculation Logic ---

            $net_totals{assets}{$period}           = $total_assets;
            $net_totals{liabilities}{$period}      = $total_liabilities;
            $net_totals{recorded_equity}{$period}  = $recorded_equity;
            $net_totals{total_equity}{$period}     = $calculated_total_equity;
            $net_totals{current_earnings}{$period} = $current_earnings;

            my $current_earnings_formatted =
              $form->format_amount( $myconfig, $current_earnings,
                $form->{decimalplaces}, '' );
            $current_earnings_html .=
              qq|<td align="right">$current_earnings_formatted</td>|;
        }
        $current_earnings_html .= "</tr>\n";
        $equity_rows_html .=
          $current_earnings_html;    # Add CE row to equity section
                                     # --- End Calculate final totals ---

        # --- Build totals rows (Relies on corrected net_totals) ---
        my $total_assets_html =
          qq|<tr valign="top"><td> </td><th align="left">TOTAL ASSETS</th>|;
        my $total_liabilities_html =
qq|<tr valign="top"><td> </td><th align="left">TOTAL LIABILITIES</th>|;
        my $total_equity_html =
          qq|<tr valign="top"><td> </td><th align="left">TOTAL EQUITY</th>|;
        foreach my $period (@periods) {
            my $asset_total = $form->format_amount(
                $myconfig,
                $net_totals{assets}{$period},
                $form->{decimalplaces}, ''
            );
            my $liability_total = $form->format_amount(
                $myconfig,
                $net_totals{liabilities}{$period},
                $form->{decimalplaces}, ''
            );
            my $equity_total = $form->format_amount(
                $myconfig,
                $net_totals{total_equity}{$period},
                $form->{decimalplaces}, ''
            );
            $total_assets_html .=
              qq|<td align="right">$asset_total<hr noshade size="2"></td>|;
            $total_liabilities_html .=
              qq|<td align="right">$liability_total<hr noshade size="2"></td>|;
            $total_equity_html .=
              qq|<td align="right">$equity_total<hr noshade size="2"></td>|;
        }
        $total_assets_html      .= "</tr>\n";
        $total_liabilities_html .= "</tr>\n";
        $total_equity_html      .= "</tr>\n";

        # --- End Build totals rows ---

        # Assign results to the form hash
        $form->{assets_rows}            = $assets_rows_html;
        $form->{liabilities_rows}       = $liabilities_rows_html;
        $form->{equity_rows}            = $equity_rows_html;
        $form->{total_assets_html}      = $total_assets_html;
        $form->{total_liabilities_html} = $total_liabilities_html;
        $form->{total_equity_html}      = $total_equity_html;
        $form->{period}                 = join( " / ", @periods );
        $form->{_periods}               = \@periods;

    }
    else {
        warn "Unknown report type: $report_type";
    }

    $form->{timeperiod} = $timeperiod;
    return 1;    # Indicate success
}

$api->get(
    '/reports/balance_sheet' => sub {
        my $c = shift;
        return unless $c->check_perms('reports.balance');
        my $client = $c->param('client');
        my $params = $c->req->params->to_hash;
        warn Dumper $params;

        my $form   = Form->new;
        my $locale = Locale->new;

        # Assign parameters
        $form->{department}      = $params->{department}      // "";
        $form->{projectnumber}   = $params->{projectnumber}   // "";
        $form->{todate}          = $params->{todate}          // "";
        $form->{currency}        = $params->{currency}        // "PKR";
        $form->{defaultcurrency} = $params->{defaultcurrency} // "PKR";
        $form->{decimalplaces}   = $params->{decimalplaces}   // "2";
        $form->{includeperiod}   = $params->{includeperiod}   // "year";
        $form->{previousyear}    = $params->{previousyear}    // "0";
        $form->{accounttype}     = $params->{accounttype}     // "standard";
        $form->{usetemplate}     = $params->{usetemplate}     // '';

        my $periods = [];
        foreach my $key ( keys %$params ) {
            if ( $key =~ /^periods\[(\d+)\]\[(\w+)\]$/ ) {
                my ( $index, $field ) = ( $1, $2 );
                $periods->[$index]{$field} = $params->{$key};
            }
        }
        $form->{periods} = $periods;

        RP->balance_sheet_periods( $c->slconfig, $form, $locale );

        warn Dumper $form;

        if ( $form->{usetemplate} eq 'Y' ) {
            my %spacer = (
                H => '',
                A => '&nbsp;&nbsp;&nbsp;'
            );
            my $account_map = {
                A => {
                    type  => 'asset',
                    ml    => 1,
                    label => $locale->text('Assets')
                },
                L => {
                    type  => 'liability',
                    ml    => 1,
                    label => $locale->text('Liabilities')
                },
                Q => {
                    type  => 'equity',
                    ml    => 1,
                    label => $locale->text('Equity')
                },
                I => {
                    type  => 'income',
                    ml    => 1,
                    label => $locale->text('Income')
                },
                E => {
                    type  => 'expense',
                    ml    => -1,
                    label => $locale->text('Expense')
                },
            };

            my $myconfig = $c->slconfig;

            my $timeperiod = "";
            if ( @{ $form->{periods} } == 1 ) {
                $timeperiod = $locale->date( \%myconfig, $form->{todate},
                    $form->{longformat} );
            }
            else {
                $timeperiod =
                  join( " / ", map { $_->{label} } @{ $form->{periods} } );
            }
            my $userspath = "tmp";
            $form->{templates} = "templates/$client/";
            $form->{IN}        = "balance_sheet_new.html";
            $form->{OUT}       = ">tmp/balance_sheet.html";

            build_report( $form, $locale, $account_map, $myconfig, $timeperiod,
                'balance_sheet' );
            $form->parse_template( \%$myconfig, $userspath );

            ( my $file_path = $form->{OUT} ) =~ s/^>//;
            open my $fh, '<', $file_path or die "Cannot open $file_path: $!";
            { local $/; $form->{html_content} = <$fh>; }
            close $fh;
            unlink $file_path or warn "Could not delete $file_path: $!";
            my $pdf = html_to_pdf( $form->{html_content} );
            unless ($pdf) {
                $c->res->status(500);
                $c->render( text => "Failed to generate PDF" );
                return;
            }
            $c->res->headers->content_type('application/pdf');
            $c->render( data => $pdf );
            return;
        }

        warn Dumper $form;
        $c->render( json => {%$form} );
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
    $form->{language_code} = '';
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
    my ( $c, $client, $form, $dbs ) = @_;

    my $invoice_type = $form->{vc} eq 'vendor' ? 'AP' : 'AR';
    my $arap_key     = $invoice_type;

    my $arap = "ar";
    if ( $form->{vc} eq 'vendor' ) {
        $arap = "ap";
    }

    if ( $invoice_type eq 'AR' ) {
        IS->retrieve_invoice( $c->slconfig, $form );
    }
    else {
        IR->retrieve_invoice( $c->slconfig, $form );
    }
    $form->{invdate}        = $form->{transdate};
    $form->{invdescription} = $form->{description};
    AA->company_details( $c->slconfig, $form );

    # Precompute common values and config
    my $default_date = $form->{transdate} || '';
    my $precision    = $form->{precision} || 2;

    my (
        @items,      @numbers,       @descriptions, @deliverydates,
        @qtys,       @units,         @makes,        @models,
        @sellprices, @discountrates, @linetotals,   @itemnotes
    );

    my $item_count = scalar( @{ $form->{invoice_details} } );
    for my $arrayref (
        \@items,      \@numbers,       \@descriptions, \@deliverydates,
        \@qtys,       \@units,         \@makes,        \@models,
        \@sellprices, \@discountrates, \@linetotals,   \@itemnotes
      )
    {
        $#$arrayref = $item_count - 1;
    }

    my $subtotal = 0;
    my $i        = 1;
    foreach my $item ( @{ $form->{invoice_details} } ) {

        # Precompute values once
        my $qty      = $item->{qty}         || 0;
        my $price    = $item->{fxsellprice} || $item->{sellprice} || 0;
        my $discount = $item->{discount}    || 0;

        # Calculate line total once
        my $linetotal = $qty * $price * ( 1 - $discount );
        $subtotal += $linetotal;

        my $formatted_qty   = $form->format_amount( $c->slconfig, $qty );
        my $formatted_price = $form->format_amount( $c->slconfig, $price );
        my $formatted_linetotal =
          $form->format_amount( $c->slconfig, $linetotal );

        my $idx = $i - 1;
        $items[$idx]         = $i;
        $numbers[$idx]       = $item->{partnumber}  || '';
        $descriptions[$idx]  = $item->{description} || '';
        $deliverydates[$idx] = $default_date;
        $qtys[$idx]          = $formatted_qty;
        $units[$idx]         = $item->{unit}  || '';
        $makes[$idx]         = $item->{make}  || '';
        $models[$idx]        = $item->{model} || '';
        $sellprices[$idx]    = $formatted_price;
        $discountrates[$idx] = $discount ? $discount * 100 : '0';
        $linetotals[$idx]    = $formatted_linetotal;
        $itemnotes[$idx]     = $item->{itemnotes} || '';

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
    $ml *= -1 if $form->{vc} eq 'customer';

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

    my $credit_remaining = $dbs->query(
        qq|SELECT SUM(a.amount - a.paid)
          FROM $arap a
          WHERE a.amount != a.paid
          AND $form->{vc}_id = $form->{"$form->{vc}_id"}|
    )->hash;
    my $credit        = -$credit_remaining->{sum};
    my $credit_before = $credit + $subtotal;
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

    sub round {
        my ( $number, $precision ) = @_;
        my $factor = 10**$precision;
        return int( $number * $factor + 0.5 ) / $factor;
    }

    # Format the credit values
    my $display_credit = $form->format_amount( $c->slconfig, abs $credit );
    $display_credit = "($display_credit)" if $credit > 0;
    $display_credit = "0"                 if $credit == 0;

    my $display_credit_before =
      $form->format_amount( $c->slconfig, abs $credit_before );
    $display_credit_before = "($display_credit_before)" if $credit_before > 0;
    $display_credit_before = "0"                        if $credit_before == 0;

    my $paid  = $paid_sum;
    my $total = ( $subtotal + $taxtotal ) - $paid;

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

    my $num2text;
    if ( $form->{language_code} ne "" ) {
        $num2text = new CP $form->{language_code};
    }
    else {
        $num2text = new CP $c->slconfig->{countrycode};
    }
    $num2text->init;

    # Totals
    $form->{subtotal} = $form->format_amount( $c->slconfig, $subtotal );
    $form->{paid}     = $form->format_amount( $c->slconfig, $paid );
    $form->{invtotal} = $form->format_amount( $c->slconfig, $total );
    $form->{total}    = $form->format_amount( $c->slconfig, $total );
    $form->{credit}                = $credit;
    $form->{display_credit}        = $display_credit;
    $form->{display_credit_before} = $display_credit_before;
    $form->{credit_before}         = $credit_before;
    $form->{due}         = $form->format_amount( $c->slconfig, $total );
    $form->{text_amount} = $num2text->num2text($total);
    $form->{decimal}     = $form->{decimal}  || '00';
    $form->{currency}    = $form->{currency} || '';
    $form->{notes}       = $form->{notes}    || '';
    $form->{terms}       = $form->{terms}    || '0';

    # ---- PARALLEL ARRAYS FOR LINE ITEMS ----
    $form->{runningnumber} = \@items;
    $form->{number}        = \@numbers;
    $form->{description}   = \@descriptions;
    $form->{deliverydate}  = \@deliverydates;
    $form->{qty}           = \@qtys;
    $form->{unit}          = \@units;
    $form->{make}          = \@makes;
    $form->{model}         = \@models;
    $form->{sellprice}     = \@sellprices;
    $form->{discountrate}  = \@discountrates;
    $form->{linetotal}     = \@linetotals;
    $form->{itemnotes}     = \@itemnotes;

    # ---- PARALLEL ARRAYS FOR TAXES ----
    $form->{taxdescription} = \@taxdescriptions;
    $form->{taxbase}        = \@taxbases;
    $form->{taxrate}        = \@taxrates;
    $form->{tax}            = \@taxamounts;

    # ---- PARALLEL ARRAYS FOR PAYMENTS ----
    $form->{paymentdate}    = \@paymentdates;
    $form->{paymentaccount} = \@paymentaccounts;
    $form->{paymentsource}  = \@paymentsources;
    $form->{payment}        = \@paymentamounts;

    # This indicates there's at least 1 payment
    $form->{paid_1} = @paymentamounts ? 1 : "";

    return $form;
}
$api->get(
    "/print_invoice/" => sub {
        my $c        = shift;
        my $template = $c->param("template");
        my $format   = $c->param("format");

        # Extract parameters
        my $client = $c->param('client') || die "Missing client parameter";
        my $vc     = $c->param('vc')     || die "Missing vc parameter";
        my $id     = $c->param('id')     || die "Missing invoice id";
        my $dbs    = $c->dbs($client);

        return unless my $form = $c->check_perms("$vc.transaction");
        $form->{vc} = $vc;
        $form->{id} = $id;

        # Build invoice and letterhead data
        build_invoice( $c, $client, $form, $dbs );

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
            die "Unsupported type: $format";
        }

        my $userspath = "tmp";
        my $defaults  = $c->get_defaults();

        # Process based on type
        if ( $format eq 'tex' ) {
            my $dvipdf = "";

            my $xelatex = $defaults->{xelatex};
            $form->parse_template( $c->slconfig, $userspath, $dvipdf,
                $xelatex );
            my $pdf_path = "tmp/invoice.pdf";

            # Read PDF file content
            open my $fh, $pdf_path or die "Cannot open file $pdf_path: $!";
            binmode $fh;
            my $pdf_content = do { local $/; <$fh> };
            close $fh;
            unlink $pdf_path or warn "Could not delete $pdf_path: $!";

            # Return PDF as response
            $c->res->headers->content_type('application/pdf');
            $c->res->headers->content_disposition(
                "attachment; filename=\"$form->{invnumber}.pdf\"");
            $c->render( data => $pdf_content );
        }
        elsif ( $format eq 'html' ) {
            $form->parse_template( $c->slconfig, $userspath );

            # Strip the '>' character from the output file path
            ( my $file_path = $form->{OUT} ) =~ s/^>//;

            # Read the HTML file content
            open my $fh, '<', $file_path or die "Cannot open $file_path: $!";
            { local $/; $form->{html_content} = <$fh> }
            close $fh;
            unlink $file_path or warn "Could not delete $file_path: $!";

            # Convert HTML to PDF
            my $pdf = html_to_pdf( $form->{html_content} );
            unless ($pdf) {
                $c->res->status(500);
                $c->render( text => "Failed to generate PDF" );
                return;
            }
            $c->res->headers->content_type('application/pdf');
            $c->render( data => $pdf );
        }
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
        $transaction_data->{OUT}               = ">tmp/transaction.pdf";
        $transaction_data->{format}            = "pdf";
        $transaction_data->{media}             = "screen";
        $transaction_data->{copies}            = 1;

        my $form      = new Form;
        my $user_path = "tmp";
        for my $k ( keys %$transaction_data ) {
            $form->{$k} = $transaction_data->{$k};
        }
        warn( Dumper $form );
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

                # Alias for google_drive support
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
            my $token_data   = $res->json;
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

$api->get(
    '/files/:module/:file' => sub {
        my $c      = shift;
        my $client = $c->param('client');
        my $module = $c->param('module');
        my $file   = $c->param('file');

        my $dbs  = $c->dbs($client);
        my $path = $dbs->query( "SELECT path FROM files WHERE id = ?", $file )
          ->hash->{path};

        my $path = $c->app->home->rel_file($path);

        # Check if the file exists, and serve it if it does
        if ( -e $path ) {
            return $c->reply->file($path);
        }
        else {
            return $c->reply->not_found;
        }
    }
);
app->start;
