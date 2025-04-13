package FM;
use strict;
use warnings;
use Mojo::UserAgent;
use Mojo::JSON qw(encode_json decode_json);
use Mojo::Util qw(url_escape);
use Data::Dumper;
use Time::Piece;
use POSIX      qw(strftime);
use File::Path qw(make_path);
use Dotenv;
use MIME::Base64;
use File::Basename qw(basename);

# Constants
use constant {
    TOKEN_REFRESH_ATTEMPTS => 2,
    MAX_UPLOAD_ATTEMPTS    => 2,
};

#----------------------------------------------------------------
# PUBLIC FUNCTIONS
#----------------------------------------------------------------

sub upload_files {
    my ( $self, $dbs, $c, $data, $module ) = @_;

    # Configure processors for different storage providers
    my %processors = (
        'dropbox'      => \&process_dropbox,
        'google_drive' => \&process_google_drive
    );

    # Default to local storage
    my $processor = \&process_local;
    my $connection_info;

    # Find active cloud storage connection
    my $connection =
      $dbs->query( "SELECT * FROM connections WHERE status = 'active' AND "
          . "(type = 'dropbox' OR type = 'google_drive') ORDER BY type LIMIT 1"
    )->hash;

    if ( $connection && exists $processors{ $connection->{type} } ) {
        $processor       = $processors{ $connection->{type} };
        $connection_info = $connection;
        $c->app->log->info("Using '$connection->{type}' processor for upload.");
    }
    else {
        $c->app->log->info("Using 'local' processor for upload.");
    }

    # Prepare directory structure
    my $client = $data->{client} || 'default';
    my ( $year, $month ) = _get_date_parts( $data->{transdate} );

    # Set paths for different storage providers
    my $remote_base = "/$client/$module/$year/$month";
    my $local_base  = "files/$client/$module/$year/$month";

    # Process each file
    my @files_info;
    foreach my $file ( @{ $data->{files} } ) {
        next unless ref($file) && $file->can('filename') && $file->can('slurp');
        my $original_filename = $file->filename;
        my $unique_filename   = _generate_unique_filename($original_filename);
        push @files_info,
          {
            file              => $file,
            original_filename => $original_filename,
            unique_filename   => $unique_filename,
            remote_path       => "$remote_base/$unique_filename",
            local_path        => "$local_base/$unique_filename",
          };
    }

    $data->{files_info} = \@files_info;
    return $processor->( $dbs, $c, $data, $module, $connection_info );
}

sub process_dropbox {
    my ( $dbs, $c, $data, $module, $connection ) = @_;
    my $client_id        = $ENV{DROPBOX_KEY}    || '';
    my $client_secret    = $ENV{DROPBOX_SECRET} || '';
    my $storage_location = 'dropbox';
    my $ua               = Mojo::UserAgent->new;
    my $upload_url       = 'https://content.dropboxapi.com/2/files/upload';
    my $shared_link_url =
      'https://api.dropboxapi.com/2/sharing/create_shared_link_with_settings';
    my $access_token = $connection->{access_token};
    my @processed_files;

    foreach my $file_info ( @{ $data->{files_info} } ) {
        my $file           = $file_info->{file};
        my $file_contents  = $file->slurp;
        my $dbx_path       = $file_info->{remote_path};
        my $attempt        = 1;
        my $upload_success = 0;

        while ( $attempt <= MAX_UPLOAD_ATTEMPTS && !$upload_success ) {

            # Check token validity and refresh if needed
            $access_token =
              _check_and_refresh_token( $dbs, $c, $connection, $client_id,
                $client_secret, 'dropbox' );

            my $headers = {
                'Authorization'   => "Bearer $access_token",
                'Dropbox-API-Arg' =>
qq/{"path": "$dbx_path", "mode": "add", "autorename": true, "mute": false}/,
                'Content-Type' => 'application/octet-stream',
            };

            my $tx  = $ua->post( $upload_url => $headers => $file_contents );
            my $res = $tx->result;

            if ( $res->is_success ) {
                $upload_success = 1;
                my $link;

                # Create shared link
                my $link_tx = $ua->post(
                    $shared_link_url => {
                        'Authorization' => "Bearer $access_token",
                        'Content-Type'  => 'application/json'
                    } => encode_json( { path => $dbx_path } )
                );

                my $link_res = $link_tx->result;
                if ( $link_res->is_success ) {
                    my $link_data = eval { decode_json( $link_res->body ) };
                    $link = $link_data->{url}
                      if $link_data && $link_data->{url};
                }

                push @processed_files,
                  {
                    original_name => $file_info->{original_filename},
                    saved_name    => $file_info->{unique_filename},
                    path          => $dbx_path,
                    link          => $link,
                  };

                _update_connection_status( $dbs, $connection->{id}, 'active' );
                last;
            }
            else {
                my $status_code   = $res->code;
                my $error_message = $res->message || "Unknown Error";

                if ( $status_code == 401 ) {
                    $c->app->log->error(
"Dropbox upload returned 401. Retrying after token refresh."
                    );
                    $attempt++;
                    next;
                }
                else {
                    $c->app->log->error(
"Dropbox upload failed: Status $status_code - $error_message (Connection type: $connection->{type})"
                    );
                    _update_connection_status( $dbs, $connection->{id},
                        'error', $error_message );
                    last;
                }
            }
        }

        # Fallback to local storage if cloud upload failed
        unless ($upload_success) {
            $c->app->log->warn( "Dropbox upload failed for file "
                  . $file_info->{original_filename}
                  . ", falling back to local processor." );

            my $local_result = process_local(
                $dbs, $c,
                {
                    files_info => [$file_info],
                    client     => $data->{client},
                    transdate  => $data->{transdate},
                    id         => $data->{id}
                },
                $module, undef
            );

            push @processed_files, $local_result->{details}{files}[0]
              if $local_result->{success};
        }

        # Record the file in the database
        eval {
            insert_file_record(
                $dbs,
                {
                    module    => $module,
                    name      => $file_info->{unique_filename},
                    extension =>
                      extract_file_extension( $file_info->{original_filename} ),
                    location     => $storage_location,
                    path         => $file_info->{remote_path},
                    link         => $processed_files[-1]{link},
                    reference_id => $data->{id},
                }
            );
        };

        if ($@) {
            $c->app->log->error(
"Failed to insert file record into database after Dropbox upload for "
                  . $file_info->{unique_filename}
                  . ": $@" );
        }
    }

    return {
        success => 1,
        details => {
            count    => scalar(@processed_files),
            files    => \@processed_files,
            location => $storage_location,
        }
    };
}

sub process_google_drive {
    my ( $dbs, $c, $data, $module, $connection ) = @_;
    my $client_id        = $ENV{GOOGLE_CLIENT_ID}     || '';
    my $client_secret    = $ENV{GOOGLE_CLIENT_SECRET} || '';
    my $storage_location = 'google_drive';
    my $ua               = Mojo::UserAgent->new;
    my $upload_url =
      'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart';

    my $access_token = $connection->{access_token};

    # First, ensure the directory structure exists and get the parent folder ID
    my $client = $data->{client} || 'default';
    my ( $year, $month ) = _get_date_parts( $data->{transdate} );
    my $folder_path = "/$client/$module/$year/$month";

    # Check and refresh token and then ensure folders exist
    $access_token = _check_and_refresh_token( $dbs, $c, $connection, $client_id,
        $client_secret, 'google_drive' );
    my $parent_id =
      _ensure_google_drive_folders( $ua, $access_token,
        $connection->{refresh_token},
        $client_id, $client_secret, $dbs, $c, $connection, $folder_path );
    unless ($parent_id) {
        $c->app->log->error(
"Failed to create/find Google Drive folder structure for: $folder_path"
        );
        return { error => "Failed to create Google Drive folder structure" };
    }

    my @processed_files;

    foreach my $file_info ( @{ $data->{files_info} } ) {
        my $file           = $file_info->{file};
        my $file_contents  = $file->slurp;
        my $filename       = $file_info->{unique_filename};
        my $remote_path    = $file_info->{remote_path};
        my $mime_type      = _get_mime_type($filename);
        my $attempt        = 1;
        my $upload_success = 0;

        while ( $attempt <= MAX_UPLOAD_ATTEMPTS && !$upload_success ) {

# Re-check token before every attempt and update parent folder if token refresh occurred.
            my $new_access_token =
              _check_and_refresh_token( $dbs, $c, $connection, $client_id,
                $client_secret, 'google_drive' );
            if ( $new_access_token ne $access_token ) {
                $access_token = $new_access_token;
                $parent_id =
                  _ensure_google_drive_folders( $ua, $access_token,
                    $connection->{refresh_token},
                    $client_id, $client_secret, $dbs, $c, $connection,
                    $folder_path );
                unless ($parent_id) {
                    $c->app->log->error(
                        "Failed to update folder structure after token refresh."
                    );
                    last;
                }
            }

            # Create metadata for the file
            my $metadata = {
                name    => $filename,
                parents => [$parent_id]
            };

            # Build multipart request body
            my $boundary = "-------" . time() . "boundary";
            my $body     = '';

            # Add metadata part
            $body .= "--$boundary\r\n";
            $body .= "Content-Type: application/json; charset=UTF-8\r\n\r\n";
            $body .= encode_json($metadata) . "\r\n";

            # Add file content part
            $body .= "--$boundary\r\n";
            $body .= "Content-Type: $mime_type\r\n\r\n";
            $body .= $file_contents . "\r\n";
            $body .= "--$boundary--";

            # Upload the file
            my $tx = $ua->post(
                $upload_url => {
                    'Authorization' => "Bearer $access_token",
                    'Content-Type'  => "multipart/related; boundary=$boundary"
                } => $body
            );

            my $res = $tx->result;
            if ( $res->is_success ) {
                $upload_success = 1;
                my $file_data = eval { decode_json( $res->body ) };

                # Make the file publicly accessible and get a link
                my $file_id = $file_data->{id};
                my $link = _create_google_drive_public_link( $ua, $access_token,
                    $file_id );

                push @processed_files,
                  {
                    original_name => $file_info->{original_filename},
                    saved_name    => $filename,
                    path          => $remote_path,
                    link          => $link,
                    file_id       => $file_id,
                  };

                _update_connection_status( $dbs, $connection->{id}, 'active' );
                last;
            }
            else {
                my $status_code   = $res->code;
                my $error_message = $res->message || "Unknown Error";

                if ( $status_code == 401 ) {
                    $c->app->log->error(
"Google Drive upload returned 401. Retrying after token refresh."
                    );
                    $attempt++;
                    next;
                }
                else {
                    $c->app->log->error(
"Google Drive upload failed: Status $status_code - $error_message (Connection type: $connection->{type})"
                    );
                    _update_connection_status( $dbs, $connection->{id},
                        'error', $error_message );
                    last;
                }
            }
            $attempt++;
        }

        # Fallback to local storage if Google Drive upload failed
        unless ($upload_success) {
            $c->app->log->warn( "Google Drive upload failed for file "
                  . $file_info->{original_filename}
                  . ", falling back to local processor." );

            my $local_result = process_local(
                $dbs, $c,
                {
                    files_info => [$file_info],
                    client     => $data->{client},
                    transdate  => $data->{transdate},
                    id         => $data->{id}
                },
                $module, undef
            );

            push @processed_files, $local_result->{details}{files}[0]
              if $local_result->{success};
        }

        # Record the file in the database
        eval {
            insert_file_record(
                $dbs,
                {
                    module    => $module,
                    name      => $file_info->{unique_filename},
                    extension =>
                      extract_file_extension( $file_info->{original_filename} ),
                    location     => $storage_location,
                    path         => $file_info->{remote_path},
                    link         => $processed_files[-1]{link},
                    reference_id => $data->{id},
                }
            );
        };

        if ($@) {
            $c->app->log->error(
"Failed to insert file record into database after Google Drive upload for "
                  . $file_info->{unique_filename}
                  . ": $@" );
        }
    }

    return {
        success => 1,
        details => {
            count    => scalar(@processed_files),
            files    => \@processed_files,
            location => $storage_location,
        }
    };
}

sub process_local {
    my ( $dbs, $c, $data, $module, $connection ) = @_;
    my $storage_location = 'local';
    my $client           = $data->{client} || 'default';
    my $local_dir;

    if ( @{ $data->{files_info} } ) {
        ( $local_dir = $data->{files_info}[0]{local_path} ) =~ s/\/[^\/]+$//;
    }
    else {
        my ( $year, $month ) = _get_date_parts( $data->{transdate} );
        $local_dir = "files/$client/$module/$year/$month";
    }

    eval { make_path($local_dir); };
    if ($@) {
        $c->app->log->error(
            "Could not create target directory '$local_dir': $@");
        return { error => "Failed to create storage directory." };
    }

    my @processed_files;
    foreach my $file_info ( @{ $data->{files_info} } ) {
        my $file = $file_info->{file};
        next unless ref($file) && $file->can('filename') && $file->can('size');

        my $target_path = $file_info->{local_path};
        eval {
            $file->move_to($target_path);
            $c->app->log->info( "Locally saved file: "
                  . $file_info->{original_filename} . " as "
                  . $file_info->{unique_filename}
                  . " (Size: "
                  . $file->size
                  . ")" );

            insert_file_record(
                $dbs,
                {
                    module    => $module,
                    name      => $file_info->{unique_filename},
                    extension =>
                      extract_file_extension( $file_info->{original_filename} ),
                    location     => $storage_location,
                    path         => $target_path,
                    link         => undef,
                    reference_id => $data->{id},
                }
            );

            push @processed_files,
              {
                original_name => $file_info->{original_filename},
                saved_name    => $file_info->{unique_filename},
                path          => $target_path,
                link          => undef,
              };
        };

        if ($@) {
            $c->app->log->error( "Error processing local file upload for '"
                  . $file_info->{original_filename}
                  . "': $@" );
        }
    }

    return { error => "Failed to process any files for local storage." }
      unless @processed_files;

    return {
        success => 1,
        details => {
            count    => scalar(@processed_files),
            files    => \@processed_files,
            location => $storage_location,
        }
    };
}

sub get_files {
    my ( $self, $dbs, $c, $data ) = @_;

    # Get all the file rows for the given reference id
    my @files =
      $dbs->query( "SELECT * FROM files WHERE reference_id = ?", $data->{id} )
      ->hashes;

    # Build result array
    my @result;
    foreach my $file (@files) {
        my $link;
        if ( $file->{location} eq 'local' ) {
            $link =
"$data->{api_url}client/$data->{client}/files/$file->{module}/$file->{id}";
        }
        else {
            $link = $file->{link};
        }

        push @result,
          { name => $file->{name}, link => $link, id => $file->{id} };
    }
    return \@result;
}

sub delete_files {
    my ( $self, $dbs, $c, $data ) = @_;

    my $reference_id = $data->{id};
    unless ($reference_id) {
        $c->app->log->error("delete_files: Missing reference id.");
        return { error => "Missing reference id." };
    }

    # Retrieve all files associated with the reference_id
    my @files =
      $dbs->query( "SELECT * FROM files WHERE reference_id = ?", $reference_id )
      ->hashes;
    unless (@files) {
        $c->app->log->info(
            "delete_files: No file records found for reference id $reference_id"
        );
        return {
            success => 0,
            error   => "No files found for reference id: $reference_id"
        };
    }

    my @deleted_files;
    my $ua = Mojo::UserAgent->new;

  FILE: foreach my $file (@files) {
        my $location = $file->{location} || '';
        my $path     = $file->{path}     || '';

        if ( $location eq 'local' ) {
            if ( -e $path ) {
                unless ( unlink $path ) {
                    $c->app->log->error(
                        "Failed to delete local file $path: $!");
                    next FILE;
                }
                $c->app->log->info("Deleted local file: $path");
            }
            else {
                $c->app->log->warn(
                    "Local file $path does not exist, skipping unlink.");
            }
            push @deleted_files,
              { name => $file->{name}, path => $path, location => 'local' };
        }
        elsif ( $location eq 'dropbox' ) {
            my $delete_url = 'https://api.dropboxapi.com/2/files/delete_v2';
            my $connection = $dbs->query(
"SELECT * FROM connections WHERE status = 'active' AND type = 'dropbox' LIMIT 1"
            )->hash;
            unless ( $connection && $connection->{access_token} ) {
                $c->app->log->error(
                    "No active Dropbox connection found for deletion.");
                next FILE;
            }

            # Check token before deletion
            my $access_token = _check_and_refresh_token(
                $dbs, $c, $connection,
                $ENV{DROPBOX_KEY} || '',
                $ENV{DROPBOX_SECRET} || '', 'dropbox'
            );
            my $headers = {
                'Authorization' => "Bearer $access_token",
                'Content-Type'  => 'application/json',
            };
            my $post_data = { path => $path };
            my $tx =
              $ua->post( $delete_url => $headers => encode_json($post_data) );
            my $res = $tx->result;
            if ( $res->is_success ) {
                $c->app->log->info("Deleted Dropbox file: $path");
                push @deleted_files,
                  {
                    name     => $file->{name},
                    path     => $path,
                    location => 'dropbox'
                  };
            }
            else {
                $c->app->log->error(
                    "Dropbox deletion failed for $path: " . $res->message );
                next FILE;
            }
        }
        elsif ( $location eq 'google_drive' ) {
            my $file_id;
            if ( $file->{link} && $file->{link} =~ /\/d\/([^\/]+)\// ) {
                $file_id = $1;
            }
            elsif ( $path && $path =~ /\/([^\/]+)$/ ) {
                $file_id = $1;
            }
            unless ($file_id) {
                $c->app->log->error(
"Could not determine Google Drive file ID for: $file->{name}"
                );
                next FILE;
            }
            my $connection = $dbs->query(
"SELECT * FROM connections WHERE status = 'active' AND type = 'google_drive' LIMIT 1"
            )->hash;
            unless ( $connection && $connection->{access_token} ) {
                $c->app->log->error(
                    "No active Google Drive connection found for deletion.");
                next FILE;
            }
            my $access_token = _check_and_refresh_token(
                $dbs, $c, $connection,
                $ENV{GOOGLE_CLIENT_ID}     || '',
                $ENV{GOOGLE_CLIENT_SECRET} || '',
                'google_drive'
            );
            my $delete_url =
              "https://www.googleapis.com/drive/v3/files/$file_id";
            my $tx = $ua->delete(
                $delete_url => { 'Authorization' => "Bearer $access_token" } );
            my $res = $tx->result;
            if ( $res->is_success ) {
                $c->app->log->info("Deleted Google Drive file: $file_id");
                push @deleted_files,
                  {
                    name     => $file->{name},
                    path     => $path,
                    location => 'google_drive'
                  };
            }
            else {
                $c->app->log->error(
                    "Google Drive deletion failed for $file_id: "
                      . $res->message );
                next FILE;
            }
        }
        else {
            $c->app->log->warn(
                "Unknown storage location '$location' for file: $file->{name}");
            next FILE;
        }

     # Remove the file record from the database after deleting the physical file
        my $sth = $dbs->query( "DELETE FROM files WHERE id = ?", $file->{id} );
        unless ( $sth && $sth->rows > 0 ) {
            $c->app->log->error(
"Failed to delete file record from database for file: $file->{name}"
            );
        }
    }

    return {
        success => 1,
        details => {
            deleted_count => scalar @deleted_files,
            deleted_files => \@deleted_files,
        }
    };
}

sub delete_file {
    my ( $self, $dbs, $c, $data ) = @_;

    my $filename = $data->{filename};
    unless ($filename) {
        $c->app->log->error("delete_file: Missing filename parameter.");
        return { error => "Missing filename parameter." };
    }

    my $file =
      $dbs->query( "SELECT * FROM files WHERE id = ?", $filename )->hash;
    unless ($file) {
        $c->app->log->info(
            "delete_file: No file record found for filename: $filename");
        return {
            success => 0,
            error   => "No file found with filename: $filename"
        };
    }

    my $location = $file->{location} || '';
    my $path     = $file->{path}     || '';
    my $deleted  = 0;
    my $ua       = Mojo::UserAgent->new;

    if ( $location eq 'local' ) {
        if ( -e $path ) {
            unless ( unlink $path ) {
                $c->app->log->error("Failed to delete local file $path: $!");
                return {
                    success => 0,
                    error   => "Could not delete local file $path: $!"
                };
            }
            $c->app->log->info("Deleted local file: $path");
            $deleted = 1;
        }
        else {
            $c->app->log->warn(
                "Local file $path does not exist, skipping unlink.");
            $deleted = 1;
        }
    }
    elsif ( $location eq 'dropbox' ) {
        my $delete_url = 'https://api.dropboxapi.com/2/files/delete_v2';
        my $connection = $dbs->query(
"SELECT * FROM connections WHERE status = 'active' AND type = 'dropbox' LIMIT 1"
        )->hash;
        unless ( $connection && $connection->{access_token} ) {
            $c->app->log->error(
                "No active Dropbox connection found for deletion.");
            return {
                success => 0,
                error   => "No active Dropbox connection for deletion."
            };
        }
        my $access_token = _check_and_refresh_token(
            $dbs, $c, $connection,
            $ENV{DROPBOX_KEY} || '',
            $ENV{DROPBOX_SECRET} || '', 'dropbox'
        );
        my $headers = {
            'Authorization' => "Bearer $access_token",
            'Content-Type'  => 'application/json',
        };
        my $post_data = { path => $path };
        my $tx =
          $ua->post( $delete_url => $headers => encode_json($post_data) );
        my $res = $tx->result;
        if ( $res->is_success ) {
            $c->app->log->info("Deleted Dropbox file: $path");
            $deleted = 1;
        }
        else {
            $c->app->log->error(
                "Dropbox deletion failed for $path: " . $res->message );
            return {
                success => 0,
                error   => "Dropbox deletion failed: " . $res->message
            };
        }
    }
    elsif ( $location eq 'google_drive' ) {
        my $file_id;
        if ( $file->{link} && $file->{link} =~ /\/d\/([^\/]+)\// ) {
            $file_id = $1;
        }
        elsif ( $path && $path =~ /\/([^\/]+)$/ ) {
            $file_id = $1;
        }
        unless ($file_id) {
            $c->app->log->error(
                "Could not determine Google Drive file ID for: $file->{name}");
            return {
                success => 0,
                error   => "Could not determine Google Drive file ID"
            };
        }
        my $connection = $dbs->query(
"SELECT * FROM connections WHERE status = 'active' AND type = 'google_drive' LIMIT 1"
        )->hash;
        unless ( $connection && $connection->{access_token} ) {
            $c->app->log->error(
                "No active Google Drive connection found for deletion.");
            return {
                success => 0,
                error   => "No active Google Drive connection for deletion."
            };
        }
        my $access_token = _check_and_refresh_token(
            $dbs, $c, $connection,
            $ENV{GOOGLE_CLIENT_ID}     || '',
            $ENV{GOOGLE_CLIENT_SECRET} || '',
            'google_drive'
        );
        my $delete_url = "https://www.googleapis.com/drive/v3/files/$file_id";
        my $tx         = $ua->delete(
            $delete_url => { 'Authorization' => "Bearer $access_token" } );
        my $res = $tx->result;
        if ( $res->is_success ) {
            $c->app->log->info("Deleted Google Drive file: $file_id");
            $deleted = 1;
        }
        else {
            $c->app->log->error(
                "Google Drive deletion failed for $file_id: " . $res->message );
            return {
                success => 0,
                error   => "Google Drive deletion failed: " . $res->message
            };
        }
    }
    else {
        $c->app->log->warn(
            "Unknown storage location '$location' for file: $filename");
        return {
            success => 0,
            error   => "Unknown storage location for file: $filename"
        };
    }

    if ($deleted) {
        my $sth = $dbs->query( "DELETE FROM files WHERE id = ?", $file->{id} );
        unless ( $sth && $sth->rows > 0 ) {
            $c->app->log->error(
"Failed to delete file record from database for filename: $filename"
            );
            return {
                success => 0,
                error   => "Failed to delete file record from database."
            };
        }
        return {
            success => 1,
            message => "File deleted successfully.",
            details => {
                name     => $file->{name},
                location => $location,
            }
        };
    }
    return { success => 0, error => "File deletion was not successful." };
}

#----------------------------------------------------------------
# HELPER FUNCTIONS
#----------------------------------------------------------------

# Generic refresh token function for both platforms.
sub _refresh_token {
    my ( $dbs, $c, $connection, $client_id, $client_secret, $platform ) = @_;
    my %urls = (
        google_drive => 'https://oauth2.googleapis.com/token',
        dropbox      => 'https://api.dropboxapi.com/oauth2/token',
    );
    my $token_url = $urls{$platform} or die "Unsupported platform: $platform";
    my $refresh_token = $connection->{refresh_token};
    unless ($refresh_token) {
        $c->app->log->error("Missing refresh token for $platform connection");
        _update_connection_status( $dbs, $connection->{id}, 'error',
            "Missing refresh token" );
        return 0;
    }

    my $ua         = Mojo::UserAgent->new;
    my $refresh_tx = $ua->post(
        $token_url => form => {
            grant_type    => 'refresh_token',
            refresh_token => $refresh_token,
            client_id     => $client_id,
            client_secret => $client_secret,
        }
    );
    my $refresh_res = $refresh_tx->result;
    unless ( $refresh_res->is_success ) {
        my $error_msg = $refresh_res->message || "Unknown Refresh Error";
        _update_connection_status( $dbs, $connection->{id}, 'error',
            "Token refresh failed: $error_msg" );
        return 0;
    }
    my $token_data = eval { decode_json( $refresh_res->body ) };
    if ($@) {
        _update_connection_status( $dbs, $connection->{id}, 'error',
            "Token refresh failed: Invalid JSON response" );
        return 0;
    }
    my $new_access_token = $token_data->{access_token};
    my $expires_in       = $token_data->{expires_in};
    unless ( $new_access_token && defined $expires_in ) {
        _update_connection_status( $dbs, $connection->{id}, 'error',
            "Token refresh failed: Missing token/expiry" );
        return 0;
    }
    my $new_expiry = time() + $expires_in;
    my $update_ok =
      _update_connection_status( $dbs, $connection->{id}, 'active', undef,
        $new_access_token, $new_expiry );
    unless ($update_ok) {
        $c->app->log->error("Failed to store refreshed token in database");
        return 0;
    }
    return $new_access_token;
}

# Checks if the token is near expiry (less than 5 minutes left) and refreshes if needed.
sub _check_and_refresh_token {
    my ( $dbs, $c, $connection, $client_id, $client_secret, $platform ) = @_;
    if ( $connection->{token_expires} ) {
        my $expiry = $connection->{token_expires};

        # If token_expires is not numeric, try parsing it.
        if ( $expiry !~ /^\d+$/ ) {
            eval {
                my $t = Time::Piece->strptime( $expiry, '%Y-%m-%d %H:%M:%S%z' );
                $expiry = $t->epoch;
            } or do {
                $c->app->log->error("Failed to parse token_expires");
                $expiry = 0;
            };
        }
        if ( $expiry - time() < 300 ) {    # less than 5 minutes remaining
            my $new_access_token =
              _refresh_token( $dbs, $c, $connection, $client_id,
                $client_secret, $platform );
            return $new_access_token if $new_access_token;
        }
    }
    else {
        my $new_access_token =
          _refresh_token( $dbs, $c, $connection, $client_id, $client_secret,
            $platform );
        return $new_access_token if $new_access_token;
    }
    return $connection->{access_token};
}

sub _ensure_google_drive_folders {
    my (
        $ua,        $access_token,  $refresh_token,
        $client_id, $client_secret, $dbs,
        $c,         $connection,    $folder_path
    ) = @_;
    my $folder_url = 'https://www.googleapis.com/drive/v3/files';

    my @folders = grep { $_ } split( '/', $folder_path );
    return 'root' unless @folders;

    my $parent_id = 'root';
    foreach my $folder_name (@folders) {
        my $search_query =
"name='$folder_name' and mimeType='application/vnd.google-apps.folder' and '$parent_id' in parents and trashed=false";
        my $encoded_query = url_escape($search_query);
        my $tx            = $ua->get( "$folder_url?q=$encoded_query" =>
              { 'Authorization' => "Bearer $access_token" } );
        my $res = $tx->result;

        if ( !$res->is_success ) {
            my $status_code   = $res->code;
            my $error_message = $res->message || "Unknown Error";
            if ( $status_code == 401 && $refresh_token ) {
                my $new_access_token =
                  _refresh_token( $dbs, $c, $connection, $client_id,
                    $client_secret, 'google_drive' );
                if ( !$new_access_token ) {
                    $c->app->log->error(
"Google Drive token refresh failed during folder creation"
                    );
                    return undef;
                }
                $access_token = $new_access_token;
                $tx           = $ua->get( "$folder_url?q=$encoded_query" =>
                      { 'Authorization' => "Bearer $access_token" } );
                $res = $tx->result;
                if ( !$res->is_success ) {
                    $c->app->log->error(
"Google Drive folder query failed after token refresh: $error_message"
                    );
                    return undef;
                }
            }
            else {
                $c->app->log->error(
                    "Google Drive folder query failed: $error_message");
                return undef;
            }
        }

        my $folder_data = eval { decode_json( $res->body ) };
        if ($@) {
            $c->app->log->error(
                "Failed to parse Google Drive API response: $@");
            return undef;
        }

        if ( $folder_data->{files} && @{ $folder_data->{files} } ) {
            $parent_id = $folder_data->{files}[0]{id};
        }
        else {
            my $create_tx = $ua->post(
                $folder_url => {
                    'Authorization' => "Bearer $access_token",
                    'Content-Type'  => 'application/json'
                } => json => {
                    name     => $folder_name,
                    mimeType => 'application/vnd.google-apps.folder',
                    parents  => [$parent_id]
                }
            );

            my $create_res = $create_tx->result;
            if ( !$create_res->is_success ) {
                $c->app->log->error(
                    "Failed to create Google Drive folder '$folder_name': "
                      . $create_res->message );
                return undef;
            }
            my $new_folder = eval { decode_json( $create_res->body ) };
            if ( $@ || !$new_folder->{id} ) {
                $c->app->log->error(
                    "Failed to parse folder creation response: $@");
                return undef;
            }
            $parent_id = $new_folder->{id};
        }
    }
    return $parent_id;
}

sub _create_google_drive_public_link {
    my ( $ua, $access_token, $file_id ) = @_;
    my $permission_url =
      "https://www.googleapis.com/drive/v3/files/$file_id/permissions";
    my $tx = $ua->post(
        $permission_url => {
            'Authorization' => "Bearer $access_token",
            'Content-Type'  => 'application/json'
        } => json => {
            role => 'reader',
            type => 'anyone'
        }
    );
    my $file_url =
      "https://www.googleapis.com/drive/v3/files/$file_id?fields=webViewLink";
    my $link_tx =
      $ua->get( $file_url => { 'Authorization' => "Bearer $access_token" } );
    my $link_res = $link_tx->result;
    if ( $link_res->is_success ) {
        my $link_data = eval { decode_json( $link_res->body ) };
        if ( $link_data && $link_data->{webViewLink} ) {
            return $link_data->{webViewLink};
        }
    }
    return "https://drive.google.com/file/d/$file_id/view";
}

sub _get_mime_type {
    my ($filename) = @_;
    my %mime_types = (
        '.pdf'  => 'application/pdf',
        '.jpg'  => 'image/jpeg',
        '.jpeg' => 'image/jpeg',
        '.png'  => 'image/png',
        '.txt'  => 'text/plain',
        '.doc'  => 'application/msword',
        '.docx' =>
'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.xls'  => 'application/vnd.ms-excel',
        '.xlsx' =>
          'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        '.csv' => 'text/csv',
    );

    my $ext = lc( extract_file_extension($filename) );
    return $mime_types{$ext} || 'application/octet-stream';
}

sub _get_date_parts {
    my ($transdate) = @_;
    if ( $transdate && $transdate =~ /^(\d{4})-(\d{2})-\d{2}$/ ) {
        return ( $1, $2 );
    }
    else {
        my @lt    = localtime;
        my $year  = $lt[5] + 1900;
        my $month = sprintf( "%02d", $lt[4] + 1 );
        return ( $year, $month );
    }
}

sub _generate_unique_filename {
    my ($original_filename) = @_;
    my $unique_filename = time() . '_' . $original_filename;
    $unique_filename = lc($unique_filename);
    $unique_filename =~ s/[^a-z0-9_.-]/_/g;
    return $unique_filename;
}

sub extract_file_extension {
    my ($filename) = @_;
    if ( defined $filename && $filename =~ /(\.[^.]+)$/ ) {
        return lc($1);
    }
    return '';
}

sub insert_file_record {
    my ( $dbs, $file_data ) = @_;
    for my $key (qw(module name extension location path reference_id)) {
        unless ( defined $file_data->{$key} ) {
            warn "Missing required key '$key' for insert_file_record";
            return;
        }
    }
    my $sql =
"INSERT INTO files (module, name, extension, location, path, link, reference_id) VALUES (?, ?, ?, ?, ?, ?, ?)";
    my @params = (
        $file_data->{module},    $file_data->{name},
        $file_data->{extension}, $file_data->{location},
        $file_data->{path},      $file_data->{link},
        $file_data->{reference_id}
    );
    my $sth = $dbs->query( $sql, @params );
    unless ( $sth && $sth->rows > 0 ) {
        warn "Database insert failed for file: " . $file_data->{name};
    }
    return $sth;
}

# Updated to format epoch expiry into a timestamp string
sub _update_connection_status {
    my ( $dbs, $connection_id, $status, $error_message, $new_token, $expiry ) =
      @_;
    my $sql =
      "UPDATE connections SET status = ?, error = ?, updated_at = now()";
    my @params = ( $status, $error_message );

    if ( defined $new_token && defined $expiry ) {

        # Convert the epoch to a properly formatted timestamp
        my $formatted_expiry =
          strftime( '%Y-%m-%d %H:%M:%S', localtime($expiry) );
        $sql .= ", access_token = ?, token_expires = ?";
        push @params, $new_token, $formatted_expiry;
    }

    $sql .= " WHERE id = ?";
    push @params, $connection_id;

    my $sth = $dbs->query( $sql, @params );
    unless ( $sth && $sth->rows > 0 ) {
        warn
"Failed to update connection status in database for connection ID $connection_id!";
        return 0;
    }
    return 1;
}

1;
