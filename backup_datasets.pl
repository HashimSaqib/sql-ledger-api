#!/usr/bin/perl

use strict;
use warnings;
use DBI;
use File::Path qw(make_path);
use File::Find;
use POSIX qw(strftime);
use Dotenv;

# Load environment variables from .env file
Dotenv->load;

# Database connection - from .env file
my $postgres_user = $ENV{POSTGRES_USER}
  || die "POSTGRES_USER not found in .env file";
my $postgres_password = $ENV{POSTGRES_PASSWORD}
  || die "POSTGRES_PASSWORD not found in .env file";
my $postgres_host = 'localhost';
my $postgres_port = '5432';
my $central_db    = 'centraldb';

# Backup configuration
my $backup_dir       = '/var/backups/neoledger';
my $retention_days   = 14;
my $compress_backups = 0;
my $verbose          = 0;
my $log_file         = '/var/log/neoledger_backups.log';

# Global variable to store the current backup session directory
my $current_backup_session_dir;

# Start main execution
main();

sub main {
    my $start_time = time();
    my $timestamp  = strftime( "%Y-%m-%d %H:%M:%S", localtime($start_time) );

    log_message("=== Starting dataset backup process at $timestamp ===");

    eval {
        # Ensure backup directory exists
        setup_backup_directory();

        # Create timestamped session directory for this backup run
        create_backup_session_directory($start_time);

        # Get list of datasets from centraldb
        my $datasets = get_datasets();

        # Add centraldb to the list
        push @$datasets, 'centraldb';

        log_message( "Found "
              . ( scalar(@$datasets) - 1 )
              . " datasets plus centraldb to backup" );

        # Backup each dataset (including centraldb)
        my $success_count = 0;
        my $error_count   = 0;
        my @errors;

        for my $dataset (@$datasets) {
            eval {
                backup_dataset($dataset);
                $success_count++;
                log_message("✓ Successfully backed up: $dataset");
            } or do {
                my $error = $@ || 'Unknown error';
                $error_count++;
                push @errors, "$dataset: $error";
                log_message("✗ Failed to backup $dataset: $error");
            };
        }

        # Cleanup old backups
        cleanup_old_backups();

        # Summary
        my $duration = time() - $start_time;
        my $summary =
          sprintf( "Backup completed in %d seconds. Success: %d, Errors: %d",
            $duration, $success_count, $error_count );

        log_message("=== $summary ===");
        log_message("Backup session directory: $current_backup_session_dir");

        if ( $error_count > 0 ) {
            exit 1;    # Signal failure to cron
        }

    } or do {
        my $error = $@ || 'Unknown error';
        log_message("FATAL ERROR: $error");
        exit 2;        # Fatal error
    };
}

sub setup_backup_directory {

    unless ( -d $backup_dir ) {
        log_message("Creating backup directory: $backup_dir");

        # Create the directory and all parent directories if they don't exist
        eval { make_path( $backup_dir, { mode => 0755 } ); };
        if ($@) {
            die "Cannot create backup directory '$backup_dir': $@";
        }
    }

    # Check if directory is writable
    unless ( -w $backup_dir ) {
        die "Backup directory is not writable: $backup_dir";
    }

    log_message( "Backup directory ready: $backup_dir", 1 );
}

sub create_backup_session_directory {
    my ($start_time) = @_;

    # Create timestamped directory name
    my $session_timestamp = strftime( "%Y%m%d_%H%M%S", localtime($start_time) );
    $current_backup_session_dir = "$backup_dir/backup_$session_timestamp";

    log_message(
        "Creating backup session directory: $current_backup_session_dir");

    # Create the session directory
    eval { make_path( $current_backup_session_dir, { mode => 0755 } ); };
    if ($@) {
        die
"Cannot create backup session directory '$current_backup_session_dir': $@";
    }

    # Check if directory is writable
    unless ( -w $current_backup_session_dir ) {
        die
"Backup session directory is not writable: $current_backup_session_dir";
    }

    log_message( "Backup session directory ready: $current_backup_session_dir",
        1 );
}

sub get_datasets {

    # Connect to centraldb to get list of tenant datasets
    my $dsn = sprintf( "dbi:Pg:dbname=%s;host=%s;port=%s",
        $central_db, $postgres_host, $postgres_port );

    my $dbh =
      DBI->connect( $dsn, $postgres_user, $postgres_password,
        { AutoCommit => 1, RaiseError => 1 } )
      or die "Failed to connect to central database: $DBI::errstr";

    # Get all dataset names from the dataset table
    my $sth = $dbh->prepare("SELECT db_name FROM dataset ORDER BY db_name");
    $sth->execute();

    my @datasets;
    while ( my ($db_name) = $sth->fetchrow_array() ) {
        push @datasets, $db_name;
    }

    $sth->finish();
    $dbh->disconnect();

    return \@datasets;
}

sub backup_dataset {
    my ($dataset) = @_;

    # Generate timestamped filename
    my $timestamp       = strftime( "%Y%m%d_%H%M%S", localtime() );
    my $backup_filename = "${dataset}_${timestamp}.sql";

    # Add .gz extension if compression is enabled
    if ($compress_backups) {
        $backup_filename .= ".gz";
    }

    my $backup_path = "$current_backup_session_dir/$backup_filename";

    log_message( "Backing up '$dataset' to '$backup_path'", 1 );

    # Build pg_dump command with standard options
    my @cmd = (
        'pg_dump',                  '--host=' . $postgres_host,
        '--port=' . $postgres_port, '--username=' . $postgres_user,
        '--no-password',            '--verbose',
        '--clean',                  '--if-exists',
        '--create',                 '--format=plain',
        $dataset
    );

    # Set PostgreSQL password via environment variable
    local $ENV{PGPASSWORD} = $postgres_password;

    # Execute backup with or without compression
    if ($compress_backups) {
        my $cmd_str = join( ' ', @cmd ) . " | gzip > '$backup_path'";
        system($cmd_str) == 0 or die "pg_dump failed: $?";
    }
    else {
        push @cmd, "--file=$backup_path";
        system(@cmd) == 0 or die "pg_dump failed: $?";
    }

    # Verify backup file was created and has content
    unless ( -f $backup_path && -s $backup_path ) {
        die "Backup file was not created or is empty: $backup_path";
    }

    # Log backup completion with file size
    my $size    = -s $backup_path;
    my $size_mb = sprintf( "%.2f", $size / 1024 / 1024 );
    log_message( "Backup completed: $backup_filename (${size_mb} MB)", 1 );
}

sub cleanup_old_backups {

    # Remove backup session directories older than retention period
    my $cutoff_time = time() - ( $retention_days * 24 * 60 * 60 );
    my @old_dirs;

    log_message("Cleaning up backup sessions older than $retention_days days");

    # Find all backup session directories older than cutoff time
    find(
        sub {
            return unless -d $_;
            return
              unless
              /^backup_\d{8}_\d{6}$/;   # Match backup session directory pattern

            my $mtime = ( stat($_) )[9];
            if ( $mtime < $cutoff_time ) {
                push @old_dirs, $File::Find::name;
            }
        },
        $backup_dir
    );

    # Remove old backup session directories
    for my $dir (@old_dirs) {
        log_message( "Removing old backup session: $dir", 1 );

        # Remove all files in the directory first
        find(
            sub {
                return unless -f $_;
                unlink $_
                  or log_message("Warning: Could not remove file $_: $!");
            },
            $dir
        );

        # Remove the directory
        rmdir $dir
          or log_message("Warning: Could not remove directory $dir: $!");
    }

    if (@old_dirs) {
        log_message( "Removed "
              . scalar(@old_dirs)
              . " old backup session directories" );
    }
    else {
        log_message("No old backup session directories to remove");
    }
}

sub log_message {
    my ( $message, $verbose_only ) = @_;

    return if $verbose_only && !$verbose;

    my $timestamp = strftime( "%Y-%m-%d %H:%M:%S", localtime() );
    my $log_line  = "[$timestamp] $message\n";

    # Print to STDOUT (for cron capture)
    print $log_line;

    # Also log to file if specified
    if ($log_file) {
        if ( open( my $fh, '>>', $log_file ) ) {
            print $fh $log_line;
            close $fh;
        }
    }
}
