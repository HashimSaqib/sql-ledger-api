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

# Configuration constants
use constant {
    SECONDS_PER_DAY => 24 * 60 * 60,
    MB_IN_BYTES     => 1024 * 1024,
    DEFAULT_MODE    => 0755,
};

# Database connection - from .env file
my $postgres_user = $ENV{POSTGRES_USER}
  || die "POSTGRES_USER not found in .env file";
my $postgres_password = $ENV{POSTGRES_PASSWORD}
  || die "POSTGRES_PASSWORD not found in .env file";
my $postgres_host = 'localhost';
my $postgres_port = '5432';
my $central_db    = 'centraldb';

# Backup configuration - from environment variables with fallbacks
my $backup_dir       = $ENV{BACKUP_DIR}            || '/var/backups/neoledger';
my $retention_days   = $ENV{BACKUP_RETENTION_DAYS} || 14;
my $compress_backups = $ENV{BACKUP_COMPRESS}       || 0;
my $verbose          = $ENV{BACKUP_VERBOSE}        || 0;
my $log_file = $ENV{BACKUP_LOG_FILE} || '/var/log/neoledger_backups.log';

# Global variable to store the current backup session directory
my $current_backup_session_dir;

# Start main execution
main();

sub main {
    my $start_time = time();
    my $timestamp  = strftime( "%Y-%m-%d %H:%M:%S", localtime($start_time) );

    log_message("=== Starting dataset backup process at $timestamp ===");

    my $result = eval {

        # Setup and preparation
        setup_backup_directory();
        create_backup_session_directory($start_time);

        # Get datasets and perform backups
        my $datasets = get_datasets();
        push @$datasets, 'centraldb';

        log_message( "Found "
              . ( scalar(@$datasets) - 1 )
              . " datasets plus centraldb to backup" );

        my $backup_results = backup_all_datasets($datasets);

        # Cleanup old backups
        safe_cleanup_old_backups();

        # Generate summary
        my $duration = time() - $start_time;
        my $summary  = sprintf(
            "Backup completed in %d seconds. Success: %d, Errors: %d",
            $duration,
            $backup_results->{success_count},
            $backup_results->{error_count}
        );

        log_message("=== $summary ===");
        log_message("Backup session directory: $current_backup_session_dir");

        return $backup_results;
    } or do {
        my $error = $@ || 'Unknown error';
        log_message("FATAL ERROR: $error");
        return undef;
    };

    # Handle exit outside of eval block
    handle_exit($result);
}

sub backup_all_datasets {
    my ($datasets) = @_;

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

    return { success_count => $success_count, error_count => $error_count };
}

sub safe_cleanup_old_backups {
    eval { cleanup_old_backups(); } or do {
        my $cleanup_error = $@ || 'Unknown cleanup error';
        log_message("Warning: Cleanup encountered issues: $cleanup_error");
    };
}

sub handle_exit {
    my ($result) = @_;

    if ( defined($result) ) {
        if ( $result->{error_count} > 0 ) {
            log_message("Exiting with error code 1 due to backup failures");
            exit 1;
        }
        else {
            log_message("Backup completed successfully");
            exit 0;
        }
    }
    else {
        log_message("Exiting with error code 2 due to fatal error");
        exit 2;
    }
}

sub setup_backup_directory {
    unless ( -d $backup_dir ) {
        log_message("Creating backup directory: $backup_dir");
        create_directory_safely( $backup_dir, "backup directory" );
    }

    die "Backup directory is not writable: $backup_dir"
      unless ( -w $backup_dir );
    log_message( "Backup directory ready: $backup_dir", 1 );
}

sub create_backup_session_directory {
    my ($start_time) = @_;

    my $session_timestamp = strftime( "%Y%m%d_%H%M%S", localtime($start_time) );
    $current_backup_session_dir = "$backup_dir/backup_$session_timestamp";

    log_message(
        "Creating backup session directory: $current_backup_session_dir");
    create_directory_safely( $current_backup_session_dir,
        "backup session directory" );

    die "Backup session directory is not writable: $current_backup_session_dir"
      unless ( -w $current_backup_session_dir );

    log_message( "Backup session directory ready: $current_backup_session_dir",
        1 );
}

sub create_directory_safely {
    my ( $path, $description ) = @_;

    eval { make_path( $path, { mode => 0755 } ) };
    if ($@) {
        die "Cannot create $description '$path': $@";
    }
}

sub get_datasets {
    my $dsn = sprintf( "dbi:Pg:dbname=%s;host=%s;port=%s",
        $central_db, $postgres_host, $postgres_port );

    my $dbh =
      DBI->connect( $dsn, $postgres_user, $postgres_password,
        { AutoCommit => 1, RaiseError => 1 } )
      or die "Failed to connect to central database: $DBI::errstr";

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

    my $backup_filename = generate_backup_filename($dataset);
    my $backup_path     = "$current_backup_session_dir/$backup_filename";

    log_message( "Backing up '$dataset' to '$backup_path'", 1 );

    execute_pg_dump( $dataset, $backup_path );
    verify_backup_file( $backup_path, $backup_filename );
}

sub generate_backup_filename {
    my ($dataset) = @_;
    my $timestamp = strftime( "%Y%m%d_%H%M%S", localtime() );
    my $filename  = "${dataset}_${timestamp}.sql";
    $filename .= ".gz" if $compress_backups;
    return $filename;
}

sub execute_pg_dump {
    my ( $dataset, $backup_path ) = @_;

    my @cmd = (
        'pg_dump',                  '--host=' . $postgres_host,
        '--port=' . $postgres_port, '--username=' . $postgres_user,
        '--no-password',            '--verbose',
        '--clean',                  '--if-exists',
        '--create',                 '--format=plain',
        $dataset
    );

    local $ENV{PGPASSWORD} = $postgres_password;

    if ($compress_backups) {
        my $cmd_str = join( ' ', @cmd ) . " | gzip > '$backup_path'";
        system($cmd_str) == 0 or die "pg_dump failed: $?";
    }
    else {
        push @cmd, "--file=$backup_path";
        system(@cmd) == 0 or die "pg_dump failed: $?";
    }
}

sub verify_backup_file {
    my ( $backup_path, $backup_filename ) = @_;

    unless ( -f $backup_path && -s $backup_path ) {
        die "Backup file was not created or is empty: $backup_path";
    }

    my $size    = -s $backup_path;
    my $size_mb = sprintf( "%.2f", $size / MB_IN_BYTES );
    log_message( "Backup completed: $backup_filename (${size_mb} MB)", 1 );
}

sub cleanup_old_backups {
    my $cutoff_time = time() - ( $retention_days * 24 * 60 * 60 );
    my @old_dirs    = find_old_backup_directories($cutoff_time);

    log_message("Cleaning up backup sessions older than $retention_days days");

    for my $dir (@old_dirs) {
        remove_backup_directory($dir);
    }

    log_cleanup_results(@old_dirs);
}

sub find_old_backup_directories {
    my ($cutoff_time) = @_;
    my @old_dirs;

    find(
        sub {
            return unless -d $_;
            return unless /^backup_\d{8}_\d{6}$/;

            my $mtime = ( stat($_) )[9];
            push @old_dirs, $File::Find::name if ( $mtime < $cutoff_time );
        },
        $backup_dir
    );

    return @old_dirs;
}

sub remove_backup_directory {
    my ($dir) = @_;

    log_message( "Removing old backup session: $dir", 1 );

    # Remove all files in the directory first
    find(
        sub {
            return unless -f $_;
            unlink $_ or log_message("Warning: Could not remove file $_: $!");
        },
        $dir
    );

    # Remove the directory safely
    eval {
        rmdir $dir
          or log_message("Warning: Could not remove directory $dir: $!");
    };
    if ($@) {
        log_message("Warning: Error during cleanup of $dir: $@");
    }
}

sub log_cleanup_results {
    my (@old_dirs) = @_;

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
