#!/usr/bin/perl

#=======================================================================
# Set.pm / IPTables::Log::Set
# $Id: Set.pm 13 2009-10-15 08:52:18Z andys $
# $HeadURL: https://daedalus.nocarrier.org.uk/svn/IPTables-Log/trunk/IPTables-Log/lib/IPTables/Log/Set.pm $
# (c)2009 Andy Smith <andy.smith@netprojects.org.uk>
#-----------------------------------------------------------------------
#:Description
# This class holds a set of IPTables::Log::Set::Record objects
#-----------------------------------------------------------------------
#:Synopsis
# NOTE: This class isn't designed to be created directly.
#
# use IPTables::Log;
# my $l = IPTables::Log->new;
# my $s = $l->create_set;
# my $r = $s->create_record({text => '...IN=eth0 OUT=eth1 MAC=00:...'});
# $r->parse;
# $s->add($r);
#=======================================================================

# The pod (Perl Documentation) for this module is provided inline. For a
# better-formatted version, please run:-
# $ perldoc Set.pm

=head1 NAME

IPTables::Log::Set - Holds a set of IPTables::Log::Set::Record objects.

=head1 SYNOPSIS

Note that this class isn't designed to be created directly. You can create these objects via a C<IPTables::Log> object.

  use IPTables::Log;
  my $l = IPTables::Log->new;
  my $s = $l->create_set;

=head1 DEPENDENCIES

=over 4

=item * Class::Accessor - for accessor methods

=item * Data::GUID - for GUID generation

=item * NetAddr::IP - for the C<src> and C<dst> methods (required by L<IPTables::Log::Set::Record>)

=back

=cut

# Set our package name
package IPTables::Log::Set;

# Minimum version
use 5.010000;
# Use strict and warnings
use strict;
use warnings;

# Use Data::GUID for generating GUIDs
use Data::GUID;
# Use IPTables::Log::Set::Record for individual log entries
use IPTables::Log::Set::Record;

# Inherit from Class::Accessor to simplify accessor method generation
use base qw(Class::Accessor);
# Follow best practice
__PACKAGE__->follow_best_practice;
# Create log and guid as read-only accessor methods
__PACKAGE__->mk_ro_accessors( qw(log guid) );

# Set version information
our $VERSION = '0.0001';

=head1 CONSTRUCTORS

=head2 Set->create

Creates a new C<IPTables::Log::Set> object. This isn't the recommended way to do this, however. The proper way is to create an object via a L<IPTables::Log> object with C<create_set>.

=cut

sub create
{
	my ($class, $args) = @_;

	my $self = __PACKAGE__->new($args);
	$self->{records} = {};

	# Generate a GUID for the set
	my $g = Data::GUID->new;
	$self->{guid} = $g->as_string;

	return $self;
}

=head1 METHODS

=head2 $set->create_record(I<{text => '...IN=eth0 OUT=eth1 MAC=00:...'}>))

Creates a new L<IPTables::Log::Set::Record> object. This is the B<recommended> way to create C<IPTables::Log::Set::Record> objects, as it ensures various settings are inherited from the C<Log> class.

The text of the log entry can be passed here, or it can be passed with the C<set_text> accessor method to the C<IPTables::Log::Set::Record> object itself.

=cut

sub create_record
{
	my ($self, $args) = @_;

	$args->{log} = $self->get_log;

	my $record = IPTables::Log::Set::Record->create($args);

	return $record;
}

=head2 $set->load_file($filename)

Loads in logs from I<$filename>, discarding any which don't appear to be iptables/netfilter logs. A L<IPTables::Log::Set::Record> object is then created for each entry, and the content is then parsed. Finally, each entry is then added to the set created with C<create_record>.

=cut

sub load_file
{
	my ($self, $filename) = @_;

	# Check we've been passed a filename
	if(!$filename)
	{
		$self->get_log->fatal("No filename given!");
	}

	# Check that the file exists, and barf if not.
	if(!-f $filename)
	{
		$self->get_log->fatal("Cannot find ".$self->get_log->fcolour('yellow', $filename));
	}

	$self->get_log->debug("Opening ".$self->get_log->fcolour('yellow', $filename)."...");
	# Open the logfile
	open(LOGFILE, $filename) || $self->get_log->fatal("Cannot open ".$self->get_log->fcolour('yellow', $filename));
	my @logs = <LOGFILE>;
	$self->get_log->debug("Finished reading in logs.");

	# It's a fair bet that if we don't have an IN= and an OUT= and it doesn't have a source of 'kernel', then it's not an iptables log.
	# We'll discard those before even attempting to parse it.
	foreach my $log (@logs)
	{
		if($log =~ /kernel.+IN=.+OUT=/)
		{
			chomp($log);
			$self->get_log->debug_nolf("Parsing iptables log entry... ");
			my $record = $self->create_record({'text' => $log});
			$record->parse;
			$self->get_log->debug("done.");
			$self->add($record);
			$self->get_log->debug("Added record with GUID ".$self->get_log->fcolour('yellow', $record->get_guid). " to set.");
		}
		else
		{
			$self->get_log->debug("Log entry is not an iptables log entry, so skipping...");
		}
	}
}

=head2 $set->add($record)

Adds a L<IPTables::Log::Set::Record> object to a set created with C<create_set>.

=cut

sub add
{
	my ($self, $record) = @_;

	if($record)
	{
		my $guid = $record->get_guid;

		$self->{records}{$guid} = $record;
	}
}

=head1 CAVEATS

None.

=head1 BUGS

None that I'm aware of ;-)

=head1 AUTHOR

This module was written by B<Andy Smith> <andy.smith@netprojects.org.uk>.

=head1 COPYRIGHT

$Id: Set.pm 13 2009-10-15 08:52:18Z andys $

(c)2009 Andy Smith (L<http://andys.org.uk/>)

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=cut

1
