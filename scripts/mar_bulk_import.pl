#!/usr/bin/perl
# =============================================================================
# MAR Bulk Import Script
# =============================================================================
#
# This script bulk-imports MAC Address Repository (MAR) entries from a CSV file
# into the Forescout CounterACT engine.  It is designed to replicate the
# behaviour of the GUI "Import CSV in MAR" button but runs entirely on the CLI.
#
# How it works:
#   - Bootstraps the Forescout Perl environment (cu_util.ph) so we get a
#     persistent connection to the engine's devinfo subsystem.
#   - Reads a CSV file whose header row names the MAR fields
#     (e.g. dot1x_mac, dot1x_target_access, dot1x_mar_comment, ...).
#   - For every data row it normalises the MAC address to bare lowercase hex,
#     builds a field hash, and calls cutil_update_devinfo("mar", ...) which
#     is an upsert — existing entries are updated, new ones are created.
#   - Each entry automatically gets dot1x_approved_by = "by_import" unless the
#     CSV already provides a value for that field.
#
# Performance:
#   ~1000 entries/second (vs ~1.5/s when spawning a separate fstool per entry).
#
# Usage (on the EM / SA appliance):
#   cd /usr/local/forescout
#   perl -X -I lib/perl/inc /tmp/mar_bulk_import.pl /tmp/mar_data.csv
#
# CSV format (must match the Forescout MAR export format):
#   dot1x_mac,dot1x_auth_method,dot1x_target_access,dot1x_mar_comment,...
#   000000021d85,bypass,vlan:222<TAB>IsCOA:false,my comment,...
#
# =============================================================================
use strict; use warnings;
BEGIN { chdir "/usr/local/forescout"; unshift @INC, "lib/perl", "lib/perl/inc"; }
require "forescout/cu_util.ph";
my $csv = $ARGV[0] or die "Usage: $0 <csv>\n";
open(my $fh, '<', $csv) or die "Cannot open $csv: $!\n";
my $hdr = <$fh>; chomp $hdr; $hdr =~ s/\r//g;
my @cols = split /,/, $hdr;
my ($ok,$fail,$n) = (0,0,0);
while (<$fh>) {
    chomp; s/\r//g; next if /^\s*$/;
    my @v = split /,/, $_, -1;
    my %r; @r{@cols} = @v;
    my $mac = $r{dot1x_mac} // next;
    $mac =~ s/[-:.]//g; $mac = lc $mac;
    next unless length($mac)==12;
    my %p = (dot1x_mac => $mac);
    for my $c (@cols) {
        next if $c eq "dot1x_mac";
        my $val = $r{$c}; next unless defined $val && $val ne "";
        $p{$c} = $val;
    }
    $p{dot1x_approved_by} //= "by_import";
    eval { cutil_update_devinfo("mar", $mac, \%p, 0); $ok++ };
    $fail++ if $@; $n++;
    print "progress $n ($ok ok $fail fail)\n" if $n % 200 == 0;
}
close $fh;
print "done ok=$ok fail=$fail total=$n\n";

