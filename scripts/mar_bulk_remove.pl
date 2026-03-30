#!/usr/bin/perl
# =============================================================================
# MAR Bulk Remove Script
# =============================================================================
#
# This script bulk-removes MAC Address Repository (MAR) entries whose MAC
# addresses appear in a CSV file.  It is the counterpart to mar_bulk_import.pl.
#
# How it works:
#   - Bootstraps the Forescout Perl environment (cu_util.ph) for a persistent
#     engine connection.
#   - Skips the CSV header row, then reads each subsequent row and takes the
#     first comma-separated value as the MAC address.
#   - Normalises the MAC to bare lowercase hex and calls
#     cutil_rm_devinfo({"mar" => [$mac]}) to delete the entry.
#   - The mar.pl daemon on the CA automatically removes the corresponding
#     Redis key, so no restart is needed.
#
# Performance:
#   ~100 entries/second.
#
# Usage (on the EM / SA appliance):
#   cd /usr/local/forescout
#   perl -X -I lib/perl/inc /tmp/mar_bulk_remove.pl /tmp/mar_data.csv
#
# CSV format (first column must be MAC address):
#   dot1x_mac,...
#   000000021d85,...
#
# =============================================================================
use strict; use warnings;
BEGIN { chdir "/usr/local/forescout"; unshift @INC, "lib/perl", "lib/perl/inc"; }
require "forescout/cu_util.ph";
my $csv = $ARGV[0] or die "Usage: $0 <csv>\n";
open(my $fh, '<', $csv) or die "Cannot open $csv: $!\n";
<$fh>;
my ($ok,$n) = (0,0);
while (<$fh>) {
    chomp; s/\r//g; next if /^\s*$/;
    my $mac = (split /,/)[0]; next unless $mac;
    $mac =~ s/[-:.]//g; $mac = lc $mac;
    next unless length($mac)==12;
    eval { cutil_rm_devinfo({"mar" => [$mac]}); $ok++ }; $n++;
    print "progress $n ($ok removed)\n" if $n % 200 == 0;
}
close $fh;
print "done removed=$ok total=$n\n";

