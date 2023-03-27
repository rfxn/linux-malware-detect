#!/usr/bin/perl
#
##
# Linux Malware Detect v1.6.5.1
#             (C) 2002-2023, R-fx Networks <proj@r-fx.org>
#             (C) 2023, Ryan MacDonald <ryan@r-fx.org>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#

use warnings;

if ($#ARGV < "1") {
 print "usage: hexfile string\n";
 exit;
}

$hexfile = $ARGV[0];
$instr = $ARGV[1];

$dat_hexstring = $hexfile;
open(DAT, $dat_hexstring) || die("Could not open $dat_hexstring");
@raw_data=<DAT>;
close(DAT); 

foreach $hexptr (@raw_data) {
 chomp($hexptr);
 ($ptr,$name)=split(/:/,$hexptr);
 if ( grep(/$ptr/, $instr) ) {
 	print "$ptr $name \n";
	exit;
 }
}
