#!/usr/bin/perl
#
##
# Linux Malware Detect v1.6.5
#             (C) 2002-2023, R-fx Networks <proj@r-fx.org>
#             (C) 2023, Ryan MacDonald <ryan@r-fx.org>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#

if ($#ARGV != "0") {
 print "usage: hexfile\n";
 exit;
}

$hexfile = $ARGV[0];

$named_pipe_name = "/usr/local/maldetect/internals/hexfifo";
$timeout = "1";

if (-p $named_pipe_name) {
    eval {
      local $SIG{ALRM} = sub { die "alarm\n" }; # NB: \n required
      alarm $timeout;
      if (sysopen(FIFO, $named_pipe_name, O_RDONLY)) {
        while(my $this_line = <FIFO>) {
          chomp($this_line);
          $return .= $this_line;
        }
        close(FIFO);
      } else {
        $errormsg = "ERROR: Failed to open named pipe $named_pipe_name for reading: $!";
      }
      alarm 0;
    };
    if ($@) {
      if ($@ eq "alarm\n") {
        # timed out
        $errormsg = "Timed out reading from named pipe $named_pipe_name";
      } else {
        $errormsg = "Error reading from named pipe: $!";
      }
    } else {
      # didn't time out
      $instr = $return;
    }
 }

$dat_hexstring=$hexfile;
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
