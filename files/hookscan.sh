#!/usr/bin/env bash
file="$1"
isclamd=`pidof clamd 2> /dev/null`
clamdloc=`which clamdscan 2> /dev/null`
if [ "$isclamd" ] && [ -f "$clamdloc" ]; then
	clamd_scan=1
fi
cd /tmp ; /usr/local/maldetect/maldet --config-option quar_hits=1,quar_clean=0,tmpdir=/var/tmp,scan_tmpdir_paths='',scan_clamscan=$clamd_scan --hook-scan -a "$file"
