#!/usr/bin/env bash
file="$1"

inspath='/usr/local/maldetect'
intcnf="$inspath/internals/internals.conf"
if [ -f "$intcnf" ]; then
	source $intcnf
fi

isclamd=`pidof clamd 2> /dev/null`
if [ "$isclamd" ] && [ -f "$clamdscan" ]; then
	clamd_scan=1
fi
cd /tmp ; $inspath/maldet --config-option quarantine_hits=1,quarantine_clean=0,tmpdir=/var/tmp,scan_tmpdir_paths='',scan_clamscan=$clamd_scan --hook-scan -a "$file"
