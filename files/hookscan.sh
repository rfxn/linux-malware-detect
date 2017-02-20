#!/usr/bin/env bash
file="$1"

inspath='/usr/local/maldetect'
intcnf="$inspath/internals/internals.conf"
if [ -f "$intcnf" ]; then
	source $intcnf
fi

## these values can be overridden in conf.maldet.hookscan
quarantine_hits=1
quarantine_clean=0
scan_tmpdir_paths=''
hscan=1

isclamd=`pidof clamd 2> /dev/null`
if [ "$isclamd" ] && [ -f "$clamdscan" ]; then
	clamd_scan=1
else
	clamd_scan=0
fi

hookcnf="$inspath/conf.maldet.hookscan"
if [ -f "$hookcnf" ]; then
        source $hookcnf
fi

cd /tmp ; $inspath/maldet --hook-scan --config-option quarantine_hits=$quarantine_hits,quarantine_clean=$quarantine_clean,tmpdir=/var/tmp,scan_tmpdir_paths=$scan_tmpdir_paths,scan_clamscan=$clamd_scan -a "$file"
