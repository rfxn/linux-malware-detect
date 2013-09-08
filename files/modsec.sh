#!/bin/sh
file="$1"
cd /tmp ; /usr/local/maldetect/maldet --config-option quar_hits=1,quar_clean=0,clamav_scan=0 --modsec -a "$file"
