#!/bin/bash
#
##
# Linux Malware Detect v1.4.1
#             (C) 2002-2013, R-fx Networks <proj@r-fx.org>
#             (C) 2013, Ryan MacDonald <ryan@r-fx.org>
# inotifywait (C) 2007, Rohan McGovern  <rohan@mcgovern.id.au>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
inspath=/usr/local/maldetect
logf=$inspath/event_log
cnftemp=.ca.def

if [ ! -d "$inspath" ] && [ -d "files" ]; then
	mkdir -p $inspath
	chmod 755 $inspath
	cp -pR files/* $inspath
	chmod 755 $inspath/maldet
	ln -fs $inspath/maldet /usr/local/sbin/maldet
	ln -fs $inspath/maldet /usr/local/sbin/lmd
	cp $inspath/inotify/libinotifytools.so.0 /usr/lib/
	cp -f CHANGELOG COPYING.GPL README $inspath/
else
	$inspath/maldet -k >> /dev/null 2>&1
	mv $inspath $inspath.bk$$
	rm -f $inspath.last
	ln -fs $inspath.bk$$ $inspath.last
        mkdir -p $inspath
        chmod 755 $inspath
        cp -pR files/* $inspath
        chmod 755 $inspath/maldet
	ln -fs $inspath/maldet /usr/local/sbin/maldet
	ln -fs $inspath/maldet /usr/local/sbin/lmd
	cp $inspath/inotify/libinotifytools.so.0 /usr/lib/
	cp -f $inspath.bk$$/ignore_* $inspath/  >> /dev/null 2>&1
	cp -f $inspath.bk$$/sess/* $inspath/sess/ >> /dev/null 2>&1
	cp -f $inspath.bk$$/tmp/* $inspath/tmp/ >> /dev/null 2>&1
	cp -f $inspath.bk$$/quarantine/* $inspath/quarantine/ >> /dev/null 2>&1
	cp -f CHANGELOG COPYING.GPL README $inspath/
fi

if [ -d "/etc/cron.daily" ]; then
	cp -f cron.daily /etc/cron.daily/maldet
	chmod 755 /etc/cron.daily/maldet
fi

if [ -d "/etc/cron.d" ]; then
	cp -f cron.d.pub /etc/cron.d/maldet_pub
	chmod 644 /etc/cron.d/maldet_pub
fi

	touch $logf
	$inspath/maldet --alert-daily
	$inspath/maldet --alert-weekly
        echo "Linux Malware Detect v1.4.1"
        echo "            (C) 2002-2013, R-fx Networks <proj@r-fx.org>"
        echo "            (C) 2013, Ryan MacDonald <ryan@r-fx.org>"
        echo "inotifywait (C) 2007, Rohan McGovern <rohan@mcgovern.id.au>"
        echo "This program may be freely redistributed under the terms of the GNU GPL"
	echo ""
	echo "installation completed to $inspath"
	echo "config file: $inspath/conf.maldet"
	echo "exec file: $inspath/maldet"
	echo "exec link: /usr/local/sbin/maldet"
	echo "exec link: /usr/local/sbin/lmd"
	echo "cron.daily: /etc/cron.daily/maldet"
	echo ""
	if [ -f "$cnftemp" ] && [ -f "$inspath.bk$$/conf.maldet" ]; then
		. files/conf.maldet
		. $inspath.bk$$/conf.maldet
		. $cnftemp
		echo "imported config options from $inspath.last/conf.maldet"
	fi
	$inspath/maldet --update 1
