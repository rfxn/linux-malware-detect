#!/usr/bin/env bash
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH
echo "This will completely remove Linux Malware Detect from your server including all quarantine data!"
echo -n "Would you like to proceed? "
read -p "[y/n] " -n 1 Z
echo
if [ "$Z" == "y" ] || [ "$Z" == "Y" ]; then
	if [ "$OSTYPE" != "FreeBSD" ]; then
		if test `cat /proc/1/comm` = "systemd"
		then
			systemctl disable maldet.service
			systemctl stop maldet.service
			rm -f /usr/lib/systemd/system/maldet.service
			systemctl daemon-reload
		else
			maldet -k
			if [ -f /etc/redhat-release ]; then
				/sbin/chkconfig maldet off
				/sbin/chkconfig maldet --del
			elif [ -f /etc/debian_version ] || [ -f /etc/lsb-release ]; then
				update-rc.d -f maldet remove
			elif [ -f /etc/gentoo-release ]; then
				rc-update del maldet default
			elif [ -f /etc/slackware-version ]; then
				rm -f /etc/rc.d/rc3.d/S70maldet
				rm -f /etc/rc.d/rc4.d/S70maldet
				rm -f /etc/rc.d/rc5.d/S70maldet
			else
				/sbin/chkconfig maldet off
				/sbin/chkconfig maldet --del
			fi
			rm -f /etc/init.d/maldet
		fi
	fi
	rm -rf /usr/local/maldetect* /etc/cron.d/maldet_pub /etc/cron.daily/maldet /usr/local/sbin/maldet /usr/local/sbin/lmd
	clamav_paths="/usr/local/cpanel/3rdparty/share/clamav/ /var/lib/clamav/ /var/clamav/ /usr/share/clamav/ /usr/local/share/clamav"
	for cpath in $clamav_paths; do
		rm -f $cpath/rfxn.* $cpath/lmd.user.*
	done
	echo "Linux Malware Detect has been uninstalled."
else
	echo "You selected No or provided an invalid confirmation, nothing has been done!"
fi
