#!/bin/bash
#
# maldet    Linux Malware Detect monitoring
#
# chkconfig: 345 70 30
# description: Linux Malware Detect file monitoring
# processname: maldet

# Source function library.
. /etc/init.d/functions
if [ -f "/etc/sysconfig/maldet" ]; then
	. /etc/sysconfig/maldet
elif [ "$(egrep ^default_monitor_mode /usr/local/maldetect/conf.maldet 2> /dev/null)" ]; then
	. /usr/local/maldetect/conf.maldet
	if [ "$default_monitor_mode" ]; then
		MONITOR_MODE="$default_monitor_mode"
	fi
fi
RETVAL=0
prog="maldet"
LOCKFILE=/var/lock/subsys/$prog

if [ -z "$MONITOR_MODE" ]; then
	echo "error no default monitor mode defined, set \$MONITOR_MODE in /etc/sysconfig/maldet or \$default_monitor_mode in /usr/local/maldetect/conf.maldet"
	exit 1
fi

start() {
        echo -n "Starting $prog: "
        /usr/local/maldetect/maldet --monitor $MONITOR_MODE
        RETVAL=$? [ $RETVAL -eq 0 ] && touch $LOCKFILE
        echo
        return $RETVAL
}

stop() {
        echo -n "Shutting down $prog: "
        /usr/local/maldetect/maldet --kill-monitor && success || failure
        RETVAL=$? [ $RETVAL -eq 0 ] && rm -f $LOCKFILE
        echo
        return $RETVAL
}

restart() {
        stop
        start
}

status() {
        echo -n "Checking $prog monitoring status: "
        if [ "$(ps -A --user root -o "cmd" | grep maldetect | grep inotifywait)" ]; then
            echo "Running"
	    exit 0
        else
            echo "Not running"
            exit 1
        fi
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    status)
        status
        ;;
    restart)
        restart
        ;;
    condrestart)
        if [ -f $LOCKFILE ]; then
            restart
        fi
        ;;
    *)
        echo "Usage: $prog {start|stop|status|restart|condrestart}"
        exit 1
        ;;
esac
exit $RETVAL
