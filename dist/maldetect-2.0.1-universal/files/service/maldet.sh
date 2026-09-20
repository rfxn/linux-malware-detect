#!/usr/bin/env bash
#
##
# Linux Malware Detect v2.0.1
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
# maldet    Linux Malware Detect monitoring
#
# chkconfig: 345 70 30
# description: Linux Malware Detect file monitoring
# processname: maldet

### BEGIN INIT INFO
# Provides:          maldet
# Required-Start:    $local_fs $remote_fs $network $syslog $named
# Required-Stop:     $local_fs $remote_fs $network $syslog $named
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# X-Interactive:     true
# Short-Description: Start/stop maldet in monitor mode
### END INIT INFO
inspath='/usr/local/maldetect'
intcnf="$inspath/internals/internals.conf"

if [ -f "$intcnf" ]; then
	# shellcheck disable=SC1090,SC1091
	source "$intcnf"
	# shellcheck disable=SC1090,SC1091,SC2154
	source "$cnf"
	# shellcheck disable=SC2154
	if [ -f "$compatcnf" ]; then
		# shellcheck disable=SC1090,SC1091
		source "$compatcnf"
	fi
else
	echo "$intcnf not found."
	exit 1
fi

# Source function library.
if [ -f /etc/init.d/functions ]; then
        # shellcheck source=/dev/null
        . /etc/init.d/functions
elif [ -f /lib/lsb/init-functions ]; then
        # shellcheck source=/dev/null
        . /lib/lsb/init-functions
fi

if [ -f "/etc/sysconfig/maldet" ]; then
	# shellcheck source=/dev/null
	. /etc/sysconfig/maldet
elif [ -f "/etc/default/maldet" ]; then
	# shellcheck source=/dev/null
	. /etc/default/maldet
fi

if [ "$default_monitor_mode" ]; then
	MONITOR_MODE="$default_monitor_mode"
fi

RETVAL=0
prog="maldet"
if [ -d /var/lock/subsys ]; then
        LOCKFILE=/var/lock/subsys/$prog
else
        LOCKFILE=/var/lock/$prog
fi

if [ -z "$MONITOR_MODE" ]; then
    if [ -f /etc/redhat-release ]; then
        echo "error no default monitor mode defined, set \$MONITOR_MODE in /etc/sysconfig/maldet, or \$default_monitor_mode in $cnf"
    elif [ -f /etc/debian_version ]; then
        echo "error no default monitor mode defined, set \$MONITOR_MODE in /etc/default/maldet, or \$default_monitor_mode in $cnf"
    else
        echo "error no default monitor mode defined, set \$MONITOR_MODE in /etc/sysconfig/maldet, or \$default_monitor_mode in $cnf"
    fi
	exit 1
fi

start() {
        echo -n "Starting $prog: "
        $inspath/maldet -b --monitor "$MONITOR_MODE"
        RETVAL=$?; [ $RETVAL -eq 0 ] && touch $LOCKFILE
        echo
        return $RETVAL
}

stop() {
        echo -n "Shutting down $prog: "
        # shellcheck disable=SC2015
        if [ -f /etc/redhat-release ]; then
            $inspath/maldet --kill-monitor && success || failure
        elif [ -f /etc/debian_version ]; then
            $inspath/maldet --kill-monitor && log_success_msg || log_failure_msg
        else
            $inspath/maldet --kill-monitor && success || failure
        fi
        RETVAL=$?; [ $RETVAL -eq 0 ] && command rm -f $LOCKFILE
        echo
        return $RETVAL
}

restart() {
        stop
        start
}

status() {
        echo -n "Checking $prog monitoring status: "
        # shellcheck disable=SC2154
        if [ -f "$tmpdir/monitor.pid" ]; then
            local _mpid
            _mpid=$(cat "$tmpdir/monitor.pid")
            if [ -n "$_mpid" ] && kill -0 "$_mpid" 2>/dev/null; then  # validate PID is alive
                echo "Running (pid $_mpid)"
                exit 0
            fi
        fi
        if [ "$(pgrep -f 'inotify.paths.[0-9]+')" ]; then
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
