#!/usr/bin/env bash
#
# SysV fallback for the Maldet WebGUI.
#
### BEGIN INIT INFO
# Provides:          maldet-gui
# Required-Start:    $local_fs $remote_fs $network
# Required-Stop:     $local_fs $remote_fs $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start the Maldet WebGUI
### END INIT INFO

inspath=/usr/local/maldetect
pidfile="$inspath/tmp/maldet-gui.pid"
logfile=/var/log/maldet/gui.log
[ -f /etc/default/maldet-gui ] && . /etc/default/maldet-gui
[ -f /etc/sysconfig/maldet-gui ] && . /etc/sysconfig/maldet-gui
MALDET_GUI_HOST="${MALDET_GUI_HOST:-127.0.0.1}"
MALDET_GUI_PORT="${MALDET_GUI_PORT:-32501}"
MALDET_BIN="${MALDET_BIN:-/usr/local/sbin/maldet}"

start() {
	[ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null && return 0
	mkdir -p "$inspath/tmp" "$(dirname "$logfile")"
	nohup "$(command -v python3)" "$inspath/gui/maldet_gui.py" \
		--host "$MALDET_GUI_HOST" --port "$MALDET_GUI_PORT" \
		--base-dir "$inspath" --maldet-bin "$MALDET_BIN" \
		>>"$logfile" 2>&1 </dev/null &
	echo $! > "$pidfile"
}

stop() {
	if [ -f "$pidfile" ]; then
		kill "$(cat "$pidfile")" 2>/dev/null || true
		rm -f "$pidfile"
	fi
}

case "${1:-}" in
	start) start ;;
	stop) stop ;;
	restart) stop; start ;;
	status) [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null ;;
	*) echo "Usage: $0 {start|stop|restart|status}"; exit 1 ;;
esac
