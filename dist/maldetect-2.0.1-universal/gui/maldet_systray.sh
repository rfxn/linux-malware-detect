#!/usr/bin/env bash
#
# Maldet GUI system tray launcher.
#
set -euo pipefail

URL="${MALDET_GUI_URL:-http://127.0.0.1:${MALDET_GUI_PORT:-8080}}"
INTERVAL="${MALDET_SYSTRAY_INTERVAL:-5}"
START_GUI="${MALDET_SYSTRAY_START_GUI:-1}"
GUI_LAUNCHER="${MALDET_GUI_LAUNCHER:-/usr/local/sbin/maldet-gui}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUI_LOG="${MALDET_SYSTRAY_LOG:-${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/maldet/gui.log}"

case "$INTERVAL" in
	''|*[!0-9]*) INTERVAL=5 ;;
esac
[ "$INTERVAL" -gt 0 ] || INTERVAL=5

if [ "${1:-}" = "--open" ]; then
	OPEN_URL="${2:-$URL}"
	if command -v xdg-open >/dev/null 2>&1; then
		xdg-open "$OPEN_URL" >/dev/null 2>&1 || true
	else
		echo "Open $OPEN_URL in your browser."
	fi
	exit 0
fi
if [ "${1:-}" = "--quit" ]; then
	exit 0
fi

if ! command -v yad >/dev/null 2>&1; then
	echo "Error: yad is required for the Maldet system tray icon." >&2
	echo "Install the 'yad' package or run the WebGUI directly." >&2
	exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
	echo "Error: Python 3 is required to read the Maldet GUI status." >&2
	exit 1
fi

if [ ! -x "$GUI_LAUNCHER" ] && [ -x "$SCRIPT_DIR/launch.sh" ]; then
	GUI_LAUNCHER="$SCRIPT_DIR/launch.sh"
fi

GUI_START_EPOCH=0
gui_healthy() {
	python3 - "$URL/api/check" <<'PY' >/dev/null 2>&1
import sys
from urllib.request import urlopen
with urlopen(sys.argv[1], timeout=2) as response:
    raise SystemExit(0 if response.status == 200 else 1)
PY
}

ensure_gui() {
	[ "$START_GUI" = "1" ] || return 0
	gui_healthy && return 0
	[ -x "$GUI_LAUNCHER" ] || return 1
	local now
	now=$(date +%s)
	[ $((now - GUI_START_EPOCH)) -ge 15 ] || return 1
	GUI_START_EPOCH="$now"
	mkdir -p "$(dirname "$GUI_LOG")" 2>/dev/null || true
	printf '%s\n' "Starting WebGUI because $URL/api/check is unavailable" >>"$GUI_LOG"
	nohup "$GUI_LAUNCHER" >>"$GUI_LOG" 2>&1 </dev/null &
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		sleep 1
		gui_healthy && return 0
	done
	printf '%s\n' "WebGUI did not become ready after launch" >>"$GUI_LOG"
	return 1
}

status_text() {
	ensure_gui >/dev/null 2>&1 || true
	python3 - "$URL/api/scans/active" <<'PY'
import json
import sys
from urllib.error import URLError
from urllib.request import urlopen

try:
    with urlopen(sys.argv[1], timeout=3) as response:
        data = json.loads(response.read().decode("utf-8"))
    scans = data.get("active_scans", data.get("active", []))
    if not isinstance(scans, list):
        scans = []
    if not scans:
        print("Maldet: no active scans")
    else:
        states = {}
        for scan in scans:
            state = str(scan.get("state", "running"))
            states[state] = states.get(state, 0) + 1
        summary = ", ".join("%s=%d" % item for item in sorted(states.items()))
        print("Maldet: %d active scan(s) (%s)" % (len(scans), summary))
except (OSError, URLError, ValueError, TypeError) as exc:
    print("Maldet: WebGUI unavailable (%s)" % exc)
PY
}

cleanup() {
	if [ -n "${YAD_PID:-}" ] && kill -0 "$YAD_PID" 2>/dev/null; then
		kill "$YAD_PID" 2>/dev/null || true
	fi
}
trap cleanup EXIT HUP INT TERM

# Ensure the first tray tooltip reflects a live GUI instead of waiting for the
# first polling interval.
ensure_gui >/dev/null 2>&1 || true

coproc YAD_PROCESS {
	yad --notification --listen \
		--image=security-high \
		--text="Maldet" \
		--command="$0 --open '$URL'" \
		--menu="Open Web GUI!$0 --open '$URL'|Quit!$0 --quit"
}
YAD_PID="$YAD_PROCESS_PID"

while kill -0 "$YAD_PID" 2>/dev/null; do
	printf 'tooltip:%s\n' "$(status_text)" >&"${YAD_PROCESS[1]}" || break
	sleep "$INTERVAL"
done
