#!/usr/bin/env bash
#
# Start Maldet WebGUI and open it in the default browser.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
URL="${MALDET_GUI_URL:-http://127.0.0.1:${MALDET_GUI_PORT:-8080}}"
LAUNCHER="${MALDET_GUI_LAUNCHER:-$SCRIPT_DIR/launch.sh}"
LOG="${MALDET_GUI_LOG:-${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/maldet/gui.log}"

if ! command -v python3 >/dev/null 2>&1; then
	echo "Error: Python 3 is required for the Maldet WebGUI." >&2
	exit 1
fi
[ -x "$LAUNCHER" ] || {
	echo "Error: GUI launcher not found: $LAUNCHER" >&2
	exit 1
}

if ! python3 - "$URL/api/check" <<'PY' >/dev/null 2>&1
import sys
from urllib.request import urlopen
with urlopen(sys.argv[1], timeout=2) as response:
    raise SystemExit(0 if response.status == 200 else 1)
PY
then
	mkdir -p "$(dirname "$LOG")" 2>/dev/null || true
	nohup "$LAUNCHER" >>"$LOG" 2>&1 </dev/null &
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		sleep 1
		if python3 - "$URL/api/check" <<'PY' >/dev/null 2>&1
import sys
from urllib.request import urlopen
with urlopen(sys.argv[1], timeout=2) as response:
    raise SystemExit(0 if response.status == 200 else 1)
PY
		then
			break
		fi
	done
fi

if command -v xdg-open >/dev/null 2>&1; then
	xdg-open "$URL" >/dev/null 2>&1 || true
else
	echo "WebGUI started at $URL (xdg-open is not installed)." >&2
fi
