#!/usr/bin/env bash
#
# Maldet GUI - Launch Script
# Starts the web interface for Linux Malware Detect
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Default settings
HOST="${MALDET_GUI_HOST:-127.0.0.1}"
PORT="${MALDET_GUI_PORT:-8080}"
MALDET_BIN="${MALDET_BIN:-maldet}"
BASE_DIR="${MALDET_BASE_DIR:-/usr/local/maldetect}"

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --base-dir) BASE_DIR="$2"; shift 2 ;;
        --maldet-bin) MALDET_BIN="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --host HOST        Bind address (default: 127.0.0.1)"
            echo "  --port PORT        Port number (default: 8080)"
            echo "  --base-dir PATH    Maldet installation directory"
            echo "  --maldet-bin PATH  Path to maldet binary"
            echo "  --help, -h         Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  MALDET_GUI_HOST    Bind address"
            echo "  MALDET_GUI_PORT    Port number"
            echo "  MALDET_BIN         Path to maldet binary"
            echo "  MALDET_BASE_DIR    Maldet installation directory"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Check Python 3
if ! command -v python3 &>/dev/null; then
    echo "Error: Python 3 is required but not found."
    exit 1
fi

# Check maldet binary
if ! command -v "$MALDET_BIN" &>/dev/null; then
    echo "Warning: maldet binary '$MALDET_BIN' not found in PATH."
    echo "The GUI will start but maldet operations will fail."
    echo "Use --maldet-bin to specify the correct path."
fi

echo "Starting Maldet GUI..."
echo "  URL: http://${HOST}:${PORT}"
echo "  Maldet: $MALDET_BIN"
echo "  Install: $BASE_DIR"
echo ""
echo "Press Ctrl+C to stop."
echo ""

# Start the server
exec python3 maldet_gui.py \
    --host "$HOST" \
    --port "$PORT" \
    --base-dir "$BASE_DIR" \
    --maldet-bin "$MALDET_BIN"
