# Maldet GUI — Web Interface for Linux Malware Detect

A self-contained, zero-dependency web-based GUI for [Linux Malware Detect (maldet)](https://github.com/rfxn/linux-malware-detect).

Built with Python 3 standard library only — no pip installs, no frameworks, no Node.js build steps.

## Features

- **Dashboard** — System overview, maldet version, signature version, monitor status, active scans
- **Scanner** — Full scan, recent scan, file-list scan with config overrides, include/exclude regex, background mode
- **Scan Management** — List active scans, kill/pause/unpause/stop/continue, view progress and ETA
- **Quarantine** — View quarantined files, restore individual files, bulk operations
- **Reports** — View all scan reports, JSON reports, hook scan activity, email reports
- **Monitoring** — Start/stop/reload inotify monitor, view monitor configuration
- **Updates** — Update signatures, update maldet version (stable/beta channel)
- **Configuration** — Full conf.maldet editor with sections, toggles, and text inputs
- **Event Log** — View the maldet event log with color-coded entries
- **Ignore Lists** — Edit ignore_paths, ignore_file_ext, ignore_sigs, ignore_inotify
- **Maintenance** — Run maintenance tasks, purge data, configure retention
- **System Info** — Host details, binary detection, disk/memory usage
- **System tray** — Optional `yad` tray icon with active-scan status and a link to the WebGUI
- **Languages** — English and Brazilian Portuguese selectable in the top bar, persisted in the browser

## Requirements

- Python 3.6+
- Linux Malware Detect (maldet) installed
- A modern web browser
- `yad` and `xdg-utils` for the optional system tray launcher

## Installation

No installation required. The GUI is a standalone Python script.

```bash
# Clone or copy the gui/ directory
cd linux-malware-detect/gui

# Make the launch script executable
chmod +x launch.sh
```

## Usage

### Quick Start

```bash
# Start the GUI (binds to localhost:8080 by default)
./launch.sh

# Start the server in the background and open the browser
./open_gui.sh

# Or run directly with Python
python3 maldet_gui.py
```

Then open your browser to: **http://127.0.0.1:8080**

### System tray

On a graphical Linux desktop, start the tray icon with:

```bash
maldet-systray
```

The icon polls `/api/scans/active`, shows the number and state of active scans
in its tooltip, and opens the WebGUI from its menu. If the GUI is not already
running, it attempts to start `maldet-gui`. The tray launcher is optional and
exits with an actionable message when `yad` or a graphical session is absent.

Environment variables:

```
MALDET_GUI_URL=http://127.0.0.1:8080
MALDET_SYSTRAY_INTERVAL=5
MALDET_SYSTRAY_START_GUI=1
```

### Command-Line Options

```
python3 maldet_gui.py [OPTIONS]

Options:
  --host HOST        Bind address (default: 127.0.0.1)
  --port PORT        Port number (default: 8080)
  --base-dir PATH    Maldet installation directory (default: /usr/local/maldetect)
  --maldet-bin PATH  Path to maldet binary (default: auto-detect)
```

### Examples

```bash
# Run on a different port
python3 maldet_gui.py --port 9090

# Run on all interfaces (for remote access)
python3 maldet_gui.py --host 0.0.0.0 --port 8080

# Specify custom maldet installation
python3 maldet_gui.py --base-dir /opt/maldet --maldet-bin /usr/local/sbin/maldet
```

## Security Notes

- By default, the GUI binds to `127.0.0.1` (localhost only)
- For remote access, use `--host 0.0.0.0` and ensure proper firewall rules
- The GUI executes maldet commands with the privileges of the running user
- For production use, consider running behind a reverse proxy with authentication
- All maldet operations require appropriate permissions (root for most operations)

## API Reference

The GUI provides a JSON API at `/api/*`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/system` | GET | System information |
| `/api/version` | GET | Version info |
| `/api/config` | GET | Read configuration |
| `/api/config` | PUT | Update a config key |
| `/api/scans` | GET | List all scan reports (JSON) |
| `/api/scans/active` | GET | List active scans |
| `/api/scan` | POST | Start a new scan |
| `/api/scan/{id}` | GET | Get scan report (JSON) |
| `/api/scan/{id}` | POST | Scan actions (kill, pause, etc.) |
| `/api/quarantine` | GET | List quarantined files |
| `/api/quarantine/stats` | GET | Quarantine statistics |
| `/api/quarantine/restore` | POST | Restore a file |
| `/api/logs` | GET | Event log entries |
| `/api/monitor` | POST | Start/stop/reload monitor |
| `/api/update/sigs` | POST | Update signatures |
| `/api/update/version` | POST | Update maldet version |
| `/api/test-alert` | POST | Send test alert |
| `/api/purge` | POST | Purge all data |
| `/api/maintenance` | POST | Run maintenance |
| `/api/digest` | POST | Fire digest alert |
| `/api/alert-daily` | POST | Generate monitor digest |
| `/api/ignore` | GET | Get ignore lists |
| `/api/ignore` | PUT | Update ignore lists |
| `/api/reports/hooks` | GET | Hook scan activity |
| `/api/check` | GET | Health check |

## Architecture

```
gui/
├── maldet_gui.py          # Python HTTP server + API + CLI wrapper
├── open_gui.sh             # Starts the server and opens the default browser
├── static/
│   ├── style.css          # Dark-theme stylesheet
│   └── app.js             # Frontend JavaScript SPA
├── templates/
│   └── index.html         # HTML shell
├── maldet_systray.sh      # Optional yad system tray launcher
├── README.md              # This file
├── requirements.txt       # Python dependencies (none)
└── launch.sh              # Launch script
```

## License

GNU GPL v2 — same license as Linux Malware Detect.

## Support

- [Linux Malware Detect GitHub](https://github.com/rfxn/linux-malware-detect)
- [Maldet Documentation](https://github.com/rfxn/linux-malware-detect/blob/master/README.md)
