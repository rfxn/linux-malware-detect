#!/bin/bash
#
# elog_lib.sh — Structured Event Logging Library 1.0.6
###
# Copyright (C) 2002-2026 R-fx Networks <proj@rfxn.com>
#                         Ryan MacDonald <ryan@rfxn.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
###
#
# Shared structured event logging library for rfxn projects.
# Source this file after setting ELOG_* configuration variables.
# No project-specific code — all behavior controlled via variables.

# Source guard — safe for repeated sourcing
# shellcheck disable=SC2154
[[ -n "${_ELOG_LIB_LOADED:-}" ]] && return 0 2>/dev/null  # suppress error when executed (not sourced)
_ELOG_LIB_LOADED=1
# shellcheck disable=SC2034 # version checked by consumers
ELOG_LIB_VERSION="1.0.6"

# Config vars consulted at use site via ${VAR:-default} — safe when sourced
# from inside functions (e.g. BATS). See README.md § 3. Configuration.

_ELOG_INIT_DONE=0
_ELOG_WRITE_COUNT=0
_ELOG_AUDIT_WRITE_COUNT=0
_ELOG_RET=""
_ELOG_TRUNCATE_CHECK_INTERVAL=50

# Event context staging — set by elog_event() before dispatch, read by SIEM handlers
_ELOG_EVT_TS=""
_ELOG_EVT_TYPE=""
_ELOG_EVT_LEVEL=""
_ELOG_EVT_MSG=""
_ELOG_EVT_TAG=""
_ELOG_EVT_EXTRAS=""
_ELOG_EVT_HOST=""

# Pre-formatted SIEM lines — set by elog_event() when modules are enabled
_ELOG_STAGE_CEF=""
_ELOG_STAGE_GELF=""
_ELOG_STAGE_ELK=""

# Cached hostname — resolved once, reused for all log calls
_ELOG_HOSTNAME=""

# UDP delivery method — detected at init or first use
_ELOG_UDP_METHOD=""

# HTTP delivery method — detected at init or first use (curl, wget, or none)
_ELOG_HTTP_METHOD=""

# _elog_level_num(name) — maps level name to numeric value (unknown → info)
_elog_level_num() {
	case "${1:-info}" in
		debug)    _ELOG_RET=0 ;;
		info)     _ELOG_RET=1 ;;
		warn)     _ELOG_RET=2 ;;
		error)    _ELOG_RET=3 ;;
		critical) _ELOG_RET=4 ;;
		*)        _ELOG_RET=1 ;;
	esac
}

# _elog_level_name(num) — maps numeric value to level name
_elog_level_name() {
	case "${1:-1}" in
		0) _ELOG_RET="debug" ;;
		1) _ELOG_RET="info" ;;
		2) _ELOG_RET="warn" ;;
		3) _ELOG_RET="error" ;;
		4) _ELOG_RET="critical" ;;
		*) _ELOG_RET="info" ;;
	esac
}

# _elog_json_escape(str) — escape string for safe JSON embedding per RFC 8259 §7
# Named escapes for \ " \n \t \r \b \f, then \uXXXX sweep for remaining C0
# control chars (0x01-0x1F). NUL (0x00) unreachable: bash cannot store NUL bytes.
_elog_json_escape() {
	_ELOG_RET="$1"
	_ELOG_RET="${_ELOG_RET//\\/\\\\}"
	_ELOG_RET="${_ELOG_RET//\"/\\\"}"
	_ELOG_RET="${_ELOG_RET//$'\n'/\\n}"
	_ELOG_RET="${_ELOG_RET//$'\t'/\\t}"
	_ELOG_RET="${_ELOG_RET//$'\r'/\\r}"
	_ELOG_RET="${_ELOG_RET//$'\x08'/\\b}"
	_ELOG_RET="${_ELOG_RET//$'\x0c'/\\f}"
	local _c
	for _c in $'\x01' $'\x02' $'\x03' $'\x04' $'\x05' $'\x06' $'\x07' \
	          $'\x0b' $'\x0e' $'\x0f' $'\x10' $'\x11' $'\x12' $'\x13' $'\x14' \
	          $'\x15' $'\x16' $'\x17' $'\x18' $'\x19' $'\x1a' $'\x1b' $'\x1c' \
	          $'\x1d' $'\x1e' $'\x1f'; do
		if [[ "$_ELOG_RET" == *"$_c"* ]]; then
			local _hex
			_hex=$(printf '%04x' "'$_c")
			_ELOG_RET="${_ELOG_RET//$_c/\\u$_hex}"
		fi
	done
}

# _elog_parse_extras(extras, callback_fn) — parse space-delimited key=val pairs
# Invokes callback_fn(key, val) per valid pair; skips malformed or empty-key pairs.
_elog_parse_extras() {
	local _extras="$1" _callback="$2"
	[ -z "$_extras" ] && return 0
	local _pair _key _val
	while IFS= read -r -d ' ' _pair || [ -n "$_pair" ]; do
		_key="${_pair%%=*}"
		_val="${_pair#*=}"
		_val="${_val%$'\n'}"  # strip trailing newline from here-string
		[ "$_key" = "$_pair" ] && continue  # no = found
		[ -z "$_key" ] && continue
		"$_callback" "$_key" "$_val"
	done <<< "$_extras"
}

# _elog_extract_tag(msg) — extract {tag} prefix from message (empty if absent)
_elog_extract_tag() {
	local msg="$1"
	local tag_pat='^\{([^}]+)\}'
	if [[ "$msg" =~ $tag_pat ]]; then
		_ELOG_RET="${BASH_REMATCH[1]}"
	else
		_ELOG_RET=""
	fi
}

# _elog_strip_tag(msg) — strip {tag} prefix (and trailing space) from message
_elog_strip_tag() {
	local msg="$1"
	local tag_pat='^\{[^}]+\} '
	if [[ "$msg" =~ $tag_pat ]]; then
		_ELOG_RET="${msg#"${BASH_REMATCH[0]}"}"
	else
		_ELOG_RET="$msg"
	fi
}

# _elog_resolve_hostname — resolve and cache FQDN into _ELOG_HOSTNAME (idempotent)
_elog_resolve_hostname() {
	[ -n "$_ELOG_HOSTNAME" ] && return 0
	_ELOG_HOSTNAME=$(hostname -f 2>/dev/null || hostname -s 2>/dev/null || hostname)  # fallback chain for all target OSes
}

# elog_init() — initialize log environment; call once after setting ELOG_APP
# Auto-enables file, audit_file, and syslog_file modules — does NOT enable stdout
# (daemon-mode default). Sets ELOG_LOG_DIR/FILE/AUDIT_FILE back into env.
elog_init() {
	local _app="${ELOG_APP:-${0##*/}}"
	local _log_dir="${ELOG_LOG_DIR:-/var/log/${_app}}"
	local _log_file="${ELOG_LOG_FILE:-${_log_dir}/${_app}.log}"
	# Use ${VAR-default} (no colon) so consumers can set ELOG_AUDIT_FILE=""
	# to disable audit logging — distinguishes unset from empty
	local _audit_file="${ELOG_AUDIT_FILE-${_log_dir}/audit.log}"

	ELOG_LOG_DIR="$_log_dir"
	ELOG_LOG_FILE="$_log_file"
	ELOG_AUDIT_FILE="$_audit_file"

	# Restrictive umask during file creation (restored after)
	local _old_umask
	_old_umask=$(umask)
	umask 027

	if [ ! -d "$_log_dir" ]; then
		if ! mkdir -p "$_log_dir" 2>/dev/null; then  # suppress permission errors; failure handled below
			echo "elog_lib: failed to create log directory: $_log_dir" >&2
			umask "$_old_umask"
			return 1
		fi
		chmod 750 "$_log_dir"
	fi

	# Enforce 640 on existing files even when touch is skipped
	local _f
	for _f in "$_log_file" "$_audit_file"; do
		[ -z "$_f" ] && continue  # skip empty paths (audit disabled)
		if [ ! -f "$_f" ]; then
			touch "$_f" 2>/dev/null || {  # suppress permission errors; failure handled in || block
				echo "elog_lib: failed to create log file: $_f" >&2
				umask "$_old_umask"
				return 1
			}
		fi
		chmod 640 "$_f"
	done

	umask "$_old_umask"

	# Create legacy symlink; skip if regular file exists to avoid
	# replacing a file the consumer may be actively writing to
	if [ -n "${ELOG_LEGACY_LOG:-}" ]; then
		if [ ! -f "$ELOG_LEGACY_LOG" ]; then
			ln -sf "$_log_file" "$ELOG_LEGACY_LOG" 2>/dev/null || true  # safe: legacy symlink is optional
		fi
	fi

	if [ -n "$_log_file" ]; then
		elog_output_enable "file" 2>/dev/null || true  # safe: module may not be registered yet
	fi
	if [ -n "$_audit_file" ]; then
		elog_output_enable "audit_file" 2>/dev/null || true  # safe: module may not be registered yet
	fi
	if [ -n "${ELOG_SYSLOG_FILE:-}" ]; then
		elog_output_enable "syslog_file" 2>/dev/null || true  # safe: module may not be registered yet
	fi

	# Probe UDP transport only if syslog_udp module is actually enabled
	# (_elog_output_find always succeeds since syslog_udp is always registered;
	# lazy detection in _elog_out_syslog_udp handles post-init enablement)
	if elog_output_enabled "syslog_udp"; then
		_elog_udp_detect
	fi

	# Probe HTTP transport only if gelf or elk_json modules are actually enabled
	# (lazy detection in handlers covers post-init enablement)
	if elog_output_enabled "gelf" || elog_output_enabled "elk_json"; then
		_elog_http_detect
	fi

	_ELOG_INIT_DONE=1
	return 0
}

# elog_logrotate_snippet() — emit logrotate config to stdout (pipe to /etc/logrotate.d/<project>)
elog_logrotate_snippet() {
	local _app="${ELOG_APP:-${0##*/}}"
	local _log_dir="${ELOG_LOG_DIR:-/var/log/${_app}}"
	local _log_file="${ELOG_LOG_FILE:-${_log_dir}/${_app}.log}"
	local _audit_file="${ELOG_AUDIT_FILE-${_log_dir}/audit.log}"
	local _freq="${ELOG_ROTATE_FREQUENCY:-weekly}"
	local _count="${ELOG_ROTATE_COUNT:-12}"
	local _compress="${ELOG_ROTATE_COMPRESS:-compress}"

	# Build file list — omit audit file when audit is disabled (empty path)
	local _files="$_log_file"
	[ -n "$_audit_file" ] && _files="${_files} ${_audit_file}"

	cat <<-LOGROTATE
	${_files} {
	    ${_freq}
	    rotate ${_count}
	    ${_compress}
	    delaycompress
	    missingok
	    notifempty
	    create 640 root root
	    sharedscripts
	    postrotate
	        # Signal consumer to reopen log handles (if applicable)
	        [ -f /var/run/${_app}.pid ] && kill -HUP \$(cat /var/run/${_app}.pid) 2>/dev/null || true  # safe: PID may not exist
	    endscript
	}
	LOGROTATE
}

# _elog_truncate_check_file(file, max_lines) — truncate a log file if over limit
# Atomic: tail+cat to preserve inode (critical for inotifywait consumers).
# Refuses to truncate symlinks. Saves/restores consumer signal handlers.
_elog_truncate_check_file() {
	local _file="$1" _max="$2"
	[ "$_max" -le 0 ] 2>/dev/null && return 0  # suppress non-integer warning when unset/empty
	[ -z "$_file" ] && return 0
	[ ! -f "$_file" ] && return 0
	if [ -L "$_file" ]; then
		echo "elog_lib: refusing to truncate symlink: $_file" >&2
		return 1
	fi

	local _count
	_count=$(wc -l < "$_file")
	_count="${_count## }"
	if [ "$_count" -gt "$_max" ]; then
		local _tmpf
		_tmpf=$(mktemp "${_file}.XXXXXX") || return 0
		# Save consumer signal handlers before overriding
		local _prev_trap_hup _prev_trap_term _prev_trap_int
		_prev_trap_hup=$(trap -p HUP)
		_prev_trap_term=$(trap -p TERM)
		_prev_trap_int=$(trap -p INT)
		# shellcheck disable=SC2064
		trap "command rm -f '$_tmpf'" HUP TERM INT
		tail -n "$_max" "$_file" > "$_tmpf"
		command cat "$_tmpf" > "$_file"
		command rm -f "$_tmpf"
		# Restore consumer signal handlers; reset to default if none were set
		if [ -n "$_prev_trap_hup" ]; then eval "$_prev_trap_hup"; else trap - HUP; fi
		if [ -n "$_prev_trap_term" ]; then eval "$_prev_trap_term"; else trap - TERM; fi
		if [ -n "$_prev_trap_int" ]; then eval "$_prev_trap_int"; else trap - INT; fi
	fi
}

# _elog_truncate_check() — truncate app log if over ELOG_LOG_MAX_LINES
# Wrapper for backward compatibility; called periodically from elog().
_elog_truncate_check() {
	_elog_truncate_check_file "${ELOG_LOG_FILE:-}" "${ELOG_LOG_MAX_LINES:-0}"
}

# _elog_auto_enable — enable output modules on first use (pre-init fallback)
# Enables all 4 built-in modules (gated by file variable).
# Source filtering in _elog_dispatch prevents cross-contamination.
_elog_auto_enable() {
	[ "$_ELOG_INIT_DONE" -ne 0 ] && return 0
	if [ -n "${ELOG_LOG_FILE:-}" ] && ! elog_output_enabled "file"; then
		elog_output_enable "file" 2>/dev/null || true  # safe: module may not be registered yet
	fi
	# Note: ${:-} here is correct — treats both unset and empty as "disabled"
	# (matches the enable-gate intent, complementing ${-} default at init)
	if [ -n "${ELOG_AUDIT_FILE:-}" ] && ! elog_output_enabled "audit_file"; then
		elog_output_enable "audit_file" 2>/dev/null || true  # safe: module may not be registered yet
	fi
	if [ -n "${ELOG_SYSLOG_FILE:-}" ] && ! elog_output_enabled "syslog_file"; then
		elog_output_enable "syslog_file" 2>/dev/null || true  # safe: module may not be registered yet
	fi
	if ! elog_output_enabled "stdout"; then
		elog_output_enable "stdout" 2>/dev/null || true  # safe: module may not be registered yet
	fi
	_ELOG_INIT_DONE=1
}

# Parallel indexed arrays (no declare -A — breaks when sourced from functions)
_ELOG_OUTPUT_NAMES=()
_ELOG_OUTPUT_HANDLERS=()
_ELOG_OUTPUT_ENABLED=()
_ELOG_OUTPUT_FORMATS=()
_ELOG_OUTPUT_SOURCES=()

# _elog_output_find name — locate module index; sets _ELOG_OUTPUT_IDX (no subshell)
_elog_output_find() {
	local name="$1"
	local i
	_ELOG_OUTPUT_IDX=-1
	for i in "${!_ELOG_OUTPUT_NAMES[@]}"; do
		if [ "${_ELOG_OUTPUT_NAMES[$i]}" = "$name" ]; then
			_ELOG_OUTPUT_IDX=$i
			return 0
		fi
	done
	return 1
}

# elog_output_register name handler_fn format source — register an output module
# format ∈ {classic,json,cef,gelf,elk}; source ∈ {all,elog,event}. Starts disabled.
elog_output_register() {
	local name="$1" handler_fn="$2" format="${3:-classic}" source="${4:-all}"
	if [ -z "$name" ]; then
		echo "elog_lib: output name cannot be empty." >&2
		return 1
	fi
	if [ -z "$handler_fn" ]; then
		echo "elog_lib: handler function cannot be empty for output '$name'." >&2
		return 1
	fi
	if _elog_output_find "$name"; then
		echo "elog_lib: output '$name' already registered." >&2
		return 1
	fi
	_ELOG_OUTPUT_NAMES+=("$name")
	_ELOG_OUTPUT_HANDLERS+=("$handler_fn")
	_ELOG_OUTPUT_ENABLED+=("0")
	_ELOG_OUTPUT_FORMATS+=("$format")
	_ELOG_OUTPUT_SOURCES+=("$source")
	return 0
}

# elog_output_enable name — mark output module as active
elog_output_enable() {
	local name="$1"
	if ! _elog_output_find "$name"; then
		echo "elog_lib: output '$name' not registered." >&2
		return 1
	fi
	_ELOG_OUTPUT_ENABLED[_ELOG_OUTPUT_IDX]=1
	return 0
}

# elog_output_disable name — mark output module as inactive
elog_output_disable() {
	local name="$1"
	if ! _elog_output_find "$name"; then
		echo "elog_lib: output '$name' not registered." >&2
		return 1
	fi
	_ELOG_OUTPUT_ENABLED[_ELOG_OUTPUT_IDX]=0
	return 0
}

# elog_output_enabled name — 0 if active, 1 if disabled or not registered
elog_output_enabled() {
	local name="$1"
	if ! _elog_output_find "$name"; then
		return 1
	fi
	[ "${_ELOG_OUTPUT_ENABLED[_ELOG_OUTPUT_IDX]}" = "1" ]
}

# _elog_module_active(cached_idx) — fast O(1) enabled check using cached index
_elog_module_active() {
	[ "${_ELOG_OUTPUT_ENABLED[$1]}" = "1" ]
}

# _elog_safe_append(file, line) — append with symlink guard
# Refuses to write through symlinks to prevent log-target hijacking.
_elog_safe_append() {
	local _file="$1" _line="$2"
	if [ -L "$_file" ]; then
		echo "elog_lib: refusing to append to symlink: $_file" >&2
		return 1
	fi
	echo "$_line" >> "$_file"
}

# _elog_out_file formatted_line — append to ELOG_LOG_FILE
_elog_out_file() {
	local _line="$1"
	if [ -n "${ELOG_LOG_FILE:-}" ]; then
		_elog_safe_append "$ELOG_LOG_FILE" "$_line"
	fi
}

# _elog_out_audit formatted_line — append JSONL to ELOG_AUDIT_FILE (always JSON regardless of ELOG_FORMAT)
_elog_out_audit() {
	local _line="$1"
	if [ -n "${ELOG_AUDIT_FILE:-}" ]; then
		_elog_safe_append "$ELOG_AUDIT_FILE" "$_line"
	fi
}

# _elog_out_syslog_file formatted_line — append to ELOG_SYSLOG_FILE
_elog_out_syslog_file() {
	local _line="$1"
	if [ -n "${ELOG_SYSLOG_FILE:-}" ]; then
		_elog_safe_append "$ELOG_SYSLOG_FILE" "$_line"
	fi
}

# _elog_out_stdout line level msg stdout_flag — terminal output (ELOG_STDOUT/_PREFIX)
_elog_out_stdout() {
	local _line="$1" _level="$2" _msg="$3" _stdout_flag="${4:-}"
	local _stdout="${ELOG_STDOUT:-always}"
	local _app="${ELOG_APP:-${0##*/}}"
	local _pid="$$"

	case "$_stdout" in
		always) ;;
		never) return 0 ;;
		flag)
			[ -z "$_stdout_flag" ] && return 0
			;;
	esac

	local _prefix="${ELOG_STDOUT_PREFIX:-full}"
	case "$_prefix" in
		full)  echo "$_line" ;;
		short) echo "${_app}(${_pid}): $_msg" ;;
		none)  echo "$_msg" ;;
	esac
}

# _elog_severity_cef(level) — map elog level name to CEF severity (0-10)
_elog_severity_cef() {
	case "${1:-info}" in
		debug)    _ELOG_RET=1 ;;
		info)     _ELOG_RET=3 ;;
		warn)     _ELOG_RET=5 ;;
		error)    _ELOG_RET=7 ;;
		critical) _ELOG_RET=10 ;;
		*)        _ELOG_RET=3 ;;
	esac
}

# _elog_cef_escape_header(str) — escape pipe, backslash, and newline for CEF header fields
_elog_cef_escape_header() {
	_ELOG_RET="$1"
	_ELOG_RET="${_ELOG_RET//\\/\\\\}"
	_ELOG_RET="${_ELOG_RET//|/\\|}"
	_ELOG_RET="${_ELOG_RET//$'\n'/\\n}"
}

# _elog_cef_escape_ext(str) — escape equals, newline, backslash for CEF extension
_elog_cef_escape_ext() {
	_ELOG_RET="$1"
	_ELOG_RET="${_ELOG_RET//\\/\\\\}"
	_ELOG_RET="${_ELOG_RET//=/\\=}"
	_ELOG_RET="${_ELOG_RET//$'\n'/\\n}"
}

# _elog_fmt_cef(type, level, msg, tag, extras) — build CEF formatted string
# CEF:0|vendor|product|version|signatureId|name|severity|extension
_elog_fmt_cef() {
	local _type="$1" _level="$2" _msg="$3" _tag="${4:-}" _extras="${5:-}"
	local _vendor _product _version _sev _name _ext

	_elog_cef_escape_header "${ELOG_CEF_VENDOR:-R-fx Networks}"
	_vendor="$_ELOG_RET"
	_elog_cef_escape_header "${ELOG_CEF_PRODUCT:-${ELOG_APP:-${0##*/}}}"
	_product="$_ELOG_RET"
	_elog_cef_escape_header "${ELOG_CEF_VERSION:-${ELOG_LIB_VERSION}}"
	_version="$_ELOG_RET"
	_elog_severity_cef "$_level"
	_sev="$_ELOG_RET"

	# SignatureId: header-escape the type for defensive correctness
	local _sig_id
	_elog_cef_escape_header "$_type"
	_sig_id="$_ELOG_RET"

	# CEF Name field capped at 128 chars per spec
	local _trunc_msg="${_msg:0:128}"
	_elog_cef_escape_header "$_trunc_msg"
	_name="$_ELOG_RET"

	_ext=""
	if [ -n "$_tag" ]; then
		local _esc_tag
		_elog_cef_escape_ext "$_tag"
		_esc_tag="$_ELOG_RET"
		_ext="tag=${_esc_tag}"
	fi

	# Parse extras via shared helper — callback accesses _ext from parent scope
	# shellcheck disable=SC2317  # invoked indirectly via _elog_parse_extras
	_cef_extra_cb() {
		local _key="$1" _val="$2"
		_elog_cef_escape_ext "$_val"
		local _esc_val="$_ELOG_RET"
		_key="${_key//[= $'\n']/}"  # strip characters illegal in CEF extension keys
		[ -z "$_key" ] && return 0
		if [ -n "$_ext" ]; then
			_ext="${_ext} ${_key}=${_esc_val}"
		else
			_ext="${_key}=${_esc_val}"
		fi
	}
	_elog_parse_extras "$_extras" "_cef_extra_cb"

	echo "CEF:0|${_vendor}|${_product}|${_version}|${_sig_id}|${_name}|${_sev}|${_ext}"
}

# _elog_out_cef(line) — handler: write CEF line to ELOG_CEF_FILE
_elog_out_cef() {
	local _line="$1"
	if [ -n "${ELOG_CEF_FILE:-}" ]; then
		_elog_safe_append "$ELOG_CEF_FILE" "$_line"
	fi
}

# _elog_severity_syslog(level) — map elog level name to syslog severity (0-7)
_elog_severity_syslog() {
	case "${1:-info}" in
		critical) _ELOG_RET=2 ;;
		error)    _ELOG_RET=3 ;;
		warn)     _ELOG_RET=4 ;;
		info)     _ELOG_RET=6 ;;
		debug)    _ELOG_RET=7 ;;
		*)        _ELOG_RET=6 ;;
	esac
}

# _elog_syslog_pri(facility, severity) — compute PRI value (facility * 8 + severity)
_elog_syslog_pri() {
	local _facility="${1:-1}" _severity="${2:-6}"
	_ELOG_RET=$(( _facility * 8 + _severity ))
}

# _elog_fmt_syslog_5424(pri, ts, host, app, pid, msg) — build RFC 5424 syslog line
# Format: <PRI>1 TIMESTAMP HOSTNAME APP PID - - MSG
_elog_fmt_syslog_5424() {
	local _pri="$1" _ts="$2" _host="$3" _app="$4" _pid="$5" _msg="$6"
	echo "<${_pri}>1 ${_ts} ${_host} ${_app} ${_pid} - - ${_msg}"
}

# _elog_fmt_syslog_3164(pri, ts, host, app, pid, msg) — build RFC 3164 syslog line
# Format: <PRI>TIMESTAMP HOSTNAME APP[PID]: MSG
_elog_fmt_syslog_3164() {
	local _pri="$1" _ts="$2" _host="$3" _app="$4" _pid="$5" _msg="$6"
	echo "<${_pri}>${_ts} ${_host} ${_app}[${_pid}]: ${_msg}"
}

# _elog_udp_detect() — probe for /dev/udp and nc at init time
# Sets _ELOG_UDP_METHOD to "bash", "nc", or "none"
_elog_udp_detect() {
	# Test bash /dev/udp support — safe even if nothing listens on target
	if (echo test > /dev/udp/127.0.0.1/1) 2>/dev/null; then
		_ELOG_UDP_METHOD="bash"
	elif command -v nc >/dev/null 2>&1; then
		_ELOG_UDP_METHOD="nc"
	else
		_ELOG_UDP_METHOD="none"
		echo "elog_lib: syslog_udp: no UDP transport available (no /dev/udp, no nc)" >&2
	fi
}

# _elog_udp_send(host, port, payload) — fire-and-forget background send
_elog_udp_send() {
	local _host="$1" _port="$2" _payload="$3"
	# Fire-and-forget via background subshell — caller never blocks
	( case "$_ELOG_UDP_METHOD" in
		bash) echo "$_payload" > "/dev/udp/${_host}/${_port}" ;;
		nc)   echo "$_payload" | nc -w1 -u "$_host" "$_port" ;;
	esac ) 2>/dev/null &  # suppress errors from background delivery
}

# _elog_out_syslog_udp(line) — handler: wrap in syslog header, send via UDP
_elog_out_syslog_udp() {
	local _line="$1"

	[ -z "${ELOG_SYSLOG_UDP_HOST:-}" ] && return 0

	if [ -z "$_ELOG_UDP_METHOD" ]; then
		_elog_udp_detect
	fi
	[ "$_ELOG_UDP_METHOD" = "none" ] && return 0

	local _facility="${ELOG_SYSLOG_UDP_FACILITY:-1}"
	local _level="${_ELOG_EVT_LEVEL:-info}"
	local _sev _pri
	_elog_severity_syslog "$_level"
	_sev="$_ELOG_RET"
	_elog_syslog_pri "$_facility" "$_sev"
	_pri="$_ELOG_RET"

	local _app _pid _ts
	_elog_resolve_hostname
	local _host="$_ELOG_HOSTNAME"
	_app="${ELOG_APP:-${0##*/}}"
	_pid="$$"

	local _payload="$_line"
	local _payload_type="${ELOG_SYSLOG_UDP_PAYLOAD:-classic}"
	# cef payload falls back to classic when _ELOG_STAGE_CEF is empty (cef module disabled)
	if [ "$_payload_type" = "cef" ] && [ -n "$_ELOG_STAGE_CEF" ]; then
		_payload="$_ELOG_STAGE_CEF"
	fi

	local _syslog_line
	local _format="${ELOG_SYSLOG_UDP_FORMAT:-5424}"
	if [ "$_format" = "3164" ]; then
		_ts=$(date +"%b %e %H:%M:%S")
		_syslog_line=$(_elog_fmt_syslog_3164 "$_pri" "$_ts" "$_host" "$_app" "$_pid" "$_payload")
	else
		_ts=$(date +"%Y-%m-%dT%H:%M:%S%z")
		_syslog_line=$(_elog_fmt_syslog_5424 "$_pri" "$_ts" "$_host" "$_app" "$_pid" "$_payload")
	fi

	_elog_udp_send "${ELOG_SYSLOG_UDP_HOST}" "${ELOG_SYSLOG_UDP_PORT:-514}" "$_syslog_line"
}

# _elog_http_detect() — probe for curl/wget at init time
# Sets _ELOG_HTTP_METHOD to "curl", "wget", or "none"
_elog_http_detect() {
	if command -v curl >/dev/null 2>&1; then
		_ELOG_HTTP_METHOD="curl"
	elif command -v wget >/dev/null 2>&1; then
		_ELOG_HTTP_METHOD="wget"
	else
		_ELOG_HTTP_METHOD="none"
		echo "elog_lib: http: no HTTP transport available (no curl, no wget)" >&2
	fi
}

# _elog_http_send(url, payload, content_type) — fire-and-forget HTTP POST
_elog_http_send() {
	local _url="$1" _payload="$2" _content_type="${3:-application/json}"

	if [ -z "$_ELOG_HTTP_METHOD" ]; then
		_elog_http_detect
	fi
	[ "$_ELOG_HTTP_METHOD" = "none" ] && return 0

	# Fire-and-forget via background subshell — caller never blocks;
	# stderr suppressed: network errors are non-fatal for logging
	( case "$_ELOG_HTTP_METHOD" in
		curl) curl -sf -X POST -H "Content-Type: ${_content_type}" \
			-d "$_payload" --connect-timeout 3 --max-time 5 "$_url" ;;
		wget) wget -q --timeout=5 --header="Content-Type: ${_content_type}" \
			--post-data="$_payload" -O /dev/null "$_url" ;;
	esac ) 2>/dev/null &  # suppress errors from background HTTP delivery
}

# _elog_ts_epoch(iso_ts) — convert ISO 8601 timestamp to Unix epoch seconds
# Uses GNU date -d for ISO-to-epoch conversion (works on all 9 target OSes)
_elog_ts_epoch() {
	local _ts="$1"
	_ELOG_RET=$(date -d "$_ts" +%s 2>/dev/null || echo "0")  # fallback: epoch 0 if parse fails
}

# _elog_fmt_gelf(type, level, msg, tag, extras, ts, host) — build GELF 1.1 JSON
_elog_fmt_gelf() {
	local _type="$1" _level="$2" _msg="$3" _tag="${4:-}" _extras="${5:-}"
	local _ts="${6:-}" _host="${7:-}"
	local _sev _epoch _app _pid

	_elog_severity_syslog "$_level"
	_sev="$_ELOG_RET"
	_elog_ts_epoch "$_ts"
	_epoch="$_ELOG_RET"
	_app="${ELOG_APP:-${0##*/}}"
	_pid="$$"

	# GELF short_message capped at 256; full_message emitted only when truncated
	local _short_msg="${_msg:0:256}"
	local _esc_short _esc_host _esc_app _esc_type
	_elog_json_escape "$_short_msg"
	_esc_short="$_ELOG_RET"
	_elog_json_escape "$_host"
	_esc_host="$_ELOG_RET"
	_elog_json_escape "$_app"
	_esc_app="$_ELOG_RET"
	_elog_json_escape "$_type"
	_esc_type="$_ELOG_RET"

	local _gelf="{\"version\":\"1.1\",\"host\":\"${_esc_host}\",\"short_message\":\"${_esc_short}\""

	if [ ${#_msg} -gt 256 ]; then
		local _esc_full
		_elog_json_escape "$_msg"
		_esc_full="$_ELOG_RET"
		_gelf="${_gelf},\"full_message\":\"${_esc_full}\""
	fi

	_gelf="${_gelf},\"timestamp\":${_epoch},\"level\":${_sev}"
	_gelf="${_gelf},\"_app\":\"${_esc_app}\",\"_pid\":${_pid},\"_event_type\":\"${_esc_type}\""

	if [ -n "$_tag" ]; then
		local _esc_tag
		_elog_json_escape "$_tag"
		_esc_tag="$_ELOG_RET"
		_gelf="${_gelf},\"_tag\":\"${_esc_tag}\""
	fi

	# Parse extras via shared helper — callback accesses _gelf from parent scope
	# shellcheck disable=SC2317  # invoked indirectly via _elog_parse_extras
	_gelf_extra_cb() {
		local _key="$1" _val="$2"
		_elog_json_escape "$_key"
		local _esc_key="$_ELOG_RET"
		_elog_json_escape "$_val"
		local _esc_val="$_ELOG_RET"
		_gelf="${_gelf},\"_${_esc_key}\":\"${_esc_val}\""
	}
	_elog_parse_extras "$_extras" "_gelf_extra_cb"

	_gelf="${_gelf}}"
	echo "$_gelf"
}

# _elog_out_gelf(line) — handler: send GELF via configured transport
_elog_out_gelf() {
	local _line="$1"

	# ELOG_GELF_FILE is a capture path for testing/debug; separate from network delivery
	if [ -n "${ELOG_GELF_FILE:-}" ]; then
		_elog_safe_append "$ELOG_GELF_FILE" "$_line"
	fi

	[ -z "${ELOG_GELF_HOST:-}" ] && return 0

	local _transport="${ELOG_GELF_TRANSPORT:-udp}"
	local _port="${ELOG_GELF_PORT:-12201}"

	case "$_transport" in
		udp)
			if [ -z "$_ELOG_UDP_METHOD" ]; then
				_elog_udp_detect
			fi
			[ "$_ELOG_UDP_METHOD" = "none" ] && return 0
			_elog_udp_send "${ELOG_GELF_HOST}" "$_port" "$_line"
			;;
		http)
			_elog_http_send "http://${ELOG_GELF_HOST}:${_port}/gelf" "$_line" "application/json"
			;;
	esac
}

# _elog_ecs_category(event_type) — map elog event type to ECS event.category
_elog_ecs_category() {
	case "${1:-}" in
		threat_detected|threshold_exceeded|pattern_matched|scan_started|scan_completed)
			_ELOG_RET="intrusion_detection" ;;
		block_added|block_removed|block_escalated|quarantine_added|quarantine_removed)
			_ELOG_RET="intrusion_detection" ;;
		trust_added|trust_removed)
			_ELOG_RET="configuration" ;;
		rule_loaded|rule_removed|service_state)
			_ELOG_RET="network" ;;
		alert_sent|alert_failed)
			_ELOG_RET="notification" ;;
		monitor_started|monitor_stopped)
			_ELOG_RET="process" ;;
		config_loaded|config_error|file_cleaned|error_occurred)
			_ELOG_RET="configuration" ;;
		*)
			_ELOG_RET="event" ;;
	esac
}

# _elog_ecs_type(event_type) — map elog event type to ECS event.type
_elog_ecs_type() {
	case "${1:-}" in
		block_added|quarantine_added)
			_ELOG_RET="denied" ;;
		block_removed|quarantine_removed)
			_ELOG_RET="allowed" ;;
		block_escalated)
			_ELOG_RET="denied" ;;
		trust_added|trust_removed)
			_ELOG_RET="change" ;;
		rule_loaded)
			_ELOG_RET="connection" ;;
		rule_removed)
			_ELOG_RET="connection" ;;
		service_state|monitor_started)
			_ELOG_RET="start" ;;
		monitor_stopped)
			_ELOG_RET="end" ;;
		config_loaded|file_cleaned)
			_ELOG_RET="change" ;;
		config_error|error_occurred|alert_failed)
			_ELOG_RET="error" ;;
		*)
			_ELOG_RET="info" ;;
	esac
}

# _elog_fmt_elk(type, level, msg, tag, extras, ts, host) — build ECS-aligned JSON
_elog_fmt_elk() {
	local _type="$1" _level="$2" _msg="$3" _tag="${4:-}" _extras="${5:-}"
	local _ts="${6:-}" _host="${7:-}"
	local _app _pid _category _ecs_type

	_app="${ELOG_APP:-${0##*/}}"
	_pid="$$"
	_elog_ecs_category "$_type"
	_category="$_ELOG_RET"
	_elog_ecs_type "$_type"
	_ecs_type="$_ELOG_RET"

	local _esc_ts _esc_level _esc_msg _esc_host _esc_app _esc_type
	local _esc_category _esc_ecs_type
	_elog_json_escape "$_ts"
	_esc_ts="$_ELOG_RET"
	_elog_json_escape "$_level"
	_esc_level="$_ELOG_RET"
	_elog_json_escape "$_msg"
	_esc_msg="$_ELOG_RET"
	_elog_json_escape "$_host"
	_esc_host="$_ELOG_RET"
	_elog_json_escape "$_app"
	_esc_app="$_ELOG_RET"
	_elog_json_escape "$_type"
	_esc_type="$_ELOG_RET"
	_elog_json_escape "$_category"
	_esc_category="$_ELOG_RET"
	_elog_json_escape "$_ecs_type"
	_esc_ecs_type="$_ELOG_RET"

	local _elk="{\"@timestamp\":\"${_esc_ts}\",\"log.level\":\"${_esc_level}\",\"message\":\"${_esc_msg}\""
	_elk="${_elk},\"event.kind\":\"event\",\"event.category\":\"${_esc_category}\""
	_elk="${_elk},\"event.type\":\"${_esc_ecs_type}\",\"event.action\":\"${_esc_type}\""
	_elk="${_elk},\"host.name\":\"${_esc_host}\",\"process.name\":\"${_esc_app}\",\"process.pid\":${_pid}"

	if [ -n "$_tag" ]; then
		local _esc_tag
		_elog_json_escape "$_tag"
		_esc_tag="$_ELOG_RET"
		_elk="${_elk},\"tags\":[\"${_esc_tag}\"]"
	fi

	# Parse extras via shared helper — callback accesses _labels, _elk from parent scope
	local _labels=""
	# shellcheck disable=SC2317  # invoked indirectly via _elog_parse_extras
	_elk_extra_cb() {
		local _key="$1" _val="$2"
		_elog_json_escape "$_key"
		local _esc_key="$_ELOG_RET"
		_elog_json_escape "$_val"
		local _esc_val="$_ELOG_RET"
		if [ -n "$_labels" ]; then
			_labels="${_labels},\"${_esc_key}\":\"${_esc_val}\""
		else
			_labels="\"${_esc_key}\":\"${_esc_val}\""
		fi
	}
	_elog_parse_extras "$_extras" "_elk_extra_cb"
	if [ -n "$_labels" ]; then
		_elk="${_elk},\"labels\":{${_labels}}"
	fi

	_elk="${_elk}}"
	echo "$_elk"
}

# _elog_out_elk_json(line) — handler: send ECS JSON via HTTP to Elasticsearch
_elog_out_elk_json() {
	local _line="$1"

	# ELOG_ELK_FILE is a capture path for testing/debug; separate from network delivery
	if [ -n "${ELOG_ELK_FILE:-}" ]; then
		_elog_safe_append "$ELOG_ELK_FILE" "$_line"
	fi

	[ -z "${ELOG_ELK_URL:-}" ] && return 0

	local _index="${ELOG_ELK_INDEX:-elog-events}"
	_elog_http_send "${ELOG_ELK_URL}/${_index}/_doc" "$_line" "application/json"
}

# _elog_dispatch api_source classic json level msg stdout_flag — route to enabled modules
# api_source ∈ {elog,event}; modules with source="all" receive both streams
_elog_dispatch() {
	local _api="$1" _classic="$2" _json="$3" _level="$4" _msg="$5" _stdout_flag="${6:-}"
	local _i _name _handler _enabled _format _source _line

	for _i in "${!_ELOG_OUTPUT_NAMES[@]}"; do
		_enabled="${_ELOG_OUTPUT_ENABLED[$_i]}"
		[ "$_enabled" = "1" ] || continue

		_source="${_ELOG_OUTPUT_SOURCES[$_i]}"
		# Source filter: "all" accepts both, otherwise must match
		if [ "$_source" != "all" ] && [ "$_source" != "$_api" ]; then
			continue
		fi

		_name="${_ELOG_OUTPUT_NAMES[$_i]}"
		_handler="${_ELOG_OUTPUT_HANDLERS[$_i]}"
		_format="${_ELOG_OUTPUT_FORMATS[$_i]}"

		case "$_format" in
			json)    _line="$_json" ;;
			cef)     _line="$_ELOG_STAGE_CEF" ;;
			gelf)    _line="$_ELOG_STAGE_GELF" ;;
			elk)     _line="$_ELOG_STAGE_ELK" ;;
			*)       _line="$_classic" ;;
		esac

		# stdout handler gets extra args for prefix handling
		if [ "$_name" = "stdout" ]; then
			"$_handler" "$_line" "$_level" "$_msg" "$_stdout_flag"
		else
			"$_handler" "$_line"
		fi
	done
}

# _elog_event_type_valid(type) — 0 for known event types, 1 for unknown
# Guidance only: elog_event() does not enforce; consumers may pass unknown types.
_elog_event_type_valid() {
	case "${1:-}" in
		threat_detected|threshold_exceeded|pattern_matched|scan_started|scan_completed)
			return 0 ;;
		block_added|block_removed|block_escalated|quarantine_added|quarantine_removed)
			return 0 ;;
		trust_added|trust_removed)
			return 0 ;;
		rule_loaded|rule_removed|service_state)
			return 0 ;;
		alert_sent|alert_failed)
			return 0 ;;
		monitor_started|monitor_stopped)
			return 0 ;;
		config_loaded|config_error|file_cleaned|error_occurred)
			return 0 ;;
		*)
			return 1 ;;
	esac
}

# _elog_event_severity(type) — default severity name for event type
# No types default to "critical" — consumers must escalate explicitly.
_elog_event_severity() {
	case "${1:-}" in
		block_escalated|alert_failed|config_error|error_occurred)
			echo "error" ;;
		threat_detected|threshold_exceeded|block_added|quarantine_added)
			echo "warn" ;;
		*)
			echo "info" ;;
	esac
}

# elog(level, message [, stdout_flag]) — primary logging API (BFD v1.0.0 compatible)
# debug: stdout-only bare text, gated by ELOG_VERBOSE=1 (bypasses ELOG_LEVEL).
# Always returns 0 — logging must never propagate failure to the caller.
elog() {
	local _level="${1:-info}"
	local _msg="${2:-}"
	local _stdout_flag="${3:-}"

	[ -z "$_msg" ] && return 0

	_elog_level_num "$_level"
	local _level_num="$_ELOG_RET"

	# debug bypasses ELOG_LEVEL filtering — ELOG_VERBOSE is its own independent gate
	if [ "$_level_num" -eq 0 ]; then
		if [ "${ELOG_VERBOSE:-0}" = "1" ]; then
			echo "$_msg"
		fi
		return 0
	fi

	local _min_level="${ELOG_LEVEL:-1}"

	[ "$_level_num" -lt "$_min_level" ] && return 0

	# Backward-compat: auto-enable modules when consumer did not call elog_init
	_elog_auto_enable

	local _ts _host _app _pid _iso_ts
	local _both_ts
	_both_ts=$(date +"${ELOG_TS_FORMAT:-%b %e %H:%M:%S}|%Y-%m-%dT%H:%M:%S%z")
	_ts="${_both_ts%%|*}"
	_iso_ts="${_both_ts#*|}"
	_elog_resolve_hostname
	_host="$_ELOG_HOSTNAME"
	_app="${ELOG_APP:-${0##*/}}"
	_pid="$$"

	# Sanitize newlines in classic line to prevent log injection
	local _classic_msg="${_msg//$'\n'/\\n}"
	local _classic_line
	_classic_line="$_ts $_host ${_app}(${_pid}): $_classic_msg"

	local _json_line _esc_msg _tag _esc_tag _json_msg
	_elog_extract_tag "$_msg"
	_tag="$_ELOG_RET"
	if [ -n "$_tag" ]; then
		_elog_strip_tag "$_msg"
		_json_msg="$_ELOG_RET"
	else
		_json_msg="$_msg"
	fi
	_elog_json_escape "$_json_msg"
	_esc_msg="$_ELOG_RET"
	local _esc_host _esc_app _esc_level
	_elog_json_escape "$_host"
	_esc_host="$_ELOG_RET"
	_elog_json_escape "$_app"
	_esc_app="$_ELOG_RET"
	_elog_json_escape "$_level"
	_esc_level="$_ELOG_RET"
	if [ -n "$_tag" ]; then
		_elog_json_escape "$_tag"
		_esc_tag="$_ELOG_RET"
		_json_line="{\"ts\":\"${_iso_ts}\",\"host\":\"${_esc_host}\",\"app\":\"${_esc_app}\",\"pid\":${_pid},\"level\":\"${_esc_level}\",\"tag\":\"${_esc_tag}\",\"msg\":\"${_esc_msg}\"}"
	else
		_json_line="{\"ts\":\"${_iso_ts}\",\"host\":\"${_esc_host}\",\"app\":\"${_esc_app}\",\"pid\":${_pid},\"level\":\"${_esc_level}\",\"msg\":\"${_esc_msg}\"}"
	fi

	local _fmt="${ELOG_FORMAT:-classic}"
	local _out_classic _out_json
	if [ "$_fmt" = "json" ]; then
		_out_classic="$_json_line"
	else
		_out_classic="$_classic_line"
	fi
	_out_json="$_json_line"
	# Stage level for SIEM handlers (syslog_udp reads _ELOG_EVT_LEVEL)
	_ELOG_EVT_LEVEL="$_level"
	_elog_dispatch "elog" "$_out_classic" "$_out_json" "$_level" "$_msg" "$_stdout_flag"
	_ELOG_EVT_LEVEL=""

	_ELOG_WRITE_COUNT=$((_ELOG_WRITE_COUNT + 1))
	if [ $((_ELOG_WRITE_COUNT % _ELOG_TRUNCATE_CHECK_INTERVAL)) -eq 0 ]; then
		_elog_truncate_check
	fi

	return 0
}

elog_debug() { elog debug "$@"; }
elog_info()  { elog info "$@"; }
elog_warn()  { elog warn "$@"; }
elog_error() { elog error "$@"; }
elog_critical() { elog critical "$@"; }

# elog_event(event_type, severity, message [, key=val ...]) — structured event API
# Dispatches via api_source="event" to audit_file and modules registered with
# source="event"|"all". Extra values must NOT contain spaces (space-delimited
# internal format). Empty type returns 1; everything else returns 0.
elog_event() {
	local _type="${1:-}"
	local _level="${2:-info}"
	local _msg="${3:-}"

	if [ -z "$_type" ]; then
		echo "elog_lib: elog_event() requires event_type as first argument" >&2
		return 1
	fi

	[ -z "$_msg" ] && return 0

	_elog_level_num "$_level"
	local _level_num="$_ELOG_RET"
	local _min_level="${ELOG_LEVEL:-1}"
	[ "$_level_num" -lt "$_min_level" ] && return 0

	_elog_auto_enable

	local _ts _host _app _pid _iso_ts
	local _both_ts
	_both_ts=$(date +"${ELOG_TS_FORMAT:-%b %e %H:%M:%S}|%Y-%m-%dT%H:%M:%S%z")
	_ts="${_both_ts%%|*}"
	_iso_ts="${_both_ts#*|}"
	_elog_resolve_hostname
	_host="$_ELOG_HOSTNAME"
	_app="${ELOG_APP:-${0##*/}}"
	_pid="$$"

	local _tag _json_msg
	_elog_extract_tag "$_msg"
	_tag="$_ELOG_RET"
	if [ -n "$_tag" ]; then
		_elog_strip_tag "$_msg"
		_json_msg="$_ELOG_RET"
	else
		_json_msg="$_msg"
	fi

	local _esc_msg _esc_type
	_elog_json_escape "$_json_msg"
	_esc_msg="$_ELOG_RET"
	_elog_json_escape "$_type"
	_esc_type="$_ELOG_RET"
	local _esc_host _esc_app _esc_level
	_elog_json_escape "$_host"
	_esc_host="$_ELOG_RET"
	_elog_json_escape "$_app"
	_esc_app="$_ELOG_RET"
	_elog_json_escape "$_level"
	_esc_level="$_ELOG_RET"

	# Build JSON extras and raw SIEM extras in a single pass to avoid re-parsing
	local _pair _key _val _esc_key _esc_val _extra="" _raw_extras=""
	shift 3 2>/dev/null || true  # safe: fewer than 3 args means no extras
	for _pair in "$@"; do
		_key="${_pair%%=*}"
		_val="${_pair#*=}"
		[ "$_key" = "$_pair" ] && continue  # no = found
		[ -z "$_key" ] && continue           # empty key
		_elog_json_escape "$_key"
		_esc_key="$_ELOG_RET"
		_elog_json_escape "$_val"
		_esc_val="$_ELOG_RET"
		_extra="${_extra},\"${_esc_key}\":\"${_esc_val}\""
		# SIEM handlers consume raw (unescaped) extras in space-separated key=value form
		if [ -n "$_raw_extras" ]; then
			_raw_extras="${_raw_extras} ${_key}=${_val}"
		else
			_raw_extras="${_key}=${_val}"
		fi
	done

	local _json_line
	_json_line="{\"ts\":\"${_iso_ts}\",\"host\":\"${_esc_host}\",\"app\":\"${_esc_app}\",\"pid\":${_pid},\"type\":\"${_esc_type}\",\"level\":\"${_esc_level}\",\"msg\":\"${_esc_msg}\""
	if [ -n "$_tag" ]; then
		local _esc_tag
		_elog_json_escape "$_tag"
		_esc_tag="$_ELOG_RET"
		_json_line="${_json_line},\"tag\":\"${_esc_tag}\""
	fi
	_json_line="${_json_line}${_extra}}"

	# Sanitize newlines in classic line to prevent log injection
	local _classic_msg="${_json_msg//$'\n'/\\n}"
	local _classic_line
	if [ -n "$_tag" ]; then
		_classic_line="$_ts $_host ${_app}(${_pid}): [${_type}] {${_tag}} ${_classic_msg}"
	else
		_classic_line="$_ts $_host ${_app}(${_pid}): [${_type}] ${_classic_msg}"
	fi

	# Stage event context for SIEM handlers (CEF, syslog_udp)
	_ELOG_EVT_TS="$_iso_ts"
	_ELOG_EVT_TYPE="$_type"
	_ELOG_EVT_LEVEL="$_level"
	_ELOG_EVT_MSG="$_json_msg"
	_ELOG_EVT_TAG="$_tag"
	_ELOG_EVT_HOST="$_host"
	_ELOG_EVT_EXTRAS="$_raw_extras"

	# Pre-format SIEM lines if modules are enabled (avoid overhead otherwise)
	_ELOG_STAGE_CEF=""
	if _elog_module_active "$_ELOG_IDX_CEF"; then
		_ELOG_STAGE_CEF=$(_elog_fmt_cef "$_type" "$_level" "$_json_msg" "$_tag" "$_ELOG_EVT_EXTRAS")
	fi
	_ELOG_STAGE_GELF=""
	if _elog_module_active "$_ELOG_IDX_GELF"; then
		_ELOG_STAGE_GELF=$(_elog_fmt_gelf "$_type" "$_level" "$_json_msg" "$_tag" "$_ELOG_EVT_EXTRAS" "$_iso_ts" "$_host")
	fi
	_ELOG_STAGE_ELK=""
	if _elog_module_active "$_ELOG_IDX_ELK"; then
		_ELOG_STAGE_ELK=$(_elog_fmt_elk "$_type" "$_level" "$_json_msg" "$_tag" "$_ELOG_EVT_EXTRAS" "$_iso_ts" "$_host")
	fi

	# Dispatch via event api_source — reaches audit_file and source="all" modules
	_elog_dispatch "event" "$_classic_line" "$_json_line" "$_level" "$_msg" ""

	_ELOG_AUDIT_WRITE_COUNT=$((_ELOG_AUDIT_WRITE_COUNT + 1))
	if [ $((_ELOG_AUDIT_WRITE_COUNT % _ELOG_TRUNCATE_CHECK_INTERVAL)) -eq 0 ]; then
		_elog_truncate_check_file "${ELOG_AUDIT_FILE:-}" "${ELOG_AUDIT_MAX_LINES:-0}"
	fi

	_ELOG_EVT_TS=""
	_ELOG_EVT_TYPE=""
	_ELOG_EVT_LEVEL=""
	_ELOG_EVT_MSG=""
	_ELOG_EVT_TAG=""
	_ELOG_EVT_EXTRAS=""
	_ELOG_EVT_HOST=""
	_ELOG_STAGE_CEF=""
	_ELOG_STAGE_GELF=""
	_ELOG_STAGE_ELK=""

	return 0
}

# Built-in output modules — consumers enable via elog_output_enable or elog_init
elog_output_register "file" "_elog_out_file" "classic" "elog"
elog_output_register "audit_file" "_elog_out_audit" "json" "event"
elog_output_register "syslog_file" "_elog_out_syslog_file" "classic" "elog"
elog_output_register "stdout" "_elog_out_stdout" "classic" "all"
# SIEM output modules — disabled by default, consumers enable with elog_output_enable
elog_output_register "cef" "_elog_out_cef" "cef" "event"
elog_output_register "syslog_udp" "_elog_out_syslog_udp" "classic" "all"
elog_output_register "gelf" "_elog_out_gelf" "gelf" "event"
elog_output_register "elk_json" "_elog_out_elk_json" "elk" "event"

# Cache indices for frequently-checked modules (avoids linear scan per check)
_elog_output_find "cef"; _ELOG_IDX_CEF=$_ELOG_OUTPUT_IDX
_elog_output_find "gelf"; _ELOG_IDX_GELF=$_ELOG_OUTPUT_IDX
_elog_output_find "elk_json"; _ELOG_IDX_ELK=$_ELOG_OUTPUT_IDX
