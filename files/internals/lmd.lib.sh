#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC1090,SC1091
##
# Linux Malware Detect v2.0.1
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
# Central sourcing hub — loads all vendored libs, sub-libraries, and config.
# Requires: internals.conf already sourced (provides $inspath, $tlog_lib, etc.)

# Source guard
[[ -n "${_LMD_LIB_LOADED:-}" ]] && return 0 2>/dev/null
_LMD_LIB_LOADED=1

# Resolve internals directory from this file's location
_internals_dir="${BASH_SOURCE[0]%/*}"

##
# Exit code constants
# 0 = success
# 1 = error (missing dependency, invalid args, runtime failure)
# 2 = malware found (scan completed with hits)
##

## elog_lib event taxonomy constants
# shellcheck disable=SC2034
ELOG_EVT_CONFIG_LOADED="config_loaded"
# shellcheck disable=SC2034
ELOG_EVT_SCAN_STARTED="scan_started"
# shellcheck disable=SC2034
ELOG_EVT_SCAN_COMPLETED="scan_completed"
# shellcheck disable=SC2034
ELOG_EVT_THREAT_DETECTED="threat_detected"
# shellcheck disable=SC2034
ELOG_EVT_QUARANTINE_ADDED="quarantine_added"
# shellcheck disable=SC2034
ELOG_EVT_QUARANTINE_REMOVED="quarantine_removed"
# shellcheck disable=SC2034
ELOG_EVT_FILE_CLEANED="file_cleaned"
# shellcheck disable=SC2034
ELOG_EVT_MONITOR_STARTED="monitor_started"
# shellcheck disable=SC2034
ELOG_EVT_MONITOR_STOPPED="monitor_stopped"
# shellcheck disable=SC2034
ELOG_EVT_ALERT_SENT="alert_sent"
# shellcheck disable=SC2034
ELOG_EVT_ALERT_FAILED="alert_failed"
# shellcheck disable=SC2034
ELOG_EVT_PURGE_COMPLETED="purge_completed"
# shellcheck disable=SC2034
ELOG_EVT_RATE_LIMITED="threshold_exceeded"  # reuse upstream type for hook rate limiting
# shellcheck disable=SC2034
ELOG_EVT_UPDATE_COMPLETED="update_completed"
# shellcheck disable=SC2034
ELOG_EVT_UPDATE_FAILED="update_failed"
# shellcheck disable=SC2034
ELOG_EVT_UPDATE_STARTED="update_started"
# shellcheck disable=SC2034
ELOG_EVT_HOOK_STARTED="hook_started"
# shellcheck disable=SC2034
ELOG_EVT_HOOK_COMPLETED="hook_completed"
# shellcheck disable=SC2034
ELOG_EVT_HOOK_FAILED="hook_failed"
# shellcheck disable=SC2034
ELOG_EVT_HOOK_TIMEOUT="hook_timeout"

## Shared utility functions
# These are used across multiple sub-libraries and must be defined before
# any sub-library is sourced.

lbreakifs() {
	if [ "$1" == "set" ]; then
		IFS=$'\n'
	else
		unset IFS
	fi
}

_build_nice_command() {
	local _cpunice="$1" _ionice_val="$2" _cpulimit_val="$3"
	nice_command=""
	if [ -f "$nice" ]; then
		nice_command="$nice -n $_cpunice"
	fi
	if [ -f "$ionice" ] && [ ! -d "/proc/vz" ]; then
		nice_command="$nice_command $ionice -c2 -n $_ionice_val"
	fi
	if [ -f "$cpulimit" ] && [ "$_cpulimit_val" -gt 0 ] 2>/dev/null; then
		local max_cpulimit
		max_cpulimit=$(( $(grep -E -w processor /proc/cpuinfo -c) * 100 ))
		if [ "$_cpulimit_val" -le "$max_cpulimit" ]; then
			nice_command="$cpulimit -l $_cpulimit_val -- $nice_command"
		fi
	fi
}

_require_bin() {
	if [ -z "$2" ]; then
		header
		echo "could not find required binary $1, aborting."
		exit 1
	fi
}

eout() {
	# Sync dynamic log path (--user flag changes $maldet_log after init)
	ELOG_LOG_FILE="$maldet_log"
	if command -v elog >/dev/null 2>&1; then
		elog info "$1" "$2"
	else
		# Fallback if elog_lib not loaded
		echo "$(date +"%b %d %Y %H:%M:%S") $(hostname -s) maldet($$): $1" >> "$maldet_log"
		if [ -n "$2" ]; then echo "maldet($$): $1"; fi
	fi
}

get_filestat() {
	file="$1"
	times="$2"
	local _statout
	if [ "$os_freebsd" == "1" ]; then
		if [ "$times" ]; then
			_statout="$($stat -f '%Su:%Sg:%p:%Z:%a:%m:%c' "$file")"
		else
			_statout="$($stat -f '%Su:%Sg:%p:%Z' "$file")"
		fi
		file_owner="${_statout%%:*}"; _statout="${_statout#*:}"
		file_group="${_statout%%:*}"; _statout="${_statout#*:}"
		file_mode="${_statout%%:*}"; file_mode="${file_mode#?}"; _statout="${_statout#*:}"
		file_size="${_statout%%:*}"
		if [ "$times" ]; then
			file_times="${_statout#*:}"
		fi
	else
		if [ "$times" ]; then
			_statout="$($stat -c '%U:%G:%a:%s:%X:%Y:%Z' "$file")"
		else
			_statout="$($stat -c '%U:%G:%a:%s' "$file")"
		fi
		file_owner="${_statout%%:*}"; _statout="${_statout#*:}"
		file_group="${_statout%%:*}"; _statout="${_statout#*:}"
		file_mode="${_statout%%:*}"; _statout="${_statout#*:}"
		file_size="${_statout%%:*}"
		if [ "$times" ]; then
			file_times="${_statout#*:}"
		fi
	fi
	local _md5out
	_md5out="$($md5sum "$file")"
	md5_hash="${_md5out%% *}"
}

# Backslash MUST be escaped first — subsequent substitutions insert \ characters
# that would otherwise get double-escaped.
#
# Two call patterns:
#   $(_json_escape_string "$x")   — readable; forks a subshell (use in cold paths)
#   _json_escape_var "$x"; use "$_JSON_ESC_OUT"  — zero forks (hot loops)
_json_escape_var() {
	_JSON_ESC_OUT="${1//\\/\\\\}"
	_JSON_ESC_OUT="${_JSON_ESC_OUT//\"/\\\"}"
	_JSON_ESC_OUT="${_JSON_ESC_OUT//$'\t'/\\t}"
	_JSON_ESC_OUT="${_JSON_ESC_OUT//$'\r'/\\r}"
	_JSON_ESC_OUT="${_JSON_ESC_OUT//$'\n'/\\n}"
}

_json_escape_string() {
	_json_escape_var "$1"
	printf '%s' "$_JSON_ESC_OUT"
}

## Source vendored libraries

if [ -f "$tlog_lib" ]; then
	source "$tlog_lib"
else
	header
	echo "maldet($$): {glob} \$tlog_lib not found, aborting." >&2
	exit 1
fi

if [ -f "$alert_lib" ]; then
	source "$alert_lib"
else
	header
	echo "maldet($$): {glob} \$alert_lib not found, aborting." >&2
	exit 1
fi

if [ -f "$lmd_alert_lib" ]; then
	source "$lmd_alert_lib"
else
	header
	echo "maldet($$): {glob} \$lmd_alert_lib not found, aborting." >&2
	exit 1
fi

# elog_lib is optional — LMD works without it
if [ -f "$elog_lib" ]; then
	. "$elog_lib"
fi

## Source configuration

if [ -f "$cnf" ]; then
	source "$cnf"
else
	header
	echo "maldet($$): {glob} \$cnf not found, aborting." >&2
	exit 1
fi

## Source LMD sub-libraries

if [ -f "$_internals_dir/lmd_config.sh" ]; then
	source "$_internals_dir/lmd_config.sh"
else
	header
	echo "maldet($$): {glob} lmd_config.sh not found, aborting." >&2
	exit 1
fi

if [ -f "$_internals_dir/lmd_init.sh" ]; then
	source "$_internals_dir/lmd_init.sh"
else
	header
	echo "maldet($$): {glob} lmd_init.sh not found, aborting." >&2
	exit 1
fi

if [ -f "$_internals_dir/lmd_clamav.sh" ]; then
	source "$_internals_dir/lmd_clamav.sh"
else
	header
	echo "maldet($$): {glob} lmd_clamav.sh not found, aborting." >&2
	exit 1
fi

if [ -f "$_internals_dir/lmd_sigs.sh" ]; then
	source "$_internals_dir/lmd_sigs.sh"
else
	header
	echo "maldet($$): {glob} lmd_sigs.sh not found, aborting." >&2
	exit 1
fi

if [ -f "$_internals_dir/lmd_engine.sh" ]; then
	source "$_internals_dir/lmd_engine.sh"
else
	header
	echo "maldet($$): {glob} lmd_engine.sh not found, aborting." >&2
	exit 1
fi

if [ -f "$_internals_dir/lmd_yara.sh" ]; then
	source "$_internals_dir/lmd_yara.sh"
else
	header
	echo "maldet($$): {glob} lmd_yara.sh not found, aborting." >&2
	exit 1
fi

if [ -f "$_internals_dir/lmd_quarantine.sh" ]; then
	source "$_internals_dir/lmd_quarantine.sh"
else
	header
	echo "maldet($$): {glob} lmd_quarantine.sh not found, aborting." >&2
	exit 1
fi

if [ -f "$_internals_dir/lmd_session.sh" ]; then
	source "$_internals_dir/lmd_session.sh"
else
	header
	echo "maldet($$): {glob} lmd_session.sh not found, aborting." >&2
	exit 1
fi

if [ -f "$_internals_dir/lmd_lifecycle.sh" ]; then
	source "$_internals_dir/lmd_lifecycle.sh"
else
	header
	echo "maldet($$): {glob} lmd_lifecycle.sh not found, aborting." >&2
	exit 1
fi

if [ -f "$_internals_dir/lmd_scan.sh" ]; then
	source "$_internals_dir/lmd_scan.sh"
else
	header
	echo "maldet($$): {glob} lmd_scan.sh not found, aborting." >&2
	exit 1
fi

# lmd_hook.sh is optional — hook feature degrades gracefully if absent
if [ -f "$_internals_dir/lmd_hook.sh" ]; then
	source "$_internals_dir/lmd_hook.sh"
fi

if [ -f "$_internals_dir/lmd_monitor.sh" ]; then
	source "$_internals_dir/lmd_monitor.sh"
else
	header
	echo "maldet($$): {glob} lmd_monitor.sh not found, aborting." >&2
	exit 1
fi

if [ -f "$_internals_dir/lmd_update.sh" ]; then
	source "$_internals_dir/lmd_update.sh"
else
	header
	echo "maldet($$): {glob} lmd_update.sh not found, aborting." >&2
	exit 1
fi

## Source optional configuration overlays

if [ -f "$compatcnf" ]; then
	source "$compatcnf"
fi

if [ -n "${syscnf:-}" ] && [ -f "$syscnf" ]; then
	source "$syscnf"
fi
