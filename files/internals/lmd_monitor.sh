#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC1090,SC1091
##
# Linux Malware Detect v2.0.1
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
# Monitor mode — supervisor, cycle tick, and housekeeping

# Source guard
[[ -n "${_LMD_MONITOR_LOADED:-}" ]] && return 0 2>/dev/null
_LMD_MONITOR_LOADED=1

_monitor_parse_interval() {
	# Parse a digest_interval value (Nh, Nm, Nd, 0) into seconds.
	# Prints seconds to stdout. Returns 1 on invalid input.
	local _val="$1"
	if [ -z "$_val" ]; then
		return 1
	fi
	if [ "$_val" = "0" ]; then
		echo "0"
		return 0
	fi
	local _num _suffix
	_num="${_val%[hHmMdD]}"
	_suffix="${_val##*[0-9]}"
	# Validate: numeric part must be all digits, suffix must be exactly 1 char
	if [ -z "$_num" ] || [ -z "$_suffix" ] || ! [[ "$_num" =~ ^[0-9]+$ ]]; then
		return 1
	fi
	case "$_suffix" in
		h|H) echo "$((_num * 3600))" ;;
		m|M) echo "$((_num * 60))" ;;
		d|D) echo "$((_num * 86400))" ;;
		*) return 1 ;;
	esac
}

_monitor_escape_ere() {
	# Escape POSIX ERE metacharacters in a string for safe use in
	# inotifywait --exclude regex. Characters: . + * ? ( ) [ ] { } | \ ^ $
	local _str="$1"
	# Backslash must be escaped first (before we add more backslashes)
	_str="${_str//\\/\\\\}"
	_str="${_str//./\\.}"
	_str="${_str//+/\\+}"
	_str="${_str//\*/\\*}"
	_str="${_str//\?/\\?}"
	_str="${_str//\(/\\(}"
	_str="${_str//\)/\\)}"
	_str="${_str//\[/\\[}"
	_str="${_str//\]/\\]}"
	# shellcheck disable=SC1083
	_str="${_str//\{/\\{}"
	# bash 4.2 misparses } in replacement — use variable (CLAUDE.md §Shell Portability)
	local _rep_close_brace='\\}'
	# shellcheck disable=SC1083
	_str="${_str//\}/$_rep_close_brace}"
	_str="${_str//|/\\|}"
	_str="${_str//^/\\^}"
	_str="${_str//\$/\\\$}"
	echo "$_str"
}

_monitor_to_ere_entry() {
	# Semantic dispatch for ignore_inotify entry preparation.
	# $1=entry $2=source (user|defaults)
	# source=defaults      → always escape (curated substrings; safe default)
	# source=user, literal: → strip prefix, escape remainder (opt-in literal mode)
	# source=user, no prefix → return entry unchanged (raw ERE; v1.6.6 semantics)
	local _entry="$1" _source="$2"
	case "$_source" in
		defaults) _monitor_escape_ere "$_entry" ;;
		user)
			case "$_entry" in
				literal:*)
					local _lit="${_entry#literal:}"
					[ -z "$_lit" ] && return 0  # empty after prefix — skip
					_monitor_escape_ere "$_lit"
					;;
				*) printf '%s\n' "$_entry" ;;
			esac
			;;
		*) return 1 ;;  # unknown source — fail loud
	esac
}

_monitor_filter_events() {
	# Extract + dedupe CREATE/MODIFY/MOVED_TO event paths from inotifywait
	# stdin. Ignore-path filtering is applied downstream via grep -E -vf
	# (see call site in monitor_cycle; matches scan-mode ERE semantics).
	awk '
		/ CREATE| MODIFY| MOVED_TO/ {
			if (match($0, / (CREATE|MODIFY|MOVED_TO)[^ ]* [0-9][0-9]* [A-Za-z][A-Za-z]* [0-9:][0-9:]*$/)) {
				path = substr($0, 1, RSTART - 1)
				if (path == "" || seen[path]++) next
				print path
			}
		}
	'
}

_monitor_append_extra_paths() {
	# Append valid directories from monitor_paths_extra file to the
	# inotify watch list file. Skips blank lines, comments, and
	# non-directory paths.
	local _extra_file="$1" _fpaths_file="$2"
	if [ ! -f "$_extra_file" ] || [ ! -s "$_extra_file" ]; then
		return 0
	fi
	local _line
	while IFS= read -r _line || [ -n "$_line" ]; do
		# Skip blank lines and comments
		case "$_line" in
			''|\#*) continue ;;
		esac
		if [ -d "$_line" ]; then
			echo "$_line" >> "$_fpaths_file"
			eout "{mon} added $_line to inotify monitoring array (extra paths)" 1
		else
			eout "{mon} ignored invalid extra path: $_line" 1
		fi
	done < "$_extra_file"
}

_monitor_load_ignore_inotify_union() {
	# Union user ignore_inotify + ignore_inotify.defaults. Emit prefixed
	# tuples ("u:<entry>" / "d:<entry>") for downstream semantic dispatch.
	# Skip blanks and '#' comments; dedupe the combined prefixed stream.
	# See issue #480 (two-file defaults) and #484 (source-tag semantics).
	local _user="$1" _defaults="$2" _f _prefix _line
	for _f in "$_user" "$_defaults"; do
		[ -f "$_f" ] && [ -s "$_f" ] || continue
		case "$_f" in
			"$_user")     _prefix="u:" ;;
			"$_defaults") _prefix="d:" ;;
		esac
		while IFS= read -r _line || [ -n "$_line" ]; do
			case "$_line" in
				''|\#*) continue ;;
			esac
			printf '%s%s\n' "$_prefix" "$_line"
		done < "$_f"
	done | awk '!seen[$0]++'
}

_monitor_shutdown() {
	# Supervisor shutdown handler. Called on SIGTERM/SIGINT.
	# Kills inotifywait child, finalizes session, cleans temps.
	if [ "$_monitor_stopping" = "1" ]; then
		return  # prevent re-entrant shutdown
	fi
	_monitor_stopping=1
	if [ -n "$_inotify_pid" ] && kill -0 "$_inotify_pid" 2>/dev/null; then
		kill "$_inotify_pid" 2>/dev/null
		wait "$_inotify_pid" 2>/dev/null
	fi
	# Finalize current session TSV if it exists
	if [ -f "$scan_session" ] && [ -s "$scan_session" ]; then
		_session_write_header "$scan_session" "monitor"
	fi
	command rm -f "$tmpdir/monitor.pid" "$tmpdir/stop_monitor"
	if [ -n "$_inotify_fpaths" ]; then
		command rm -f "$_inotify_fpaths"
	fi
	eout "{mon} monitor stopped" 1
	_lmd_elog_event "$ELOG_EVT_MONITOR_STOPPED" "info" "inotify monitor stopped"
	exit 0
}

_monitor_should_stop() {
	# Returns 0 (true) if the supervisor should stop.
	# Checks internal flag + backward-compat stop file sentinel.
	if [ "$_monitor_stopping" = "1" ]; then
		return 0
	fi
	# Transition compat: old maldet -k creates this file
	if [ -f "$tmpdir/stop_monitor" ]; then
		return 0
	fi
	return 1
}

_monitor_restart_inotify() {
	# Restart inotifywait after crash. Exponential backoff (2s->60s).
	# Exits supervisor after 3 consecutive failures.
	_inotify_fail_count=$((_inotify_fail_count + 1))
	local _exit_code=0
	wait "$_inotify_pid" 2>/dev/null
	_exit_code=$?
	eout "{mon} inotifywait died (exit=$_exit_code, failures=$_inotify_fail_count)" 1

	if [ "$_inotify_fail_count" -ge 3 ]; then
		eout "{mon} inotifywait failed $_inotify_fail_count consecutive times, exiting" 1
		eout "{mon} possible cause: inotify watch limit exceeded — increase inotify_base_watches or reduce monitored paths" 1
		_monitor_stopping=1
		return
	fi

	eout "{mon} restarting inotifywait in ${_inotify_backoff}s (attempt $_inotify_fail_count/3)" 1
	sleep "$_inotify_backoff"
	# Double backoff, cap at 60
	_inotify_backoff=$((_inotify_backoff * 2))
	if [ "$_inotify_backoff" -gt 60 ]; then
		_inotify_backoff=60
	fi

	# Restart with same arguments
	$nice_command $inotify -r --fromfile "$_inotify_fpaths" "${_inotify_exclude[@]}" \
		--timefmt "%d %b %H:%M:%S" --format "%w%f %e %T" -m \
		-e create,move,modify >> "$inotify_log" 2>&1 &
	_inotify_pid=$!

	sleep 1
	if kill -0 "$_inotify_pid" 2>/dev/null; then
		eout "{mon} inotifywait restarted successfully (pid: $_inotify_pid)" 1
		_inotify_fail_count=0
		_inotify_backoff=2
	fi
}

_monitor_housekeeping() {
	# Runs every tick. Cheap operations only — no forks when possible.
	# Config reload timer
	_mon_elapsed=$((_mon_elapsed + inotify_sleep))
	if [ "$_mon_elapsed" -ge "$inotify_reloadtime" ] || [ -f "$inspath/reload_monitor" ]; then
		if [ -f "$inspath/reload_monitor" ]; then
			command rm -f "$inspath/reload_monitor"
		fi
		# shellcheck disable=SC1090,SC1091
		source "$intcnf"
		# shellcheck disable=SC1090,SC1091
		source "$cnf"
		import_conf
		if [ -f "$compatcnf" ]; then
			# shellcheck disable=SC1090,SC1091
			source "$compatcnf"
		fi
		if [ -f "$syscnf" ]; then
			# shellcheck disable=SC1090,SC1091
			source "$syscnf"
		fi
		_mon_elapsed=0
		_lmd_alert_init
		_lmd_elog_init
		_build_scan_filters
		# Clear cached state for re-discovery on next scan cycle
		_yara_bin="" _yara_type="" _yara_has_scan_list=""
		_sigs_ready=""
		_clam_cached=""
		_resolve_hashtype
		_resolve_clamscan
		_resolve_yara
		if [ "$_effective_hashtype" = "both" ]; then
			eout "{mon} WARNING: scan_hashtype=both doubles hash I/O per monitor cycle" 1
		fi
		# Re-parse digest interval in case config changed
		if [ -n "$digest_interval" ] && [ "$digest_interval" != "0" ]; then
			_digest_interval_secs=$(_monitor_parse_interval "$digest_interval") || {
				eout "{mon} WARNING: invalid digest_interval '$digest_interval', defaulting to 86400 (24h)"
				_digest_interval_secs=86400
			}
		else
			_digest_interval_secs=0
		fi
		# Advisory: monitor_paths_extra changes require restart (spec S3.5)
		if [ -f "${monitor_paths_extra:-}" ] && [ -s "${monitor_paths_extra:-}" ]; then
			eout "{mon} NOTE: path changes in monitor_paths_extra require monitor restart to take effect"
		fi
		eout "{mon} reloaded configuration data" 1
		_lmd_elog_event "$ELOG_EVT_CONFIG_LOADED" "info" "configuration reloaded" "config=$cnf"
	fi

	# Digest timer (wall-clock — avoids drift from variable-duration scan cycles)
	if [ "$_digest_interval_secs" -gt 0 ]; then
		local _now
		_now=$(date +%s)
		if [ "$_now" -ge "$_next_digest_time" ]; then
			eout "{mon} firing periodic digest alert (interval=${digest_interval})" 1
			genalert digest
			# Post-scan hook (digest): monitor always forces async
			if [ -n "${_LMD_HOOK_LOADED:-}" ]; then
				_scan_hook_dispatch "post" "digest"
			fi
			# Rotate session
			scanid="$datestamp.$$"
			scan_session="$sessdir/session.tsv.$scanid"
			touch "$scan_session"
			_session_write_header "$scan_session" "monitor"
			echo "$scan_session" > "$sessdir/session.monitor.current"
			_next_digest_time=$((_now + _digest_interval_secs))
		fi
	fi

	# ignore_sigs change detection — regenerate sigs if hash changed
	if [ -f "$ignore_sigs" ]; then
		local _md5out _cur_md5
		_md5out="$(md5sum "$ignore_sigs")"
		_cur_md5="${_md5out%% *}"
		if [ "$_cur_md5" != "$_ignore_sigs_last_md5" ]; then
			gensigs 1
			_md5out="$(md5sum "$ignore_sigs")"
			_cur_md5="${_md5out%% *}"
			eout "{mon} regenerated signature files on ignore_sigs file change detected" 1
			_sigs_ready=1
		fi
		_ignore_sigs_last_md5="$_cur_md5"
	fi

	# Log trim check (byte-size gate to avoid wc -l every cycle)
	local _inotify_trim_bytes
	_inotify_trim_bytes=$((_inotify_trim_threshold * 80))
	if [ "${_cur_log_size:-0}" -ge "$_inotify_trim_bytes" ]; then
		local _log_lines
		_log_lines=$($wc -l < "$inotify_log" 2>/dev/null) || _log_lines=0
		if [ "$_log_lines" -ge "$inotify_trim" ]; then
			_inotify_trim_log "$((_log_lines - 1000))"
		fi
	fi
}

_monitor_cycle_tick() {
	# Three-tier monitor cycle. Called every $inotify_sleep seconds.

	# inotifywait health check
	if ! kill -0 "$_inotify_pid" 2>/dev/null; then
		_monitor_restart_inotify
		return
	fi
	if [ "$_inotify_fail_count" -gt 0 ]; then
		_inotify_fail_count=0
		_inotify_backoff=2
	fi

	# Tier 0: idle detection via stat
	local _cur_size
	_cur_size=$($stat -c %s "$inotify_log" 2>/dev/null) || _cur_size=0
	_cur_log_size="$_cur_size"  # expose to housekeeping for trim check
	if [ "$_cur_size" -eq "$_last_log_size" ]; then
		_monitor_housekeeping
		return
	fi
	_last_log_size="$_cur_size"

	# Tier 1: event filtering (extraction + dedup, then ERE ignore-path filter)
	local _event_list
	_event_list=$(mktemp "$tmpdir/.mon_events.XXXXXX")
	if [ -s "$ignore_paths" ]; then
		tlog_read "$inotify_log" "inotify" "$tmpdir" "bytes" | \
			_monitor_filter_events | \
			grep -E -vf "$ignore_paths" > "$_event_list"
	else
		tlog_read "$inotify_log" "inotify" "$tmpdir" "bytes" | \
			_monitor_filter_events > "$_event_list"
	fi

	local _event_count
	_event_count=$($wc -l < "$_event_list" 2>/dev/null) || _event_count=0
	if [ "$_event_count" -eq 0 ]; then
		command rm -f "$_event_list"
		_monitor_housekeeping
		return
	fi

	# Apply scan filters: file existence, size, extension, permissions
	# Ownership filters (ignore_root/ignore_user/ignore_group) are only applied
	# when monitor_scan_owner_filters=1 (opt-in). The default (0) admits all
	# owners so that root-owned files are not silently dropped — the root cause
	# of issue #485 where monitor mode quarantined 0 files despite detections.
	local _filtered_list
	_filtered_list=$(mktemp "$tmpdir/.mon_filtered.XXXXXX")
	local _owner_filter_args=()
	if [ "${monitor_scan_owner_filters:-0}" = "1" ]; then
		_owner_filter_args=("${ignore_root[@]}" "${ignore_user[@]}" "${ignore_group[@]}")
	fi
	while IFS= read -r _fpath; do
		[ -f "$_fpath" ] || continue
		# Expand with find filter for size/ext/perm/user/group
		$nice_command "$find" "$_fpath" -maxdepth 0 $find_opts -type f \
			-size +"${scan_min_filesize}c" -size -"${scan_max_filesize}" \
			-not -perm 000 "${ignore_fext_args[@]}" \
			"${_owner_filter_args[@]}" 2>/dev/null >> "$_filtered_list"
	done < "$_event_list"
	command rm -f "$_event_list"

	local _tot_files
	_tot_files=$($wc -l < "$_filtered_list" 2>/dev/null) || _tot_files=0
	if [ "$_tot_files" -eq 0 ]; then
		command rm -f "$_filtered_list"
		eout "{mon} filtered $_event_count event(s) — none passed scan filter"
		_monitor_housekeeping
		return
	fi

	# Tier 2: scan delegation
	find_results="$_filtered_list"
	tot_files="$_tot_files"
	hrspath="monitor"

	# First-cycle sig generation (deferred — see spec S3.3)
	if [ -z "$_sigs_ready" ]; then
		gensigs
		_sigs_ready=1
	fi

	# ClamAV discovery (cached across cycles)
	if [ "$scan_clamscan" = "1" ] && [ -z "$_clam_cached" ]; then
		monitor_mode=1
		clamselector
		_clam_cached=1
	fi

	# Snapshot session line count before scan for per-cycle hit delta
	local _pre_scan_lines
	_pre_scan_lines=$(grep -c '^[^#]' "$scan_session" 2>/dev/null) || _pre_scan_lines=0

	if [ "$scan_clamscan" = "1" ]; then
		clamscan_results=$(mktemp "$tmpdir/.clamscan.result.XXXXXX")
		chmod 600 "$clamscan_results"
		_clamd_retry_scan "$_filtered_list"
		local _clam_fatal
		_clam_fatal=$(grep -m1 'no reply from clamd' "$clamscan_results" 2>/dev/null)
		if [ -n "$_clam_fatal" ]; then
			eout "{mon} clamscan returned a fatal error (no reply from clamd), skipping quarantine for this cycle" 1
			command rm -f "$clamscan_results" "$_filtered_list"
			_monitor_housekeeping
			return
		fi
		_process_clamav_hits "$clamscan_results"
		# YARA scan for ClamAV path (not included internally)
		if [ "$scan_yara" = "1" ]; then
			_run_yara_scan "$_filtered_list"
		fi
		command rm -f "$clamscan_results"
	else
		_scan_run_native  # includes YARA scan internally
	fi

	# Record scanned files in monitor history
	cat "$_filtered_list" >> "$monitor_scanned_history" 2>/dev/null  # safe: file may not exist yet

	# Count per-cycle hits (delta since pre-scan snapshot)
	local _post_scan_lines _cycle_hits
	_post_scan_lines=$(grep -c '^[^#]' "$scan_session" 2>/dev/null) || _post_scan_lines=0
	_cycle_hits=$((_post_scan_lines - _pre_scan_lines))

	eout "{mon} scanned $_tot_files new/changed files"

	# Escalation check (per-cycle hits, not cumulative)
	if [ "${digest_escalate_hits:-0}" -gt 0 ] && [ "$_cycle_hits" -ge "$digest_escalate_hits" ]; then
		eout "{mon} escalation threshold reached ($_cycle_hits hits >= $digest_escalate_hits), firing immediate alert" 1
		genalert file "$scan_session"
		# Post-scan hook (escalation): monitor always forces async
		if [ -n "${_LMD_HOOK_LOADED:-}" ]; then
			_scan_hook_dispatch "post" "escalation"
		fi
	fi

	command rm -f "$_filtered_list"
	_monitor_housekeeping
}

monitor_kill() {
	# Send SIGTERM to the monitor supervisor. Escalate to SIGKILL after 10s.
	# Called by maldet -k/--kill-monitor.
	local _pid
	if [ -f "$tmpdir/monitor.pid" ]; then
		_pid=$(cat "$tmpdir/monitor.pid")
	fi
	if [ -z "$_pid" ] || ! kill -0 "$_pid" 2>/dev/null; then
		# Fallback: find by inotifywait process (old-style)
		_pid=$(pgrep -f 'inotify.paths.[0-9]+' 2>/dev/null)
		if [ -n "$_pid" ]; then
			# Kill inotifywait directly (legacy mode)
			kill -9 "$_pid" 2>/dev/null
		fi
		# Also create stop file for transition compat
		touch "$tmpdir/stop_monitor"
		command rm -f "$tmpdir/monitor.pid"
		_lmd_elog_event "$ELOG_EVT_MONITOR_STOPPED" "info" "inotify monitor stopped"
		return 0
	fi
	# Send SIGTERM to supervisor
	kill "$_pid" 2>/dev/null
	# Wait up to 10 seconds for clean shutdown
	local _waited=0
	while [ "$_waited" -lt 10 ] && kill -0 "$_pid" 2>/dev/null; do
		sleep 1
		_waited=$((_waited + 1))
	done
	if kill -0 "$_pid" 2>/dev/null; then
		eout "{mon} supervisor did not exit after 10s, sending SIGKILL" 1
		kill -9 "$_pid" 2>/dev/null
	fi
	command rm -f "$tmpdir/monitor.pid"
	_lmd_elog_event "$ELOG_EVT_MONITOR_STOPPED" "info" "inotify monitor stopped"
}

monitor_init() {
	local inopt="$1"

	# Validation
	if [ -z "$inopt" ]; then
		eout "invalid usage of -m|--monitor, aborting." 1
		exit 1
	fi

	if [ ! -f "$inotify" ]; then
		eout "{mon} could not find inotifywait command, install yum package inotify-tools or download from https://github.com/rvoicilas/inotify-tools/wiki/" 1
		exit 1
	fi

	# Kernel support: pragmatic test via inotifywait on $tmpdir (defect #4)
	local _test_stderr
	_test_stderr=$($inotify -t 1 "$tmpdir" 2>&1 >/dev/null) || true  # inotifywait -t 1 exits 2 on timeout (expected)
	if echo "$_test_stderr" | grep -qiE 'not support|no such|permission denied|invalid'; then
		eout "{mon} inotify not functional: $_test_stderr" 1
		exit 1
	fi

	# Check for existing monitor
	if [ -f "$tmpdir/monitor.pid" ]; then
		local _existing_pid
		_existing_pid=$(cat "$tmpdir/monitor.pid")
		if [ -n "$_existing_pid" ] && kill -0 "$_existing_pid" 2>/dev/null; then
			eout "{mon} existing monitor process detected (pid: $_existing_pid, try -k)" 1
			exit 1
		fi
		command rm -f "$tmpdir/monitor.pid"
	fi
	# Also check for old-style inotifywait orphans
	local _old_inotify_pid
	_old_inotify_pid=$(pgrep -f 'inotify.paths.[0-9]+' 2>/dev/null)
	if [ -n "$_old_inotify_pid" ]; then
		eout "{mon} existing inotify process detected (try -k): $_old_inotify_pid" 1
		exit 1
	fi

	command rm -f "$tmpdir/stop_monitor" "$tmpdir/inotifywait.pid"

	# Kernel tuning
	if [ -f "/proc/sys/fs/inotify/max_user_instances" ] && [ -f "/proc/sys/fs/inotify/max_user_watches" ]; then
		local cur_user_watches cur_user_instances users_tot inotify_user_watches
		cur_user_watches=$(cat /proc/sys/fs/inotify/max_user_watches)
		cur_user_instances=$(cat /proc/sys/fs/inotify/max_user_instances)
		users_tot=$(awk -F: -v min="$inotify_minuid" '$3 >= min {n++} END {print n+0}' /etc/passwd)
		inotify_user_watches=$((inotify_base_watches * users_tot))
		if [ "$cur_user_instances" -lt "$inotify_user_instances" ]; then
			eout "{mon} set inotify max_user_instances to $inotify_user_instances" 1
			echo "$inotify_user_instances" > /proc/sys/fs/inotify/max_user_instances
		fi
		if [ "$cur_user_watches" -lt "$inotify_user_watches" ]; then
			eout "{mon} set inotify max_user_watches to $inotify_user_watches" 1
			echo "$inotify_user_watches" > /proc/sys/fs/inotify/max_user_watches
		fi
	else
		eout "{mon} could not find fs.inotify.max_user_instances|watches tunable files, aborting." 1
		exit 1
	fi

	# Build watch list
	_inotify_fpaths=$(mktemp "$sessdir/.inotify.paths.XXXXXX")
	touch "$inotify_log"
	chmod 640 "$inotify_log"

	local icnt=0
	if [[ "$inopt" =~ ^[Uu][Ss][Ee][Rr][Ss]?$ ]]; then
		while IFS=':' read -r user user_id user_home; do
			icnt=$((icnt + 1))
			if [ "$user_id" -ge "$inotify_minuid" ]; then
				if [ -n "$inotify_docroot" ] && [ -d "$user_home" ]; then
					while IFS= read -r docroot; do
						if [ -d "$user_home/$docroot" ]; then
							echo "$user_home/$docroot" >> "$_inotify_fpaths"
							eout "{mon} added $user_home/$docroot to inotify monitoring array" 1
						fi
					done < <(echo "$inotify_docroot" | tr ', ' '\n' | grep -v '^$')
				elif [ -d "$user_home" ]; then
					echo "$user_home" >> "$_inotify_fpaths"
					eout "{mon} added $user_home to inotify monitoring array" 1
				else
					eout "{mon} could not find any suitable user home paths"
				fi
			fi
		done < <(cut -d':' -f1,3,6 /etc/passwd | sort)

		if [ -d "/dev/shm" ]; then
			echo "/dev/shm" >> "$_inotify_fpaths"
			eout "{mon} added /dev/shm to inotify monitoring array" 1
		fi
		if [ -d "/var/tmp" ]; then
			echo "/var/tmp" >> "$_inotify_fpaths"
			eout "{mon} added /var/tmp to inotify monitoring array" 1
		fi
		if [ -d "/tmp" ]; then
			echo "/tmp" >> "$_inotify_fpaths"
			eout "{mon} added /tmp to inotify monitoring array" 1
		fi
	elif [ -f "$inopt" ]; then
		local tot_paths
		tot_paths=$($wc -l < "$inopt")
		if [ "$tot_paths" = "0" ]; then
			eout "{mon} no paths specified in $inopt, aborting." 1
			exit 1
		fi
		while IFS= read -r i; do
			if [ -d "$i" ]; then
				eout "{mon} added $i to inotify monitoring array" 1
				echo "$i" >> "$_inotify_fpaths"
			else
				eout "{mon} ignored invalid path $i" 1
			fi
		done < "$inopt"
	elif [ -d "$inopt" ] || [[ "$inopt" == *,* ]]; then
		while IFS= read -r i; do
			if [ -d "$i" ]; then
				eout "{mon} added $i to inotify monitoring array" 1
				echo "$i" >> "$_inotify_fpaths"
			else
				eout "{mon} invalid path $i specified, ignoring." 1
			fi
		done < <(echo "$inopt" | tr ',' '\n')
	else
		eout "{mon} no valid option or invalid file/path provided, aborting." 1
		exit 1
	fi

	# Additive path composition (defect: path model was either/or)
	_monitor_append_extra_paths "${monitor_paths_extra:-}" "$_inotify_fpaths"

	# Build inotifywait --exclude regex — union ignore_inotify + defaults (issue #480)
	# Per-entry semantic dispatch via _monitor_to_ere_entry (issue #484)
	_inotify_exclude=()
	local _igregexp=""
	local _src _ent _prepared
	while IFS= read -r _line; do
		_src="${_line:0:1}"
		_ent="${_line:2}"
		case "$_src" in
			u) _prepared=$(_monitor_to_ere_entry "$_ent" "user") ;;
			d) _prepared=$(_monitor_to_ere_entry "$_ent" "defaults") ;;
			*) continue ;;
		esac
		[ -z "$_prepared" ] && continue  # literal: empty skip, etc.
		if [ -n "$_igregexp" ]; then
			_igregexp="$_igregexp|$_prepared"
		else
			_igregexp="($_prepared"
		fi
	done < <(_monitor_load_ignore_inotify_union "$ignore_inotify" "${ignore_inotify_defaults:-}")
	if [ -n "$_igregexp" ]; then
		_igregexp="$_igregexp)"
		_inotify_exclude=(--exclude "$_igregexp")
	fi

	# Session setup
	scanid="$datestamp.$$"
	scan_session="$sessdir/session.tsv.$scanid"
	touch "$scan_session"
	echo "$scan_session" > "$sessdir/session.monitor.current"
	_session_write_header "$scan_session" "monitor"

	local tot_paths
	tot_paths=$($wc -l < "$_inotify_fpaths")
	eout "{mon} starting inotify process on $tot_paths paths, this might take awhile..." 1

	# Spawn inotifywait (only child process)
	inotify_cpunice="${inotify_cpunice:-19}"
	inotify_ionice="${inotify_ionice:-6}"
	_build_nice_command "$inotify_cpunice" "$inotify_ionice" "$inotify_cpulimit"

	$nice_command $inotify -r --fromfile "$_inotify_fpaths" "${_inotify_exclude[@]}" \
		--timefmt "%d %b %H:%M:%S" --format "%w%f %e %T" -m \
		-e create,move,modify >> "$inotify_log" 2>&1 &
	_inotify_pid=$!
	sleep 2

	if ! kill -0 "$_inotify_pid" 2>/dev/null; then
		eout "{mon} inotifywait failed to start, check $inotify_log for errors." 1
		exit 1
	fi

	eout "{mon} inotify startup successful (pid: $_inotify_pid)" 1
	eout "{mon} inotify monitoring log: $inotify_log" 1
	_lmd_elog_event "$ELOG_EVT_MONITOR_STARTED" "info" "inotify monitor started (pid: $_inotify_pid)"
	_lmd_elog_event "$ELOG_EVT_CONFIG_LOADED" "info" "configuration loaded" "config=$cnf"

	# Supervisor state initialization
	TLOG_FLOCK=1
	echo "${BASHPID:-$$}" > "$tmpdir/monitor.pid"
	_monitor_stopping=0
	_last_log_size=0
	_cur_log_size=0
	_mon_elapsed=0
	_inotify_fail_count=0
	_inotify_backoff=2
	_sigs_ready=""
	_clam_cached=""
	_ignore_sigs_last_md5=""
	_inotify_trim_threshold="$inotify_trim"
	_resolve_hashtype
	_resolve_clamscan
	_resolve_yara
	_build_scan_filters

	_digest_interval_secs=0
	if [ -n "${digest_interval:-}" ] && [ "${digest_interval:-}" != "0" ]; then
		_digest_interval_secs=$(_monitor_parse_interval "$digest_interval") || {
			eout "{mon} WARNING: invalid digest_interval '$digest_interval', defaulting to 86400 (24h)"
			_digest_interval_secs=86400
		}
	fi
	_next_digest_time=0
	if [ "$_digest_interval_secs" -gt 0 ]; then
		_next_digest_time=$(($(date +%s) + _digest_interval_secs))
	fi

	# Install signal handlers
	trap _monitor_shutdown SIGTERM SIGINT

	# Interactive TTY notice
	if [ -t 0 ]; then
		eout "{mon} running in foreground (interactive console detected)" 1
		eout "{mon} use -b or --background to run as a daemon" 1
		eout "{mon} press Ctrl+C to stop" 1
	fi

	# Supervisor main loop
	while ! _monitor_should_stop; do
		# Background sleep + wait: bash defers trap handlers during foreground
		# external commands (sleep), but fires them immediately during 'wait'.
		# Without this, SIGTERM is blocked for up to $inotify_sleep seconds.
		sleep "$inotify_sleep" &
		wait $! 2>/dev/null || true  # wait returns 128+sig when interrupted by trap
		_monitor_cycle_tick
	done

	_monitor_shutdown
}
