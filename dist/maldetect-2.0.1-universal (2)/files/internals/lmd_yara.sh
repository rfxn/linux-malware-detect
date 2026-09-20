#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC1090,SC1091
##
# Linux Malware Detect v2.0.1
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
# YARA scanning functions

# Source guard
[[ -n "${_LMD_YARA_LOADED:-}" ]] && return 0 2>/dev/null
_LMD_YARA_LOADED=1

_yara_filter_filelist() {
	# Rebuild file list keeping only files that still exist and are readable.
	# Filters out files quarantined (perms 000) by prior scan stages.
	local src="$1" dst _yf
	dst=$(mktemp "$tmpdir/.yara_flist.$$.XXXXXX")
	while IFS= read -r _yf; do
		[ -f "$_yf" ] && [ -r "$_yf" ] && printf '%s\n' "$_yf"
	done < "$src" > "$dst"
	echo "$dst"
}

_yara_init_cache() {
	# Cache YARA binary selection and --scan-list detection in globals.
	# Called once per scan; monitor config-reload clears the cache.
	if [ -n "$_yara_bin" ]; then
		return
	fi
	if [ -n "$yr" ] && [ -f "$yr" ]; then
		_yara_bin="$yr"
		_yara_type="yr"
	elif [ -n "$yara" ] && [ -f "$yara" ]; then
		_yara_bin="$yara"
		_yara_type="yara"
	else
		_yara_bin=""
		_yara_type=""
		_yara_has_scan_list=""
		return
	fi
	_yara_has_scan_list=0
	if [ "$_yara_type" == "yr" ]; then
		if "$_yara_bin" scan --help 2>&1 | grep -q -- '--scan-list'; then
			_yara_has_scan_list=1
		fi
	else
		if "$_yara_bin" --help 2>&1 | grep -q -- 'scan-list'; then
			_yara_has_scan_list=1
		fi
	fi
}

_yara_scan_rules() {
	# Scan files with YARA using given rules argument and log label.
	# Explicit parameters from scan_stage_yara(); globals used directly:
	#   nice_command (process priority), clean_state (scan config),
	#   scan_session (session path), ignore_sigs (sig filter),
	#   clean_failed (output flag), tmpdir (temp directory)
	local rules_arg="$1"
	local log_label="$2"
	local yara_bin="$3"
	local yara_type="$4"
	local has_scan_list="$5"
	local file_list="$6"
	local yara_timeout_opts="$7"
	local yara_warn_opts="$8"
	local yara_results="$9"
	local yara_stderr="${10}"
	local yara_rc_file="${11}"
	local clean_check="${12}"
	local _y_scanid="${13:-}"

	> "$yara_results"
	> "$yara_stderr"

	local _yara_pid_file=""
	if [ -n "$_y_scanid" ]; then
		_yara_pid_file="$tmpdir/.yara_pid.$_y_scanid"
	fi

	if [ "$has_scan_list" == "1" ]; then
		if [ -n "$_yara_pid_file" ]; then
			# PID capture: run YARA in background inside sh -c, write PID, wait
			if [ "$yara_type" == "yr" ]; then
				YARA_RC="$yara_rc_file" YARA_PID_FILE="$_yara_pid_file" \
					$nice_command sh -c '"$@" & echo $! > "$YARA_PID_FILE"; wait $!; echo $? > "$YARA_RC"' -- \
					"$yara_bin" scan --scan-list $yara_timeout_opts $yara_warn_opts $rules_arg "$file_list" \
					> "$yara_results" 2> "$yara_stderr"
			else
				YARA_RC="$yara_rc_file" YARA_PID_FILE="$_yara_pid_file" \
					$nice_command sh -c '"$@" & echo $! > "$YARA_PID_FILE"; wait $!; echo $? > "$YARA_RC"' -- \
					"$yara_bin" --scan-list $yara_timeout_opts $yara_warn_opts $rules_arg "$file_list" \
					> "$yara_results" 2> "$yara_stderr"
			fi
		else
			if [ "$yara_type" == "yr" ]; then
				YARA_RC="$yara_rc_file" $nice_command sh -c '"$@"; echo $? > "$YARA_RC"' -- \
					"$yara_bin" scan --scan-list $yara_timeout_opts $yara_warn_opts $rules_arg "$file_list" \
					> "$yara_results" 2> "$yara_stderr"
			else
				YARA_RC="$yara_rc_file" $nice_command sh -c '"$@"; echo $? > "$YARA_RC"' -- \
					"$yara_bin" --scan-list $yara_timeout_opts $yara_warn_opts $rules_arg "$file_list" \
					> "$yara_results" 2> "$yara_stderr"
			fi
		fi
	else
		local pf_rc=0 pf_last=0 scan_file _sentinel_rc
		while IFS= read -r scan_file; do
			# Check lifecycle sentinels at per-file boundary
			if [ -n "$_y_scanid" ]; then
				_lifecycle_check_sentinels "$_y_scanid"
				_sentinel_rc=$?
				if [ "$_sentinel_rc" -eq 1 ]; then
					break  # abort
				fi
				if [ "$_sentinel_rc" -eq 2 ]; then
					# Pause: sleep-loop checking abort every 2s
					while [ -f "$tmpdir/.pause.$_y_scanid" ]; do
						_lifecycle_check_sentinels "$_y_scanid"
						[ $? -eq 1 ] && break 2
						command sleep 2
					done
				fi
				# Check parent liveness — _scan_pid = actual scan PID (BASHPID); safe in background mode
				_lifecycle_check_parent "${_scan_pid:-$$}" || break
			fi
			if [ ! -f "$scan_file" ]; then
				continue
			fi
			if [ "$yara_type" == "yr" ]; then
				YARA_RC="$yara_rc_file" $nice_command sh -c '"$@"; echo $? > "$YARA_RC"' -- \
					"$yara_bin" scan $yara_timeout_opts $yara_warn_opts $rules_arg "$scan_file" \
					>> "$yara_results" 2>> "$yara_stderr"
			else
				YARA_RC="$yara_rc_file" $nice_command sh -c '"$@"; echo $? > "$YARA_RC"' -- \
					"$yara_bin" $yara_timeout_opts $yara_warn_opts $rules_arg "$scan_file" \
					>> "$yara_results" 2>> "$yara_stderr"
			fi
			read -r pf_last < "$yara_rc_file" 2>/dev/null || pf_last=0  # safe: file may be empty on fast exit
			[ "$pf_last" -gt "$pf_rc" ] && pf_rc=$pf_last
		done < "$file_list"
		echo "$pf_rc" > "$yara_rc_file"
	fi

	# Clean up YARA PID file
	if [ -n "$_yara_pid_file" ]; then
		command rm -f "$_yara_pid_file"
	fi

	# Log stderr (filter out expected "could not open/map" from quarantined files)
	if [ -s "$yara_stderr" ]; then
		local stderr_line
		while IFS= read -r stderr_line; do
			case "$stderr_line" in
				*"could not open"*|*"could not map"*|*"can't open"*) continue ;;
			esac
			eout "{yara} warning: $stderr_line"
		done < "$yara_stderr"
	fi
	local yara_rc
	read -r yara_rc < "$yara_rc_file" 2>/dev/null || yara_rc=0
	if [ "$yara_rc" -gt 0 ]; then
		eout "{yara} warning: $log_label exited with code $yara_rc"
	fi

	# Parse results into manifest and batch-process
	if [ -s "$yara_results" ]; then
		local _yara_manifest
		_yara_manifest=$(mktemp "$tmpdir/.yara_manifest.$$.XXXXXX")

		# Parse: "RULE_NAME FILEPATH" → filepath\t{YARA}RULE_NAME
		awk '{rule=$1; $1=""; sub(/^ /,"",$0); print $0 "\t{YARA}" rule}' \
			"$yara_results" > "$_yara_manifest"

		# Bulk ignore_sigs filter on signames (column 2)
		_batch_filter_ignore_sigs "$_yara_manifest"

		# Bulk dedup against scan_session (skip files already recorded by prior stages)
		if [ "$clean_state" != "1" ] && [ -n "$scan_session" ] && [ -s "$scan_session" ]; then
			local _existing_paths _yd
			_existing_paths=$(mktemp "$tmpdir/.yara_existing.$$.XXXXXX")
			awk -F'\t' '!/^#/{if ($2 != "") print $2}' "$scan_session" > "$_existing_paths"
			if [ -s "$_existing_paths" ]; then
				_yd=$(mktemp "$tmpdir/.yara_deduped.$$.XXXXXX")
				# Remove manifest lines whose filepath (col 1) matches an existing path
				awk -F'\t' 'NR==FNR{seen[$0];next} !($1 in seen)' \
					"$_existing_paths" "$_yara_manifest" > "$_yd"
				command mv "$_yd" "$_yara_manifest"
			fi
			command rm -f "$_existing_paths"
		fi

		if [ "$clean_check" == "1" ]; then
			# Clean verification mode — just set flag if any hits remain
			if [ -s "$_yara_manifest" ]; then
				clean_failed=1
			fi
		else
			_flush_hit_batch "$_yara_manifest" "yara"
		fi
		command rm -f "$_yara_manifest"
	fi
}

scan_stage_yara() {
	local file_list="$1"
	local clean_check="${2:-}"
	local _stg_scanid="${3:-}"
	if [ ! -f "$file_list" ] || [ ! -s "$file_list" ]; then
		return
	fi

	# Select yara binary from cache (populated once, cleared on config reload)
	_yara_init_cache
	if [ -z "$_yara_bin" ]; then
		eout "{yara} no yara or yr binary available, skipping YARA scan stage"
		return
	fi
	local yara_bin="$_yara_bin"
	local yara_type="$_yara_type"

	# Build list of rule files to scan
	local yara_rules_list
	yara_rules_list=$(mktemp "$tmpdir/.yara_rules.$$.XXXXXX")
	chmod 600 "$yara_rules_list"

	# Include rfxn.yara if scope allows (when ClamAV disabled or scope=all)
	if [ "$scan_clamscan" == "0" ] || [ "$scan_yara_scope" == "all" ]; then
		if [ -f "$sig_yara_file" ] && [ -s "$sig_yara_file" ]; then
			echo "$sig_yara_file" >> "$yara_rules_list"
		fi
	fi

	# Always include custom rules
	if [ -f "$sig_user_yara_file" ] && [ -s "$sig_user_yara_file" ]; then
		echo "$sig_user_yara_file" >> "$yara_rules_list"
	fi
	if [ -d "$sig_user_yara_dir" ]; then
		for yar_file in "$sig_user_yara_dir"/*.yar "$sig_user_yara_dir"/*.yara; do
			if [ -f "$yar_file" ] && [ -s "$yar_file" ]; then
				echo "$yar_file" >> "$yara_rules_list"
			fi
		done
	fi

	# Include compiled rules if available
	local compiled_rules="$sigdir/compiled.yarc"
	local has_compiled=0
	if [ -f "$compiled_rules" ] && [ -s "$compiled_rules" ]; then
		has_compiled=1
	fi
	if [ "$has_compiled" == "1" ]; then
		if [ "$yara_type" == "yr" ]; then
			"$yara_bin" scan -C "$compiled_rules" /dev/null > /dev/null 2>&1 || {
				eout "{yara} warning: compiled rules ($compiled_rules) failed validation (engine: $yara_type), skipping"
				has_compiled=0
			}
		else
			"$yara_bin" -C "$compiled_rules" /dev/null > /dev/null 2>&1 || {
				eout "{yara} warning: compiled rules ($compiled_rules) failed validation (engine: $yara_type), skipping"
				has_compiled=0
			}
		fi
	fi

	if [ ! -s "$yara_rules_list" ] && [ "$has_compiled" == "0" ]; then
		command rm -f "$yara_rules_list"
		return
	fi

	# Build yara command options
	local yara_timeout_opts=""
	local yara_warn_opts=""
	if [ "$scan_yara_timeout" ] && [ "$scan_yara_timeout" != "0" ]; then
		if [ "$yara_type" == "yr" ]; then
			yara_timeout_opts="--timeout $scan_yara_timeout"
		else
			yara_timeout_opts="--timeout=$scan_yara_timeout"
		fi
	fi
	if [ "$yara_type" == "yr" ]; then
		yara_warn_opts="--disable-warnings"
	else
		yara_warn_opts="--no-warnings"
	fi

	local has_scan_list="$_yara_has_scan_list"

	[ -n "$_stg_scanid" ] && _lifecycle_update_meta "$_stg_scanid" "stage" "yara"
	eout "{yara} starting native YARA scan stage..."

	local yara_results yara_stderr yara_rc_file rules_file
	yara_results=$(mktemp "$tmpdir/.yara_results.$$.XXXXXX")
	yara_stderr=$(mktemp "$tmpdir/.yara_stderr.$$.XXXXXX")
	yara_rc_file=$(mktemp "$tmpdir/.yara_rc.$$.XXXXXX")

	# Scan with text rules
	while IFS= read -r rules_file; do
		_yara_scan_rules "$rules_file" "$rules_file" \
			"$yara_bin" "$yara_type" "$has_scan_list" "$file_list" \
			"$yara_timeout_opts" "$yara_warn_opts" "$yara_results" \
			"$yara_stderr" "$yara_rc_file" "$clean_check" "$_stg_scanid"
	done < "$yara_rules_list"

	# Scan with compiled rules if available
	if [ "$has_compiled" == "1" ]; then
		_yara_scan_rules "-C $compiled_rules" "compiled rules" \
			"$yara_bin" "$yara_type" "$has_scan_list" "$file_list" \
			"$yara_timeout_opts" "$yara_warn_opts" "$yara_results" \
			"$yara_stderr" "$yara_rc_file" "$clean_check" "$_stg_scanid"
	fi

	command rm -f "$yara_rules_list" "$yara_results" "$yara_stderr" "$yara_rc_file"
	eout "{yara} native YARA scan stage completed"
}
