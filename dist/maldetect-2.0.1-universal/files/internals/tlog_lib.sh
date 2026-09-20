#!/bin/bash
# tlog_lib.sh — shared library for incremental log file reading
# Provides multi-mode tracking (byte-offset and line-count), rotation-aware
# delta reads, systemd journal fallback, and atomic cursor writes.
# Consumed by BFD and LMD via source inclusion.
#
# Copyright (C) 2002-2026 R-fx Networks <proj@rfxn.com>
#                         Ryan MacDonald <ryan@rfxn.com>
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# Source guard — prevent double-sourcing
[[ -n "${_TLOG_LIB_LOADED:-}" ]] && return 0 2>/dev/null  # return may fail at top-level; not an error
_TLOG_LIB_LOADED=1

# shellcheck disable=SC2034
TLOG_LIB_VERSION="2.0.6"

# Journal filter registry — consuming projects populate via tlog_journal_register()
# Uses parallel indexed arrays instead of declare -A to avoid scope issues
# when sourced from inside a function (e.g., BATS load, wrapper functions).
# Simple array assignment creates globals; declare -A creates locals in functions.
_TLOG_JOURNAL_NAMES=()
_TLOG_JOURNAL_FILTERS=()

# Numeric validation pattern — shared across cursor, size, and timestamp checks
_TLOG_NUMERIC_PAT='^[0-9]+$'

# _tlog_validate_name tlog_name — reject path-traversal tokens before file I/O
# Library context: returns 1 on invalid, never exits.
_tlog_validate_name() {
	local name="$1"
	if [[ -z "$name" ]] || [[ "$name" == "." ]] || [[ "$name" == ".." ]] || [[ "$name" == *"/"* ]]; then
		echo "tlog: invalid tlog_name: '$name'" >&2
		return 1
	fi
	return 0
}

# _tlog_check_baserun_perms baserun — warn on world-writable baserun (advisory, always returns 0)
_tlog_check_baserun_perms() {
	local baserun="$1"
	local perms world_bits
	perms=$(stat -c '%a' "$baserun" 2>/dev/null) || return 0  # stat fails if dir removed; advisory check
	world_bits="${perms: -1}"
	if [[ $((world_bits & 2)) -ne 0 ]]; then
		echo "tlog: warning: baserun directory '$baserun' is world-writable" >&2
	fi
	return 0
}

# _tlog_parse_cursor tlog_name baserun — read cursor file, detect mode
# Out-params (set in caller scope):
#   _tlog_cursor_value  numeric position, "" on first-run/corrupt
#   _tlog_cursor_mode   "bytes" or "lines", "" on first-run/corrupt
# Returns 0 on success/first-run, 2 on corrupt cursor (auto-reset).
_tlog_parse_cursor() {
	local tlog_name="$1" baserun="$2"
	local cursor_file="$baserun/$tlog_name"
	local raw_value=""

	# shellcheck disable=SC2034
	_tlog_cursor_value=""
	# shellcheck disable=SC2034
	_tlog_cursor_mode=""

	if [[ ! -f "$cursor_file" ]]; then
		return 0
	fi

	# Symlink cursor → reset (attacker-controlled target)
	if [[ -L "$cursor_file" ]]; then
		echo "tlog: symlink detected for cursor $cursor_file, resetting" >&2
		return 2
	fi

	read -r raw_value < "$cursor_file" 2>/dev/null || true  # read exits 1 on EOF; not an error

	if [[ -z "$raw_value" ]]; then
		return 0
	fi

	if [[ "$raw_value" == L:* ]]; then
		# shellcheck disable=SC2034
		_tlog_cursor_mode="lines"
		# shellcheck disable=SC2034
		_tlog_cursor_value="${raw_value#L:}"
	else
		# shellcheck disable=SC2034
		_tlog_cursor_mode="bytes"
		# shellcheck disable=SC2034
		_tlog_cursor_value="$raw_value"
	fi

	if [[ ! "$_tlog_cursor_value" =~ $_TLOG_NUMERIC_PAT ]]; then
		echo "tlog: corrupt cursor $cursor_file: '$raw_value'" >&2
		# shellcheck disable=SC2034
		_tlog_cursor_value=""
		# shellcheck disable=SC2034
		_tlog_cursor_mode=""
		return 2
	fi

	return 0
}

# _tlog_write_cursor tlog_name baserun value mode — atomic cursor write (mktemp + mv -f)
# Format: lines → "L:N", bytes → "N", raw → verbatim.
_tlog_write_cursor() {
	local tlog_name="$1" baserun="$2" value="$3" mode="$4"
	local cursor_file="$baserun/$tlog_name"
	local tmp_file formatted

	case "$mode" in
		bytes) formatted="$value" ;;
		lines) formatted="L:${value}" ;;
		raw)   formatted="$value" ;;
		*)
			echo "tlog: warning: _tlog_write_cursor: invalid mode '$mode' for $tlog_name" >&2
			return 1
			;;
	esac

	tmp_file=$(mktemp "$baserun/.${tlog_name}.XXXXXX") || {
		echo "tlog: warning: cursor write failed for $tlog_name (mktemp)" >&2
		return 1
	}
	printf '%s\n' "$formatted" > "$tmp_file"

	if ! command mv -f "$tmp_file" "$cursor_file"; then
		echo "tlog: warning: cursor write failed for $tlog_name (rename)" >&2
		command rm -f "$tmp_file"
		return 1
	fi

	return 0
}

# _tlog_get_size file mode — size on stdout (bytes via stat/wc -c, lines via wc -l)
_tlog_get_size() {
	local file="$1" mode="$2"
	local size

	case "$mode" in
		lines)
			size=$(wc -l < "$file")
			size="${size## }"
			;;
		*)
			tlog_get_file_size "$file"
			return $?
			;;
	esac

	printf '%s' "$size"
}

# _tlog_output_content file delta mode — tail dispatch (-c for bytes, -n for lines)
# Guards delta <= 0 to avoid tail's "output entire file" behavior.
_tlog_output_content() {
	local file="$1" delta="$2" mode="$3"

	if [[ "$delta" -le 0 ]]; then
		return 0
	fi

	case "$mode" in
		lines) tail -n "$delta" "$file" ;;
		*)     tail -c "$delta" "$file" ;;
	esac
}

# _tlog_is_compressed file — ext match for .gz/.xz/.bz2/.zst/.lz4 (no I/O)
_tlog_is_compressed() {
	case "$1" in
		*.gz|*.xz|*.bz2|*.zst|*.lz4) return 0 ;;
		*) return 1 ;;
	esac
}

# _tlog_cat_file file — decompress via TOOL -dc (gzip/xz/bzip2/zstd/lz4), else cat
_tlog_cat_file() {
	local file="$1"
	case "$file" in
		# suppress corrupt-archive stderr; exit code propagates to caller
		*.gz)  gzip -dc "$file" 2>/dev/null ;;
		*.xz)  xz -dc "$file" 2>/dev/null ;;
		*.bz2) bzip2 -dc "$file" 2>/dev/null ;;
		*.zst) zstd -dc "$file" 2>/dev/null ;;
		*.lz4) lz4 -dc "$file" 2>/dev/null ;;
		*)     cat "$file" ;;
	esac
}

# _tlog_find_rotated file — locate rotated log in priority order
# Priority: uncompressed .1 first (no decompress needed), then .gz/.xz/.bz2/.zst/.lz4
# (only returned if the corresponding tool is available on PATH).
_tlog_find_rotated() {
	local file="$1"
	local ext tool

	if [[ -f "${file}.1" ]]; then
		printf '%s' "${file}.1"
		return 0
	fi

	for ext in gz xz bz2 zst lz4; do
		if [[ -f "${file}.1.${ext}" ]]; then
			case "$ext" in
				gz)  tool="gzip" ;;
				xz)  tool="xz" ;;
				bz2) tool="bzip2" ;;
				zst) tool="zstd" ;;
				lz4) tool="lz4" ;;
			esac
			if command -v "$tool" >/dev/null 2>&1; then
				printf '%s' "${file}.1.${ext}"
				return 0
			fi
		fi
	done

	return 1
}

# _tlog_rotation_via_pipe rtfile cursor_size mode — zero-disk fallback for compressed rotation
# Decompresses twice (size + content) via pipe. Used when temp-file path fails
# (low disk, quota, permissions, corrupt archive) — preserves data at CPU cost.
_tlog_rotation_via_pipe() {
	local rtfile="$1" cursor_size="$2" mode="$3"
	local rtsize rt_delta

	if [[ "$mode" == "lines" ]]; then
		rtsize=$(_tlog_cat_file "$rtfile" | wc -l)
	else
		rtsize=$(_tlog_cat_file "$rtfile" | wc -c)
	fi
	rtsize="${rtsize## }"

	if [[ "$rtsize" -ge "$cursor_size" ]]; then
		rt_delta=$((rtsize - cursor_size))
		if [[ "$rt_delta" -gt 0 ]]; then
			if [[ "$mode" == "lines" ]]; then
				_tlog_cat_file "$rtfile" | tail -n "$rt_delta"
			else
				_tlog_cat_file "$rtfile" | tail -c "$rt_delta"
			fi
		fi
	fi
}

# _tlog_handle_rotation rtfile cursor_size mode tlog_name baserun — emit rotated tail
# Compressed: temp-file path first (single decompress); any failure → pipe fallback
# via _tlog_rotation_via_pipe (no data loss). Uncompressed: direct read.
_tlog_handle_rotation() {
	local rtfile="$1" cursor_size="$2" mode="$3"
	local tlog_name="$4" baserun="$5"
	local rtsize rt_delta tmp_decomp=""

	if _tlog_is_compressed "$rtfile"; then
		tmp_decomp=$(mktemp "$baserun/.${tlog_name}.XXXXXX" 2>/dev/null) || tmp_decomp=""  # fallback to pipe path on failure
		if [[ -n "$tmp_decomp" ]] && _tlog_cat_file "$rtfile" > "$tmp_decomp"; then
			rtsize=$(_tlog_get_size "$tmp_decomp" "$mode")
		else
			[[ -n "$tmp_decomp" ]] && command rm -f "$tmp_decomp"
			echo "tlog: warning: rotation temp file failed for $tlog_name, using pipe fallback" >&2
			_tlog_rotation_via_pipe "$rtfile" "$cursor_size" "$mode"
			return 0
		fi
	else
		rtsize=$(_tlog_get_size "$rtfile" "$mode")
	fi

	if [[ "$rtsize" -ge "$cursor_size" ]]; then
		rt_delta=$((rtsize - cursor_size))
		if [[ "$rt_delta" -gt 0 ]]; then
			if [[ -n "$tmp_decomp" ]]; then
				_tlog_output_content "$tmp_decomp" "$rt_delta" "$mode"
			else
				_tlog_output_content "$rtfile" "$rt_delta" "$mode"
			fi
		fi
	fi

	[[ -n "$tmp_decomp" ]] && command rm -f "$tmp_decomp"
	return 0
}

# tlog_get_file_size file — byte size on stdout (stat -c %s, fallback wc -c)
tlog_get_file_size() {
	local file="$1" size

	if [[ ! -f "$file" ]]; then
		return 1
	fi

	size=$(stat -c %s "$file" 2>/dev/null) || size=$(wc -c < "$file")  # stat unavailable on some platforms; wc fallback
	size="${size## }"
	printf '%s' "$size"
}

# tlog_get_line_count file — line count on stdout (wc -l)
tlog_get_line_count() {
	local file="$1" count

	if [[ ! -f "$file" ]]; then
		return 1
	fi

	count=$(wc -l < "$file")
	count="${count## }"
	printf '%s' "$count"
}

# tlog_read file tlog_name baserun [mode] — delta reader with cursor tracking
# Mode precedence: explicit arg > $TLOG_MODE > "bytes".
# Returns: 0=success, 1=file/path error, 2=cursor corrupt (auto-reset),
#          3=journal unavailable, 4=lock acquisition failed.
tlog_read() {
	local file="$1" tlog_name="$2" baserun="$3"
	local mode="${4:-${TLOG_MODE:-bytes}}"
	local newsize delta size rtfile _tlog_fd
	local cursor_corrupt=0 rc=0
	local stored_mode parse_rc

	# Reject mode typos before any I/O
	if [[ "$mode" != "bytes" ]] && [[ "$mode" != "lines" ]]; then
		echo "tlog: invalid mode '$mode' (must be 'bytes' or 'lines')" >&2
		return 1
	fi

	_tlog_validate_name "$tlog_name" || return 1

	# Baserun check must precede journal dispatch (F-010)
	if [[ ! -d "$baserun" ]]; then
		echo "tlog: baserun directory not found: $baserun" >&2
		return 1
	fi
	_tlog_check_baserun_perms "$baserun"

	# Journal dispatch when file missing and LOG_SOURCE permits
	if [[ ! -f "$file" ]] && [[ "${LOG_SOURCE}" != "file" ]]; then
		tlog_journal_read "$tlog_name" "$baserun"
		return $?
	fi

	if [[ ! -f "$file" ]]; then
		echo "tlog: file not found: $file" >&2
		return 1
	fi

	if [[ "${TLOG_FLOCK:-0}" == "1" ]]; then
		exec {_tlog_fd}>"$baserun/${tlog_name}.lock"
		if ! flock -x -w 5 "$_tlog_fd"; then
			exec {_tlog_fd}>&-
			return 4
		fi
	fi

	_tlog_parse_cursor "$tlog_name" "$baserun"
	parse_rc=$?
	if [[ $parse_rc -eq 2 ]]; then
		cursor_corrupt=1
	fi

	size="${_tlog_cursor_value}"
	stored_mode="${_tlog_cursor_mode}"

	if [[ -n "$stored_mode" ]] && [[ "$stored_mode" != "$mode" ]]; then
		echo "tlog: mode mismatch for $tlog_name: stored=$stored_mode requested=$mode, resetting" >&2
		size=""
		cursor_corrupt=1
	fi

	newsize=$(_tlog_get_size "$file" "$mode")

	if [[ -z "$size" ]]; then
		_tlog_write_cursor "$tlog_name" "$baserun" "$newsize" "$mode"

		if [[ "${TLOG_FIRST_RUN:-skip}" == "full" ]] && [[ "$newsize" -gt 0 ]]; then
			_tlog_output_content "$file" "$newsize" "$mode"
		fi

		if [[ $cursor_corrupt -eq 1 ]]; then
			rc=2
		fi

	elif [[ "$newsize" -gt "$size" ]]; then
		delta=$((newsize - size))
		_tlog_output_content "$file" "$delta" "$mode"
		_tlog_write_cursor "$tlog_name" "$baserun" "$newsize" "$mode"

	elif [[ "$newsize" -lt "$size" ]]; then
		rtfile=$(_tlog_find_rotated "$file") || true  # exit 1 = not found; [[ -n "$rtfile" ]] guards use
		if [[ -n "$rtfile" ]]; then
			_tlog_handle_rotation "$rtfile" "$size" "$mode" "$tlog_name" "$baserun"
		fi

		if [[ "$newsize" -gt 0 ]]; then
			_tlog_output_content "$file" "$newsize" "$mode"
		fi

		_tlog_write_cursor "$tlog_name" "$baserun" "$newsize" "$mode"
	fi
	# newsize == size: no output, no cursor write

	# Stale protection — touch cursor on every call, skip symlinks
	[[ ! -L "$baserun/$tlog_name" ]] && touch "$baserun/$tlog_name"

	if [[ "${TLOG_FLOCK:-0}" == "1" ]]; then
		exec {_tlog_fd}>&-
	fi

	return $rc
}

# tlog_read_full file [max_lines] — scan mode, no cursor (max_lines > 0 → tail -n, else cat)
tlog_read_full() {
	local file="$1" max_lines="${2:-0}"

	if [[ ! -f "$file" ]]; then
		return 1
	fi

	# Validate max_lines is numeric — non-numeric defaults to 0 (full output)
	if [[ -n "$max_lines" ]] && [[ ! "$max_lines" =~ $_TLOG_NUMERIC_PAT ]]; then
		echo "tlog: tlog_read_full: invalid max_lines: '$max_lines'" >&2
		max_lines="0"
	fi

	if [[ "$max_lines" -gt 0 ]]; then
		tail -n "$max_lines" "$file"
	else
		cat "$file"
	fi

	return 0
}

# tlog_adjust_cursor tlog_name baserun delta_removed — subtract from cursor after log trim
# Mode detected from stored cursor. Result clamped to 0.
tlog_adjust_cursor() {
	local tlog_name="$1" baserun="$2" delta_removed="$3"
	local new_value mode

	_tlog_validate_name "$tlog_name" || return 1

	if [[ ! "$delta_removed" =~ $_TLOG_NUMERIC_PAT ]]; then
		echo "tlog: invalid delta: $delta_removed" >&2
		return 1
	fi

	_tlog_parse_cursor "$tlog_name" "$baserun"
	if [[ -z "$_tlog_cursor_value" ]]; then
		return 0
	fi

	mode="${_tlog_cursor_mode:-bytes}"

	new_value=$((_tlog_cursor_value - delta_removed))
	if [[ "$new_value" -lt 0 ]]; then
		new_value=0
	fi

	_tlog_write_cursor "$tlog_name" "$baserun" "$new_value" "$mode"
}

# tlog_advance_cursors baserun log_pairs — fast-forward cursors to current position
# log_pairs = newline-separated FILE|TAG. Missing files fall back to journal cursor.
tlog_advance_cursors() {
	local baserun="$1" log_pairs="$2"
	local file tag newsize cursor_line jfilter
	local mode="${TLOG_MODE:-bytes}"

	if [[ "$mode" != "bytes" ]] && [[ "$mode" != "lines" ]]; then
		echo "tlog: tlog_advance_cursors: invalid mode '$mode' (must be 'bytes' or 'lines')" >&2
		return 1
	fi

	# F-010: baserun check before any file I/O
	if [[ ! -d "$baserun" ]]; then
		echo "tlog: tlog_advance_cursors: baserun directory not found: $baserun" >&2
		return 1
	fi
	_tlog_check_baserun_perms "$baserun"

	# journalctl lookup is expensive; cache once outside the loop
	local have_journalctl=0
	command -v journalctl >/dev/null 2>&1 && have_journalctl=1

	while IFS='|' read -r file tag; do
		[[ -z "$tag" ]] && continue
		_tlog_validate_name "$tag" || continue

		if [[ -f "$file" ]]; then
			newsize=$(_tlog_get_size "$file" "$mode")
			_tlog_write_cursor "$tag" "$baserun" "$newsize" "$mode"
		elif [[ "$have_journalctl" -eq 1 ]]; then
			jfilter=$(tlog_journal_filter "$tag") || continue
			cursor_line=$(_tlog_journal_get_cursor "$jfilter")
			if [[ -n "$cursor_line" ]]; then
				_tlog_write_cursor "$tag" "$baserun" "$cursor_line" "raw"
				_tlog_write_cursor "${tag}.jts" "$baserun" "$(date +%s)" "raw"
			fi
		fi
	done <<< "$log_pairs"

	return 0
}

# _tlog_journal_get_cursor jfilter — capture current journal cursor string on stdout
# $jfilter is intentionally unquoted: multi-token filters require word-splitting.
_tlog_journal_get_cursor() {
	local jfilter="$1"
	# suppress journalctl informational stderr; only stdout entries needed
	# shellcheck disable=SC2086
	journalctl $jfilter -n 0 --show-cursor 2>/dev/null \
		| grep -E '^-- cursor:' | sed 's/^-- cursor: //'
}

# tlog_journal_register tlog_name jfilter — add service→journalctl filter to registry
tlog_journal_register() {
	_TLOG_JOURNAL_NAMES+=("$1")
	_TLOG_JOURNAL_FILTERS+=("$2")
}

# tlog_journal_filter tlog_name — lookup filter on stdout, exit 1 if unregistered
tlog_journal_filter() {
	local tlog_name="$1"
	local i
	for i in "${!_TLOG_JOURNAL_NAMES[@]}"; do
		if [[ "${_TLOG_JOURNAL_NAMES[$i]}" == "$tlog_name" ]]; then
			printf '%s' "${_TLOG_JOURNAL_FILTERS[$i]}"
			return 0
		fi
	done
	return 1
}

# tlog_journal_read tlog_name baserun — cursor-based journal reader w/ timestamp fallback
# First run: capture cursor, emit nothing.
# Returns: 0=success, 1=unknown service/path error, 3=journal unavailable,
#          4=lock acquisition failed (TLOG_FLOCK=1 only).
tlog_journal_read() {
	local tlog_name="$1" baserun="$2"
	local cursor_file="$baserun/$tlog_name"
	local jts_file="$baserun/${tlog_name}.jts"
	local jfilter stored_cursor stored_jts new_cursor new_jts
	local output_data _tlog_fd

	_tlog_validate_name "$tlog_name" || return 1

	# F-010: defense-in-depth for direct callers
	if [[ ! -d "$baserun" ]]; then
		echo "tlog: baserun directory not found: $baserun" >&2
		return 1
	fi
	_tlog_check_baserun_perms "$baserun"

	if ! command -v journalctl >/dev/null 2>&1; then
		return 3
	fi

	jfilter=$(tlog_journal_filter "$tlog_name") || return 1

	# F-008: serialize journal cursor read/write
	if [[ "${TLOG_FLOCK:-0}" == "1" ]]; then
		exec {_tlog_fd}>"$baserun/${tlog_name}.lock"
		if ! flock -x -w 5 "$_tlog_fd"; then
			exec {_tlog_fd}>&-
			return 4
		fi
	fi

	stored_cursor=""
	if [[ -f "$cursor_file" ]] && [[ ! -L "$cursor_file" ]]; then
		read -r stored_cursor < "$cursor_file" 2>/dev/null || true  # read exits 1 on EOF; not an error
	elif [[ -L "$cursor_file" ]]; then
		echo "tlog: symlink detected for journal cursor $cursor_file, resetting" >&2
	fi

	# Allowlist matches real systemd cursors (s=<hex>;i=<hex>;...), rejects shell metacharacters
	local _jcursor_pat='^[a-zA-Z0-9=;_:-]+$'
	if [[ -n "$stored_cursor" ]] && [[ ! "$stored_cursor" =~ $_jcursor_pat ]]; then
		echo "tlog: corrupt journal cursor for $tlog_name, resetting" >&2
		stored_cursor=""
	fi

	stored_jts=""
	if [[ -f "$jts_file" ]] && [[ ! -L "$jts_file" ]]; then
		read -r stored_jts < "$jts_file" 2>/dev/null || true  # read exits 1 on EOF; not an error
	elif [[ -L "$jts_file" ]]; then
		echo "tlog: symlink detected for journal timestamp $jts_file, resetting" >&2
	fi

	if [[ -n "$stored_jts" ]] && [[ ! "$stored_jts" =~ $_TLOG_NUMERIC_PAT ]]; then
		echo "tlog: corrupt journal timestamp for $tlog_name, resetting" >&2
		stored_jts=""
	fi

	# First run: capture position, emit nothing
	if [[ -z "$stored_cursor" ]] && [[ -z "$stored_jts" ]]; then
		new_cursor=$(_tlog_journal_get_cursor "$jfilter")
		new_jts=$(date +%s)

		if [[ -n "$new_cursor" ]]; then
			_tlog_write_cursor "$tlog_name" "$baserun" "$new_cursor" "raw"
		fi
		_tlog_write_cursor "${tlog_name}.jts" "$baserun" "$new_jts" "raw"

		[[ ! -L "$baserun/$tlog_name" ]] && touch "$baserun/$tlog_name"
		if [[ "${TLOG_FLOCK:-0}" == "1" ]]; then
			exec {_tlog_fd}>&-
		fi
		return 0
	fi

	# Subsequent run: cursor is the strong ordering; jts is the time-based fallback
	if [[ -n "$stored_cursor" ]]; then
		# $jfilter intentionally unquoted: multi-token filters require word-splitting
		# shellcheck disable=SC2086
		if ! output_data=$(journalctl $jfilter --after-cursor="$stored_cursor" --no-pager 2>/dev/null); then  # suppress journalctl informational stderr
			if [[ -n "$stored_jts" ]]; then
				# $jfilter intentionally unquoted: multi-token filters require word-splitting
				# shellcheck disable=SC2086
				output_data=$(journalctl $jfilter --since="@${stored_jts}" --no-pager 2>/dev/null) || true  # non-zero when no entries; empty output handled below
			fi
		fi
	elif [[ -n "$stored_jts" ]]; then
		# $jfilter intentionally unquoted: multi-token filters require word-splitting
		# shellcheck disable=SC2086
		output_data=$(journalctl $jfilter --since="@${stored_jts}" --no-pager 2>/dev/null) || true  # non-zero when no entries; empty output handled below
	fi

	if [[ -n "$output_data" ]]; then
		printf '%s\n' "$output_data"
	fi

	new_cursor=$(_tlog_journal_get_cursor "$jfilter")
	new_jts=$(date +%s)

	if [[ -n "$new_cursor" ]]; then
		_tlog_write_cursor "$tlog_name" "$baserun" "$new_cursor" "raw"
	fi
	_tlog_write_cursor "${tlog_name}.jts" "$baserun" "$new_jts" "raw"

	# Stale protection — touch cursor, skip symlinks
	[[ ! -L "$baserun/$tlog_name" ]] && touch "$baserun/$tlog_name"

	if [[ "${TLOG_FLOCK:-0}" == "1" ]]; then
		exec {_tlog_fd}>&-
	fi

	return 0
}

# tlog_journal_read_full tlog_name [scan_timeout] [max_lines] — scan mode, no cursor
# Returns: 0=success, 1=unknown service, 3=journal unavailable.
tlog_journal_read_full() {
	local tlog_name="$1"
	local scan_timeout="${2:-${SCAN_TIMEOUT:-0}}"
	local max_lines="${3:-${SCAN_MAX_LINES:-0}}"
	local jfilter
	local cmd_args=()

	_tlog_validate_name "$tlog_name" || return 1

	# Non-numeric scan_timeout → 0 (no timeout)
	if [[ -n "$scan_timeout" ]] && [[ ! "$scan_timeout" =~ $_TLOG_NUMERIC_PAT ]]; then
		echo "tlog: tlog_journal_read_full: invalid scan_timeout: '$scan_timeout'" >&2
		scan_timeout="0"
	fi

	# Non-numeric max_lines → 0 (no limit)
	if [[ -n "$max_lines" ]] && [[ ! "$max_lines" =~ $_TLOG_NUMERIC_PAT ]]; then
		echo "tlog: tlog_journal_read_full: invalid max_lines: '$max_lines'" >&2
		max_lines="0"
	fi

	if ! command -v journalctl >/dev/null 2>&1; then
		return 3
	fi

	jfilter=$(tlog_journal_filter "$tlog_name") || return 1

	if [[ "$max_lines" -gt 0 ]]; then
		cmd_args+=(-n "$max_lines")
	fi
	cmd_args+=(--no-pager)

	if [[ "$scan_timeout" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
		# $jfilter intentionally unquoted: multi-token filters require word-splitting
		# shellcheck disable=SC2086
		timeout "$scan_timeout" journalctl $jfilter "${cmd_args[@]}" 2>/dev/null  # suppress journalctl informational stderr
	else
		# $jfilter intentionally unquoted: multi-token filters require word-splitting
		# shellcheck disable=SC2086
		journalctl $jfilter "${cmd_args[@]}" 2>/dev/null  # suppress journalctl informational stderr
	fi

	return 0
}
