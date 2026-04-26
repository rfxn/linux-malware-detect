#!/usr/bin/env bats
# 40-scan-lifecycle-integration.bats — Tests for scan() lifecycle meta integration
# Phase 6: meta at scan entry, _scan_aborting flag, worker exit code collection

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    TEST_DIR=$(mktemp -d)
}

teardown() {
    rm -rf "$TEST_DIR"
}

# --- Helper: source LMD stack to get all functions ---
_source_lmd_stack() {
    set +eu
    trap - ERR  # bash 5.1: BATS ERR trap leaks into sourced files even with set +e
    export inspath="$LMD_INSTALL"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/internals.conf"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/conf.maldet"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/tlog_lib.sh"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/elog_lib.sh"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/alert_lib.sh"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/lmd_alert.sh"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/lmd.lib.sh"
    set -eu
}

# --- Helper: initialize variables that _scan_cleanup references ---
# Required because _scan_cleanup uses rm -f on these variables,
# and set -u would fail on unbound references.
_init_scan_cleanup_vars() {
    find_results="${find_results:-/dev/null}"
    scan_session="${scan_session:-/dev/null}"
    runtime_ndb="${runtime_ndb:-/dev/null}"
    runtime_hdb="${runtime_hdb:-/dev/null}"
    runtime_hexstrings="${runtime_hexstrings:-/dev/null}"
    runtime_md5="${runtime_md5:-/dev/null}"
    runtime_sha256="${runtime_sha256:-/dev/null}"
    runtime_hsb="${runtime_hsb:-/dev/null}"
    clamscan_results="${clamscan_results:-/dev/null}"
    runtime_hex_literal="${runtime_hex_literal:-/dev/null}"
    runtime_hex_regex="${runtime_hex_regex:-/dev/null}"
    runtime_hex_sigmap="${runtime_hex_sigmap:-/dev/null}"
    runtime_csig_batch_compiled="${runtime_csig_batch_compiled:-/dev/null}"
    runtime_csig_literals="${runtime_csig_literals:-/dev/null}"
    runtime_csig_wildcards="${runtime_csig_wildcards:-/dev/null}"
    runtime_csig_universals="${runtime_csig_universals:-/dev/null}"
    tmpf="${tmpf:-/dev/null}"
    nsess="${nsess:-}"
    datestamp="${datestamp:-260328-1600}"
    cnffile="${cnffile:-/usr/local/maldetect/conf.maldet}"
    quarantine_hits="${quarantine_hits:-0}"
    email_ignore_clean="${email_ignore_clean:-0}"
    scan_et="${scan_et:-}"
    _timer_pid=""
}

# ========================================================================
# _scan_aborting flag initialization
# ========================================================================

# bats test_tags=lifecycle,unit
@test "lifecycle: _scan_aborting is initialized to 0 at file scope" {
    _source_lmd_stack
    [ "${_scan_aborting}" = "0" ]
}

# ========================================================================
# trap_exit() — _scan_aborting flag and meta update
# ========================================================================

# bats test_tags=lifecycle,unit
@test "lifecycle: trap_exit sets _scan_aborting=1 for scan service" {
    _source_lmd_stack
    _init_scan_cleanup_vars
    svc="a"
    scanid="260328-1600.$$"
    scan_start=$(date +%s)
    progress_hits=0
    progress_cleaned=0
    scan_session=$(mktemp "$tmpdir/.sess.XXXXXX")
    find_results=$(mktemp "$tmpdir/.find.XXXXXX")
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    # Override exit to prevent actual exit in test
    exit() { return 0; }
    trap_exit
    [ "${_scan_aborting}" = "1" ]
    unset -f exit
}

# bats test_tags=lifecycle,unit
@test "lifecycle: trap_exit updates meta state to killed when scanid is set" {
    _source_lmd_stack
    _init_scan_cleanup_vars
    svc="a"
    scanid="260328-1601.$$"
    scan_start=$(date +%s)
    progress_hits=0
    progress_cleaned=0
    scan_session=$(mktemp "$tmpdir/.sess.XXXXXX")
    find_results=$(mktemp "$tmpdir/.find.XXXXXX")
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    exit() { return 0; }
    trap_exit
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "killed" ]
    unset -f exit
}

# bats test_tags=lifecycle,unit
@test "lifecycle: trap_exit re-entry guard prevents double execution" {
    _source_lmd_stack
    _init_scan_cleanup_vars
    svc="a"
    scanid="260328-1602.$$"
    scan_start=$(date +%s)
    progress_hits=0
    progress_cleaned=0
    scan_session=$(mktemp "$tmpdir/.sess.XXXXXX")
    find_results=$(mktemp "$tmpdir/.find.XXXXXX")
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    # Pre-set the flag to simulate re-entry
    _scan_aborting=1
    exit() { return 0; }
    # Should return early without updating meta
    trap_exit
    _lifecycle_read_meta "$scanid"
    # State should remain "running" (initial write), not "killed"
    [ "$_meta_state" = "running" ]
    unset -f exit
}

# ========================================================================
# clean_exit() — meta state=completed
# ========================================================================

# bats test_tags=lifecycle,unit
@test "lifecycle: clean_exit updates meta state to completed when scanid set" {
    _source_lmd_stack
    _init_scan_cleanup_vars
    scanid="260328-1610.$$"
    scan_start=$(date +%s)
    progress_hits=0
    progress_cleaned=0
    _scan_aborting=0
    scan_session=$(mktemp "$tmpdir/.sess.XXXXXX")
    find_results=$(mktemp "$tmpdir/.find.XXXXXX")
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    clean_exit
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "completed" ]
}

# bats test_tags=lifecycle,unit
@test "lifecycle: clean_exit writes completed timestamp" {
    _source_lmd_stack
    _init_scan_cleanup_vars
    scanid="260328-1611.$$"
    scan_start=$(date +%s)
    progress_hits=0
    progress_cleaned=0
    _scan_aborting=0
    scan_session=$(mktemp "$tmpdir/.sess.XXXXXX")
    find_results=$(mktemp "$tmpdir/.find.XXXXXX")
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    clean_exit
    _lifecycle_read_meta "$scanid"
    [[ "$_meta_completed" =~ ^[0-9]+$ ]]
}

# bats test_tags=lifecycle,unit
@test "lifecycle: clean_exit writes elapsed time from scan_start" {
    _source_lmd_stack
    _init_scan_cleanup_vars
    scanid="260328-1613.$$"
    scan_start=$(( $(date +%s) - 42 ))
    progress_hits=0
    progress_cleaned=0
    _scan_aborting=0
    scan_session=$(mktemp "$tmpdir/.sess.XXXXXX")
    find_results=$(mktemp "$tmpdir/.find.XXXXXX")
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    clean_exit
    _lifecycle_read_meta "$scanid"
    # Elapsed should be >= 42 (we set scan_start 42 seconds in the past)
    [ "$_meta_elapsed" -ge 42 ]
}

# bats test_tags=lifecycle,unit
@test "lifecycle: clean_exit skips meta update when _scan_aborting=1" {
    _source_lmd_stack
    _init_scan_cleanup_vars
    scanid="260328-1612.$$"
    scan_start=$(date +%s)
    progress_hits=0
    progress_cleaned=0
    _scan_aborting=1
    scan_session=$(mktemp "$tmpdir/.sess.XXXXXX")
    find_results=$(mktemp "$tmpdir/.find.XXXXXX")
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    clean_exit
    _lifecycle_read_meta "$scanid"
    # State should remain "running" — clean_exit skipped because aborting
    [ "$_meta_state" = "running" ]
}

# bats test_tags=lifecycle,unit
@test "lifecycle: clean_exit skips meta update when scanid is empty" {
    _source_lmd_stack
    _init_scan_cleanup_vars
    scanid=""
    scan_start=""
    _scan_aborting=0
    scan_session=$(mktemp "$tmpdir/.sess.XXXXXX")
    find_results=$(mktemp "$tmpdir/.find.XXXXXX")
    # Should not error even with no scanid
    clean_exit
}

# ========================================================================
# _wait_workers_with_progress() — lifecycle exit code detection
# ========================================================================

# Helper: launch worker(s) inside the same subshell as wait to avoid
# BATS run-subshell PID ownership issue. Uses bash -c to execute the
# entire source+launch+wait sequence in one process tree.
_test_worker_exit() {
    # Args: exit_codes... (space-separated list of exit codes for workers)
    local _codes="$1"
    bash -c '
        set +eu
        export inspath="/usr/local/maldetect"
        source "$inspath/internals/internals.conf"
        source "$inspath/conf.maldet"
        source "$inspath/internals/tlog_lib.sh"
        source "$inspath/internals/elog_lib.sh"
        source "$inspath/internals/alert_lib.sh"
        source "$inspath/internals/lmd_alert.sh"
        source "$inspath/internals/lmd.lib.sh"
        _in_scan_context=0
        set_background=""
        _progress_dir=$(mktemp -d "$tmpdir/.test_progress.XXXXXX")
        _pids=()
        for code in '"$_codes"'; do
            bash -c "exit $code" &
            _pids+=($!)
        done
        _wait_workers_with_progress "test" "0" "$_progress_dir" "${_pids[@]}"
    '
}

# bats test_tags=lifecycle,unit
@test "lifecycle: _wait_workers_with_progress returns 0 for normal worker exit" {
    run _test_worker_exit "0"
    [ "$status" -eq 0 ]
}

# bats test_tags=lifecycle,unit
@test "lifecycle: _wait_workers_with_progress returns 1 for abort exit code 3" {
    run _test_worker_exit "3"
    [ "$status" -eq 1 ]
}

# bats test_tags=lifecycle,unit
@test "lifecycle: _wait_workers_with_progress returns 1 for stop exit code 4" {
    run _test_worker_exit "4"
    [ "$status" -eq 1 ]
}

# bats test_tags=lifecycle,unit
@test "lifecycle: _wait_workers_with_progress returns 1 for orphan exit code 5" {
    run _test_worker_exit "5"
    [ "$status" -eq 1 ]
}

# bats test_tags=lifecycle,unit
@test "lifecycle: _wait_workers_with_progress returns 0 for non-lifecycle error code" {
    run _test_worker_exit "1"
    [ "$status" -eq 0 ]
}

# bats test_tags=lifecycle,unit
@test "lifecycle: _wait_workers_with_progress detects abort among mixed workers" {
    run _test_worker_exit "0 3 0"
    [ "$status" -eq 1 ]
}

# ========================================================================
# scan() meta integration (full scan with meta files)
# ========================================================================

# bats test_tags=lifecycle,integration
@test "lifecycle: scan creates scan.meta file for non-hook scans" {
    local _scan_dir
    _scan_dir=$(mktemp -d)
    printf '%44s' "CLEAN_FILE_CONTENT_NO_MATCH_EXPECTED_HERE_XX" > "$_scan_dir/clean.txt"
    run "$LMD_INSTALL/maldet" -co scan_clamscan=0,scan_yara=0,scan_hashtype=md5 -a "$_scan_dir"
    local sessdir="/usr/local/maldetect/sess"
    local _found=0
    for f in "$sessdir"/scan.meta.*; do
        if [ -f "$f" ]; then
            _found=1
            break
        fi
    done
    [ "$_found" -eq 1 ]
    rm -rf "$_scan_dir"
}

# bats test_tags=lifecycle,integration
@test "lifecycle: scan meta has engine=native for non-clamav scan" {
    local _scan_dir
    _scan_dir=$(mktemp -d)
    printf '%44s' "CLEAN_FILE_CONTENT_NO_MATCH_EXPECTED_HERE_XX" > "$_scan_dir/clean.txt"
    run "$LMD_INSTALL/maldet" -co scan_clamscan=0,scan_yara=0,scan_hashtype=md5 -a "$_scan_dir"
    local sessdir="/usr/local/maldetect/sess"
    local _meta_file _engine_val
    for f in "$sessdir"/scan.meta.*; do
        [ -f "$f" ] || continue
        case "$f" in *.tmp) continue ;; esac
        _meta_file="$f"
        break
    done
    [ -n "${_meta_file:-}" ]
    _engine_val=$(grep '^engine=' "$_meta_file" | tail -1 | cut -d= -f2)
    [ "$_engine_val" = "native" ]
    rm -rf "$_scan_dir"
}

# bats test_tags=lifecycle,integration
@test "lifecycle: scan meta has state=completed after normal scan" {
    local _scan_dir
    _scan_dir=$(mktemp -d)
    printf '%44s' "CLEAN_FILE_CONTENT_NO_MATCH_EXPECTED_HERE_XX" > "$_scan_dir/clean.txt"
    run "$LMD_INSTALL/maldet" -co scan_clamscan=0,scan_yara=0,scan_hashtype=md5 -a "$_scan_dir"
    local sessdir="/usr/local/maldetect/sess"
    local _meta_file _state_val
    for f in "$sessdir"/scan.meta.*; do
        [ -f "$f" ] || continue
        case "$f" in *.tmp) continue ;; esac
        _meta_file="$f"
        break
    done
    [ -n "${_meta_file:-}" ]
    _state_val=$(grep '^state=' "$_meta_file" | tail -1 | cut -d= -f2)
    [ "$_state_val" = "completed" ]
    rm -rf "$_scan_dir"
}

# bats test_tags=lifecycle,integration
@test "lifecycle: scan meta has completed epoch timestamp" {
    local _scan_dir
    _scan_dir=$(mktemp -d)
    printf '%44s' "CLEAN_FILE_CONTENT_NO_MATCH_EXPECTED_HERE_XX" > "$_scan_dir/clean.txt"
    run "$LMD_INSTALL/maldet" -co scan_clamscan=0,scan_yara=0,scan_hashtype=md5 -a "$_scan_dir"
    local sessdir="/usr/local/maldetect/sess"
    local _meta_file _completed_val
    for f in "$sessdir"/scan.meta.*; do
        [ -f "$f" ] || continue
        case "$f" in *.tmp) continue ;; esac
        _meta_file="$f"
        break
    done
    [ -n "${_meta_file:-}" ]
    _completed_val=$(grep '^completed=' "$_meta_file" | tail -1 | cut -d= -f2)
    [[ "$_completed_val" =~ ^[0-9]+$ ]]
    rm -rf "$_scan_dir"
}

# bats test_tags=lifecycle,integration
@test "lifecycle: scan meta has hashtype and stages fields" {
    local _scan_dir
    _scan_dir=$(mktemp -d)
    printf '%44s' "CLEAN_FILE_CONTENT_NO_MATCH_EXPECTED_HERE_XX" > "$_scan_dir/clean.txt"
    run "$LMD_INSTALL/maldet" -co scan_clamscan=0,scan_yara=0,scan_hashtype=md5 -a "$_scan_dir"
    local sessdir="/usr/local/maldetect/sess"
    local _meta_file
    for f in "$sessdir"/scan.meta.*; do
        [ -f "$f" ] || continue
        case "$f" in *.tmp) continue ;; esac
        _meta_file="$f"
        break
    done
    [ -n "${_meta_file:-}" ]
    grep -q '^hashtype=md5$' "$_meta_file"
    # Stages should include md5 and hex for native engine
    grep -q '^stages=md5,hex' "$_meta_file"
    rm -rf "$_scan_dir"
}

# bats test_tags=lifecycle,integration
@test "lifecycle: hook scans do not create scan.meta file" {
    local sessdir="/usr/local/maldetect/sess"
    # Clean any existing meta files from prior tests
    rm -f "$sessdir"/scan.meta.* 2>/dev/null
    local _scan_dir
    _scan_dir=$(mktemp -d)
    printf '%44s' "CLEAN_FILE_CONTENT_NO_MATCH_EXPECTED_HERE_XX" > "$_scan_dir/clean.txt"
    run "$LMD_INSTALL/maldet" --hook-scan /dev/shm "$_scan_dir/clean.txt"
    local _count=0
    for f in "$sessdir"/scan.meta.*; do
        [ -f "$f" ] && _count=$((_count + 1))
    done
    [ "$_count" -eq 0 ]
    rm -rf "$_scan_dir"
}
