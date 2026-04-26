#!/usr/bin/env bats
# 41-lifecycle-pause.bats — Tests for pause/unpause, duration parsing, daemon gate, worker auto-resume

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

# --- Helper: source LMD stack to get lifecycle functions ---
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

# ========================================================================
# _lifecycle_pause tests
# ========================================================================

@test "lifecycle_pause: rejects completed scan" {
    _source_lmd_stack
    local scanid="260328-3000.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "completed"
    run _lifecycle_pause "$scanid"
    [ "$status" -ne 0 ]
    assert_output --partial "cannot pause"
}

@test "lifecycle_pause: rejects killed scan" {
    _source_lmd_stack
    local scanid="260328-3001.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "killed"
    run _lifecycle_pause "$scanid"
    [ "$status" -ne 0 ]
    assert_output --partial "cannot pause"
}

@test "lifecycle_pause: rejects already paused scan" {
    _source_lmd_stack
    local scanid="260328-3002.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    touch "$tmpdir/.pause.$scanid"
    run _lifecycle_pause "$scanid"
    [ "$status" -ne 0 ]
    assert_output --partial "already paused"
    rm -f "$tmpdir/.pause.$scanid"
}

@test "lifecycle_pause: rejects nonexistent scanid" {
    _source_lmd_stack
    run _lifecycle_pause "nonexistent.999"
    [ "$status" -ne 0 ]
    assert_output --partial "not found"
}

@test "lifecycle_pause: daemon gate rejects clamdscan engine (E16)" {
    _source_lmd_stack
    local scanid="260328-3003.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "clamdscan" "md5" "md5" ""
    run _lifecycle_pause "$scanid"
    [ "$status" -ne 0 ]
    assert_output --partial "daemon"
}

@test "lifecycle_pause: writes pause sentinel file" {
    _source_lmd_stack
    local scanid="260328-3004.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_pause "$scanid"
    [ -f "$tmpdir/.pause.$scanid" ]
    rm -f "$tmpdir/.pause.$scanid"
}

@test "lifecycle_pause: sentinel contains epoch= line" {
    _source_lmd_stack
    local scanid="260328-3005.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_pause "$scanid"
    grep -q '^epoch=' "$tmpdir/.pause.$scanid"
    rm -f "$tmpdir/.pause.$scanid"
}

@test "lifecycle_pause: indefinite pause (no duration) writes duration=0" {
    _source_lmd_stack
    local scanid="260328-3006.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_pause "$scanid"
    grep -q '^duration=0$' "$tmpdir/.pause.$scanid"
    rm -f "$tmpdir/.pause.$scanid"
}

@test "lifecycle_pause: parses duration in seconds (Ns)" {
    _source_lmd_stack
    local scanid="260328-3007.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_pause "$scanid" "3600s"
    grep -q '^duration=3600$' "$tmpdir/.pause.$scanid"
    rm -f "$tmpdir/.pause.$scanid"
}

@test "lifecycle_pause: parses duration in minutes (Nm)" {
    _source_lmd_stack
    local scanid="260328-3008.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_pause "$scanid" "30m"
    grep -q '^duration=1800$' "$tmpdir/.pause.$scanid"
    rm -f "$tmpdir/.pause.$scanid"
}

@test "lifecycle_pause: parses duration in hours (Nh)" {
    _source_lmd_stack
    local scanid="260328-3009.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_pause "$scanid" "2h"
    grep -q '^duration=7200$' "$tmpdir/.pause.$scanid"
    rm -f "$tmpdir/.pause.$scanid"
}

@test "lifecycle_pause: bare numeric is treated as seconds" {
    _source_lmd_stack
    local scanid="260328-3010.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_pause "$scanid" "120"
    grep -q '^duration=120$' "$tmpdir/.pause.$scanid"
    rm -f "$tmpdir/.pause.$scanid"
}

@test "lifecycle_pause: rejects invalid duration format (E8)" {
    _source_lmd_stack
    local scanid="260328-3011.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    run _lifecycle_pause "$scanid" "abc"
    [ "$status" -ne 0 ]
    assert_output --partial "invalid duration"
}

@test "lifecycle_pause: rejects duration with invalid suffix (E8)" {
    _source_lmd_stack
    local scanid="260328-3012.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    run _lifecycle_pause "$scanid" "30x"
    [ "$status" -ne 0 ]
    assert_output --partial "invalid duration"
}

@test "lifecycle_pause: updates meta state to paused" {
    _source_lmd_stack
    local scanid="260328-3013.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_pause "$scanid"
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "paused" ]
    rm -f "$tmpdir/.pause.$scanid"
}

@test "lifecycle_pause: sends SIGSTOP to clamscan PID file if present" {
    _source_lmd_stack
    local scanid="260328-3014.$$"
    # Start a sleep as a stand-in for clamscan
    sleep 300 &
    local clam_pid=$!
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "clamscan" "md5" "md5" ""
    echo "$clam_pid" > "$tmpdir/.clamscan_pid.$scanid"
    _lifecycle_pause "$scanid"
    # Process should be stopped (T state)
    local proc_state
    proc_state=$(ps -o stat= -p "$clam_pid" 2>/dev/null | tr -d ' ')
    # T = stopped
    [[ "$proc_state" == *T* ]]
    # Clean up
    kill -CONT "$clam_pid" 2>/dev/null
    kill "$clam_pid" 2>/dev/null
    wait "$clam_pid" 2>/dev/null || true
    rm -f "$tmpdir/.pause.$scanid" "$tmpdir/.clamscan_pid.$scanid"
}

@test "lifecycle_pause: sends SIGSTOP to yara PID file if present" {
    _source_lmd_stack
    local scanid="260328-3015.$$"
    sleep 300 &
    local yara_pid=$!
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    echo "$yara_pid" > "$tmpdir/.yara_pid.$scanid"
    _lifecycle_pause "$scanid"
    local proc_state
    proc_state=$(ps -o stat= -p "$yara_pid" 2>/dev/null | tr -d ' ')
    [[ "$proc_state" == *T* ]]
    kill -CONT "$yara_pid" 2>/dev/null
    kill "$yara_pid" 2>/dev/null
    wait "$yara_pid" 2>/dev/null || true
    rm -f "$tmpdir/.pause.$scanid" "$tmpdir/.yara_pid.$scanid"
}

@test "lifecycle_pause: skips SIGSTOP when no PID files exist" {
    _source_lmd_stack
    local scanid="260328-3016.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    run _lifecycle_pause "$scanid"
    [ "$status" -eq 0 ]
    rm -f "$tmpdir/.pause.$scanid"
}

@test "lifecycle_pause: allows clamscan (standalone) engine" {
    _source_lmd_stack
    local scanid="260328-3017.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "clamscan" "md5" "md5" ""
    run _lifecycle_pause "$scanid"
    [ "$status" -eq 0 ]
    rm -f "$tmpdir/.pause.$scanid"
}

# ========================================================================
# _lifecycle_unpause tests
# ========================================================================

@test "lifecycle_unpause: rejects non-paused scan" {
    _source_lmd_stack
    local scanid="260328-3100.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    run _lifecycle_unpause "$scanid"
    [ "$status" -ne 0 ]
    assert_output --partial "not paused"
}

@test "lifecycle_unpause: rejects nonexistent scanid" {
    _source_lmd_stack
    run _lifecycle_unpause "nonexistent.999"
    [ "$status" -ne 0 ]
    assert_output --partial "not found"
}

@test "lifecycle_unpause: removes pause sentinel" {
    _source_lmd_stack
    local scanid="260328-3101.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_pause "$scanid"
    [ -f "$tmpdir/.pause.$scanid" ]
    _lifecycle_unpause "$scanid"
    [ ! -f "$tmpdir/.pause.$scanid" ]
}

@test "lifecycle_unpause: updates meta state to running" {
    _source_lmd_stack
    local scanid="260328-3102.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_pause "$scanid"
    _lifecycle_unpause "$scanid"
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "running" ]
}

@test "lifecycle_unpause: sends SIGCONT to stopped clamscan process" {
    _source_lmd_stack
    local scanid="260328-3103.$$"
    sleep 300 &
    local clam_pid=$!
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "clamscan" "md5" "md5" ""
    echo "$clam_pid" > "$tmpdir/.clamscan_pid.$scanid"
    # Pause (sends SIGSTOP)
    _lifecycle_pause "$scanid"
    # Verify stopped
    local proc_state
    proc_state=$(ps -o stat= -p "$clam_pid" 2>/dev/null | tr -d ' ')
    [[ "$proc_state" == *T* ]]
    # Unpause (sends SIGCONT)
    _lifecycle_unpause "$scanid"
    # Verify resumed (should be sleeping, not stopped)
    proc_state=$(ps -o stat= -p "$clam_pid" 2>/dev/null | tr -d ' ')
    [[ "$proc_state" != *T* ]]
    kill "$clam_pid" 2>/dev/null
    wait "$clam_pid" 2>/dev/null || true
    rm -f "$tmpdir/.clamscan_pid.$scanid"
}

@test "lifecycle_unpause: sends SIGCONT to stopped yara process" {
    _source_lmd_stack
    local scanid="260328-3104.$$"
    sleep 300 &
    local yara_pid=$!
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    echo "$yara_pid" > "$tmpdir/.yara_pid.$scanid"
    _lifecycle_pause "$scanid"
    _lifecycle_unpause "$scanid"
    local proc_state
    proc_state=$(ps -o stat= -p "$yara_pid" 2>/dev/null | tr -d ' ')
    [[ "$proc_state" != *T* ]]
    kill "$yara_pid" 2>/dev/null
    wait "$yara_pid" 2>/dev/null || true
    rm -f "$tmpdir/.yara_pid.$scanid"
}

# ========================================================================
# Worker auto-resume on duration expiry
# ========================================================================

@test "worker pause loop: auto-resumes when duration expires" {
    local scanid="duration-test-$$"
    # Write a pause sentinel with epoch 10 seconds in the past and 1s duration
    # So epoch + duration < now  =>  should auto-resume immediately
    local past_epoch
    past_epoch=$(( $(date +%s) - 10 ))
    printf 'epoch=%s\nduration=1\n' "$past_epoch" > "$TEST_DIR/.pause.$scanid"

    # Worker should detect duration expired and remove the sentinel
    local chunk="$TEST_DIR/chunk.txt"
    local hexlits="$TEST_DIR/hex_lits.txt"
    local hexregex="$TEST_DIR/hex_regex.txt"
    local hexsigmap="$TEST_DIR/hex_sigmap.txt"
    local testfile="$TEST_DIR/testfile.txt"

    printf 'clean content for auto-resume test with enough padding bytes\n' > "$testfile"
    echo "$testfile" > "$chunk"
    touch "$hexlits" "$hexregex" "$hexsigmap"

    # Create a second file so we get a second micro-chunk (chunk_size=1)
    local testfile2="$TEST_DIR/testfile2.txt"
    printf 'another clean file for auto-resume test padding bytes here\n' > "$testfile2"
    echo "$testfile2" >> "$chunk"

    # Use inline snippet to run worker — tmpdir=$TEST_DIR so sentinel is found there
    run bash -c "set +eu
        export inspath='$LMD_INSTALL'
        source '$LMD_INSTALL/internals/internals.conf'
        source '$LMD_INSTALL/conf.maldet'
        source '$LMD_INSTALL/internals/tlog_lib.sh'
        source '$LMD_INSTALL/internals/elog_lib.sh'
        source '$LMD_INSTALL/internals/alert_lib.sh'
        source '$LMD_INSTALL/internals/lmd_alert.sh'
        source '$LMD_INSTALL/internals/lmd.lib.sh'
        tmpdir='$TEST_DIR'
        _hex_csig_batch_worker '$chunk' '256' \
            '$hexlits' '$hexregex' '$hexsigmap' \
            '' '' '' '' '' '1' '$scanid'
    "
    # Worker should complete successfully (auto-resumed)
    [ "$status" -eq 0 ]
    # Sentinel should have been removed by the auto-resume
    [ ! -f "$TEST_DIR/.pause.$scanid" ]
}

@test "worker pause loop: indefinite (duration=0) stays paused until sentinel removed" {
    _source_lmd_stack
    local scanid="indef-test-$$"
    local past_epoch
    past_epoch=$(( $(command date +%s) - 10 ))
    # duration=0 means indefinite — should NOT auto-resume
    printf 'epoch=%s\nduration=0\n' "$past_epoch" > "$TEST_DIR/.pause.$scanid"

    local chunk="$TEST_DIR/chunk.txt"
    local hexlits="$TEST_DIR/hex_lits.txt"
    local hexregex="$TEST_DIR/hex_regex.txt"
    local hexsigmap="$TEST_DIR/hex_sigmap.txt"

    # Two files to trigger pause at micro-chunk boundary
    local i
    for i in 1 2; do
        local f="$TEST_DIR/file${i}.txt"
        printf 'clean file for indefinite pause test padding bytes here number %s\n' "$i" > "$f"
        echo "$f" >> "$chunk"
    done
    touch "$hexlits" "$hexregex" "$hexsigmap"

    # Run worker in background, remove sentinel after 3s
    (
        sleep 3
        rm -f "$TEST_DIR/.pause.$scanid"
    ) &
    local cleanup_pid=$!

    run bash -c "set +eu
        export inspath='$LMD_INSTALL'
        source '$LMD_INSTALL/internals/internals.conf'
        source '$LMD_INSTALL/conf.maldet'
        source '$LMD_INSTALL/internals/tlog_lib.sh'
        source '$LMD_INSTALL/internals/elog_lib.sh'
        source '$LMD_INSTALL/internals/alert_lib.sh'
        source '$LMD_INSTALL/internals/lmd_alert.sh'
        source '$LMD_INSTALL/internals/lmd.lib.sh'
        tmpdir='$TEST_DIR'
        _hex_csig_batch_worker '$chunk' '256' \
            '$hexlits' '$hexregex' '$hexsigmap' \
            '' '' '' '' '' '1' '$scanid'
    "
    [ "$status" -eq 0 ]
    wait "$cleanup_pid" 2>/dev/null || true
}

# ========================================================================
# CLI --pause and --unpause handler tests
# ========================================================================

@test "maldet --pause with no argument prints error and exits 1" {
    run $LMD_INSTALL/maldet --pause
    [ "$status" -eq 1 ]
    assert_output --partial "requires a SCANID"
}

@test "maldet --unpause with no argument prints error and exits 1" {
    run $LMD_INSTALL/maldet --unpause
    [ "$status" -eq 1 ]
    assert_output --partial "requires a SCANID"
}

@test "maldet --pause with nonexistent scanid prints error" {
    run $LMD_INSTALL/maldet --pause 999999-9999.99999
    [ "$status" -ne 0 ]
    assert_output --partial "not found"
}

@test "maldet --unpause with nonexistent scanid prints error" {
    run $LMD_INSTALL/maldet --unpause 999999-9999.99999
    [ "$status" -ne 0 ]
    assert_output --partial "not found"
}

# ========================================================================
# Regression: existing kill still works with paused scans
# ========================================================================

@test "regression: kill on paused scan still works" {
    _source_lmd_stack
    sleep 300 &
    local bg_pid=$!
    local scanid="260328-3200.$$"
    _lifecycle_write_meta "$scanid" "$bg_pid" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_pause "$scanid"
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "paused" ]
    _lifecycle_kill "$scanid"
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "killed" ]
    ! kill -0 "$bg_pid" 2>/dev/null
}
