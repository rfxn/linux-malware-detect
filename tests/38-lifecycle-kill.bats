#!/usr/bin/env bats
# 38-lifecycle-kill.bats — Tests for kill, orphan sweep, duplicate guard, stale meta cleanup

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
# _lifecycle_kill tests
# ========================================================================

@test "lifecycle_kill: rejects completed scan with error" {
    _source_lmd_stack
    local scanid="260328-2000.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "completed"
    run _lifecycle_kill "$scanid"
    [ "$status" -ne 0 ]
    assert_output --partial "already completed"
}

@test "lifecycle_kill: rejects already killed scan with error" {
    _source_lmd_stack
    local scanid="260328-2001.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "killed"
    run _lifecycle_kill "$scanid"
    [ "$status" -ne 0 ]
    assert_output --partial "already killed"
}

@test "lifecycle_kill: rejects nonexistent scanid" {
    _source_lmd_stack
    run _lifecycle_kill "nonexistent.999"
    [ "$status" -ne 0 ]
    assert_output --partial "not found"
}

@test "lifecycle_kill: writes abort sentinel file" {
    _source_lmd_stack
    # Start a background sleep process that we can kill
    sleep 300 &
    local bg_pid=$!
    local scanid="260328-2002.$$"
    _lifecycle_write_meta "$scanid" "$bg_pid" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_kill "$scanid"
    # Abort sentinel should have been created (and then cleaned up)
    # The process should be dead
    ! kill -0 "$bg_pid" 2>/dev/null
    # Meta should be updated to killed
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "killed" ]
}

@test "lifecycle_kill: cleans up sentinel files after kill" {
    _source_lmd_stack
    sleep 300 &
    local bg_pid=$!
    local scanid="260328-2003.$$"
    _lifecycle_write_meta "$scanid" "$bg_pid" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    # Also create a pause sentinel to verify cleanup
    touch "$tmpdir/.pause.$scanid"
    _lifecycle_kill "$scanid"
    [ ! -f "$tmpdir/.abort.$scanid" ]
    [ ! -f "$tmpdir/.pause.$scanid" ]
}

@test "lifecycle_kill: cleans up scan-scoped runtime temp files" {
    _source_lmd_stack
    sleep 300 &
    local bg_pid=$!
    local scanid="260328-2004.$$"
    _lifecycle_write_meta "$scanid" "$bg_pid" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    # Create some runtime temp files scoped to this scanid
    touch "$tmpdir/.runtime.hex.$scanid.chunk1"
    touch "$tmpdir/.runtime.md5.$scanid.chunk2"
    _lifecycle_kill "$scanid"
    [ ! -f "$tmpdir/.runtime.hex.$scanid.chunk1" ]
    [ ! -f "$tmpdir/.runtime.md5.$scanid.chunk2" ]
}

@test "lifecycle_kill: handles stale scan (process already dead)" {
    _source_lmd_stack
    # Use a known-dead PID
    bash -c 'exit 0' &
    local dead_pid=$!
    wait "$dead_pid" 2>/dev/null || true
    local scanid="260328-2005.$$"
    _lifecycle_write_meta "$scanid" "$dead_pid" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    run _lifecycle_kill "$scanid"
    [ "$status" -eq 0 ]
    # Meta should be updated
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "killed" ]
}

@test "lifecycle_kill: sends SIGCONT before SIGTERM when scan is paused" {
    _source_lmd_stack
    # Start a stopped process — send SIGSTOP to it
    sleep 300 &
    local bg_pid=$!
    kill -STOP "$bg_pid"
    local scanid="260328-2006.$$"
    _lifecycle_write_meta "$scanid" "$bg_pid" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    touch "$tmpdir/.pause.$scanid"
    _lifecycle_kill "$scanid"
    # Process should be dead (SIGCONT was sent first, then SIGTERM)
    ! kill -0 "$bg_pid" 2>/dev/null
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "killed" ]
}

@test "lifecycle_kill: updates meta state to killed" {
    _source_lmd_stack
    sleep 300 &
    local bg_pid=$!
    local scanid="260328-2007.$$"
    _lifecycle_write_meta "$scanid" "$bg_pid" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_kill "$scanid"
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "killed" ]
}

# ========================================================================
# _lifecycle_orphan_sweep tests
# ========================================================================

@test "lifecycle_orphan_sweep: marks stale scans (dead PID, state=running)" {
    _source_lmd_stack
    # Create a meta file with a dead PID
    bash -c 'exit 0' &
    local dead_pid=$!
    wait "$dead_pid" 2>/dev/null || true
    local scanid="260328-2010.$$"
    _lifecycle_write_meta "$scanid" "$dead_pid" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_orphan_sweep
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "stale" ]
}

@test "lifecycle_orphan_sweep: does not touch running scans with live PID" {
    _source_lmd_stack
    local scanid="260328-2011.$$"
    # Use our own PID (alive)
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_orphan_sweep
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "running" ]
}

@test "lifecycle_orphan_sweep: does not touch completed scans" {
    _source_lmd_stack
    local scanid="260328-2012.$$"
    _lifecycle_write_meta "$scanid" "99999" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "completed"
    _lifecycle_orphan_sweep
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "completed" ]
}

@test "lifecycle_orphan_sweep: handles empty sessdir gracefully" {
    _source_lmd_stack
    # Clean out any existing metas
    rm -f "$sessdir"/scan.meta.*
    run _lifecycle_orphan_sweep
    [ "$status" -eq 0 ]
}

@test "lifecycle_orphan_sweep: marks multiple stale scans in one pass" {
    _source_lmd_stack
    # Create two metas with dead PIDs
    bash -c 'exit 0' &
    local dead1=$!
    wait "$dead1" 2>/dev/null || true
    bash -c 'exit 0' &
    local dead2=$!
    wait "$dead2" 2>/dev/null || true
    local sid1="260328-2013a.$$"
    local sid2="260328-2013b.$$"
    _lifecycle_write_meta "$sid1" "$dead1" "$PPID" "/home/a" "100" "1" "native" "md5" "md5" ""
    _lifecycle_write_meta "$sid2" "$dead2" "$PPID" "/home/b" "200" "1" "native" "md5" "md5" ""
    _lifecycle_orphan_sweep
    _lifecycle_read_meta "$sid1"
    [ "$_meta_state" = "stale" ]
    _lifecycle_read_meta "$sid2"
    [ "$_meta_state" = "stale" ]
}

# ========================================================================
# _lifecycle_duplicate_guard tests
# ========================================================================

@test "lifecycle_duplicate_guard: returns 0 when no active scans exist" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    run _lifecycle_duplicate_guard "/home/user1"
    [ "$status" -eq 0 ]
}

@test "lifecycle_duplicate_guard: returns 1 when exact path match exists" {
    _source_lmd_stack
    local scanid="260328-2020.$$"
    # Use our PID so it appears running
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home/user1" "100" "1" "native" "md5" "md5" ""
    run _lifecycle_duplicate_guard "/home/user1"
    [ "$status" -eq 1 ]
    assert_output --partial "$scanid"
}

@test "lifecycle_duplicate_guard: allows overlapping but non-identical paths (E7)" {
    _source_lmd_stack
    local scanid="260328-2021.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home/user1" "100" "1" "native" "md5" "md5" ""
    run _lifecycle_duplicate_guard "/home"
    [ "$status" -eq 0 ]
}

@test "lifecycle_duplicate_guard: allows different paths" {
    _source_lmd_stack
    local scanid="260328-2022.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home/user1" "100" "1" "native" "md5" "md5" ""
    run _lifecycle_duplicate_guard "/var/www"
    [ "$status" -eq 0 ]
}

@test "lifecycle_duplicate_guard: ignores completed/killed scans" {
    _source_lmd_stack
    local scanid="260328-2023.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home/user1" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "completed"
    run _lifecycle_duplicate_guard "/home/user1"
    [ "$status" -eq 0 ]
}

@test "lifecycle_duplicate_guard: detects conflict with paused scan" {
    _source_lmd_stack
    local scanid="260328-2024.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home/user1" "100" "1" "native" "md5" "md5" ""
    touch "$tmpdir/.pause.$scanid"
    run _lifecycle_duplicate_guard "/home/user1"
    [ "$status" -eq 1 ]
    rm -f "$tmpdir/.pause.$scanid"
}

# ========================================================================
# _lifecycle_cleanup_stale_metas tests
# ========================================================================

@test "lifecycle_cleanup_stale_metas: removes completed meta older than cleanup age" {
    _source_lmd_stack
    scan_meta_cleanup_age="1"
    local scanid="260328-2030.$$"
    _lifecycle_write_meta "$scanid" "99999" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "completed"
    # Touch with old mtime (2 hours ago) — older than 1 hour cleanup age
    touch -d "2 hours ago" "$sessdir/scan.meta.$scanid"
    _lifecycle_cleanup_stale_metas
    [ ! -f "$sessdir/scan.meta.$scanid" ]
}

@test "lifecycle_cleanup_stale_metas: removes killed meta older than cleanup age" {
    _source_lmd_stack
    scan_meta_cleanup_age="1"
    local scanid="260328-2031.$$"
    _lifecycle_write_meta "$scanid" "99999" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "killed"
    touch -d "2 hours ago" "$sessdir/scan.meta.$scanid"
    _lifecycle_cleanup_stale_metas
    [ ! -f "$sessdir/scan.meta.$scanid" ]
}

@test "lifecycle_cleanup_stale_metas: removes stale meta older than cleanup age" {
    _source_lmd_stack
    scan_meta_cleanup_age="1"
    local scanid="260328-2032.$$"
    _lifecycle_write_meta "$scanid" "99999" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    # State stays running but PID is dead -> stale
    touch -d "2 hours ago" "$sessdir/scan.meta.$scanid"
    _lifecycle_cleanup_stale_metas
    [ ! -f "$sessdir/scan.meta.$scanid" ]
}

@test "lifecycle_cleanup_stale_metas: preserves running scan meta" {
    _source_lmd_stack
    scan_meta_cleanup_age="1"
    local scanid="260328-2033.$$"
    # Use our own PID — still running
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    touch -d "2 hours ago" "$sessdir/scan.meta.$scanid"
    _lifecycle_cleanup_stale_metas
    [ -f "$sessdir/scan.meta.$scanid" ]
}

@test "lifecycle_cleanup_stale_metas: preserves paused scan meta" {
    _source_lmd_stack
    scan_meta_cleanup_age="1"
    local scanid="260328-2034.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    touch "$tmpdir/.pause.$scanid"
    touch -d "2 hours ago" "$sessdir/scan.meta.$scanid"
    _lifecycle_cleanup_stale_metas
    [ -f "$sessdir/scan.meta.$scanid" ]
    rm -f "$tmpdir/.pause.$scanid"
}

@test "lifecycle_cleanup_stale_metas: disabled when scan_meta_cleanup_age=0" {
    _source_lmd_stack
    scan_meta_cleanup_age="0"
    local scanid="260328-2035.$$"
    _lifecycle_write_meta "$scanid" "99999" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "completed"
    touch -d "2 hours ago" "$sessdir/scan.meta.$scanid"
    _lifecycle_cleanup_stale_metas
    # age=0 disables cleanup — file must be preserved
    [ -f "$sessdir/scan.meta.$scanid" ]
}

@test "lifecycle_cleanup_stale_metas: respects scan_meta_cleanup_age value" {
    _source_lmd_stack
    scan_meta_cleanup_age="24"
    local scanid="260328-2036.$$"
    _lifecycle_write_meta "$scanid" "99999" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "completed"
    # File was just created — mtime is now, so it should NOT be cleaned
    _lifecycle_cleanup_stale_metas
    [ -f "$sessdir/scan.meta.$scanid" ]
}

@test "lifecycle_cleanup_stale_metas: handles empty sessdir gracefully" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    run _lifecycle_cleanup_stale_metas
    [ "$status" -eq 0 ]
}

# ========================================================================
# CLI --kill handler tests
# ========================================================================

@test "maldet --kill with no argument prints error and exits 1" {
    run $LMD_INSTALL/maldet --kill
    [ "$status" -eq 1 ]
    assert_output --partial "requires a SCANID"
}

@test "maldet --kill with nonexistent scanid prints error" {
    run $LMD_INSTALL/maldet --kill 999999-9999.99999
    [ "$status" -ne 0 ]
    assert_output --partial "not found"
}
