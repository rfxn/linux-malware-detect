#!/usr/bin/env bats
# 38-lifecycle.bats — Unit tests for scan lifecycle sentinel IPC functions

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

LMD_INSTALL="/usr/local/maldetect"

# --- Helper: source LMD functions into test scope ---
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

# === _lifecycle_check_sentinels ===

# bats test_tags=lifecycle,unit
@test "lifecycle: check_sentinels returns 0 when no sentinel files exist" {
    _source_lmd_stack
    local test_tmpdir
    test_tmpdir=$(mktemp -d)
    tmpdir="$test_tmpdir"
    run _lifecycle_check_sentinels "test123"
    [ "$status" -eq 0 ]
    rm -rf "$test_tmpdir"
}

# bats test_tags=lifecycle,unit
@test "lifecycle: check_sentinels returns 1 when abort sentinel exists" {
    _source_lmd_stack
    local test_tmpdir
    test_tmpdir=$(mktemp -d)
    tmpdir="$test_tmpdir"
    touch "$test_tmpdir/.abort.scan456"
    run _lifecycle_check_sentinels "scan456"
    [ "$status" -eq 1 ]
    rm -rf "$test_tmpdir"
}

# bats test_tags=lifecycle,unit
@test "lifecycle: check_sentinels returns 2 when pause sentinel exists" {
    _source_lmd_stack
    local test_tmpdir
    test_tmpdir=$(mktemp -d)
    tmpdir="$test_tmpdir"
    touch "$test_tmpdir/.pause.scan789"
    run _lifecycle_check_sentinels "scan789"
    [ "$status" -eq 2 ]
    rm -rf "$test_tmpdir"
}

# bats test_tags=lifecycle,unit
@test "lifecycle: check_sentinels abort takes priority over pause (E15)" {
    _source_lmd_stack
    local test_tmpdir
    test_tmpdir=$(mktemp -d)
    tmpdir="$test_tmpdir"
    touch "$test_tmpdir/.abort.both100"
    touch "$test_tmpdir/.pause.both100"
    run _lifecycle_check_sentinels "both100"
    [ "$status" -eq 1 ]
    rm -rf "$test_tmpdir"
}

# bats test_tags=lifecycle,unit
@test "lifecycle: check_sentinels isolates by scanid" {
    _source_lmd_stack
    local test_tmpdir
    test_tmpdir=$(mktemp -d)
    tmpdir="$test_tmpdir"
    touch "$test_tmpdir/.abort.other999"
    run _lifecycle_check_sentinels "mine111"
    [ "$status" -eq 0 ]
    rm -rf "$test_tmpdir"
}

# === _lifecycle_check_parent ===

# bats test_tags=lifecycle,unit
@test "lifecycle: check_parent returns 0 for own PID (alive)" {
    _source_lmd_stack
    run _lifecycle_check_parent "$$"
    [ "$status" -eq 0 ]
}

# bats test_tags=lifecycle,unit
@test "lifecycle: check_parent returns 1 for dead PID" {
    _source_lmd_stack
    # Start and immediately reap a subprocess to get a known-dead PID
    bash -c 'exit 0' &
    local dead_pid=$!
    wait "$dead_pid" 2>/dev/null || true  # reap it
    run _lifecycle_check_parent "$dead_pid"
    [ "$status" -eq 1 ]
}

# bats test_tags=lifecycle,unit
@test "lifecycle: check_parent returns 0 for PID 1 (init, always alive)" {
    _source_lmd_stack
    run _lifecycle_check_parent "1"
    [ "$status" -eq 0 ]
}
