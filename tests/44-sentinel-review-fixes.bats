#!/usr/bin/env bats
# 44-sentinel-review-fixes.bats — Tests for sentinel review + UAT findings

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    TEST_DIR=$(mktemp -d)
}

teardown() {
    rm -rf "$TEST_DIR"
}

# --- Helper: source LMD stack ---
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
# MUST-FIX 1: scanid uses $$ not $BASHPID
# ========================================================================

@test "scanid uses dollar-dollar not BASHPID in lmd_scan.sh" {
    # Verify the source code does NOT contain $BASHPID in scanid assignment
    run grep 'scanid=.*BASHPID' "$LMD_INSTALL/internals/lmd_scan.sh"
    [ "$status" -eq 1 ]
    # Verify it uses $$ instead
    run grep 'scanid="\$datestamp\.\$\$"' "$LMD_INSTALL/internals/lmd_scan.sh"
    [ "$status" -eq 0 ]
}

@test "lifecycle_write_meta pid arg uses dollar-dollar not BASHPID" {
    # Verify the _lifecycle_write_meta call does not reference BASHPID
    run grep '_lifecycle_write_meta.*BASHPID' "$LMD_INSTALL/internals/lmd_scan.sh"
    [ "$status" -eq 1 ]
}

# ========================================================================
# MUST-FIX 2: SCANID format validation at CLI boundary
# ========================================================================

@test "cli: --kill rejects invalid SCANID format" {
    run maldet --kill "../../etc/passwd"
    [ "$status" -eq 1 ]
    assert_output --partial "invalid SCANID format"
}

@test "cli: --kill rejects SCANID with shell metacharacters" {
    run maldet --kill '; rm -rf /'
    [ "$status" -eq 1 ]
    assert_output --partial "invalid SCANID format"
}

@test "cli: --kill accepts valid SCANID format" {
    # Valid format but nonexistent scan — should fail for different reason
    run maldet --kill "260328-1500.12345"
    [ "$status" -ne 0 ]
    refute_output --partial "invalid SCANID format"
}

@test "cli: --pause rejects invalid SCANID format" {
    run maldet --pause "not-a-scanid"
    [ "$status" -eq 1 ]
    assert_output --partial "invalid SCANID format"
}

@test "cli: --unpause rejects invalid SCANID format" {
    run maldet --unpause "ABCDEF-GHIJ.ZZZ"
    [ "$status" -eq 1 ]
    assert_output --partial "invalid SCANID format"
}

@test "cli: --stop rejects invalid SCANID format" {
    run maldet --stop "/tmp/evil"
    [ "$status" -eq 1 ]
    assert_output --partial "invalid SCANID format"
}

@test "cli: --continue rejects invalid SCANID format" {
    run maldet --continue "bad format"
    [ "$status" -eq 1 ]
    assert_output --partial "invalid SCANID format"
}

# ========================================================================
# SHOULD-FIX 3: Stage meta updates at scan entry points
# ========================================================================

@test "scan stage updates meta with md5 stage" {
    _source_lmd_stack
    lmd_set_config scan_clamscan 0
    lmd_set_config scan_hashtype md5
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    local scanid
    scanid=$(cat "$LMD_INSTALL/sess/session.last" 2>/dev/null)
    [ -n "$scanid" ]
    local meta_file="$LMD_INSTALL/sess/scan.meta.$scanid"
    [ -f "$meta_file" ]
    # Check that stage=md5 was recorded in meta
    grep -q '^stage=md5$' "$meta_file"
}

@test "scan stage updates meta with hex stage" {
    _source_lmd_stack
    lmd_set_config scan_clamscan 0
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    local scanid
    scanid=$(cat "$LMD_INSTALL/sess/session.last" 2>/dev/null)
    [ -n "$scanid" ]
    local meta_file="$LMD_INSTALL/sess/scan.meta.$scanid"
    [ -f "$meta_file" ]
    # Check that stage=hex was recorded in meta
    grep -q '^stage=hex' "$meta_file"
}

# ========================================================================
# SHOULD-FIX 5: FreeBSD compat — no stat -c %Y in --maintenance
# ========================================================================

@test "maintenance handler does not use stat -c in source code" {
    # Verify no stat -c usage remains in maldet CLI (--maintenance handler)
    run grep -n 'stat -c' "$LMD_INSTALL/maldet"
    [ "$status" -eq 1 ]
}
