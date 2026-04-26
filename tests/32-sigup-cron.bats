#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    export LMD_TEST_MODE=1
}

# Helper: source LMD config stack for unit-level function tests.
# Disables errexit and nounset because internals.conf has command -v
# calls that return non-zero for missing binaries.
_source_lmd_stack() {
    set +eu
    trap - ERR  # bash 5.1: BATS ERR trap leaks into sourced files even with set +e
    source "$LMD_INSTALL/internals/internals.conf"
    source "$LMD_INSTALL/conf.maldet"
    source "$LMD_INSTALL/internals/lmd.lib.sh"
}

# --- Test 1: --cron-sigup handler invokes sigup ---
@test "--cron-sigup exits 0 when signatures are current" {
    # Redirect CDN to a local version file so the test is network-independent.
    # Write the current local sig version so sigup() sees "already current".
    local _local_ver
    _local_ver=$(cat "$LMD_INSTALL/sigs/maldet.sigs.ver" 2>/dev/null || echo "0")
    local _ver_file="$LMD_INSTALL/tmp/.test-sigver"
    echo "$_local_ver" > "$_ver_file"
    cp "$LMD_INSTALL/internals/internals.conf" "$LMD_INSTALL/internals/internals.conf.bak"
    sed -i "s|^sig_version_url=.*|sig_version_url=\"file://$_ver_file\"|" \
        "$LMD_INSTALL/internals/internals.conf"
    run maldet --cron-sigup
    assert_success
    # Verify sigup() was actually invoked (not skipped by flock)
    run grep -q '{sigup}' "$LMD_INSTALL/logs/event_log"
    assert_success
}

# --- Test 2: sigup_interval in _safe_source_conf allowlist ---
@test "_safe_source_conf accepts sigup_interval" {
    _source_lmd_stack
    local tmpconf
    tmpconf=$(mktemp)
    echo 'sigup_interval="12"' > "$tmpconf"
    sigup_interval=""
    _safe_source_conf "$tmpconf"
    rm -f "$tmpconf"
    [ "$sigup_interval" = "12" ]
}

# --- Test 3: _safe_source_conf rejects unknown variable ---
@test "_safe_source_conf rejects sigup_bogus" {
    _source_lmd_stack
    local tmpconf
    tmpconf=$(mktemp)
    echo 'sigup_bogus="evil"' > "$tmpconf"
    sigup_bogus=""
    _safe_source_conf "$tmpconf"
    rm -f "$tmpconf"
    [ -z "$sigup_bogus" ]
}

# --- Test 4: conf.maldet contains sigup_interval default ---
@test "conf.maldet defines sigup_interval with default 6" {
    run grep '^sigup_interval=' "$LMD_INSTALL/conf.maldet"
    assert_success
    assert_output --partial '"6"'
}
