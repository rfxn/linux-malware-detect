#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-purge"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"

    # Force MD5 mode — eicar.com is only in MD5 sigs; SHA-NI auto-selects sha256
    lmd_set_config scan_hashtype md5
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "maldet -p clears quarantine directory" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    maldet -q "$scanid"
    local qcount_before
    qcount_before=$(find "$LMD_INSTALL/quarantine" -type f | wc -l)
    [ "$qcount_before" -ge 1 ]
    run maldet -p
    assert_success
    local qcount_after
    qcount_after=$(find "$LMD_INSTALL/quarantine" -type f 2>/dev/null | wc -l)
    [ "$qcount_after" -eq 0 ]
}

@test "maldet -p clears session data" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local sess_before
    sess_before=$(find "$LMD_INSTALL/sess" -type f | wc -l)
    [ "$sess_before" -ge 1 ]
    run maldet -p
    assert_success
    local sess_after
    sess_after=$(find "$LMD_INSTALL/sess" -type f 2>/dev/null | wc -l)
    [ "$sess_after" -eq 0 ]
}

@test "maldet -p clears tmp directory" {
    touch "$LMD_INSTALL/tmp/testfile"
    run maldet -p
    assert_success
    [ ! -f "$LMD_INSTALL/tmp/testfile" ]
}

@test "maldet -p outputs success message" {
    run maldet -p
    assert_success
    assert_output --partial "cleared"
}

@test "maldet -p does not remove config files" {
    run maldet -p
    assert_success
    [ -f "$LMD_INSTALL/conf.maldet" ]
    [ -f "$LMD_INSTALL/internals/internals.conf" ]
    [ -f "$LMD_INSTALL/internals/lmd.lib.sh" ]
}

@test "maldet -p does not remove signature files" {
    run maldet -p
    assert_success
    [ -d "$LMD_INSTALL/sigs" ]
}

@test "directories are recreated after purge" {
    run maldet -p
    assert_success
    [ -d "$LMD_INSTALL/quarantine" ]
    [ -d "$LMD_INSTALL/sess" ]
    [ -d "$LMD_INSTALL/tmp" ]
}

# F-044: purge succeeds when inotify_log does not exist
@test "maldet -p succeeds when inotify_log is missing" {
    rm -f "$LMD_INSTALL/logs/inotify_log"
    run maldet -p
    assert_success
    assert_output --partial "cleared"
    refute_output --partial "No such file"
}
