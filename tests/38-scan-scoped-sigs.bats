#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR=""

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    TEST_SCAN_DIR=$(mktemp -d)
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
    # Restore lmd_scan.sh if backup exists (from cleanup-disable tests)
    if [ -f "$LMD_INSTALL/internals/lmd_scan.sh.bak" ]; then
        cp "$LMD_INSTALL/internals/lmd_scan.sh.bak" "$LMD_INSTALL/internals/lmd_scan.sh"
        rm -f "$LMD_INSTALL/internals/lmd_scan.sh.bak"
    fi
}

@test "scanid format is YYMMDD-HHMM.PID" {
    lmd_set_config scan_clamscan 0
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    [ -n "$scanid" ]
    # Verify format: 6-digit date, dash, 4-digit time, dot, numeric PID
    [[ "$scanid" =~ ^[0-9]{6}-[0-9]{4}\.[0-9]+$ ]]
}

@test "scan with scoped sigs detects malware via MD5" {
    lmd_set_config scan_clamscan 0
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -co scan_hashtype=md5 -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "scan with scoped sigs detects malware via HEX" {
    lmd_set_config scan_clamscan 0
    local hex_target="$TEST_SCAN_DIR/hex-test.php"
    printf '<?php eval(base64_decode("test")); ?>' > "$hex_target"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
}

@test "runtime sigs include scanid in temp file names" {
    lmd_set_config scan_clamscan 0
    # Disable scan cleanup to inspect runtime temp files after scan
    local scan_sh="$LMD_INSTALL/internals/lmd_scan.sh"
    cp "$scan_sh" "${scan_sh}.bak"
    sed -i 's/^_scan_cleanup() {/_scan_cleanup_orig() {/' "$scan_sh"
    sed -i '/_scan_cleanup_orig()/i _scan_cleanup() { :; }' "$scan_sh"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    [ -n "$scanid" ]
    local pid_part
    pid_part="${scanid##*.}"
    [ -n "$pid_part" ]
    # Runtime files should still exist and contain scanid PID in filename
    local count
    count=$(find "$LMD_INSTALL/tmp" -name ".runtime.*.${pid_part}.*" -type f 2>/dev/null | wc -l)
    [ "$count" -gt 0 ]
}

@test "session file uses PID-based scanid" {
    lmd_set_config scan_clamscan 0
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    [ -n "$scanid" ]
    # Session TSV file should exist with the scanid
    [ -f "$LMD_INSTALL/sess/session.tsv.${scanid}" ]
}
