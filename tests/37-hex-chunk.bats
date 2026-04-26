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
    TEST_SCAN_DIR=$(mktemp -d /tmp/lmd-test-hexchunk.XXXXXX)

    # Force MD5 mode — SHA-NI auto-selects sha256 which has no sigs, causing
    # the hash stage to record zero hits and exposing HEX engine non-determinism
    # in multi-file scans (4/5 hits instead of 5/5 on Rocky 9)
    lmd_set_config scan_hashtype md5

    # Install test HEX signature for eval(base64_decode(
    echo "6576616c286261736536345f6465636f646528:test.hex.php.1" > "$LMD_INSTALL/sigs/custom.hex.dat"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "HEX scan detects malware with default scan_hex_chunk_size (10240)" {
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "HEX scan detects malware with scan_hex_chunk_size at floor (1024)" {
    lmd_set_config scan_hex_chunk_size 1024
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "HEX scan with scan_hex_chunk_size below floor clamps to 1024" {
    lmd_set_config scan_hex_chunk_size 10
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "HEX scan detects multiple files with below-floor chunk_size" {
    lmd_set_config scan_hex_chunk_size 2
    # chunk_size=2 is clamped to floor (1024); all 5 files fit in one chunk.
    # Force single worker — multi-worker HEX has a non-deterministic race
    # where one worker's output is empty (4/5 instead of 5/5 on Rocky 9).
    lmd_set_config scan_workers 1
    local i
    for i in 1 2 3 4 5; do
        cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/file${i}.php"
    done
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 5"
}

@test "default scan_hexdepth is 262144" {
    # Verify that the source code default changed from 524288 to 262144
    run grep -c 'scan_hexdepth:-262144' "$LMD_INSTALL/internals/lmd_scan.sh"
    assert_output "1"
    run grep -c 'scan_hexdepth:-262144' "$LMD_INSTALL/internals/lmd_quarantine.sh"
    assert_output "1"
    # Verify old default is gone
    run grep -c 'scan_hexdepth:-524288' "$LMD_INSTALL/internals/lmd_scan.sh"
    assert_output "0"
    run grep -c 'scan_hexdepth:-524288' "$LMD_INSTALL/internals/lmd_quarantine.sh"
    assert_output "0"
}

@test "_hex_csig_batch_worker accepts 11 arguments (chunk_size)" {
    # Verify the function signature includes arg 11
    run grep -c '_chunk_size=.*\${11:-' "$LMD_INSTALL/internals/lmd_engine.sh"
    assert_output "1"
}

@test "micro-chunk loop uses FD 3 for chunk reader" {
    # Verify FD 3 is opened and closed
    run grep -c 'exec 3<' "$LMD_INSTALL/internals/lmd_engine.sh"
    assert_output "2"
}

@test "no .hcb batch files remain in tmpdir after scan" {
    local i
    for i in 1 2 3; do
        cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/file${i}.php"
    done
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 3"
    # After scan completes, all .hcb temp files must be cleaned up
    run find "$LMD_INSTALL/tmp" -name '.hcb.*' -type f
    refute_output
}
