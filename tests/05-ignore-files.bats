#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-ignore"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"

    # Install test HEX signature
    echo "6576616c286261736536345f6465636f646528:test.hex.php.1" > "$LMD_INSTALL/sigs/custom.hex.dat"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "ignore_paths excludes specific path from scan" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    echo "$TEST_SCAN_DIR" > "$LMD_INSTALL/ignore_paths"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "empty file list"
}

@test "ignore_sigs suppresses specific signature" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    # Pattern must match all engines: MD5 (eicar), HEX (EICAR), YARA (Eicar)
    printf '%s\n' "[Ee][Ii][Cc][Aa][Rr]" > "$LMD_INSTALL/ignore_sigs"
    run maldet -co scan_hashtype=md5 -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "malware hits 0"
}

@test "ignore_sigs does not modify on-disk signature files" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    local hex_before md5_before hex_after md5_after
    hex_before=$(md5sum "$LMD_INSTALL/sigs/hex.dat" | awk '{print $1}')
    md5_before=$(md5sum "$LMD_INSTALL/sigs/md5v2.dat" | awk '{print $1}')
    printf '%s\n' "[Ee][Ii][Cc][Aa][Rr]" > "$LMD_INSTALL/ignore_sigs"
    run maldet -co scan_hashtype=md5 -a "$TEST_SCAN_DIR"
    assert_success
    hex_after=$(md5sum "$LMD_INSTALL/sigs/hex.dat" | awk '{print $1}')
    md5_after=$(md5sum "$LMD_INSTALL/sigs/md5v2.dat" | awk '{print $1}')
    [ "$hex_before" = "$hex_after" ]
    [ "$md5_before" = "$md5_after" ]
}

@test "ignore_paths does not affect unrelated paths" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    echo "/some/other/path" > "$LMD_INSTALL/ignore_paths"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "ignore_sigs does not suppress unrelated signatures" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    echo "some.other.sig" > "$LMD_INSTALL/ignore_sigs"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "empty ignore files do not cause errors" {
    > "$LMD_INSTALL/ignore_paths"
    > "$LMD_INSTALL/ignore_file_ext"
    > "$LMD_INSTALL/ignore_sigs"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
}

@test "ignore_paths with partial path match" {
    mkdir -p "$TEST_SCAN_DIR/safe" "$TEST_SCAN_DIR/unsafe"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/safe/"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/unsafe/"
    echo "$TEST_SCAN_DIR/safe" > "$LMD_INSTALL/ignore_paths"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "ignore_file_ext excludes by extension" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/malware.com"
    echo ".com" > "$LMD_INSTALL/ignore_file_ext"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "empty file list"
}

@test "ignore_file_ext does not exclude unrelated extensions" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/malware.com"
    echo ".txt" > "$LMD_INSTALL/ignore_file_ext"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "ignore_file_ext handles multiple extensions" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/malware.com"
    printf '.txt\n.com\n' > "$LMD_INSTALL/ignore_file_ext"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "empty file list"
}

@test "--exclude-regex excludes matching files from scan" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/malware.com"
    run maldet -x '.*\.com$' -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "empty file list"
}

@test "--include-regex limits scan to matching files" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/malware.com"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -i '.*\.com$' -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}
