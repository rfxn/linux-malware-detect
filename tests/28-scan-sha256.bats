#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-sha256"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "SHA-256 scan detects known sample via custom.sha256.dat" {
    local sha256_hash sha256_size
    sha256_hash=$(sha256sum "$SAMPLES_DIR/clean-file.txt" | awk '{print $1}')
    sha256_size=$(wc -c < "$SAMPLES_DIR/clean-file.txt" | tr -d ' ')
    echo "${sha256_hash}:${sha256_size}:{SHA256}test.custom.sha256.1" > "$LMD_INSTALL/sigs/custom.sha256.dat"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -co scan_hashtype=sha256 -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
    # Verify custom SHA-256 sig counted in USER category
    assert_output --partial "1 USER"
}

@test "SHA-256 batch workers: multiple infected files" {
    local sha256_hash sha256_size
    sha256_hash=$(sha256sum "$SAMPLES_DIR/clean-file.txt" | awk '{print $1}')
    sha256_size=$(wc -c < "$SAMPLES_DIR/clean-file.txt" | tr -d ' ')
    echo "${sha256_hash}:${sha256_size}:{SHA256}test.custom.sha256.1" > "$LMD_INSTALL/sigs/custom.sha256.dat"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/file1.txt"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/file2.txt"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/file3.txt"
    run maldet -co scan_hashtype=sha256,scan_workers=2 -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 3"
}

@test "scan_hashtype=both detects MD5 and SHA-256 sigs" {
    # File A matches EICAR via MD5
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    # File B matches custom SHA-256 sig
    local sha256_hash sha256_size
    sha256_hash=$(sha256sum "$SAMPLES_DIR/clean-file.txt" | awk '{print $1}')
    sha256_size=$(wc -c < "$SAMPLES_DIR/clean-file.txt" | tr -d ' ')
    echo "${sha256_hash}:${sha256_size}:{SHA256}test.custom.sha256.1" > "$LMD_INSTALL/sigs/custom.sha256.dat"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -co scan_hashtype=both -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 2"
}

@test "scan_hashtype=md5 ignores SHA-256 sigs" {
    local sha256_hash sha256_size
    sha256_hash=$(sha256sum "$SAMPLES_DIR/clean-file.txt" | awk '{print $1}')
    sha256_size=$(wc -c < "$SAMPLES_DIR/clean-file.txt" | tr -d ' ')
    echo "${sha256_hash}:${sha256_size}:{SHA256}test.custom.sha256.1" > "$LMD_INSTALL/sigs/custom.sha256.dat"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -co scan_hashtype=md5 -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "malware hits 0"
}

@test "signature count includes SHA-256" {
    local sha256_hash sha256_size
    sha256_hash=$(sha256sum "$SAMPLES_DIR/clean-file.txt" | awk '{print $1}')
    sha256_size=$(wc -c < "$SAMPLES_DIR/clean-file.txt" | tr -d ' ')
    echo "${sha256_hash}:${sha256_size}:{SHA256}test.custom.sha256.1" > "$LMD_INSTALL/sigs/custom.sha256.dat"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -co scan_hashtype=sha256 -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --regexp "[0-9,]+ SHA "
    assert_output --partial "1 USER"
}

@test "empty custom.sha256.dat is non-fatal" {
    > "$LMD_INSTALL/sigs/custom.sha256.dat"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -co scan_hashtype=sha256 -a "$TEST_SCAN_DIR"
    assert_success
}

@test "missing sha256v2.dat is non-fatal with scan_hashtype=auto" {
    rm -f "$LMD_INSTALL/sigs/sha256v2.dat"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -co scan_hashtype=auto -a "$TEST_SCAN_DIR"
    assert_success
}

@test "scan_hashtype=sha256 warns when no SHA-256 sig files exist" {
    rm -f "$LMD_INSTALL/sigs/sha256v2.dat"
    > "$LMD_INSTALL/sigs/custom.sha256.dat"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -co scan_hashtype=sha256 -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "no SHA-256 signature files found"
}

@test "SHA-256 ignore_sigs filtering suppresses hit" {
    local sha256_hash sha256_size
    sha256_hash=$(sha256sum "$SAMPLES_DIR/clean-file.txt" | awk '{print $1}')
    sha256_size=$(wc -c < "$SAMPLES_DIR/clean-file.txt" | tr -d ' ')
    echo "${sha256_hash}:${sha256_size}:{SHA256}test.custom.sha256.1" > "$LMD_INSTALL/sigs/custom.sha256.dat"
    echo "test.custom.sha256" > "$LMD_INSTALL/ignore_sigs"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -co scan_hashtype=sha256 -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "malware hits 0"
}

@test "SHA-256 quarantine metadata .info contains 64-char hash" {
    local sha256_hash sha256_size
    sha256_hash=$(sha256sum "$SAMPLES_DIR/clean-file.txt" | awk '{print $1}')
    sha256_size=$(wc -c < "$SAMPLES_DIR/clean-file.txt" | tr -d ' ')
    echo "${sha256_hash}:${sha256_size}:{SHA256}test.custom.sha256.1" > "$LMD_INSTALL/sigs/custom.sha256.dat"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/target.txt"
    run maldet -co scan_hashtype=sha256,quarantine_hits=1 -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
    # Find the .info file in quarantine
    local info_file
    info_file=$(find "$LMD_INSTALL/quarantine" -name "*.info" | head -1)
    [ -n "$info_file" ]
    # Verify comment says "hash" not "md5"
    run grep -c 'hash:atime' "$info_file"
    assert_output "1"
    # Verify hash field is 64 chars (SHA-256)
    local hash_field
    hash_field=$(grep -v '^#' "$info_file" | head -1 | cut -d: -f5)
    [ ${#hash_field} -eq 64 ]
}

@test "SHA-256 quarantine restore roundtrip" {
    local sha256_hash sha256_size
    sha256_hash=$(sha256sum "$SAMPLES_DIR/clean-file.txt" | awk '{print $1}')
    sha256_size=$(wc -c < "$SAMPLES_DIR/clean-file.txt" | tr -d ' ')
    echo "${sha256_hash}:${sha256_size}:{SHA256}test.custom.sha256.1" > "$LMD_INSTALL/sigs/custom.sha256.dat"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/restore-test.txt"
    local orig_md5
    orig_md5=$(md5sum "$TEST_SCAN_DIR/restore-test.txt" | awk '{print $1}')
    # Quarantine
    maldet -co scan_hashtype=sha256,quarantine_hits=1 -a "$TEST_SCAN_DIR" || true
    [ ! -f "$TEST_SCAN_DIR/restore-test.txt" ]
    # Restore
    local scanid
    scanid=$(get_last_scanid)
    [ -n "$scanid" ]
    maldet -s "$scanid"
    [ -f "$TEST_SCAN_DIR/restore-test.txt" ]
    # Verify content
    local restored_md5
    restored_md5=$(md5sum "$TEST_SCAN_DIR/restore-test.txt" | awk '{print $1}')
    [ "$orig_md5" = "$restored_md5" ]
}
