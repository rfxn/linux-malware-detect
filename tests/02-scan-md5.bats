#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-scan"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"

    # Force MD5 mode — eicar.com is only in MD5 sigs; SHA-NI auto-selects sha256
    lmd_set_config scan_hashtype md5
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "MD5 scan detects known test sample (EICAR)" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "scan report is generated with SCANID" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    [ -n "$scanid" ]
    local report
    report=$(get_session_report_file "$scanid")
    [ -n "$report" ] && [ -f "$report" ]
}

@test "scan report lists detected signature name" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    [ -n "$scanid" ]
    assert_report_contains "$scanid" "eicar"
}

@test "exit code is 2 when malware detected" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_malware_found
}

@test "exit code is 0 when scan is clean" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_clean
}

@test "scan_min_filesize filters small files" {
    echo "x" > "$TEST_SCAN_DIR/tiny.txt"
    lmd_set_config scan_min_filesize 999999
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "empty file list"
}

@test "scan_max_filesize filters large files" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    lmd_set_config scan_max_filesize "1c"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "empty file list"
}

@test "multiple files scanned in single pass" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/eicar1.com"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/eicar2.com"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 2"
}

@test "scan of empty directory reports empty file list" {
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "empty file list"
}

@test "custom MD5 signatures are loaded" {
    local clean_md5
    clean_md5=$(md5sum "$SAMPLES_DIR/clean-file.txt" | awk '{print $1}')
    local clean_size
    clean_size=$(wc -c < "$SAMPLES_DIR/clean-file.txt" | tr -d ' ')
    echo "${clean_md5}:${clean_size}:test.custom.md5.1" > "$LMD_INSTALL/sigs/custom.md5.dat"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "1 USER"
}

@test "session.last updated after scan" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    [ -f "$LMD_INSTALL/sess/session.last" ]
    [ -s "$LMD_INSTALL/sess/session.last" ]
}

@test "batch MD5: multiple infected files with parallel workers" {
    lmd_set_config scan_workers 2
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/eicar1.com"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/eicar2.com"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/eicar3.com"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 3"
}

@test "batch MD5: clean files produce zero hits with workers" {
    lmd_set_config scan_workers 2
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/clean1.txt"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/clean2.txt"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "malware hits 0"
}

@test "scan exits 1 when all scan paths do not exist" {
    run maldet -a /nonexistent_lmd_test_path_xyz_plan
    [ "$status" -eq 1 ]
}

@test "scan exits 0 when path exists but has no scannable files" {
    local empty_dir
    empty_dir=$(mktemp -d)
    run maldet -a "$empty_dir"
    [ "$status" -eq 0 ]
    assert_output --partial "empty file list"
    rm -rf "$empty_dir"
}
