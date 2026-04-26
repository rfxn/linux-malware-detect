#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-filelist"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"

    # Force MD5 mode — eicar.com is only in MD5 sigs; SHA-NI auto-selects sha256
    lmd_set_config scan_hashtype md5
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "scan_max_depth limits directory traversal" {
    mkdir -p "$TEST_SCAN_DIR/a/b/c/d/e"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/a/b/c/d/e/"
    lmd_set_config scan_max_depth 2
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "empty file list"
}

@test "scan_max_depth allows files within depth" {
    mkdir -p "$TEST_SCAN_DIR/a"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/a/"
    lmd_set_config scan_max_depth 5
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "-f file list scans only listed files" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/listed.com"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/unlisted.com"
    echo "$TEST_SCAN_DIR/listed.com" > "$TEST_SCAN_DIR/scanlist.txt"
    run maldet -f "$TEST_SCAN_DIR/scanlist.txt"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "-f with empty file list reports error" {
    > "$TEST_SCAN_DIR/empty.txt"
    run maldet -f "$TEST_SCAN_DIR/empty.txt"
    assert_output --partial "empty"
}

@test "-f with missing file list reports error" {
    run maldet -f "$TEST_SCAN_DIR/nonexistent.txt"
    assert_output --partial "does not exist"
}

@test "scan_min_filesize excludes small files from file list" {
    dd if=/dev/zero of="$TEST_SCAN_DIR/small.bin" bs=100 count=1 2>/dev/null
    dd if=/dev/zero of="$TEST_SCAN_DIR/large.bin" bs=10000 count=1 2>/dev/null
    lmd_set_config scan_min_filesize 5000
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "found 1 files"
}

@test "scan_max_filesize excludes large files from file list" {
    dd if=/dev/zero of="$TEST_SCAN_DIR/small.bin" bs=100 count=1 2>/dev/null
    dd if=/dev/zero of="$TEST_SCAN_DIR/large.bin" bs=10000 count=1 2>/dev/null
    lmd_set_config scan_max_filesize "5000c"
    lmd_set_config scan_min_filesize 10
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "found 1 files"
}

@test "scan_export_filelist=1 saves find results" {
    lmd_set_config scan_export_filelist 1
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    # scan_export_filelist only works with -r (recent scan) mode
    maldet -r "$TEST_SCAN_DIR" 7
    [ -f "$LMD_INSTALL/tmp/find_results.last" ]
    run grep "$TEST_SCAN_DIR" "$LMD_INSTALL/tmp/find_results.last"
    assert_success
}

@test "glob path expansion works in scan path" {
    mkdir -p "$TEST_SCAN_DIR/user1/public_html" "$TEST_SCAN_DIR/user2/public_html"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/user1/public_html/"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/user2/public_html/"
    run maldet -a "$TEST_SCAN_DIR/user?/public_html/"
    assert_scan_completed
    assert_output --partial "malware hits 2"
}

@test "-r scans only recently modified files" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    # File was just created, so it should be found with -r 1
    run maldet -r "$TEST_SCAN_DIR" 1
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# F-072: -f background scan log shows file list path
@test "-f background scan log shows file list path" {
    local flist="$TEST_SCAN_DIR/bg-scanlist.txt"
    echo "/tmp/lmd-test-filelist" > "$flist"
    run maldet -b -f "$flist"
    assert_output --partial "launching scan of $flist to background"
}

# F-040: file_list_et initialized in -f mode
@test "-f scan report shows find elapsed time as 0s" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/test-flist.com"
    echo "$TEST_SCAN_DIR/test-flist.com" > "$TEST_SCAN_DIR/scanlist.txt"
    maldet -f "$TEST_SCAN_DIR/scanlist.txt" || true
    local scanid report
    scanid=$(get_last_scanid)
    report=$(get_session_report_file "$scanid")
    [ -n "$report" ] && [ -f "$report" ]
    # TSV header stores file_list_et as field 10; legacy text uses "[find: 0s]"
    grep -qE '\[find: 0s\]|	0	' "$report"
}
