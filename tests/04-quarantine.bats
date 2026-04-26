#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-quar"

# Shared scan+quarantine state for read-only assertion tests.
# Runs once per file, storing scanid for individual tests.
setup_file() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"

    # Force MD5 mode — eicar.com is only in MD5 sigs; SHA-NI auto-selects sha256
    lmd_set_config scan_hashtype md5

    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    echo "$scanid" > "$BATS_FILE_TMPDIR/scanid"
    maldet -q "$scanid"
}

setup() {
    mkdir -p "$TEST_SCAN_DIR"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

# --- Read-only tests: share setup_file() state ---

@test "quarantine moves file out of original location" {
    [ ! -f "$TEST_SCAN_DIR/eicar.com" ]
}

@test "quarantined file exists in quarantine directory" {
    local qcount
    qcount=$(find "$LMD_INSTALL/quarantine" -type f ! -name '*.info' | wc -l)
    [ "$qcount" -ge 1 ]
}

@test "quarantined file has permissions 000" {
    local qfile
    qfile=$(find "$LMD_INSTALL/quarantine" -type f ! -name '*.info' | head -1)
    [ -n "$qfile" ]
    local perms
    perms=$(stat -c '%a' "$qfile")
    [ "$perms" = "0" ]
}

@test "quarantine metadata recorded in quarantine.hist" {
    [ -f "$LMD_INSTALL/sess/quarantine.hist" ]
    [ -s "$LMD_INSTALL/sess/quarantine.hist" ]
}

@test "quarantine hist contains original file path" {
    run grep "$TEST_SCAN_DIR/eicar.com" "$LMD_INSTALL/sess/quarantine.hist"
    assert_success
}

@test "quarantine hist contains signature name" {
    run grep -i "eicar" "$LMD_INSTALL/sess/quarantine.hist"
    assert_success
}

# --- State-modifying tests: each performs own scan+quarantine ---

@test "restore returns file to original location" {
    source /opt/tests/helpers/reset-lmd.sh
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    maldet -q "$scanid"
    [ ! -f "$TEST_SCAN_DIR/eicar.com" ]
    run maldet -s "$scanid"
    assert_success
    [ -f "$TEST_SCAN_DIR/eicar.com" ]
}

@test "restored file has correct content" {
    source /opt/tests/helpers/reset-lmd.sh
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    local orig_md5
    orig_md5=$(md5sum "$TEST_SCAN_DIR/eicar.com" | awk '{print $1}')
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    maldet -q "$scanid"
    maldet -s "$scanid"
    local restored_md5
    restored_md5=$(md5sum "$TEST_SCAN_DIR/eicar.com" | awk '{print $1}')
    [ "$orig_md5" = "$restored_md5" ]
}

@test "batch quarantine via -q SCANID handles multiple files" {
    source /opt/tests/helpers/reset-lmd.sh
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/eicar1.com"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/eicar2.com"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -q "$scanid"
    assert_success
    [ ! -f "$TEST_SCAN_DIR/eicar1.com" ]
    [ ! -f "$TEST_SCAN_DIR/eicar2.com" ]
}

@test "batch restore via -s SCANID restores multiple files" {
    source /opt/tests/helpers/reset-lmd.sh
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/eicar1.com"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/eicar2.com"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    maldet -q "$scanid"
    run maldet -s "$scanid"
    assert_success
    [ -f "$TEST_SCAN_DIR/eicar1.com" ]
    [ -f "$TEST_SCAN_DIR/eicar2.com" ]
}

@test "restore with invalid scanid returns non-zero exit" {
    run maldet -s "999999.99999"
    assert_failure
}

@test "restore with nonexistent file returns non-zero exit" {
    run maldet -s "/nonexistent/path/file.txt"
    assert_failure
}

@test "clean file is not quarantined" {
    source /opt/tests/helpers/reset-lmd.sh
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    local scanid
    scanid=$(get_last_scanid)
    run maldet -q "$scanid"
    [ -f "$TEST_SCAN_DIR/clean-file.txt" ]
}

@test "quarantine_hits=1 auto-quarantines on scan" {
    source /opt/tests/helpers/reset-lmd.sh
    lmd_set_config quarantine_hits 1
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    [ ! -f "$TEST_SCAN_DIR/eicar.com" ]
}

@test "quarantine_hits=0 does not auto-quarantine" {
    source /opt/tests/helpers/reset-lmd.sh
    lmd_set_config quarantine_hits 0
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    [ -f "$TEST_SCAN_DIR/eicar.com" ]
}

# PR-002: quar_hitlist does not duplicate hits_history entries
@test "quar_hitlist does not duplicate hits_history entries" {
    source /opt/tests/helpers/reset-lmd.sh
    lmd_set_config quarantine_hits 0
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    # Scan without quarantine — file stays, hits_history written by scan
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    [ -n "$scanid" ]
    # File must still exist (quarantine_hits=0)
    [ -f "$TEST_SCAN_DIR/eicar.com" ]
    # Record baseline hits_history line count
    local hist_before
    hist_before=$(wc -l < "$LMD_INSTALL/sess/hits.hist")
    # Now quarantine via -q SCANID (file still at original path)
    run maldet -q "$scanid"
    assert_success
    [ ! -f "$TEST_SCAN_DIR/eicar.com" ]
    # hits_history must NOT have grown (no duplicate entries)
    local hist_after
    hist_after=$(wc -l < "$LMD_INSTALL/sess/hits.hist")
    [ "$hist_after" -eq "$hist_before" ]
}
