#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
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

# --- Helper: source LMD functions into test scope ---
# Creates a minimal environment for calling session helpers directly.
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

# --- Test 1: _session_is_tsv returns 0 for TSV file ---
@test "_session_is_tsv returns 0 for TSV format file" {
    local tsv_file="$TEST_DIR/session.tsv.test"
    printf '#LMD:v1\tscan\t123456.789\tlocalhost\t/home\t7\t-\t-\t-\t-\t10\t1\t0\t2.0.1\t-\t-\tnative\t0\t-\n' > "$tsv_file"
    _source_lmd_stack
    run _session_is_tsv "$tsv_file"
    assert_success
}

# --- Test 2: _session_is_tsv returns 1 for legacy file ---
@test "_session_is_tsv returns 1 for legacy plaintext file" {
    local legacy_file="$TEST_DIR/session.test"
    printf 'SCAN ID: 123456.789\nSTARTED: Jan 01 2026\n' > "$legacy_file"
    _source_lmd_stack
    run _session_is_tsv "$legacy_file"
    assert_failure
}

# --- Test 3: _session_is_tsv returns 1 for missing file ---
@test "_session_is_tsv returns 1 for nonexistent file" {
    _source_lmd_stack
    run _session_is_tsv "$TEST_DIR/nonexistent"
    assert_failure
}

# --- Test 4: _session_read_meta populates all 19 fields ---
@test "_session_read_meta populates metadata variables from TSV header" {
    local tsv_file="$TEST_DIR/session.tsv.test"
    printf '#LMD:v1\tscan\t260316-1030.12345\ttesthost\t/home/user\t7\tMar 16 2026 10:30:00\tMar 16 2026 10:35:00\t300\t5\t1000\t3\t1\t2.0.1\t2026031601\tmd5\tnative\t1\thost-abc\n' > "$tsv_file"
    _source_lmd_stack
    _session_read_meta "$tsv_file"
    [ "$_fmt" = "#LMD:v1" ]
    [ "$_alert_type" = "scan" ]
    [ "$scanid" = "260316-1030.12345" ]
    [ "$_hostname" = "testhost" ]
    [ "$hrspath" = "/home/user" ]
    [ "$days" = "7" ]
    [ "$scan_start_hr" = "Mar 16 2026 10:30:00" ]
    [ "$scan_end_hr" = "Mar 16 2026 10:35:00" ]
    [ "$scan_et" = "300" ]
    [ "$file_list_et" = "5" ]
    [ "$tot_files" = "1000" ]
    [ "$tot_hits" = "3" ]
    [ "$tot_cl" = "1" ]
    [ "$_scanner_ver" = "2.0.1" ]
    [ "$_sig_ver" = "2026031601" ]
    [ "$_hashtype" = "md5" ]
    [ "$_engine" = "native" ]
    [ "$_quar_enabled" = "1" ]
    [ "$_hostid" = "host-abc" ]
}

# --- Test 5: _session_read_meta handles sentinel values ---
@test "_session_read_meta handles dash sentinel for unknown fields" {
    local tsv_file="$TEST_DIR/session.tsv.test"
    printf '#LMD:v1\tscan\t260316-1030.99999\tlocalhost\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\tnative\t0\t-\n' > "$tsv_file"
    _source_lmd_stack
    _session_read_meta "$tsv_file"
    [ "$scanid" = "260316-1030.99999" ]
    [ "$hrspath" = "-" ]
    [ "$tot_files" = "-" ]
    [ "$tot_hits" = "-" ]
}

# --- Test 6: _session_resolve returns TSV path when both exist ---
@test "_session_resolve returns TSV path when both TSV and legacy exist" {
    _source_lmd_stack
    local sid="260316-1030.99999"
    printf '#LMD:v1\tscan\t%s\n' "$sid" > "$sessdir/session.tsv.$sid"
    printf 'SCAN ID: %s\n' "$sid" > "$sessdir/session.hits.$sid"
    local result
    result=$(_session_resolve "$sid")
    [ "$result" = "$sessdir/session.tsv.$sid" ]
    rm -f "$sessdir/session.tsv.$sid" "$sessdir/session.hits.$sid"
}

# --- Test 7: _session_resolve falls back to .hits ---
@test "_session_resolve falls back to legacy hits file" {
    _source_lmd_stack
    local sid="260316-1031.88888"
    printf 'SCAN ID: %s\n' "$sid" > "$sessdir/session.hits.$sid"
    local result
    result=$(_session_resolve "$sid")
    [ "$result" = "$sessdir/session.hits.$sid" ]
    rm -f "$sessdir/session.hits.$sid"
}

# --- Test 8: _session_resolve returns empty for missing session ---
@test "_session_resolve returns empty string for missing session" {
    _source_lmd_stack
    local result
    result=$(_session_resolve "999999.99999")
    [ -z "$result" ]
}

# --- Test 9: Scan produces session.tsv file ---
@test "scan produces session.tsv file" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    [ -f "$LMD_INSTALL/sess/session.tsv.${scanid}" ]
}

# --- Test 10: TSV session file starts with #LMD:v1 header ---
@test "TSV session file starts with #LMD:v1 header" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    local scanid report
    scanid=$(get_last_scanid)
    report=$(get_session_report_file "$scanid")
    local first_line
    first_line=$(head -1 "$report")
    [[ "$first_line" == "#LMD:v1"* ]]
}

# --- Test 11: TSV header has 19 tab-delimited fields ---
@test "TSV header has 19 tab-delimited fields" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    local scanid report
    scanid=$(get_last_scanid)
    report=$(get_session_report_file "$scanid")
    local field_count
    field_count=$(head -1 "$report" | awk -F'\t' '{print NF}')
    [ "$field_count" -eq 19 ]
}

# --- Test 12: TSV hit records have 11 tab-delimited fields ---
@test "TSV hit records have 11 tab-delimited fields" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -co scan_hashtype=md5 -a "$TEST_DIR" || true
    local scanid report
    scanid=$(get_last_scanid)
    report=$(get_session_report_file "$scanid")
    # Skip header (line 1), check data lines
    local data_field_count
    data_field_count=$(awk -F'\t' 'NR>1 && !/^#/ && NF>0 {print NF; exit}' "$report")
    [ "$data_field_count" -eq 11 ]
}

# --- Test 13: Legacy plaintext generated when session_legacy_compat=1 ---
@test "legacy plaintext generated when session_legacy_compat=1" {
    lmd_set_config session_legacy_compat 1
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    # Both TSV and legacy plaintext should exist
    [ -f "$LMD_INSTALL/sess/session.tsv.${scanid}" ]
    [ -f "$LMD_INSTALL/sess/session.${scanid}" ]
    # Legacy file should NOT start with #LMD:v1
    local first_line
    first_line=$(head -1 "$LMD_INSTALL/sess/session.${scanid}")
    [[ "$first_line" != "#LMD:v1"* ]]
}

# --- Test 14: No legacy plaintext when session_legacy_compat=0 ---
@test "no legacy plaintext when session_legacy_compat=0" {
    lmd_set_config session_legacy_compat 0
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    [ -f "$LMD_INSTALL/sess/session.tsv.${scanid}" ]
    [ ! -f "$LMD_INSTALL/sess/session.${scanid}" ]
}

# --- Test 15: view_report list shows sessions with legacy compat ---
@test "view_report list shows sessions when legacy compat enabled" {
    lmd_set_config session_legacy_compat 1
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -co scan_hashtype=md5 -a "$TEST_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -e list
    assert_success
    assert_output --partial "$scanid"
}

# --- Test 16: view_report renders text from TSV session ---
@test "view_report renders output from TSV session" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -a "$TEST_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -E "$scanid"
    assert_success
    [ -n "$output" ]
}

# --- Test 17: Clean scan produces TSV with zero hits ---
@test "clean scan produces TSV session with zero hit records" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_DIR/"
    maldet -a "$TEST_DIR"
    local scanid report
    scanid=$(get_last_scanid)
    report=$(get_session_report_file "$scanid")
    [ -f "$report" ]
    # Header should exist
    local first_line
    first_line=$(head -1 "$report")
    [[ "$first_line" == "#LMD:v1"* ]]
    # No data lines (only the header)
    local data_lines
    data_lines=$(awk 'NR>1 && !/^#/ && NF>0' "$report" | wc -l)
    [ "$data_lines" -eq 0 ]
}

# --- Test 18: TSV hit record contains signature name ---
@test "TSV hit record contains eicar signature (MD5 mode)" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -co scan_hashtype=md5 -a "$TEST_DIR" || true
    local scanid report
    scanid=$(get_last_scanid)
    report=$(get_session_report_file "$scanid")
    run grep -v '^#' "$report"
    assert_output --partial "eicar"
}

# --- Test 19: TSV hit record contains file path ---
@test "TSV hit record contains scanned file path" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_DIR/"
    maldet -co scan_hashtype=md5 -a "$TEST_DIR" || true
    local scanid report
    scanid=$(get_last_scanid)
    report=$(get_session_report_file "$scanid")
    run grep -v '^#' "$report"
    assert_output --partial "$TEST_DIR"
}
