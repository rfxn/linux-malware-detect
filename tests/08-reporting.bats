#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-report"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"

    # Force MD5 mode — eicar.com is only in MD5 sigs; SHA-NI auto-selects sha256
    lmd_set_config scan_hashtype md5
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "--dump-report SCANID displays report" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -E "$scanid"
    assert_success
    # TSV header starts with #LMD:v1; legacy text contains "SCAN ID"
    [[ "$output" == *"SCAN ID"* ]] || [[ "$output" == *"#LMD:v1"* ]]
}

@test "report contains hit information" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -E "$scanid"
    assert_success
    # Sig name case varies by hash engine (EICAR for MD5, eicar for SHA-256/HEX)
    assert_output --regexp '[Ee][Ii][Cc][Aa][Rr]'
}

@test "report contains file path" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -E "$scanid"
    assert_success
    assert_output --partial "$TEST_SCAN_DIR"
}

@test "report for clean scan shows zero hits" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    local scanid
    scanid=$(get_last_scanid)
    run maldet -E "$scanid"
    assert_success
    assert_output --partial "0"
}

@test "session files created for each scan" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    local scanid report
    scanid=$(get_last_scanid)
    report=$(get_session_report_file "$scanid")
    [ -n "$report" ] && [ -f "$report" ]
}

@test "report list format has columnar header with no active scan bleed" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -e list
    assert_success
    # Columnar header fields present (no colon — header row, not labeled rows)
    assert_output --partial "SCANID"
    assert_output --partial "FILES"
    assert_output --partial "HITS"
    assert_output --partial "Scan history"
    # No active-scan lifecycle output bleed
    refute_output --partial "ACTIVE SCANS"
    refute_output --partial "No active scans"
}

@test "no persistent HTML session file after scan" {
    lmd_set_config email_format "html"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid report
    scanid=$(get_last_scanid)
    # Session file (TSV or plaintext) always created; HTML rendered on-demand, not stored
    report=$(get_session_report_file "$scanid")
    [ -n "$report" ] && [ -f "$report" ]
    [ ! -f "$LMD_INSTALL/sess/session.${scanid}.html" ]
}

# ==========================================================================
# -e list columnar format — cap, --all, empty state, JSON
# ==========================================================================

@test "-e list --all flag accepted and exits 0" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    run maldet -e list --all
    assert_success
    assert_output --partial "Scan history"
    assert_output --partial "SCANID"
}

@test "-e list caps at 14 entries and shows overflow hint" {
    # Populate session.index with 16 synthetic entries (no real session files needed)
    local index_file="$LMD_INSTALL/sess/session.index"
    printf '#LMD_INDEX:v1\n' > "$index_file"
    local i
    for i in $(seq 1 16); do
        local padded
        padded=$(printf '%02d' "$i")
        # Fields: scanid epoch started_hr elapsed total_files total_hits total_cleaned total_quar path
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "260328-0100.${padded}" \
            "$((1711584000 + i * 60))" \
            "Mar 28 2026 01:${padded}:00" \
            "5" "100" "0" "0" "0" "/test/path${i}" >> "$index_file"
    done
    run maldet -e list
    assert_success
    # Should show "N total, last 14" section header
    assert_output --partial "16 total, last 14"
    # Should show overflow hint with count of older entries
    assert_output --partial "2 older"
    assert_output --partial "maldet -e list --all"
}

@test "-e list --all shows all entries without cap" {
    # Populate session.index with 16 synthetic entries
    local index_file="$LMD_INSTALL/sess/session.index"
    printf '#LMD_INDEX:v1\n' > "$index_file"
    local i
    for i in $(seq 1 16); do
        local padded
        padded=$(printf '%02d' "$i")
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "260328-0200.${padded}" \
            "$((1711584000 + i * 60))" \
            "Mar 28 2026 02:${padded}:00" \
            "3" "50" "0" "0" "0" "/test/all${i}" >> "$index_file"
    done
    run maldet -e list --all
    assert_success
    # Should show total without "last 14" qualifier
    assert_output --partial "Scan history (16)"
    # Should NOT show overflow hint
    refute_output --partial "older"
}

@test "-e list with empty sessdir shows no-scans message" {
    # reset-lmd.sh already cleared sessdir — ensure no index either
    rm -f "$LMD_INSTALL/sess/session.index"
    run maldet -e list
    assert_success
    assert_output --partial "Scan history (0)"
    assert_output --partial "No scans found"
}

@test "--json-report list produces valid JSON with reports array" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    run maldet --json-report list
    assert_success
    assert_output --partial '"reports"'
    assert_output --partial '"type": "report_list"'
    # Should contain at least one report entry
    assert_output --partial '"scan_id"'
}

@test "--json-report list with no session index still produces valid JSON" {
    # Remove index to force rebuild path (no TSV files either after reset)
    rm -f "$LMD_INSTALL/sess/session.index"
    run maldet --json-report list
    assert_success
    assert_output --partial '"reports"'
    assert_output --partial '"type": "report_list"'
}
