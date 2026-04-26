#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-csig"

# Hex constants for test patterns
# CSIG_PATTERN_ALPHA
HEX_ALPHA="435349475f5041545445524e5f414c504841"
# CSIG_PATTERN_BRAVO
HEX_BRAVO="435349475f5041545445524e5f425241564f"
# CSIG_UNIQUE_MARKER_SINGLE
HEX_SINGLE="435349475f554e495155455f4d41524b45525f53494e474c45"
# CSIG_PATTERN_CHARLIE (not in any test file — for miss testing)
HEX_CHARLIE="435349475f5041545445524e5f434841524c4945"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

# --- Test 1: Single-pattern csig detection ---
@test "csig: single-pattern detection" {
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 2: AND detection (all subsigs match) ---
@test "csig: AND detection - all subsigs match" {
    echo "${HEX_ALPHA}||${HEX_BRAVO}:{CSIG}test.csig.and.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-and.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 3: AND partial miss (not all match → no detection) ---
@test "csig: AND partial miss - no detection" {
    echo "${HEX_ALPHA}||${HEX_CHARLIE}:{CSIG}test.csig.and.2" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-partial.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 0"
}

# --- Test 4: OR/threshold detection (>=N match) ---
@test "csig: OR threshold detection - meets threshold" {
    # 3 subsigs, threshold 2 — file has ALPHA and BRAVO (2 of 3)
    echo "${HEX_ALPHA}||${HEX_BRAVO}||${HEX_CHARLIE}:{CSIG}test.csig.or.1;2" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-or.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 5: OR/threshold miss (<N match → no detection) ---
@test "csig: OR threshold miss - below threshold" {
    # 3 subsigs, threshold 3 — file has only 2 of 3
    echo "${HEX_ALPHA}||${HEX_BRAVO}||${HEX_CHARLIE}:{CSIG}test.csig.or.2;3" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-or.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 0"
}

# --- Test 6: First-match-wins across stages (MD5 hit → csig skipped) ---
@test "csig: MD5 hit takes priority over csig" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    # Add a csig that would also match eicar
    local eicar_hex
    eicar_hex=$(od -An -tx1 "$SAMPLES_DIR/eicar.com" | tr -d ' \n' | head -c 40)
    echo "${eicar_hex}:{CSIG}test.csig.eicar.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    # Force MD5 hashtype so MD5 pass runs and takes priority
    run maldet -co scan_hashtype=md5 -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
    # Verify hit is from MD5 (in session file), not CSIG
    local scanid
    scanid=$(get_last_scanid)
    local hitsfile; hitsfile=$(get_session_hits_file "$scanid")
    run grep "{MD5}" "$hitsfile"
    assert_success
}

# --- Test 7: First-match-wins within csig.dat (file order) ---
@test "csig: first-match-wins within csig rules" {
    # Two rules that both match — first should win
    printf '%s\n' \
        "${HEX_SINGLE}:{CSIG}test.csig.first.1" \
        "${HEX_SINGLE}:{CSIG}test.csig.second.1" \
        > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
    # Check session hits file for first rule, not second
    local scanid
    scanid=$(get_last_scanid)
    local hitsfile; hitsfile=$(get_session_hits_file "$scanid")
    run grep "test.csig.first" "$hitsfile"
    assert_success
    run grep "test.csig.second" "$hitsfile"
    assert_failure
}

# --- Test 8: scan_csig=0 disables pass ---
@test "csig: scan_csig=0 disables csig scanning" {
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -co scan_csig=0 -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 0"
}

# --- Test 9: Missing csig.dat → scan completes normally ---
@test "csig: missing csig.dat does not break scan" {
    rm -f "$LMD_INSTALL/sigs/csig.dat" "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 10: Empty csig.dat → scan completes normally ---
@test "csig: empty csig.dat does not break scan" {
    > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 11: Case-insensitive (i:) matching ---
@test "csig: case-insensitive (i:) matching" {
    # Csig_Mixed_Case_Marker in hex (mixed case)
    # Use the uppercase version with i: prefix
    local upper_hex
    upper_hex=$(echo -n "CSIG_MIXED_CASE_MARKER" | od -An -tx1 | tr -d ' \n')
    echo "i:${upper_hex}:{CSIG}test.csig.icase.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-icase.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 12: Wide (w:) matching ---
@test "csig: wide (w:) UTF-16LE matching" {
    # test-csig-wide.txt contains "WIDEMARKER" in UTF-16LE encoding
    # Raw hex for "WIDEMARKER" = 574944454d41524b4552
    # w: prefix causes null-byte interleaving to match UTF-16LE
    echo "w:574944454d41524b4552:{CSIG}test.csig.wide.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-wide.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 13: Bounded gap ({N-M}) matching ---
@test "csig: bounded gap {N-M} wildcard matching" {
    # test-csig-and.php has CSIG_PATTERN_ALPHA (13 bytes between CSIG_ and ALPHA)
    # Match "CSIG_" then {3-20} byte gap then "ALPHA"
    echo "435349475f{3-20}414c504841:{CSIG}test.csig.gap.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-and.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 14: csig hit quarantined ---
@test "csig: detected file is quarantined" {
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    lmd_set_config quarantine_hits 1
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_quarantined "$TEST_SCAN_DIR/test-csig-single.php"
}

# --- Test 15: csig hit in scan report with {CSIG} prefix ---
@test "csig: scan report shows {CSIG} prefix" {
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
    # Verify {CSIG} prefix in session hits file
    local scanid
    scanid=$(get_last_scanid)
    local hitsfile; hitsfile=$(get_session_hits_file "$scanid")
    run grep "{CSIG}test.csig.single" "$hitsfile"
    assert_success
}

# --- Test 16: Signature count includes csig ---
@test "csig: signature count includes csig sigs" {
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "1 USER"
}

# --- Test 17: ignore_sigs filters csig rules ---
@test "csig: ignore_sigs filters csig rules" {
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    echo "test.csig.single" > "$LMD_INSTALL/ignore_sigs"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 0"
}

# --- Test 18: Malformed line skipped with warning ---
@test "csig: malformed line skipped with warning" {
    printf '%s\n' \
        "malformed_no_colon_separator" \
        "${HEX_SINGLE}:{CSIG}test.csig.single.1" \
        > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    # Valid rule still detects
    assert_output --partial "malware hits 1"
}

# --- Test 19: Single-worker mode works ---
@test "csig: single-worker mode (scan_workers=1)" {
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -co scan_workers=1 -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 20: Clean operation strips {CSIG} prefix correctly (CH-001) ---
@test "csig: clean() strips {CSIG} prefix from sig name" {
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    lmd_set_config quarantine_hits 1
    lmd_set_config quarantine_clean 1
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    # Should not show error about {CSIG} prefix in clean rule path
    refute_output --partial '{CSIG}test.csig.single'
}

# --- Test 21: OR subsig with ClamAV alternation (a|b) parsed correctly (CH-003) ---
@test "csig: alternation group in subsig does not split incorrectly" {
    # Use an alternation (4d5a|5a4d) inside a subsig to test || parsing
    # The file has CSIG_PATTERN_ALPHA
    echo "(435349475f|deadbeef)||${HEX_ALPHA}:{CSIG}test.csig.altgrp.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-and.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 22: Grouped OR-in-AND detection ---
@test "csig: grouped OR-in-AND detection" {
    # Group: (ALPHA or CHARLIE, need 1) AND BRAVO
    # File has both ALPHA and BRAVO → group match (ALPHA), AND match (BRAVO) → hit
    echo "(${HEX_ALPHA}||${HEX_CHARLIE});1||${HEX_BRAVO}:{CSIG}test.csig.group.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-and.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 23: Group threshold=0 rejected with warning ---
# Validates the threshold=0 guard in _csig_compile_rules() (CH-002/CH-003).
# A rule with threshold=0 would always match every file — the compiler must
# log a WARNING and skip the rule entirely.
@test "csig: group threshold=0 rejected with warning" {
    # Rule with threshold=0: should be skipped
    echo "${HEX_ALPHA}||${HEX_BRAVO}:{CSIG}test.csig.zero.1;0" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-and.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    # threshold=0 rule must NOT produce a hit
    assert_output --partial "malware hits 0"
    # Verify WARNING was logged
    run grep "WARNING: threshold=0 produces always-matching rule" "$LMD_INSTALL/logs/event_log"
    assert_success
}

# --- Test 24: Comments in csig.dat are ignored ---
@test "csig: comment lines in csig.dat are ignored" {
    printf '%s\n' \
        "# This is a comment" \
        "${HEX_SINGLE}:{CSIG}test.csig.single.1" \
        > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# Helper to source the LMD function stack for direct function testing
_source_lmd_stack() {
    set +eu
    trap - ERR  # bash 5.1: BATS ERR trap leaks into sourced files even with set +e
    source "$LMD_INSTALL/internals/internals.conf"
    source "$LMD_INSTALL/conf.maldet"
    source "$LMD_INSTALL/internals/lmd.lib.sh"
}

# --- Test 25: Batch compilation produces SID-referenced files ---
@test "csig: batch compilation produces literals/wildcards/universals files" {
    _source_lmd_stack
    local runtime_csig_batch_compiled runtime_csig_literals
    local runtime_csig_wildcards runtime_csig_universals
    runtime_csig_batch_compiled=$(mktemp)
    runtime_csig_literals=$(mktemp)
    runtime_csig_wildcards=$(mktemp)
    runtime_csig_universals=$(mktemp)

    # Create a csig source with one literal-only AND rule
    local csig_src
    csig_src=$(mktemp)
    echo "${HEX_ALPHA}||${HEX_BRAVO}:{CSIG}test.batch.and.1" > "$csig_src"
    _csig_compile_rules "$csig_src"

    # Batch files must exist
    [ -s "$runtime_csig_batch_compiled" ]
    [ -s "$runtime_csig_literals" ]
    # Batch compiled must have SID-referenced format (no ERE metacharacters in SPEC field)
    local spec_field
    spec_field=$(cut -f4 "$runtime_csig_batch_compiled")
    # Should contain comma-separated SIDs (digits, commas, plus signs, or:)
    [[ "$spec_field" =~ ^[0-9,+or:]+$ ]]

    rm -f "$csig_src" "$runtime_csig_batch_compiled" "$runtime_csig_literals" \
        "$runtime_csig_wildcards" "$runtime_csig_universals"
}

# --- Test 26: Subsig dedup — shared pattern gets one SID ---
@test "csig: shared subsig across rules gets single SID in literals" {
    _source_lmd_stack
    local runtime_csig_batch_compiled runtime_csig_literals
    local runtime_csig_wildcards runtime_csig_universals
    runtime_csig_batch_compiled=$(mktemp)
    runtime_csig_literals=$(mktemp)
    runtime_csig_wildcards=$(mktemp)
    runtime_csig_universals=$(mktemp)

    # Two rules sharing HEX_ALPHA as a subsig
    local csig_src
    csig_src=$(mktemp)
    printf '%s\n' \
        "${HEX_ALPHA}:{CSIG}test.dedup.rule1" \
        "${HEX_ALPHA}||${HEX_BRAVO}:{CSIG}test.dedup.rule2" \
        > "$csig_src"
    _csig_compile_rules "$csig_src"

    # HEX_ALPHA pattern should appear exactly once in literals file
    local alpha_count
    alpha_count=$(grep -cF "${HEX_ALPHA}" "$runtime_csig_literals" || echo 0)
    [ "$alpha_count" -eq 1 ]

    # Both rules should exist in batch compiled
    grep -q "test.dedup.rule1" "$runtime_csig_batch_compiled"
    grep -q "test.dedup.rule2" "$runtime_csig_batch_compiled"

    rm -f "$csig_src" "$runtime_csig_batch_compiled" "$runtime_csig_literals" \
        "$runtime_csig_wildcards" "$runtime_csig_universals"
}

# --- Test 27: Wildcard subsig classified correctly ---
@test "csig: wildcard subsig goes to wildcards file, not literals" {
    _source_lmd_stack
    local runtime_csig_batch_compiled runtime_csig_literals
    local runtime_csig_wildcards runtime_csig_universals
    runtime_csig_batch_compiled=$(mktemp)
    runtime_csig_literals=$(mktemp)
    runtime_csig_wildcards=$(mktemp)
    runtime_csig_universals=$(mktemp)

    # Rule with a bounded gap wildcard: CSIG_ {3-20} ALPHA
    local csig_src
    csig_src=$(mktemp)
    echo "435349475f{3-20}414c504841:{CSIG}test.wc.1" > "$csig_src"
    _csig_compile_rules "$csig_src"

    # Wildcards file should have content (the compiled ERE)
    [ -s "$runtime_csig_wildcards" ]
    # Literals file should be empty (the pattern is a wildcard)
    [ ! -s "$runtime_csig_literals" ]

    rm -f "$csig_src" "$runtime_csig_batch_compiled" "$runtime_csig_literals" \
        "$runtime_csig_wildcards" "$runtime_csig_universals"
}

# --- Test 28: HEX hit suppresses CSIG on same file (merged worker) ---
@test "csig: HEX hit on file suppresses CSIG detection for same file" {
    # Create a file that matches BOTH a HEX sig and a CSIG sig
    local test_file="$TEST_SCAN_DIR/dual-hit.php"
    cp "$SAMPLES_DIR/test-csig-single.php" "$test_file"

    # HEX sig matching the CSIG_UNIQUE_MARKER_SINGLE pattern
    echo "${HEX_SINGLE}:{HEX}test.hex.single.1" > "$LMD_INSTALL/sigs/custom.hex.dat"
    # CSIG sig matching the same pattern
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"

    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"

    # Should be reported as HEX hit, not CSIG
    local scanid
    scanid=$(get_last_scanid)
    local hitsfile; hitsfile=$(get_session_hits_file "$scanid")
    run grep "{HEX}" "$hitsfile"
    assert_success
    run grep "{CSIG}" "$hitsfile"
    assert_failure
}

# --- Test 29: Multi-file batch: mixed HEX and CSIG hits ---
@test "csig: multi-file batch produces both HEX and CSIG hits" {
    # File 1: matches CSIG only
    local test_file_csig="$TEST_SCAN_DIR/csig-target.php"
    cp "$SAMPLES_DIR/test-csig-single.php" "$test_file_csig"

    # File 2: matches HEX only (unique content)
    local hex_marker="4845585f554e495155455f4d41524b4552"  # HEX_UNIQUE_MARKER
    local test_file_hex="$TEST_SCAN_DIR/hex-target.php"
    printf '<?php // HEX_UNIQUE_MARKER\n' > "$test_file_hex"

    echo "${hex_marker}:{HEX}test.hex.marker.1" > "$LMD_INSTALL/sigs/custom.hex.dat"
    echo "${HEX_SINGLE}:{CSIG}test.csig.single.1" > "$LMD_INSTALL/sigs/custom.csig.dat"

    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 2"

    local scanid
    scanid=$(get_last_scanid)
    local hitsfile; hitsfile=$(get_session_hits_file "$scanid")
    run grep "{HEX}" "$hitsfile"
    assert_success
    run grep "{CSIG}" "$hitsfile"
    assert_success
}

# --- Test 30: scan_csig=0 with merged worker still detects HEX ---
@test "csig: scan_csig=0 still detects HEX patterns in merged worker" {
    local test_file="$TEST_SCAN_DIR/hex-only.php"
    cp "$SAMPLES_DIR/test-csig-single.php" "$test_file"

    # Custom HEX sig that matches the csig single marker
    echo "${HEX_SINGLE}:{HEX}test.hex.only.1" > "$LMD_INSTALL/sigs/custom.hex.dat"
    # CSIG sig that would also match — but csig is disabled
    echo "${HEX_SINGLE}:{CSIG}test.csig.disabled.1" > "$LMD_INSTALL/sigs/custom.csig.dat"

    run maldet -co scan_csig=0 -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"

    local scanid
    scanid=$(get_last_scanid)
    local hitsfile; hitsfile=$(get_session_hits_file "$scanid")
    run grep "{HEX}" "$hitsfile"
    assert_success
}

# --- Test 31: CSIG-only mode — no HEX sigs, only CSIG rules (edge case 2) ---
@test "csig: CSIG detection works when no HEX signatures exist" {
    # Clear all hex sigs so only CSIG rules are active
    > "$LMD_INSTALL/sigs/hex.dat"
    > "$LMD_INSTALL/sigs/custom.hex.dat"
    echo "${HEX_SINGLE}:{CSIG}test.csig.only.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
    local scanid
    scanid=$(get_last_scanid)
    local hitsfile; hitsfile=$(get_session_hits_file "$scanid")
    run grep "{CSIG}" "$hitsfile"
    assert_success
}

# --- Test 32: Universal subsig in OR group rejected (compiler guard) ---
@test "csig: universal subsig in OR group rejected — no false positive" {
    # "aa" is 2 hex chars (1 byte) — universal tier (< 8 chars).
    # A universal alternative in an OR group defeats filtering (always matches),
    # so the compiler must reject the entire rule with a warning.
    echo "(${HEX_CHARLIE}||aa);1:{CSIG}test.csig.uni.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-single.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 0"
    run grep "universal subsig" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "csig: AND-rule hit output unchanged after SID preload refactor" {
    echo "${HEX_ALPHA}||${HEX_BRAVO}:{CSIG}test.csig.and.regression.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-and.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
    # Verify signame in session hits file (confirms _check_sid_match evaluation correct)
    local scanid hitsfile
    scanid=$(get_last_scanid)
    hitsfile=$(get_session_hits_file "$scanid")
    [ -n "$hitsfile" ]
    run grep "test.csig.and.regression.1" "$hitsfile"
    assert_success
}

# --- Test 34: Combined iw: modifier (case-insensitive + wide) ---
@test "csig: combined iw: modifier matching" {
    # "Hi" in hex: 48 69 → case-folded: (48|68)(69|49)
    # Wide interleave adds 00 between bytes: (48|68)00(69|49)
    # Remove trailing 00: (48|68)00(69|49)
    # Test file must contain the UTF-16LE representation of "Hi" (any case)
    local test_file="$TEST_SCAN_DIR/test-iw.bin"
    # Write "hi" in UTF-16LE: 68 00 69 00 (lowercase)
    printf '\x68\x00\x69\x00' > "$test_file"
    # Pad to exceed scan_min_filesize (24 bytes)
    dd if=/dev/zero bs=1 count=24 >> "$test_file" 2>/dev/null
    # CSIG with iw: prefix — matches "Hi" case-insensitively in UTF-16LE
    # Note: scan_csig=1 is the default — matches convention of tests 1-33
    # in this file which all rely on the default
    echo "iw:4869:{CSIG}test.csig.iw.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 35: && between groups rejected with warning ---
@test "csig: && between groups rejected — no false positive" {
    # && is not a valid clause separator; the correct separator is ||.
    # Without this guard, the parser treats the whole expression as one OR group
    # and garbage alternatives (including short patterns) cause match-everything.
    echo "(${HEX_ALPHA}||${HEX_BRAVO})&&(${HEX_CHARLIE}):{CSIG}test.csig.amp.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-and.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 0"
    run grep "not a valid separator" "$LMD_INSTALL/logs/event_log"
    assert_success
}

# --- Test 36: All-OR-group sig matches when all groups satisfied ---
@test "csig: all-OR-group sig matches when all groups satisfied" {
    # Two OR groups with no plain AND anchor — file has ALPHA + BRAVO.
    # Group 1 (ALPHA||CHARLIE): ALPHA present → satisfied
    # Group 2 (BRAVO||CHARLIE): BRAVO present → satisfied
    # All groups pass → hit
    echo "(${HEX_ALPHA}||${HEX_CHARLIE})||(${HEX_BRAVO}||${HEX_CHARLIE}):{CSIG}test.csig.allor.hit.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-and.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# --- Test 37: All-OR-group sig misses when one group unsatisfied ---
@test "csig: all-OR-group sig misses when one group unsatisfied" {
    # Two OR groups — file has ALPHA + BRAVO but NOT CHARLIE.
    # Group 1 (ALPHA||BRAVO): ALPHA present → satisfied
    # Group 2 (CHARLIE only): not present → unsatisfied → miss
    echo "(${HEX_ALPHA}||${HEX_BRAVO})||(${HEX_CHARLIE}):{CSIG}test.csig.allor.miss.1" > "$LMD_INSTALL/sigs/custom.csig.dat"
    cp "$SAMPLES_DIR/test-csig-and.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 0"
}
