#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-yara"

setup() {
    command -v yara >/dev/null 2>&1 || command -v yr >/dev/null 2>&1 || skip "no yara or yr binary available"
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"

    # Force MD5 mode — eicar.com is only in MD5 sigs; SHA-NI auto-selects sha256
    lmd_set_config scan_hashtype md5
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
    # Restore internals.conf if a test modified it
    if [ -f "$LMD_INSTALL/internals/internals.conf.bak" ]; then
        cp "$LMD_INSTALL/internals/internals.conf.bak" "$LMD_INSTALL/internals/internals.conf"
        rm -f "$LMD_INSTALL/internals/internals.conf.bak"
    fi
}

# ── Group 1: Binary Discovery & Config ──

@test "YARA: yara or yr binary discovered in internals.conf" {
    run bash -c 'source '"$LMD_INSTALL"'/internals/internals.conf 2>/dev/null; echo "yara=$yara yr=$yr"'
    [[ "$output" == *"yara=/usr"* ]] || [[ "$output" == *"yr=/usr"* ]]
}

@test "YARA: scan_yara=0 disables YARA scan stage" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 0
    cp "$SAMPLES_DIR/test-yara-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "malware hits 0"
}

@test "YARA: missing yara binary disables YARA gracefully" {
    lmd_set_config scan_yara 1
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    # Save internals.conf, override yara paths, then restore after scan
    cp "$LMD_INSTALL/internals/internals.conf" "$LMD_INSTALL/internals/internals.conf.bak"
    echo 'yara=""' >> "$LMD_INSTALL/internals/internals.conf"
    echo 'yr=""' >> "$LMD_INSTALL/internals/internals.conf"
    run maldet -a "$TEST_SCAN_DIR"
    cp "$LMD_INSTALL/internals/internals.conf.bak" "$LMD_INSTALL/internals/internals.conf"
    assert_success
    # _yara_init_cache finds no binary — scan_stage_yara logs skip to event_log (not stdout)
    run grep -c "skipping YARA scan stage" "$LMD_INSTALL/logs/event_log"
    [ "$status" -ne 1 ]
}

# ── Group 2: Basic Detection ──

@test "YARA: detects file matching custom.yara rule" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    cp "$SAMPLES_DIR/test-yara-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "YARA: clean file produces no YARA hits" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "malware hits 0"
}

@test "YARA: hit recorded with {YARA} prefix in report" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    cp "$SAMPLES_DIR/test-yara-match.php" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    [ -n "$scanid" ]
    assert_report_contains "$scanid" "{YARA}"
}

@test "YARA: hit recorded with rule name in report" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    cp "$SAMPLES_DIR/test-yara-match.php" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    [ -n "$scanid" ]
    assert_report_contains "$scanid" "test_yara_marker"
}

@test "YARA: multiple files scanned, only matching ones flagged" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    cp "$SAMPLES_DIR/test-yara-match.php" "$TEST_SCAN_DIR/"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# ── Group 3: Custom Rules ──

@test "YARA: custom.yara.d/ drop-in rules are loaded" {
    lmd_set_config scan_yara 1
    mkdir -p "$LMD_INSTALL/sigs/custom.yara.d"
    cat > "$LMD_INSTALL/sigs/custom.yara.d/dropin.yar" <<'EOF'
rule dropin_test_rule
{
    strings:
        $marker = "YARATEST_MARKER_STRING_1234567890"
    condition:
        $marker
}
EOF
    cp "$SAMPLES_DIR/test-yara-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "YARA: empty custom.yara does not cause errors" {
    lmd_set_config scan_yara 1
    > "$LMD_INSTALL/sigs/custom.yara"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "malware hits 0"
}

@test "YARA: empty custom.yara.d/ does not cause errors" {
    lmd_set_config scan_yara 1
    rm -rf "$LMD_INSTALL/sigs/custom.yara.d"/*
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "malware hits 0"
}

@test "YARA: multiple .yar files in custom.yara.d/ all loaded" {
    lmd_set_config scan_yara 1
    mkdir -p "$LMD_INSTALL/sigs/custom.yara.d"
    cat > "$LMD_INSTALL/sigs/custom.yara.d/rule1.yar" <<'EOF'
rule yar_rule_one
{
    strings:
        $m = "YARATEST_MARKER_STRING_1234567890"
    condition:
        $m
}
EOF
    cat > "$LMD_INSTALL/sigs/custom.yara.d/rule2.yar" <<'EOF'
rule yar_rule_two
{
    strings:
        $m = "SECOND_UNIQUE_MARKER_ABCDEFGHIJ"
    condition:
        $m
}
EOF
    echo 'SECOND_UNIQUE_MARKER_ABCDEFGHIJ' > "$TEST_SCAN_DIR/marker2.txt"
    cp "$SAMPLES_DIR/test-yara-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 2"
}

@test "YARA: signature count includes custom YARA rules" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    # The output should show a YARA count > 0 and USER count > 0
    assert_output --regexp "[0-9,]+ YARA"
    assert_output --regexp "[0-9,]+ USER"
}

# ── Group 4: Ignore & Quarantine Integration ──

@test "YARA: ignore_sigs suppresses YARA hit" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    echo "test_yara_marker" >> "$LMD_INSTALL/ignore_sigs"
    cp "$SAMPLES_DIR/test-yara-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "malware hits 0"
}

@test "YARA: ignore_paths excludes files from YARA scan" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    echo "$TEST_SCAN_DIR" >> "$LMD_INSTALL/ignore_paths"
    cp "$SAMPLES_DIR/test-yara-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    # Directory is fully excluded, so no hits (and possibly no scan report)
    refute_output --partial "malware hits 1"
}

@test "YARA: quarantine works on YARA hits" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    lmd_set_config quarantine_hits 1
    cp "$SAMPLES_DIR/test-yara-match.php" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    assert_quarantined "$TEST_SCAN_DIR/test-yara-match.php"
}

@test "YARA: -co scan_yara=1 enables YARA at runtime" {
    source /opt/tests/helpers/create-yara-sigs.sh
    cp "$SAMPLES_DIR/test-yara-match.php" "$TEST_SCAN_DIR/"
    run maldet -co scan_yara=1 -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# ── Group 5: ClamAV Interaction ──

@test "YARA: scan_yara_scope=custom skips rfxn.yara in native scan" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    lmd_set_config scan_yara_scope "custom"
    # With scope=custom and ClamAV enabled, only custom rules should be used
    lmd_set_config scan_clamscan 1
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    # Should complete without error regardless of ClamAV availability
    [[ "$status" -eq 0 ]] || [[ "$status" -eq 2 ]]
}

@test "YARA: scan_yara_scope=all includes rfxn.yara in native YARA scan" {
    lmd_set_config scan_yara 1
    lmd_set_config scan_yara_scope "all"
    lmd_set_config scan_clamscan 0
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "malware hits 0"
}

@test "YARA: native YARA runs alongside native scanner without conflict" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    lmd_set_config scan_clamscan 0
    cp "$SAMPLES_DIR/test-yara-match.php" "$TEST_SCAN_DIR/"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# ── Group 6: Timeout & Edge Cases ──

@test "YARA: scan_yara_timeout=0 disables timeout" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    lmd_set_config scan_yara_timeout 0
    cp "$SAMPLES_DIR/test-yara-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "YARA: no YARA rules available produces no errors" {
    lmd_set_config scan_yara 1
    lmd_set_config scan_clamscan 0
    lmd_set_config scan_yara_scope "custom"
    > "$LMD_INSTALL/sigs/custom.yara"
    rm -rf "$LMD_INSTALL/sigs/custom.yara.d"/*
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "malware hits 0"
}

@test "YARA: sig_user_yara_file and sig_user_yara_dir paths set" {
    run bash -c 'source '"$LMD_INSTALL"'/internals/internals.conf 2>/dev/null; echo "$sig_user_yara_file $sig_user_yara_dir"'
    assert_output --partial "custom.yara"
    assert_output --partial "custom.yara.d"
}

# ── Group 7: Batch Scanning & Error Handling ──

@test "YARA: syntax error in custom rule logs warning" {
    lmd_set_config scan_yara 1
    mkdir -p "$LMD_INSTALL/sigs/custom.yara.d"
    cat > "$LMD_INSTALL/sigs/custom.yara.d/bad.yar" <<'EOF'
rule broken { strings: $x = "test" condition: $x and UNDEFINED_ID }
EOF
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    # Should complete without crashing
    [[ "$status" -eq 0 ]] || [[ "$status" -eq 2 ]]
    # Check event log for warning
    run grep -c "{yara} warning:" "$LMD_INSTALL/logs/event_log"
    [[ "$output" -ge 1 ]]
}

@test "YARA: batch scan identifies match among many clean files" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    for i in $(seq 1 20); do
        echo "clean content $i" > "$TEST_SCAN_DIR/clean-$i.txt"
    done
    cp "$SAMPLES_DIR/test-yara-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "YARA: quarantined files do not produce 'could not open' warnings" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    lmd_set_config quarantine_hits 1
    # EICAR triggers MD5 stage quarantine; YARA should not warn about missing file
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    [[ "$status" -eq 0 ]] || [[ "$status" -eq 2 ]]
    # "could not open" / "can't open" must NOT appear in event log
    run grep -c -E "could not open|can't open" "$LMD_INSTALL/logs/event_log"
    [[ "$output" -eq 0 ]]
}

@test "YARA: --scan-list feature detection logged in event log" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    # Verify YARA scan stage ran
    run grep -c "native YARA scan stage" "$LMD_INSTALL/logs/event_log"
    [[ "$output" -ge 1 ]]
}

# ── Group 8: compiled.yarc Validation ──

@test "YARA: corrupt compiled.yarc skipped with warning" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    # Write 64 random bytes as a corrupt compiled rules file
    dd if=/dev/urandom of="$LMD_INSTALL/sigs/compiled.yarc" bs=64 count=1 2>/dev/null
    cp "$SAMPLES_DIR/test-yara-match.php" "$TEST_SCAN_DIR/"
    > "$LMD_INSTALL/logs/event_log"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    # Text rules should still detect the file
    assert_output --partial "malware hits 1"
    # Corrupt compiled rules should be skipped with warning
    run grep "failed validation" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "YARA: valid compiled.yarc used in scan" {
    command -v yarac >/dev/null 2>&1 || skip "yarac not available"
    lmd_set_config scan_yara 1
    lmd_set_config scan_clamscan 0
    lmd_set_config scan_yara_scope "custom"
    # Write a YARA rule matching a unique marker
    local rule_file
    rule_file=$(mktemp "$LMD_INSTALL/tmp/.yara_test.XXXXXX")
    cat > "$rule_file" <<'EOF'
rule compiled_yarc_test
{
    strings:
        $m = "COMPILED_YARC_TEST_MARKER"
    condition:
        $m
}
EOF
    yarac "$rule_file" "$LMD_INSTALL/sigs/compiled.yarc"
    rm -f "$rule_file"
    # Remove all text rules so only compiled rules can match
    > "$LMD_INSTALL/sigs/custom.yara"
    rm -rf "$LMD_INSTALL/sigs/custom.yara.d"/*
    # Create test file containing the marker
    echo "COMPILED_YARC_TEST_MARKER" > "$TEST_SCAN_DIR/compiled-test.txt"
    > "$LMD_INSTALL/logs/event_log"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
    # No validation failure in event log
    run grep "failed validation" "$LMD_INSTALL/logs/event_log"
    assert_failure
}

@test "YARA: scan completes normally without compiled.yarc" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    rm -f "$LMD_INSTALL/sigs/compiled.yarc"
    cp "$SAMPLES_DIR/test-yara-match.php" "$TEST_SCAN_DIR/"
    > "$LMD_INSTALL/logs/event_log"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
    # No validation failure in event log
    run grep "failed validation" "$LMD_INSTALL/logs/event_log"
    assert_failure
}

# ── Group 9: clean() YARA Rescan & YARA(cav) Display ──

@test "YARA: clean() invokes YARA rescan after cleaning" {
    # HEX sig matching infected-base64.php with clean script name
    echo "6576616c286261736536345f6465636f646528:base64.inject.unclassed.99" \
        > "$LMD_INSTALL/sigs/custom.hex.dat"
    # Suppress builtin sigs that match eval(base64_decode but have no clean script.
    # ignore_sigs uses grep -E; regex patterns future-proof against CDN sig additions.
    printf '%s\n' "php\.base64\.inject" "php\.inject\." > "$LMD_INSTALL/ignore_sigs"
    lmd_set_config quarantine_hits 1
    lmd_set_config quarantine_clean 1
    lmd_set_config scan_yara 1
    cp "$SAMPLES_DIR/infected-base64.php" "$TEST_SCAN_DIR/"
    > "$LMD_INSTALL/logs/event_log"
    maldet -a "$TEST_SCAN_DIR" || true
    # clean() should have logged rescanning entries
    run grep "{clean}" "$LMD_INSTALL/logs/event_log"
    assert_success
    # Verify the YARA rescan message specifically
    run grep "{clean} rescanning" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "YARA: signature count shows YARA(no engine) when both ClamAV and YARA disabled" {
    lmd_set_config scan_clamscan 0
    lmd_set_config scan_yara 0
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "YARA(no engine)"
}

@test "YARA: signature count shows YARA (not cav) when scan_yara=1" {
    source /opt/tests/helpers/create-yara-sigs.sh
    lmd_set_config scan_yara 1
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    # Should show plain YARA label, not YARA(cav)
    refute_output --partial "YARA(cav)"
    assert_output --regexp "[0-9,]+ YARA [|]"
}
