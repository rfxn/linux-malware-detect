#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-clean"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"

    # Custom HEX sig matching eval(base64_decode( → maps to clean/base64.inject.unclassed
    echo "6576616c286261736536345f6465636f646528:base64.inject.unclassed.99" \
        > "$LMD_INSTALL/sigs/custom.hex.dat"

    # Suppress builtin sigs that match eval(base64_decode but have no clean script.
    # ignore_sigs uses grep -E; regex patterns future-proof against CDN sig additions.
    printf '%s\n' "php\.base64\.inject" "php\.inject\." > "$LMD_INSTALL/ignore_sigs"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "clean scripts directory exists" {
    [ -d "$LMD_INSTALL/clean" ]
}

@test "base64.inject.unclassed clean script is executable" {
    [ -x "$LMD_INSTALL/clean/base64.inject.unclassed" ]
}

@test "clean_hitlist requires quarantine_clean enabled" {
    lmd_set_config quarantine_hits 1
    lmd_set_config quarantine_clean 0
    cp "$SAMPLES_DIR/infected-base64.php" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -n "$scanid"
    assert_output --partial "disabled"
}

@test "clean_hitlist requires quarantine_hits enabled" {
    lmd_set_config quarantine_hits 0
    lmd_set_config quarantine_clean 1
    cp "$SAMPLES_DIR/infected-base64.php" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -n "$scanid"
    assert_output --partial "disabled"
}

@test "auto-clean removes base64 injection during quarantine" {
    lmd_set_config quarantine_hits 1
    lmd_set_config quarantine_clean 1
    cp "$SAMPLES_DIR/infected-base64.php" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    # After auto-clean, file should be restored with injection removed
    [ -f "$TEST_SCAN_DIR/infected-base64.php" ]
    # The eval(base64_decode line should be cleaned out
    run grep "eval(base64_decode" "$TEST_SCAN_DIR/infected-base64.php"
    assert_failure
}

@test "clean records success in event log" {
    lmd_set_config quarantine_hits 1
    lmd_set_config quarantine_clean 1
    cp "$SAMPLES_DIR/infected-base64.php" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    run grep "{clean}" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "failed clean when no matching clean rule exists" {
    lmd_set_config quarantine_hits 1
    lmd_set_config quarantine_clean 1
    # Use a signature name that has no clean script
    echo "6576616c286261736536345f6465636f646528:php.nocleanrule.test.1" \
        > "$LMD_INSTALL/sigs/custom.hex.dat"
    cp "$SAMPLES_DIR/infected-base64.php" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    run grep "could not find clean rule" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "batch clean via maldet -n SCANID" {
    lmd_set_config quarantine_hits 1
    lmd_set_config quarantine_clean 1
    cp "$SAMPLES_DIR/infected-base64.php" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    # -n invokes clean_hitlist() on the scanid. Since auto-clean already
    # ran during -a, quarantine entries are already processed, so -n has
    # nothing new to clean. Verify it accepts the scanid (no error) and
    # the original auto-clean produced {clean} log entries.
    maldet -n "$scanid" || true
    run grep "invalid scanid" "$LMD_INSTALL/logs/event_log"
    assert_failure
    run grep "{clean}" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "clean handles multiple infected files" {
    lmd_set_config quarantine_hits 1
    lmd_set_config quarantine_clean 1
    cp "$SAMPLES_DIR/infected-base64.php" "$TEST_SCAN_DIR/infected1.php"
    cp "$SAMPLES_DIR/infected-base64.php" "$TEST_SCAN_DIR/infected2.php"
    maldet -a "$TEST_SCAN_DIR" || true
    # Both files should be restored after clean
    [ -f "$TEST_SCAN_DIR/infected1.php" ]
    [ -f "$TEST_SCAN_DIR/infected2.php" ]
}

@test "clean file no longer matches signature after cleaning" {
    lmd_set_config quarantine_hits 1
    lmd_set_config quarantine_clean 1
    cp "$SAMPLES_DIR/infected-base64.php" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    # File should exist (restored and cleaned)
    [ -f "$TEST_SCAN_DIR/infected-base64.php" ]
    # Rescan should find no hits
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "malware hits 0"
}

@test "legitimate content survives cleaning" {
    lmd_set_config quarantine_hits 1
    lmd_set_config quarantine_clean 1
    cp "$SAMPLES_DIR/infected-base64.php" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    [ -f "$TEST_SCAN_DIR/infected-base64.php" ]
    run grep "legitimate content" "$TEST_SCAN_DIR/infected-base64.php"
    assert_success
}

# F-005: clean() derives clean rule name from arg2, not global $hitname
@test "clean uses file_signame parameter not global hitname for rule lookup" {
    lmd_set_config quarantine_hits 1
    lmd_set_config quarantine_clean 1
    cp "$SAMPLES_DIR/infected-base64.php" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    # The auto-clean should have used the correct sig name from arg2
    # Verify the log references base64.inject.unclassed (from the custom sig)
    # and not some stale or wrong name
    run grep "base64.inject.unclassed" "$LMD_INSTALL/logs/event_log"
    assert_success
    assert_output --partial "clean"
}
