#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-elog"
AUDIT_LOG="/var/log/maldet/audit.log"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"

    # Force MD5 mode — eicar.com is only in MD5 sigs; SHA-NI auto-selects sha256
    lmd_set_config scan_hashtype md5

    rm -f "$AUDIT_LOG"
    rm -f "$LMD_INSTALL/logs/event_log"
    touch "$LMD_INSTALL/logs/event_log"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "elog_lib.sh exists after install" {
    [ -f "$LMD_INSTALL/internals/elog_lib.sh" ]
}

@test "elog_lib.sh is sourced and elog function available" {
    run bash -c "source '$LMD_INSTALL/internals/internals.conf'; source '$LMD_INSTALL/internals/elog_lib.sh'; command -v elog"
    assert_success
}

@test "eout writes to log file" {
    run "$LMD_INSTALL/maldet" -a "$TEST_SCAN_DIR"
    assert_success
    [ -s "$LMD_INSTALL/logs/event_log" ]
}

@test "eout stdout flag works" {
    # Run a scan on empty dir — generates stdout output via eout(..., 1)
    run "$LMD_INSTALL/maldet" -a "$TEST_SCAN_DIR"
    assert_success
    # Should have maldet(PID): prefix in stdout
    assert_output --partial "maldet("
}

@test "eout preserves timestamp format" {
    run "$LMD_INSTALL/maldet" -a "$TEST_SCAN_DIR"
    # Log should have LMD's date format: "Mon DD YYYY HH:MM:SS"
    run grep -E '^[A-Z][a-z]{2} [0-9]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}' "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "_lmd_elog_init sets ELOG vars" {
    run bash -c '
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/internals/elog_lib.sh"
        source "'"$LMD_INSTALL"'/conf.maldet"
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        _lmd_elog_init
        echo "APP=$ELOG_APP"
        echo "STDOUT=$ELOG_STDOUT"
        echo "PREFIX=$ELOG_STDOUT_PREFIX"
        echo "FORMAT=$ELOG_FORMAT"
    '
    assert_success
    assert_output --partial "APP=maldet"
    assert_output --partial "STDOUT=flag"
    assert_output --partial "PREFIX=short"
    assert_output --partial "FORMAT=classic"
}

@test "_lmd_elog_init enables audit for root" {
    # Create a test script that runs as nobody
    local test_script="/tmp/elog-nonroot-test.sh"
    cat > "$test_script" <<'TESTEOF'
#!/usr/bin/env bash
source /usr/local/maldetect/internals/internals.conf
source /usr/local/maldetect/internals/elog_lib.sh
source /usr/local/maldetect/conf.maldet
source /usr/local/maldetect/internals/lmd.lib.sh
_lmd_elog_init
echo "AUDIT=$ELOG_AUDIT_FILE"
TESTEOF
    chmod 755 "$test_script"
    # When run as root, audit file should be set
    run bash "$test_script"
    assert_success
    assert_output --partial "AUDIT=/var/log/maldet/audit.log"
}

@test "elog_event writes to audit log" {
    # Run a scan with scannable content — produces scan_started/scan_completed events
    mkdir -p /var/log/maldet "$TEST_SCAN_DIR"
    echo "clean test content padding for minimum filesize check" > "$TEST_SCAN_DIR/clean-file.php"
    lmd_set_config scan_ignore_root 0
    run "$LMD_INSTALL/maldet" -a "$TEST_SCAN_DIR"
    assert_success
    # Audit log should exist and contain JSONL
    [ -f "$AUDIT_LOG" ]
    run grep -c '"type"' "$AUDIT_LOG"
    assert_success
}

@test "elog_event scan_started has required fields" {
    mkdir -p /var/log/maldet "$TEST_SCAN_DIR"
    echo "clean test content padding for minimum filesize check" > "$TEST_SCAN_DIR/clean-file.php"
    lmd_set_config scan_ignore_root 0
    run "$LMD_INSTALL/maldet" -a "$TEST_SCAN_DIR"
    assert_success
    [ -f "$AUDIT_LOG" ]
    run grep '"scan_started"' "$AUDIT_LOG"
    assert_success
    assert_output --partial '"path":'
}

@test "elog_event scan_completed has required fields" {
    mkdir -p /var/log/maldet "$TEST_SCAN_DIR"
    echo "clean test content padding for minimum filesize check" > "$TEST_SCAN_DIR/clean-file.php"
    lmd_set_config scan_ignore_root 0
    run "$LMD_INSTALL/maldet" -a "$TEST_SCAN_DIR"
    assert_success
    [ -f "$AUDIT_LOG" ]
    run grep '"scan_completed"' "$AUDIT_LOG"
    assert_success
    assert_output --partial '"hits":'
    assert_output --partial '"files":'
}

@test "elog_event threat_detected has required fields" {
    mkdir -p /var/log/maldet "$TEST_SCAN_DIR"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/testfile.php" 2>/dev/null || \
        echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$TEST_SCAN_DIR/testfile.php"
    lmd_set_config quarantine_hits 0
    run "$LMD_INSTALL/maldet" -a "$TEST_SCAN_DIR"
    [ -f "$AUDIT_LOG" ]
    run grep '"threat_detected"' "$AUDIT_LOG"
    assert_success
    assert_output --partial '"file":'
    assert_output --partial '"sig":'
}

@test "eout fallback works without elog_lib" {
    # Temporarily rename elog_lib to simulate missing library
    mv "$LMD_INSTALL/internals/elog_lib.sh" "$LMD_INSTALL/internals/elog_lib.sh.bak"
    run "$LMD_INSTALL/maldet" --help
    assert_success
    mv "$LMD_INSTALL/internals/elog_lib.sh.bak" "$LMD_INSTALL/internals/elog_lib.sh"
}

@test "log truncation respects maldet_log_truncate" {
    lmd_set_config maldet_log_truncate 1
    mkdir -p /var/log/maldet
    # Run maldet to trigger elog with truncation configured
    run "$LMD_INSTALL/maldet" -a "$TEST_SCAN_DIR"
    assert_success
    # Verify ELOG_LOG_MAX_LINES was set (check via _lmd_elog_init)
    run bash -c '
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/internals/elog_lib.sh"
        source "'"$LMD_INSTALL"'/conf.maldet"
        maldet_log_truncate=1
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        _lmd_elog_init
        echo "MAX=$ELOG_LOG_MAX_LINES"
    '
    assert_success
    assert_output --partial "MAX=20000"
}
