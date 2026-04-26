#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
AUDIT_LOG="/var/log/maldet/audit.log"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    _audit_setup
}

teardown() {
    rm -rf "$TEST_DIR"
}

# Helper: clear audit log and ensure directory exists
_audit_setup() {
    mkdir -p /var/log/maldet
    :> "$AUDIT_LOG"
    TEST_DIR=$(mktemp -d)
}

# Helper: set up a fake LMD install for non-root hookscan rate limit testing.
# Sets _fake, _audit_dir, _nobody_uid in the caller's scope.
_setup_ratelimit_env() {
    _nobody_uid=$(id -u nobody)
    _fake="$TEST_DIR/fake-lmd"
    _audit_dir="$TEST_DIR/audit"
    mkdir -p "$_fake/internals" "$_fake/tmp" "$_fake/sess" "$_audit_dir"
    cp "$LMD_INSTALL/internals/internals.conf" "$_fake/internals/"
    cp "$LMD_INSTALL/internals/elog_lib.sh" "$_fake/internals/"
    cp "$LMD_INSTALL/hookscan.sh" "$_fake/"
    cp "$LMD_INSTALL/maldet" "$_fake/"
    sed -i "s|/usr/local/maldetect|$_fake|g" "$_fake/internals/internals.conf"
    printf 'hookscan_service_users=apache,nginx\n' > "$_fake/conf.maldet.hookscan"
    chmod 644 "$_fake/conf.maldet.hookscan"
    chmod 777 "$_fake/tmp" "$_audit_dir"
    chmod 755 "$_fake" "$_fake/internals" "$_fake/sess" "$_fake/hookscan.sh" "$_fake/maldet"
    chmod 644 "$_fake/internals/internals.conf" "$_fake/internals/elog_lib.sh"
    # Patch audit paths for non-root: redirect to test dir, enable for non-root
    sed -i 's|ELOG_AUDIT_FILE="\$logdir/audit\.log"|ELOG_AUDIT_FILE="'"$_audit_dir"'/audit.log"|g' "$_fake/hookscan.sh"
    sed -i 's|\$logdir|'"$_audit_dir"'|g' "$_fake/hookscan.sh"
    sed -i 's|ELOG_AUDIT_FILE=""|ELOG_AUDIT_FILE="'"$_audit_dir"'/audit.log"|' "$_fake/hookscan.sh"
    # Pre-seed counter at limit
    printf '%s %s\n' "$(date +%s)" "60" > "$_fake/tmp/.hook_rate_${_nobody_uid}"
    chmod 666 "$_fake/tmp/.hook_rate_${_nobody_uid}"
    # Create test file
    echo "this is a clean test file with enough bytes to pass min size" > "$TEST_DIR/upload.txt"
    chmod 644 "$TEST_DIR/upload.txt"
    chmod 755 "$TEST_DIR"
}

# Helper: set up sigup version-check failure environment.
# Patches internals.conf to point sig_version_url at a dead endpoint.
_setup_sigup_fail() {
    cp "$LMD_INSTALL/internals/internals.conf" "$LMD_INSTALL/internals/internals.conf.bak"
    sed -i 's|sig_version_url=.*|sig_version_url="http://127.0.0.1:1/nonexistent"|' \
        "$LMD_INSTALL/internals/internals.conf"
    sed -i 's|remote_uri_timeout=.*|remote_uri_timeout="2"|' \
        "$LMD_INSTALL/internals/internals.conf"
    sed -i 's|remote_uri_retries=.*|remote_uri_retries="0"|' \
        "$LMD_INSTALL/internals/internals.conf"
}

_teardown_sigup_fail() {
    cp "$LMD_INSTALL/internals/internals.conf.bak" "$LMD_INSTALL/internals/internals.conf"
    rm -f "$LMD_INSTALL/internals/internals.conf.bak"
}

# ==========================================================================
# G-01: Purge audit events
# ==========================================================================

@test "G-01: purge emits purge_completed audit event" {
    run maldet -p
    assert_success
    [ -f "$AUDIT_LOG" ]
    run grep -c '"type":"purge_completed"' "$AUDIT_LOG"
    assert_success
    [ "$output" -ge 1 ]
}

@test "G-01: purge audit event includes user field" {
    run maldet -p
    assert_success
    run grep '"purge_completed"' "$AUDIT_LOG"
    assert_success
    assert_output --partial '"user":"root"'
}

@test "G-01: purge audit event survives log truncation" {
    # Seed the event_log with content so we can verify truncation
    local event_log="$LMD_INSTALL/logs/event_log"
    echo "seed line 1" >> "$event_log"
    echo "seed line 2" >> "$event_log"
    run maldet -p
    assert_success
    # event_log should be truncated — purge() does :> then re-logs one line
    local _lines
    _lines=$(wc -l < "$event_log")
    [ "$_lines" -le 2 ]
    # The key assertion: audit.log retains the purge event despite truncation
    [ -f "$AUDIT_LOG" ]
    run grep -c '"purge_completed"' "$AUDIT_LOG"
    assert_success
    [ "$output" -ge 1 ]
}

# ==========================================================================
# G-02: Update audit events
# ==========================================================================

@test "G-02: update event constants are defined" {
    run grep -c 'ELOG_EVT_UPDATE_' "$LMD_INSTALL/internals/lmd.lib.sh"
    assert_success
    # 3 constants: UPDATE_STARTED, UPDATE_COMPLETED, UPDATE_FAILED
    [ "$output" -ge 3 ]
}

@test "G-02: sigup version check failure emits update_failed" {
    _setup_sigup_fail
    run maldet -u
    _teardown_sigup_fail
    [ -f "$AUDIT_LOG" ]
    run grep '"update_failed"' "$AUDIT_LOG"
    assert_success
    assert_output --partial '"action":"sigup"'
}

@test "G-02: update_failed includes reason=version_check_failed" {
    _setup_sigup_fail
    run maldet -u
    _teardown_sigup_fail
    [ -f "$AUDIT_LOG" ]
    run grep '"update_failed"' "$AUDIT_LOG"
    assert_success
    assert_output --partial '"reason":"version_check_failed"'
}

# ==========================================================================
# G-03: Alert failure audit events
# ==========================================================================

@test "G-03: alert_failed constant is defined" {
    run grep 'ELOG_EVT_ALERT_FAILED="alert_failed"' "$LMD_INSTALL/internals/lmd.lib.sh"
    assert_success
}

@test "G-03: alert_failed events wired for all channels" {
    # Expect 5 _lmd_elog_event calls with ALERT_FAILED:
    # slack, telegram, discord, scan email, digest email
    run grep -c '_lmd_elog_event.*ALERT_FAILED' "$LMD_INSTALL/internals/lmd_alert.sh"
    assert_success
    [ "$output" -eq 5 ]
}

@test "G-03: email alert_failed includes channel=email metadata" {
    # Static verification: the email alert_failed event has channel=email
    run grep 'ALERT_FAILED.*channel=email' "$LMD_INSTALL/internals/lmd_alert.sh"
    assert_success
}

# ==========================================================================
# G-04: Hookscan audit events
# ==========================================================================

@test "G-04: hook scan includes source=hook in scan_started" {
    echo "this is a clean test file with enough bytes to pass min size" > "$TEST_DIR/testfile.txt"
    lmd_set_config scan_ignore_root 0
    run maldet --hook-scan -a "$TEST_DIR"
    [ -f "$AUDIT_LOG" ]
    run grep '"scan_started"' "$AUDIT_LOG"
    assert_success
    assert_output --partial '"source":"hook"'
}

@test "G-04: hook scan includes source=hook in scan_completed" {
    echo "this is a clean test file with enough bytes to pass min size" > "$TEST_DIR/testfile.txt"
    lmd_set_config scan_ignore_root 0
    run maldet --hook-scan -a "$TEST_DIR"
    [ -f "$AUDIT_LOG" ]
    run grep '"scan_completed"' "$AUDIT_LOG"
    assert_success
    assert_output --partial '"source":"hook"'
}

@test "G-04: CLI scan does not include source=hook" {
    echo "this is a clean test file with enough bytes to pass min size" > "$TEST_DIR/testfile.txt"
    lmd_set_config scan_ignore_root 0
    run maldet -a "$TEST_DIR"
    assert_success
    [ -f "$AUDIT_LOG" ]
    # scan_started should exist but without source=hook
    run grep '"scan_started"' "$AUDIT_LOG"
    assert_success
    refute_output --partial '"source":"hook"'
}

@test "G-04: hookscan sources elog_lib for audit trail" {
    run grep 'source "$elog_lib"' "$LMD_INSTALL/hookscan.sh"
    assert_success
}

@test "G-04: hookscan ELOG_STDOUT is never" {
    run grep 'ELOG_STDOUT="never"' "$LMD_INSTALL/hookscan.sh"
    assert_success
}

@test "G-04: rate limit threshold_exceeded constant defined" {
    run grep 'ELOG_EVT_RATE_LIMITED="threshold_exceeded"' "$LMD_INSTALL/internals/lmd.lib.sh"
    assert_success
}

@test "G-04: rate limit emits threshold_exceeded event" {
    _setup_ratelimit_env
    run su -s /bin/bash nobody -c "export inspath=$_fake; $_fake/hookscan.sh generic $TEST_DIR/upload.txt"
    [ "$status" -eq 1 ]
    assert_output --partial "rate limit exceeded"
    [ -f "$_audit_dir/audit.log" ]
    run grep '"threshold_exceeded"' "$_audit_dir/audit.log"
    assert_success
}

@test "G-04: threshold_exceeded event includes uid and count metadata" {
    _setup_ratelimit_env
    run su -s /bin/bash nobody -c "export inspath=$_fake; $_fake/hookscan.sh generic $TEST_DIR/upload.txt"
    [ "$status" -eq 1 ]
    [ -f "$_audit_dir/audit.log" ]
    run grep '"threshold_exceeded"' "$_audit_dir/audit.log"
    assert_success
    assert_output --partial "\"uid\":\"$_nobody_uid\""
    assert_output --partial '"count":"60"'
}
