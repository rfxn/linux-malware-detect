#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-logging"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "event_log is written during scan" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    [ -f "$LMD_INSTALL/logs/event_log" ]
    [ -s "$LMD_INSTALL/logs/event_log" ]
}

@test "event_log entries contain timestamps" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    # Log format: Mon DD HH:MM:SS YYYY
    run grep -cE '[A-Z][a-z]{2} [0-9]{1,2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}' "$LMD_INSTALL/logs/event_log"
    [ "$output" -ge 1 ]
}

@test "event_log entries contain hostname" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    local hostname
    hostname=$(hostname)
    run grep -c "$hostname" "$LMD_INSTALL/logs/event_log"
    [ "$output" -ge 1 ]
}

@test "event_log entries contain maldet PID" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    run grep -cE 'maldet\([0-9]+\)' "$LMD_INSTALL/logs/event_log"
    [ "$output" -ge 1 ]
}

@test "event_log contains scan start and completion entries" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    run grep -c "scan completed" "$LMD_INSTALL/logs/event_log"
    [ "$output" -ge 1 ]
}

