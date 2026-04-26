#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
TEST_SCAN_DIR="/tmp/lmd-test-strlen"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"
    # Clear event_log so grep assertions only see current test's entries
    > "$LMD_INSTALL/logs/event_log"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "string_length_scan=1 detects file with long unbroken string" {
    lmd_set_config string_length_scan 1
    lmd_set_config string_length 1000
    # Create a text file (not PHP) with a long unbroken string to avoid HEX sig matches
    printf 'AAAA' > "$TEST_SCAN_DIR/obfuscated.txt"
    head -c 2000 /dev/urandom | base64 | tr -d '\n' >> "$TEST_SCAN_DIR/obfuscated.txt"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    # strlength hits are logged to event_log
    run grep "{strlen}" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "string_length_scan=0 disables statistical analysis" {
    lmd_set_config string_length_scan 0
    lmd_set_config string_length 1000
    printf 'AAAA' > "$TEST_SCAN_DIR/obfuscated.txt"
    head -c 2000 /dev/urandom | base64 | tr -d '\n' >> "$TEST_SCAN_DIR/obfuscated.txt"
    maldet -a "$TEST_SCAN_DIR" || true
    run grep "{strlen}" "$LMD_INSTALL/logs/event_log"
    assert_failure
}

@test "string below threshold is not flagged" {
    lmd_set_config string_length_scan 1
    lmd_set_config string_length 100000
    # Create file with short string (well under threshold)
    printf 'AAAA' > "$TEST_SCAN_DIR/short.txt"
    head -c 100 /dev/urandom | base64 | tr -d '\n' >> "$TEST_SCAN_DIR/short.txt"
    maldet -a "$TEST_SCAN_DIR" || true
    run grep "{strlen}" "$LMD_INSTALL/logs/event_log"
    assert_failure
}

@test "custom string_length threshold is respected" {
    lmd_set_config string_length_scan 1
    lmd_set_config string_length 500
    # Create file with string just over threshold
    printf 'AAAA' > "$TEST_SCAN_DIR/threshold.txt"
    head -c 600 /dev/urandom | base64 | tr -d '\n' >> "$TEST_SCAN_DIR/threshold.txt"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    run grep "{strlen}" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "clean file not flagged by string length analysis" {
    lmd_set_config string_length_scan 1
    lmd_set_config string_length 1000
    cp /opt/tests/samples/clean-file.txt "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    run grep "{strlen}" "$LMD_INSTALL/logs/event_log"
    assert_failure
}

@test "scan_strlen skips and returns 0 on FreeBSD (wc -L unavailable)" {
    # Source the engine function in isolation to test the guard.
    # Mock eout() to capture output; verify guard exits 0 and does not invoke wc.
    run bash -c "
      os_freebsd=1
      string_length_scan=1
      eout() { echo \"eout: \$1\"; }
      source /usr/local/maldetect/internals/lmd_engine.sh 2>/dev/null || true
      scan_strlen file /dev/null
    "
    [ "$status" -eq 0 ]
    [[ "$output" == *"skipped on FreeBSD"* ]]
}
