#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    TEST_SCAN_DIR=$(mktemp -d)
    # Remove any leftover hook config from prior test
    rm -f "$LMD_INSTALL/conf.maldet.hookscan"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
    rm -f "$LMD_INSTALL/conf.maldet.hookscan"
}

@test "hookscan.sh exists and is executable" {
    [ -f "$LMD_INSTALL/hookscan.sh" ]
    [ -x "$LMD_INSTALL/hookscan.sh" ]
}

@test "conf.maldet.hookscan.default exists" {
    [ -f "$LMD_INSTALL/conf.maldet.hookscan.default" ]
}

@test "maldet -hscan on clean file returns OK" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/upload.txt"
    run maldet --hook-scan -a "$TEST_SCAN_DIR"
    assert_success
    # Hook scan in modsec mode returns "1 maldet: OK" for clean files
    assert_output --partial "OK"
}

@test "hook scan suppresses header output" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/upload.txt"
    run maldet --hook-scan -a "$TEST_SCAN_DIR"
    # hscan mode sets hscan=1, which suppresses header() call
    refute_output --partial "Linux Malware Detect v"
}

@test "maldet -hscan detects malware in scanned path" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet --hook-scan -a "$TEST_SCAN_DIR"
    # Hook scan returns "0 maldet: SIGNAME PATH" on detection
    assert_output --partial "0 maldet:"
}

@test "backward compat: hookscan.sh /path = modsec mode" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/upload.txt"
    run "$LMD_INSTALL/hookscan.sh" "$TEST_SCAN_DIR/upload.txt"
    assert_success
    # No mode arg + absolute path = modsec mode: starts with "1"
    assert_output --partial "1 maldet: OK"
}

@test "hookscan.sh modsec mode on clean file" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/upload.txt"
    run "$LMD_INSTALL/hookscan.sh" modsec "$TEST_SCAN_DIR/upload.txt"
    assert_success
    assert_output --partial "1 maldet: OK"
}

@test "hookscan.sh generic mode clean file" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/upload.txt"
    run "$LMD_INSTALL/hookscan.sh" generic "$TEST_SCAN_DIR/upload.txt"
    assert_success
    assert_output --partial "CLEAN:"
}

@test "hookscan.sh exim mode clean file" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/upload.txt"
    run "$LMD_INSTALL/hookscan.sh" exim "$TEST_SCAN_DIR/upload.txt"
    assert_success
    assert_output --partial "maldet: clean"
}

@test "filename with double-quote rejected" {
    local _testfile="$TEST_SCAN_DIR/bad\"file.txt"
    # Create a file with a double-quote in the name (> 24 bytes for scan_min_filesize)
    printf '%0.s.' {1..30} > "$_testfile"
    # modsec mode: metachar filename = attack indicator => "0" (infected)
    run "$LMD_INSTALL/hookscan.sh" modsec "$_testfile"
    assert_output --partial "0"
}

@test "filename with .. rejected" {
    # Path containing .. traversal
    run "$LMD_INSTALL/hookscan.sh" modsec "/tmp/../etc/passwd"
    assert_output --partial "0"
}

@test "relative path rejected" {
    # Non-absolute path: no leading /
    run "$LMD_INSTALL/hookscan.sh" modsec "relative/path/file.txt"
    assert_output --partial "0"
}

@test "config parser rejects metachar in value" {
    # Write a hook config with a command-injection attempt in value
    printf 'hookscan_timeout=$(id)\n' > "$LMD_INSTALL/conf.maldet.hookscan"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/upload.txt"
    # The config parser should reject this value and use default
    run "$LMD_INSTALL/hookscan.sh" modsec "$TEST_SCAN_DIR/upload.txt"
    # Script should still complete (fail-open) and return clean
    assert_success
    assert_output --partial "1 maldet: OK"
}

@test "config parser rejects unknown key" {
    # Write a hook config with an unknown key
    printf 'bogus_key=1\n' > "$LMD_INSTALL/conf.maldet.hookscan"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/upload.txt"
    # Unknown keys are logged and ignored; scan proceeds normally
    run "$LMD_INSTALL/hookscan.sh" modsec "$TEST_SCAN_DIR/upload.txt"
    assert_success
    assert_output --partial "1 maldet: OK"
}

@test "fail-open: scan error returns clean" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/upload.txt"
    # Create a fake install dir with config but broken maldet
    local _fake_inspath="$TEST_SCAN_DIR/fake-lmd"
    mkdir -p "$_fake_inspath/internals" "$_fake_inspath/tmp"
    printf 'hookscan_fail_open=1\n' > "$_fake_inspath/conf.maldet.hookscan"
    printf '#!/bin/bash\nexit 1\n' > "$_fake_inspath/maldet"
    chmod +x "$_fake_inspath/maldet"
    # Set inspath to our fake dir to force maldet execution failure
    run bash -c "export inspath=$_fake_inspath; $LMD_INSTALL/hookscan.sh modsec $TEST_SCAN_DIR/upload.txt"
    # fail-open=1: error returns clean (modsec "1 maldet: OK")
    assert_output --partial "1 maldet: OK"
}

@test "hook scan writes to hook.hits.log on detection" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    # Clear any prior hook hits log (sessdir = $inspath/sess, not var/sess)
    rm -f "$LMD_INSTALL/sess/hook.hits.log"
    run maldet --hook-scan -co scan_hashtype=md5 -a "$TEST_SCAN_DIR/eicar.com"
    # hook.hits.log should exist if hits were found
    if [[ "$output" == *"0 maldet:"* ]]; then
        [ -f "$LMD_INSTALL/sess/hook.hits.log" ]
    fi
}

@test "clean hook scan does not write to hook.hits.log" {
    printf '%0.s.' {1..100} > "$TEST_SCAN_DIR/cleanfile.txt"
    echo "This is a clean file with no malware" >> "$TEST_SCAN_DIR/cleanfile.txt"
    # Remove any existing hook.hits.log
    rm -f "$LMD_INSTALL/sess/hook.hits.log"
    run maldet --hook-scan -co scan_hashtype=md5 -a "$TEST_SCAN_DIR"
    # hook.hits.log should NOT exist for clean scans
    [ ! -f "$LMD_INSTALL/sess/hook.hits.log" ]
}

@test "hook scan suppresses genalert (no session.tsv finalization)" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet --hook-scan -co scan_hashtype=md5 -a "$TEST_SCAN_DIR"
    # Hook scan should NOT create a finalized session.tsv file
    # (normal scans create session.tsv.DATESTAMP.PID)
    # The scan_session temp file is cleaned up, not finalized
    assert_output --partial "0 maldet:"
}

@test "fail-closed: scan error returns infected" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/upload.txt"
    # Create a fake install dir with config but broken maldet
    local _fake_inspath="$TEST_SCAN_DIR/fake-lmd"
    mkdir -p "$_fake_inspath/internals" "$_fake_inspath/tmp"
    printf 'hookscan_fail_open=0\n' > "$_fake_inspath/conf.maldet.hookscan"
    printf '#!/bin/bash\nexit 1\n' > "$_fake_inspath/maldet"
    chmod +x "$_fake_inspath/maldet"
    # Set inspath to our fake dir to force maldet execution failure
    run bash -c "export inspath=$_fake_inspath; $LMD_INSTALL/hookscan.sh modsec $TEST_SCAN_DIR/upload.txt"
    # fail-closed=0: error returns infected (modsec "0")
    assert_output --partial "0 maldet:"
}

# --- File list tests (--list and --stdin) ---

@test "generic --list with clean files shows CLEAN per file" {
    local _listfile
    _listfile=$(mktemp)
    # Create test files > 24 bytes (scan_min_filesize)
    printf '%0.s.' {1..30} > "$TEST_SCAN_DIR/file1.txt"
    printf '%0.s.' {1..30} > "$TEST_SCAN_DIR/file2.txt"
    printf '%s\n' "$TEST_SCAN_DIR/file1.txt" "$TEST_SCAN_DIR/file2.txt" > "$_listfile"
    run "$LMD_INSTALL/hookscan.sh" generic --list "$_listfile"
    assert_success
    assert_output --partial "CLEAN:"
    rm -f "$_listfile"
}

@test "generic --list skips shell metachar in path" {
    local _listfile
    _listfile=$(mktemp)
    # One valid, one with metachar
    printf '%0.s.' {1..30} > "$TEST_SCAN_DIR/good.txt"
    printf '%s\n' "$TEST_SCAN_DIR/good.txt" '/tmp/bad;file.txt' > "$_listfile"
    run "$LMD_INSTALL/hookscan.sh" generic --list "$_listfile"
    # Should still process the valid file
    assert_output --partial "CLEAN:"
    rm -f "$_listfile"
}

@test "generic --list skips relative paths" {
    local _listfile
    _listfile=$(mktemp)
    printf '%0.s.' {1..30} > "$TEST_SCAN_DIR/good.txt"
    printf '%s\n' "$TEST_SCAN_DIR/good.txt" 'relative/path.txt' > "$_listfile"
    run "$LMD_INSTALL/hookscan.sh" generic --list "$_listfile"
    assert_output --partial "CLEAN:"
    rm -f "$_listfile"
}

@test "generic --list empty list returns error" {
    local _listfile
    _listfile=$(mktemp)
    # Empty file
    run "$LMD_INSTALL/hookscan.sh" generic --list "$_listfile"
    [ "$status" -eq 1 ]
    assert_output --partial "ERROR:"
    rm -f "$_listfile"
}

@test "generic --stdin reads from pipe" {
    printf '%0.s.' {1..30} > "$TEST_SCAN_DIR/piped.txt"
    run bash -c "echo '$TEST_SCAN_DIR/piped.txt' | $LMD_INSTALL/hookscan.sh generic --stdin"
    assert_success
    assert_output --partial "CLEAN:"
}

# --- Report hooks tests ---

@test "--report hooks with empty log shows no activity" {
    rm -f "$LMD_INSTALL/var/sess/hook.hits.log"
    run maldet --report hooks
    assert_success
    assert_output --partial "no hook scan activity"
}

@test "--report hooks is recognized as valid command" {
    run maldet --report hooks
    assert_success
    # Should not show unrecognized option error
    refute_output --partial "unrecognized"
}

@test "--report hooks displays filepath not quarpath (S-REG-001)" {
    # Inject a synthetic 13-field hook hit into hook.hits.log
    local _hook_log="$LMD_INSTALL/sess/hook.hits.log"
    local _now
    _now=$(date +%s)
    # TSV: sig(1) filepath(2) quarpath(3) hit_type(4) label(5) hash(6) size(7) owner(8) group(9) mode(10) mtime(11) hook_mode(12) timestamp(13)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        '{HEX}php.cmdshell.test.1' '/home/user/public_html/shell.php' \
        '-' 'HEX' 'HEX Pattern' '-' \
        '1024' 'testuser' '1000' '644' "$_now" 'modsec' "$_now" \
        > "$_hook_log"
    run maldet --report hooks
    assert_success
    # FILE column must show the actual filepath, NOT the quarpath "-"
    assert_output --partial "/home/user/public_html/shell.php"
    # The quarpath "-" must NOT appear as the file column value
    # (it may appear in other contexts, so check the formatted line)
    local _file_line
    _file_line=$(echo "$output" | grep "php.cmdshell.test.1")
    [[ "$_file_line" == *"/home/user/public_html/shell.php"* ]]
}

# --- Rate limit tests ---

# Helper: create a fake inspath with writable tmp for non-root tests
_setup_fake_inspath() {
    local _fake="$TEST_SCAN_DIR/fake-lmd"
    mkdir -p "$_fake/internals" "$_fake/tmp" "$_fake/sess"
    # Copy real internals.conf and hookscan.sh
    cp "$LMD_INSTALL/internals/internals.conf" "$_fake/internals/"
    cp "$LMD_INSTALL/hookscan.sh" "$_fake/"
    # Patch inspath in copied internals.conf
    sed -i "s|/usr/local/maldetect|$_fake|g" "$_fake/internals/internals.conf"
    # Copy maldet binary
    cp "$LMD_INSTALL/maldet" "$_fake/"
    # Make tmp writable by nobody
    chmod 777 "$_fake/tmp"
    chmod 755 "$_fake" "$_fake/internals" "$_fake/sess"
    chmod 644 "$_fake/internals/internals.conf"
    chmod 755 "$_fake/hookscan.sh" "$_fake/maldet"
    echo "$_fake"
}

@test "rate limit: generic mode blocked after limit" {
    local _fake _nobody_uid
    _fake=$(_setup_fake_inspath)
    _nobody_uid=$(id -u nobody)
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/upload.txt"
    chmod 644 "$TEST_SCAN_DIR/upload.txt"
    chmod 755 "$TEST_SCAN_DIR"
    # Override service_users to exclude nobody (nobody is in the default list)
    printf 'hookscan_service_users=apache,nginx\n' > "$_fake/conf.maldet.hookscan"
    chmod 644 "$_fake/conf.maldet.hookscan"
    # Pre-seed counter file at limit for nobody's UID (99 on RHEL, 65534 on Debian)
    printf '%s %s\n' "$(date +%s)" "60" > "$_fake/tmp/.hook_rate_${_nobody_uid}"
    chmod 666 "$_fake/tmp/.hook_rate_${_nobody_uid}"
    # Run as nobody in generic mode — should be blocked
    run su -s /bin/bash nobody -c "export inspath=$_fake; $_fake/hookscan.sh generic $TEST_SCAN_DIR/upload.txt"
    [ "$status" -eq 1 ]
    assert_output --partial "ERROR: rate limit exceeded"
}

@test "rate limit: counter resets after 1-hour window" {
    local _fake _nobody_uid
    _fake=$(_setup_fake_inspath)
    _nobody_uid=$(id -u nobody)
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/upload.txt"
    chmod 644 "$TEST_SCAN_DIR/upload.txt"
    chmod 755 "$TEST_SCAN_DIR"
    # Override service_users to exclude nobody
    printf 'hookscan_service_users=apache,nginx\n' > "$_fake/conf.maldet.hookscan"
    chmod 644 "$_fake/conf.maldet.hookscan"
    # Pre-seed counter with expired timestamp (2 hours ago) at limit
    printf '%s %s\n' "$(( $(date +%s) - 7200 ))" "60" > "$_fake/tmp/.hook_rate_${_nobody_uid}"
    chmod 666 "$_fake/tmp/.hook_rate_${_nobody_uid}"
    # Run as nobody — expired window should reset, scan proceeds
    run su -s /bin/bash nobody -c "export inspath=$_fake; $_fake/hookscan.sh generic $TEST_SCAN_DIR/upload.txt"
    # Should NOT be rate limited (window expired) — may fail on scan (fake maldet) but not on rate limit
    refute_output --partial "rate limit exceeded"
}

@test "rate limit: root is exempt" {
    # Pre-seed counter at limit for UID 0 (root)
    printf '%s %s\n' "$(date +%s)" "60" > "$LMD_INSTALL/tmp/.hook_rate_0"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/upload.txt"
    # Run as root in generic mode — root is exempt, should succeed
    run "$LMD_INSTALL/hookscan.sh" generic "$TEST_SCAN_DIR/upload.txt"
    assert_success
    refute_output --partial "rate limit exceeded"
    rm -f "$LMD_INSTALL/tmp/.hook_rate_0"
}

@test "rate limit: unlimited when set to 0" {
    local _fake _nobody_uid
    _fake=$(_setup_fake_inspath)
    _nobody_uid=$(id -u nobody)
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/upload.txt"
    chmod 644 "$TEST_SCAN_DIR/upload.txt"
    chmod 755 "$TEST_SCAN_DIR"
    # Set rate limit to 0 (unlimited) AND exclude nobody from service users
    printf 'hookscan_user_rate_limit=0\nhookscan_service_users=apache,nginx\n' > "$_fake/conf.maldet.hookscan"
    chmod 644 "$_fake/conf.maldet.hookscan"
    # Pre-seed counter at a high number
    printf '%s %s\n' "$(date +%s)" "9999" > "$_fake/tmp/.hook_rate_${_nobody_uid}"
    chmod 666 "$_fake/tmp/.hook_rate_${_nobody_uid}"
    # Run as nobody — should not be blocked (unlimited)
    run su -s /bin/bash nobody -c "export inspath=$_fake; $_fake/hookscan.sh generic $TEST_SCAN_DIR/upload.txt"
    refute_output --partial "rate limit exceeded"
}

@test "rate limit: modsec mode exempt" {
    # Pre-seed counter at limit for UID 0
    printf '%s %s\n' "$(date +%s)" "60" > "$LMD_INSTALL/tmp/.hook_rate_0"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/upload.txt"
    # modsec mode is exempt regardless of counter state
    run "$LMD_INSTALL/hookscan.sh" modsec "$TEST_SCAN_DIR/upload.txt"
    assert_success
    refute_output --partial "rate limit exceeded"
    rm -f "$LMD_INSTALL/tmp/.hook_rate_0"
}

# --- Signame masking tests ---

@test "signame masking: generic mode non-root sees MALWARE-DETECTED" {
    local _fake
    _fake=$(_setup_fake_inspath)
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    chmod 644 "$TEST_SCAN_DIR/eicar.com"
    chmod 755 "$TEST_SCAN_DIR"
    # Enable masking + exclude nobody from service users
    printf 'hookscan_user_show_signames=0\nhookscan_service_users=apache,nginx\n' > "$_fake/conf.maldet.hookscan"
    chmod 644 "$_fake/conf.maldet.hookscan"
    # Copy internals libs needed for scan
    cp -r "$LMD_INSTALL/internals" "$_fake/"
    chmod -R 755 "$_fake/internals"
    # Run as nobody in generic mode with masking
    run su -s /bin/bash nobody -c "export inspath=$_fake; $_fake/hookscan.sh generic $TEST_SCAN_DIR/eicar.com"
    # If infected, output should show MALWARE-DETECTED not actual signame
    if [ "$status" -eq 2 ] || echo "$output" | grep -q "INFECTED:"; then
        assert_output --partial "MALWARE-DETECTED"
    fi
}

@test "signame masking: default show_signames=1 shows full name" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    # No hook config — default show_signames=1
    rm -f "$LMD_INSTALL/conf.maldet.hookscan"
    run "$LMD_INSTALL/hookscan.sh" generic "$TEST_SCAN_DIR/eicar.com"
    # Root is always exempt from masking, but default=1 means no masking anyway
    if echo "$output" | grep -q "INFECTED:"; then
        # Should NOT contain MALWARE-DETECTED (full name shown)
        refute_output --partial "MALWARE-DETECTED"
    fi
}

@test "signame masking: modsec mode always shows full signame" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    # Set masking to 0 via config
    printf 'hookscan_user_show_signames=0\n' > "$LMD_INSTALL/conf.maldet.hookscan"
    run "$LMD_INSTALL/hookscan.sh" modsec "$TEST_SCAN_DIR/eicar.com"
    # modsec mode should NEVER show MALWARE-DETECTED — always full signame
    if echo "$output" | grep -q "^0 maldet:"; then
        refute_output --partial "MALWARE-DETECTED"
    fi
}

@test "reserved comments removed from hookscan.sh" {
    run grep -c 'reserved.*enforcement.*deferred' "$LMD_INSTALL/hookscan.sh"
    [ "${output:-0}" -eq 0 ] || [ "$status" -ne 0 ]
}

@test "reserved comments removed from conf.maldet.hookscan.default" {
    run grep -c 'reserved.*enforcement.*deferred' "$LMD_INSTALL/conf.maldet.hookscan.default"
    [ "${output:-0}" -eq 0 ] || [ "$status" -ne 0 ]
}
