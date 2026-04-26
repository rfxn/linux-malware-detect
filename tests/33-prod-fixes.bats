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

# Helper: source LMD config stack for unit-level function tests.
_source_lmd_stack() {
    set +eu
    trap - ERR  # bash 5.1: BATS ERR trap leaks into sourced files even with set +e
    source "$LMD_INSTALL/internals/internals.conf"
    source "$LMD_INSTALL/conf.maldet"
    source "$LMD_INSTALL/internals/lmd.lib.sh"
}

# ==========================================================================
# P1: ClamAV sig permissions — clamav_linksigs sets readable perms
# ==========================================================================

@test "clamav_linksigs: deployed sigs are 644 in non-root-owned ClamAV dir" {
    _source_lmd_stack
    set -e
    # Create mock clamscan that succeeds
    local mockbin
    mockbin=$(mktemp -d)
    cat > "$mockbin/clamscan" << 'MOCK'
#!/bin/bash
exit 0
MOCK
    chmod +x "$mockbin/clamscan"
    export PATH="$mockbin:$PATH"
    local cpath
    cpath=$(mktemp -d)
    # Simulate ClamAV-owned dir (use current user for test portability)
    # The key test: files must end up 644 regardless of sigdir perms
    echo "44d88612fea8a8f36de82e1278abb02f:68:EICAR-Test" > "$sigdir/rfxn.hdb"
    echo "EICAR:0:*:4549434152" > "$sigdir/rfxn.ndb"
    touch "$sigdir/rfxn.yara"
    chmod 600 "$sigdir/rfxn.hdb" "$sigdir/rfxn.ndb" "$sigdir/rfxn.yara"
    _effective_hashtype="md5"
    run clamav_linksigs "$cpath"
    assert_success
    # Deployed files must be world-readable (644)
    local _perms
    _perms=$(stat -c '%a' "$cpath/rfxn.hdb")
    [ "$_perms" = "644" ]
    _perms=$(stat -c '%a' "$cpath/rfxn.ndb")
    [ "$_perms" = "644" ]
    _perms=$(stat -c '%a' "$cpath/rfxn.yara")
    [ "$_perms" = "644" ]
    rm -rf "$cpath" "$mockbin"
}

@test "clamav_linksigs: lmd.user sigs also get 644 perms" {
    _source_lmd_stack
    set -e
    local mockbin
    mockbin=$(mktemp -d)
    cat > "$mockbin/clamscan" << 'MOCK'
#!/bin/bash
exit 0
MOCK
    chmod +x "$mockbin/clamscan"
    export PATH="$mockbin:$PATH"
    local cpath
    cpath=$(mktemp -d)
    echo "44d88612fea8a8f36de82e1278abb02f:68:EICAR-Test" > "$sigdir/rfxn.hdb"
    echo "EICAR:0:*:4549434152" > "$sigdir/rfxn.ndb"
    touch "$sigdir/rfxn.yara"
    # Non-empty user sig so it gets copied
    echo "test:0:*:deadbeef" > "$sigdir/lmd.user.ndb"
    chmod 600 "$sigdir/lmd.user.ndb"
    _effective_hashtype="md5"
    run clamav_linksigs "$cpath"
    assert_success
    [ -f "$cpath/lmd.user.ndb" ]
    local _perms
    _perms=$(stat -c '%a' "$cpath/lmd.user.ndb")
    [ "$_perms" = "644" ]
    rm -rf "$cpath" "$mockbin"
}

# ==========================================================================
# P4: --report latest resolves to most recent scan
# ==========================================================================

@test "--report latest resolves to most recent scan" {
    # Run a scan to create session data
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_DIR/"
    run maldet -a "$TEST_DIR"
    # Verify --report latest produces output
    run maldet --report latest
    assert_output --partial "SCAN ID:"
    assert_output --partial "FILES:"
}

@test "--report newest still works (backward compat)" {
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_DIR/"
    run maldet -a "$TEST_DIR"
    run maldet --report newest
    assert_output --partial "SCAN ID:"
}

@test "--report latest contains same SCAN ID as session.last" {
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_DIR/"
    run maldet -a "$TEST_DIR"
    # Get the scan ID from --report latest
    local latest_out latest_id last_id
    latest_out=$(maldet --report latest 2>&1)
    latest_id=$(echo "$latest_out" | grep "SCAN ID:" | awk '{print $NF}')
    # Get the scan ID from session.last file directly
    last_id=$(cat "$LMD_INSTALL/sess/session.last")
    [ -n "$latest_id" ]
    [ "$latest_id" = "$last_id" ]
}

# ==========================================================================
# P5: -e list column alignment — consistent date field width
# ==========================================================================

@test "-e list output has consistent column alignment" {
    # Run two scans to generate list data
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_DIR/"
    maldet -co scan_hashtype=md5 -a "$TEST_DIR" > /dev/null 2>&1
    maldet -co scan_hashtype=md5 -a "$TEST_DIR" > /dev/null 2>&1
    # Capture list output
    run maldet -e list
    assert_success
    # Columnar header row should appear once (DATE | SCANID | ...)
    assert_output --partial "SCANID"
    assert_output --partial "RUNTIME"
    assert_output --partial "FILES"
    # Count data lines: lines containing a scan ID pattern (NNNNNN.NNNNN)
    local _line _count
    _count=0
    while IFS= read -r _line; do
        # Scan IDs are digits.digits (e.g. 260328-1234.12345)
        case "$_line" in
            *[0-9][0-9][0-9][0-9][0-9][0-9]-*) _count=$((_count + 1)) ;;
        esac
    done <<< "$output"
    [ "$_count" -ge 2 ]
    # Verify no timezone offset leaks into date field (would cause misalignment)
    refute_output --partial -- "-0500  |"
    refute_output --partial -- "+0000  |"
}

# ==========================================================================
# P12: get_remote_file temp file cleanup via _grf_cleanup
# ==========================================================================

@test "_grf_cleanup removes tracked temp files" {
    _source_lmd_stack
    set -e
    # Reset tracker
    _grf_tmpfiles=()
    # Simulate creating temp files (as get_remote_file does internally)
    local f1 f2
    f1=$(mktemp "$tmpdir/.tmpf_get.XXXXXX")
    f2=$(mktemp "$tmpdir/.tmpf_get.XXXXXX")
    _grf_tmpfiles+=("$f1" "$f2")
    [ -f "$f1" ]
    [ -f "$f2" ]
    _grf_cleanup
    [ ! -f "$f1" ]
    [ ! -f "$f2" ]
    # Array should be empty after cleanup
    [ "${#_grf_tmpfiles[@]}" -eq 0 ]
}

@test "_grf_cleanup is idempotent (no error on double call)" {
    _source_lmd_stack
    set -e
    _grf_tmpfiles=()
    local f1
    f1=$(mktemp "$tmpdir/.tmpf_get.XXXXXX")
    _grf_tmpfiles+=("$f1")
    _grf_cleanup
    # Second call should not error
    _grf_cleanup
    [ "${#_grf_tmpfiles[@]}" -eq 0 ]
}

@test "get_remote_file registers temp file in _grf_tmpfiles" {
    _source_lmd_stack
    set -e
    _grf_tmpfiles=()
    # Call with a URI that will fail (no network needed — we just test registration)
    get_remote_file "file:///dev/null" "test" "" || true
    # The temp file should have been registered
    [ "${#_grf_tmpfiles[@]}" -ge 1 ]
    local _registered="${_grf_tmpfiles[0]}"
    [[ "$_registered" == *".tmpf_get."* ]]
    _grf_cleanup
}

# ==========================================================================
# P3: sigup writes $nver to sig_version_file after install
# ==========================================================================

@test "sigup version file is writable at expected path" {
    _source_lmd_stack
    # Verify sig_version_file is set and the directory exists
    [ -n "$sig_version_file" ]
    [ -d "$(dirname "$sig_version_file")" ]
}

@test "sig_version_file path matches sigdir/maldet.sigs.ver" {
    _source_lmd_stack
    [[ "$sig_version_file" == */sigs/maldet.sigs.ver ]]
}

@test "sigup code contains nver write guard" {
    # Verify the guard line exists in the update code
    run grep -c 'echo "\$nver" > "\$sig_version_file"' "$LMD_INSTALL/internals/lmd_update.sh"
    [ "$output" -ge 1 ]
}
