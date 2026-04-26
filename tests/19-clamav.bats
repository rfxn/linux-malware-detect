#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-clamav"
MOCK_CLAMAV_DIR="/tmp/mock-clamav"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"
    rm -rf "$MOCK_CLAMAV_DIR"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR" "$MOCK_CLAMAV_DIR"
    # Restore clamav_paths in internals.conf if modified
    if [ -f "$LMD_INSTALL/internals/internals.conf.bak" ]; then
        mv "$LMD_INSTALL/internals/internals.conf.bak" "$LMD_INSTALL/internals/internals.conf"
    fi
}

@test "gensigs creates NDB symlink in sigdir after scan" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -co scan_clamscan=1 -a "$TEST_SCAN_DIR"
    [ -L "$LMD_INSTALL/sigs/lmd.user.ndb" ]
}

@test "gensigs creates HDB symlink in sigdir after scan" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    # Force MD5 mode and ClamAV — on SHA-NI hardware, auto mode skips HDB generation
    maldet -co scan_clamscan=1 -co scan_hashtype=md5 -a "$TEST_SCAN_DIR"
    [ -L "$LMD_INSTALL/sigs/lmd.user.hdb" ]
}

@test "gensigs merges custom hex signatures into scan" {
    # Add custom hex sig and verify it produces a detection
    echo "6576616c286261736536345f6465636f646528:custom.gensigs.test.1" \
        > "$LMD_INSTALL/sigs/custom.hex.dat"
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    assert_report_contains "$scanid" "custom.gensigs.test"
}

@test "clamav_linksigs copies signatures to mock ClamAV directory" {
    mkdir -p "$MOCK_CLAMAV_DIR"
    # Create a mock main.cvd so clamav_linksigs recognizes this as a ClamAV dir
    touch "$MOCK_CLAMAV_DIR/main.cvd"
    # Add mock dir to clamav_paths
    cp "$LMD_INSTALL/internals/internals.conf" "$LMD_INSTALL/internals/internals.conf.bak"
    sed -i "s|^clamav_paths=.*|clamav_paths=\"$MOCK_CLAMAV_DIR\"|" "$LMD_INSTALL/internals/internals.conf"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -co scan_clamscan=1 -a "$TEST_SCAN_DIR"
    # rfxn.hdb and rfxn.ndb should be copied to the mock dir
    [ -f "$MOCK_CLAMAV_DIR/rfxn.hdb" ] || [ -f "$MOCK_CLAMAV_DIR/rfxn.ndb" ]
}

@test "clamav_linksigs skips empty lmd.user sig files" {
    _source_lmd_stack_clamav
    mkdir -p "$MOCK_CLAMAV_DIR"
    # Create empty user sig symlinks (simulates pre-population state)
    local _empty_ndb _empty_hdb
    _empty_ndb=$(mktemp "$tmpdir/.empty.ndb.XXXXXX")
    _empty_hdb=$(mktemp "$tmpdir/.empty.hdb.XXXXXX")
    ln -fs "$_empty_ndb" "$sigdir/lmd.user.ndb"
    ln -fs "$_empty_hdb" "$sigdir/lmd.user.hdb"
    clamav_linksigs "$MOCK_CLAMAV_DIR"
    # Empty files must NOT be copied — ClamAV rejects 0-byte .ndb/.hdb
    [ ! -f "$MOCK_CLAMAV_DIR/lmd.user.ndb" ]
    [ ! -f "$MOCK_CLAMAV_DIR/lmd.user.hdb" ]
    rm -f "$_empty_ndb" "$_empty_hdb"
}

@test "clamav_linksigs copies non-empty lmd.user sig files" {
    _source_lmd_stack_clamav
    mkdir -p "$MOCK_CLAMAV_DIR"
    # Create non-empty user sig files
    local _pop_ndb _pop_hdb
    _pop_ndb=$(mktemp "$tmpdir/.pop.ndb.XXXXXX")
    _pop_hdb=$(mktemp "$tmpdir/.pop.hdb.XXXXXX")
    echo "test:0:*:deadbeef" > "$_pop_ndb"
    echo "d41d8cd98f00b204e9800998ecf8427e:0:test" > "$_pop_hdb"
    ln -fs "$_pop_ndb" "$sigdir/lmd.user.ndb"
    ln -fs "$_pop_hdb" "$sigdir/lmd.user.hdb"
    clamav_linksigs "$MOCK_CLAMAV_DIR"
    [ -f "$MOCK_CLAMAV_DIR/lmd.user.ndb" ]
    [ -f "$MOCK_CLAMAV_DIR/lmd.user.hdb" ]
    rm -f "$_pop_ndb" "$_pop_hdb"
}

@test "clamav_linksigs skips non-existent directories" {
    cp "$LMD_INSTALL/internals/internals.conf" "$LMD_INSTALL/internals/internals.conf.bak"
    sed -i 's|^clamav_paths=.*|clamav_paths="/nonexistent/clamav/path"|' "$LMD_INSTALL/internals/internals.conf"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    # Should complete without error
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
}

@test "scan completes with native engine when scan_clamscan=0" {
    lmd_set_config scan_clamscan 0
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "scan_clamscan=1 without ClamAV binaries falls back gracefully" {
    lmd_set_config scan_clamscan 1
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    # No ClamAV installed in test container — clamselector sets scan_clamscan=0
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# Helper: source LMD config stack for unit-level function tests.
# Disables errexit and nounset because internals.conf has command -v
# calls that return non-zero for missing binaries.
_source_lmd_stack_clamav() {
    set +eu
    trap - ERR  # bash 5.1: BATS ERR trap leaks into sourced files even with set +e
    source "$LMD_INSTALL/internals/internals.conf"
    source "$LMD_INSTALL/conf.maldet"
    source "$LMD_INSTALL/internals/lmd.lib.sh"
}

@test "_process_clamav_hits prefixes YARA hits with {YARA} not {YARA backslash}" {
    _source_lmd_stack_clamav

    # Create a file for the [ -f ] check inside _process_clamav_hits
    echo "yara test content" > "$TEST_SCAN_DIR/yara-test.php"

    # Set up minimal infrastructure
    local scan_session_file
    scan_session_file=$(mktemp "$tmpdir/.scan_session.XXXXXX")
    scan_session="$scan_session_file"
    hits_history=$(mktemp "$tmpdir/.hits_hist.XXXXXX")
    progress_hits=0
    quarantine_hits=0
    _in_scan_context=""

    # Create mock ClamAV results with a YARA hit:
    # ClamAV reports YARA matches as "YARA.RULE_NAME"
    local mock_results
    mock_results=$(mktemp "$tmpdir/.mock_clam_results.XXXXXX")
    echo "$TEST_SCAN_DIR/yara-test.php: YARA.Safe0ver_Shell FOUND" > "$mock_results"

    _process_clamav_hits "$mock_results" ""

    # Must contain {YARA} prefix without backslash
    run grep -F '{YARA}' "$scan_session_file"
    assert_success
    # Must NOT contain escaped \}
    run grep -F '{YARA\}' "$scan_session_file"
    assert_failure

    rm -f "$mock_results" "$scan_session_file" "$hits_history"
}

# S-003: F-006 unit test — _process_clamav_hits() colon-path parsing
# ClamAV output uses ": " (colon-space) as the filepath/signame separator.
# Filepaths containing colons must not be truncated at the first colon.
# The greedy sed in _process_clamav_hits() ensures the full filepath
# (including colons) is captured.
@test "_process_clamav_hits parses filepath containing colons" {
    _source_lmd_stack_clamav

    # Create a file with a colon in its path for the [ -f ] check
    local colon_dir="$TEST_SCAN_DIR/path:with:colons"
    mkdir -p "$colon_dir"
    echo "malicious content for testing" > "$colon_dir/evil.php"

    # Set up minimal infrastructure for _process_clamav_hits
    local scan_session_file
    scan_session_file=$(mktemp "$tmpdir/.scan_session.XXXXXX")
    scan_session="$scan_session_file"
    hits_history=$(mktemp "$tmpdir/.hits_hist.XXXXXX")
    progress_hits=0
    quarantine_hits=0
    _in_scan_context=""

    # Create mock ClamAV results in the format clamscan produces:
    #   /path/to/file: Sig.Name FOUND
    local mock_results
    mock_results=$(mktemp "$tmpdir/.mock_clam_results.XXXXXX")
    echo "$colon_dir/evil.php: Php.Malware.TestSig-1 FOUND" > "$mock_results"

    # Call the function under test
    _process_clamav_hits "$mock_results" ""

    # Verify the full colon-containing filepath appears in scan_session
    run grep -F "$colon_dir/evil.php" "$scan_session_file"
    assert_success

    # Verify the signature was recorded with {CAV} prefix
    run grep -F "{CAV}Php.Malware.TestSig-1" "$scan_session_file"
    assert_success

    # Cleanup
    rm -f "$mock_results" "$scan_session_file" "$hits_history"
    rm -rf "$colon_dir"
}

# --- ClamAV signature validation gate ---

@test "clamav_validate_sigs: valid hdb passes validation" {
    _source_lmd_stack_clamav
    set -e  # restore errexit after sourcing (set +eu in _source_lmd_stack_clamav)
    # Create mock clamscan that succeeds (simulates valid database)
    local mockbin
    mockbin=$(mktemp -d)
    cat > "$mockbin/clamscan" << 'MOCK'
#!/bin/bash
exit 0
MOCK
    chmod +x "$mockbin/clamscan"
    local staging
    staging=$(mktemp -d)
    echo "44d88612fea8a8f36de82e1278abb02f:68:EICAR-Test" > "$staging/rfxn.hdb"
    PATH="$mockbin" run _clamav_validate_sigs "$staging"
    rm -rf "$staging" "$mockbin"
    assert_success
}

@test "clamav_validate_sigs: malformed hdb fails validation (issue 467)" {
    _source_lmd_stack_clamav
    set -e  # restore errexit after sourcing
    # Create mock clamscan that fails (simulates malformed database rejection)
    local mockbin
    mockbin=$(mktemp -d)
    cat > "$mockbin/clamscan" << 'MOCK'
#!/bin/bash
echo "LibClamAV Error: Malformed database" >&2
exit 2
MOCK
    chmod +x "$mockbin/clamscan"
    local staging
    staging=$(mktemp -d)
    echo "/536f24111b28ff9febcdaef4ceb47adb:9385:{MD5}bin.downloader.nemucod" > "$staging/rfxn.hdb"
    PATH="$mockbin" run _clamav_validate_sigs "$staging"
    rm -rf "$staging" "$mockbin"
    assert_failure
}

@test "clamav_validate_sigs: missing clamscan binary degrades to pass" {
    _source_lmd_stack_clamav
    set -e  # restore errexit after sourcing
    # Override PATH to hide clamscan; assumes no cPanel installation
    # (Docker test containers do not have /usr/local/cpanel/)
    local staging
    staging=$(mktemp -d)
    echo "/INVALID:0:bad" > "$staging/rfxn.hdb"
    PATH="/nonexistent" run _clamav_validate_sigs "$staging"
    rm -rf "$staging"
    assert_success
}

@test "clamav_validate_sigs: exit code captured in _clamav_validate_rc" {
    _source_lmd_stack_clamav
    set -e
    local mockbin
    mockbin=$(mktemp -d)
    cat > "$mockbin/clamscan" << 'MOCK'
#!/bin/bash
echo "LibClamAV Error: Malformed database" >&2
exit 2
MOCK
    chmod +x "$mockbin/clamscan"
    local staging
    staging=$(mktemp -d)
    echo "/INVALID:0:bad" > "$staging/rfxn.hdb"
    PATH="$mockbin" run _clamav_validate_sigs "$staging"
    rm -rf "$staging" "$mockbin"
    assert_failure
    # Verify exit code was captured (global, not local to run subshell)
    # Re-run outside of `run` to check the global
    _source_lmd_stack_clamav
    set -e
    mockbin=$(mktemp -d)
    cat > "$mockbin/clamscan" << 'MOCK'
#!/bin/bash
echo "LibClamAV Error: Malformed database" >&2
exit 2
MOCK
    chmod +x "$mockbin/clamscan"
    staging=$(mktemp -d)
    echo "/INVALID:0:bad" > "$staging/rfxn.hdb"
    PATH="$mockbin" _clamav_validate_sigs "$staging" || true
    rm -rf "$staging" "$mockbin"
    [ "$_clamav_validate_rc" = "2" ]
}

# --- ClamAV linksigs validation gate ---

@test "clamav_linksigs: valid sigs are copied to ClamAV path (validation gate)" {
    _source_lmd_stack_clamav
    set -e  # restore errexit after sourcing
    # Create mock clamscan that succeeds (simulates valid database)
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
    # Seed sigdir with valid files
    echo "44d88612fea8a8f36de82e1278abb02f:68:EICAR-Test" > "$sigdir/rfxn.hdb"
    echo "EICAR:0:*:4549434152" > "$sigdir/rfxn.ndb"
    touch "$sigdir/rfxn.yara"
    _effective_hashtype="md5"
    run clamav_linksigs "$cpath"
    assert_success
    [ -f "$cpath/rfxn.hdb" ]
    [ -f "$cpath/rfxn.ndb" ]
    rm -rf "$cpath" "$mockbin"
}

@test "clamav_linksigs: malformed sigs are NOT copied and existing removed" {
    _source_lmd_stack_clamav
    set -e  # restore errexit after sourcing
    # Create mock clamscan that fails (simulates malformed database rejection)
    local mockbin
    mockbin=$(mktemp -d)
    cat > "$mockbin/clamscan" << 'MOCK'
#!/bin/bash
echo "LibClamAV Error: Malformed database" >&2
exit 2
MOCK
    chmod +x "$mockbin/clamscan"
    export PATH="$mockbin:$PATH"
    local cpath
    cpath=$(mktemp -d)
    # Pre-plant an old rfxn.hdb in the ClamAV path (simulates existing deployment)
    echo "valid_old_content" > "$cpath/rfxn.hdb"
    # Seed sigdir with malformed file (issue #467)
    echo "/BADHASH:9385:{MD5}bad.sig" > "$sigdir/rfxn.hdb"
    echo "EICAR:0:*:4549434152" > "$sigdir/rfxn.ndb"
    touch "$sigdir/rfxn.yara"
    _effective_hashtype="md5"
    run clamav_linksigs "$cpath"
    assert_failure
    # Old rfxn.hdb must have been removed to protect ClamAV
    [ ! -f "$cpath/rfxn.hdb" ]
    rm -rf "$cpath" "$mockbin"
}

@test "clamav_linksigs: failure log message is lowercase with exit code" {
    _source_lmd_stack_clamav
    set -e
    local mockbin
    mockbin=$(mktemp -d)
    cat > "$mockbin/clamscan" << 'MOCK'
#!/bin/bash
echo "LibClamAV Error: Malformed database" >&2
exit 2
MOCK
    chmod +x "$mockbin/clamscan"
    export PATH="$mockbin:$PATH"
    local cpath
    cpath=$(mktemp -d)
    echo "valid_old_content" > "$cpath/rfxn.hdb"
    echo "/BADHASH:9385:{MD5}bad.sig" > "$sigdir/rfxn.hdb"
    echo "EICAR:0:*:4549434152" > "$sigdir/rfxn.ndb"
    touch "$sigdir/rfxn.yara"
    _effective_hashtype="md5"
    # Capture eout output by overriding it
    local _eout_log
    _eout_log=$(mktemp)
    eval 'eout() { echo "$1" >> "'"$_eout_log"'"; }'
    clamav_linksigs "$cpath" "scan" || true
    # Verify single line, lowercase, includes rc and path
    local _msg
    _msg=$(cat "$_eout_log")
    rm -f "$_eout_log"
    rm -rf "$cpath" "$mockbin"
    # Must contain lowercase "clamav signature validation failed"
    echo "$_msg" | grep -q 'clamav signature validation failed'
    # Must contain the exit code
    echo "$_msg" | grep -q 'rc=2'
    # Must contain the context tag {scan}
    echo "$_msg" | grep -q '{scan}'
    # Must NOT contain uppercase "ClamAV" or "FAILED" or "LMD"
    ! echo "$_msg" | grep -q 'ClamAV'
    ! echo "$_msg" | grep -q 'FAILED'
    ! echo "$_msg" | grep -q 'LMD signatures'
}

# --- YARA rule validation in ClamAV path ---

@test "clamav_validate_sigs: malformed YARA rule fails validation" {
    _source_lmd_stack_clamav
    set -e
    # Mock clamscan that fails when staging dir contains a .yara file
    # (simulates ClamAV rejecting malformed YARA syntax)
    local mockbin
    mockbin=$(mktemp -d)
    cat > "$mockbin/clamscan" << 'MOCK'
#!/bin/bash
echo "LibClamAV Error: Can't parse YARA rule at line 1" >&2
exit 2
MOCK
    chmod +x "$mockbin/clamscan"
    local staging
    staging=$(mktemp -d)
    # Broken YARA: unclosed rule block
    echo 'rule broken_rule {' > "$staging/rfxn.yara"
    PATH="$mockbin" run _clamav_validate_sigs "$staging"
    rm -rf "$staging" "$mockbin"
    assert_failure
}

@test "clamav_linksigs: malformed YARA blocks deployment and removes existing" {
    _source_lmd_stack_clamav
    set -e
    # Mock clamscan that fails (simulates ClamAV rejecting YARA syntax)
    local mockbin
    mockbin=$(mktemp -d)
    cat > "$mockbin/clamscan" << 'MOCK'
#!/bin/bash
echo "LibClamAV Error: Can't parse YARA rule at line 1" >&2
exit 2
MOCK
    chmod +x "$mockbin/clamscan"
    export PATH="$mockbin:$PATH"
    local cpath
    cpath=$(mktemp -d)
    # Pre-plant existing LMD sigs in ClamAV path (simulates prior deployment)
    echo "valid_hdb" > "$cpath/rfxn.hdb"
    echo "valid_ndb" > "$cpath/rfxn.ndb"
    echo "rule old_rule { condition: true }" > "$cpath/rfxn.yara"
    # Seed sigdir with valid hash sigs but broken YARA
    echo "44d88612fea8a8f36de82e1278abb02f:68:EICAR-Test" > "$sigdir/rfxn.hdb"
    echo "EICAR:0:*:4549434152" > "$sigdir/rfxn.ndb"
    echo 'rule broken_rule {' > "$sigdir/rfxn.yara"
    _effective_hashtype="md5"
    run clamav_linksigs "$cpath"
    assert_failure
    # All existing LMD sigs must be removed to protect ClamAV
    [ ! -f "$cpath/rfxn.hdb" ]
    [ ! -f "$cpath/rfxn.ndb" ]
    [ ! -f "$cpath/rfxn.yara" ]
    rm -rf "$cpath" "$mockbin"
}

@test "clamav_validate_sigs: real clamscan rejects malformed YARA (integration)" {
    # Integration test: uses real clamscan binary — skip if unavailable
    local real_clamscan=""
    if [ -f "/usr/local/cpanel/3rdparty/bin/clamscan" ]; then
        real_clamscan="/usr/local/cpanel/3rdparty/bin/clamscan"
    else
        real_clamscan=$(command -v clamscan 2>/dev/null) || true
    fi
    if [ -z "$real_clamscan" ]; then
        skip "clamscan not available in this environment"
    fi
    _source_lmd_stack_clamav
    set -e
    local staging
    staging=$(mktemp -d)
    # Malformed YARA: unclosed rule block
    echo 'rule broken_rule {' > "$staging/rfxn.yara"
    run _clamav_validate_sigs "$staging"
    rm -rf "$staging"
    assert_failure
}

@test "clamav_unlinksigs removes LMD sigs from ClamAV dirs" {
    _source_lmd_stack_clamav
    local mock_clamdir
    mock_clamdir=$(mktemp -d)
    touch "$mock_clamdir/rfxn.hdb" "$mock_clamdir/rfxn.ndb" "$mock_clamdir/rfxn.yara"
    touch "$mock_clamdir/lmd.user.ndb" "$mock_clamdir/lmd.user.hdb"
    touch "$mock_clamdir/main.cvd"

    clamav_paths="$mock_clamdir"
    clamav_unlinksigs

    [ ! -f "$mock_clamdir/rfxn.hdb" ]
    [ ! -f "$mock_clamdir/rfxn.ndb" ]
    [ ! -f "$mock_clamdir/rfxn.yara" ]
    [ ! -f "$mock_clamdir/lmd.user.ndb" ]
    [ ! -f "$mock_clamdir/lmd.user.hdb" ]
    [ -f "$mock_clamdir/main.cvd" ]

    rm -rf "$mock_clamdir"
}

@test "gensigs skips ClamAV formatting when scan_clamscan=0" {
    lmd_set_config scan_clamscan 0
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    # No .ndb symlink should exist when ClamAV is disabled
    [ ! -L "$LMD_INSTALL/sigs/lmd.user.ndb" ]
}
