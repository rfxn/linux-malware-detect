#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-security"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
    rm -f /tmp/pwned
}

# Verify hex batch temp files are cleaned up after scan
@test "hex batch temp files cleaned after scan" {
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    # No hex batch/worker/chunk temp files should remain
    local leftovers
    leftovers=$(find "$LMD_INSTALL/tmp" -name '.hex_batch*' -o -name '.hex_worker*' -o -name '.hex_chunk*' 2>/dev/null)
    [ -z "$leftovers" ]
}

# F-022: conf.maldet permissions
@test "conf.maldet is not world-readable" {
    local perms
    perms=$(stat -c '%a' "$LMD_INSTALL/conf.maldet")
    [ "$perms" = "640" ]
}

# F-004: hookscan filename validation
# Calls hookscan.sh directly to validate that dangerous filenames are rejected.
# Metachar filenames produce modsec "infected" output (attack indicator);
# non-existent files produce modsec "clean" output (safe default).
@test "hookscan rejects dangerous and invalid filenames" {
    # $() command substitution — metachar rejection (output starts with 0)
    run "$LMD_INSTALL/hookscan.sh" modsec '/tmp/test$(whoami).php'
    assert_output --partial "0"
    # Backtick injection — metachar rejection (output starts with 0)
    run "$LMD_INSTALL/hookscan.sh" modsec '/tmp/test`id`.php'
    assert_output --partial "0"
    # Non-existent file — safe "clean" response (readlink -e fails)
    run "$LMD_INSTALL/hookscan.sh" modsec "/tmp/nonexistent_file_xyz.php"
    assert_output --partial "1 maldet: OK"
}

# F-002: -co config option injection
@test "-co rejects command substitution in values" {
    run maldet -co 'scan_max_filesize=$(id)' -a /tmp
    assert_output --partial "rejected unsafe -co value"
}

@test "-co rejects backtick injection" {
    run maldet -co 'scan_max_filesize=`id`' -a /tmp
    assert_output --partial "rejected unsafe -co value"
}

@test "-co neutralizes semicolon in value via quoting" {
    # sed pipeline wraps values in double quotes, making ; a literal
    mkdir -p /tmp/lmd-co-test
    echo "clean" > /tmp/lmd-co-test/file.txt
    run maldet -co 'scan_max_filesize=1;echo pwned' -a /tmp/lmd-co-test
    # The semicolon is neutralized by quoting — no command execution
    refute_output --partial "pwned"
    rm -rf /tmp/lmd-co-test
}

@test "-co accepts legitimate variable assignment" {
    mkdir -p /tmp/lmd-co-test
    echo "clean" > /tmp/lmd-co-test/file.txt
    run maldet -co scan_max_filesize=1 -a /tmp/lmd-co-test
    assert_success
    rm -rf /tmp/lmd-co-test
}

# F-001: import_conf safe config sourcing
# Helper: source LMD config stack (internals.conf has command -v calls
# that return non-zero for missing binaries, and functions uses unset
# variables, so disable errexit and nounset for the caller's scope)
_source_lmd_stack() {
    set +eu
    trap - ERR  # bash 5.1: BATS ERR trap leaks into sourced files even with set +e
    source "$LMD_INSTALL/internals/internals.conf"
    source "$LMD_INSTALL/conf.maldet"
    source "$LMD_INSTALL/internals/lmd.lib.sh"
}

@test "import_conf rejects command substitution in remote config" {
    local sessdir="$LMD_INSTALL/sess"
    echo 'email_alert=$(id>/tmp/pwned)' > "$sessdir/.import_conf.cache"
    echo "999999999" > "$sessdir/.import_conf.utime"
    lmd_set_config import_config_url "http://127.0.0.1/fake"
    _source_lmd_stack
    import_conf
    # The command substitution should NOT have executed
    [ ! -f /tmp/pwned ]
    # The variable should NOT have been set to the malicious value
    [ "$email_alert" != '$(id>/tmp/pwned)' ]
}

@test "import_conf accepts safe variable assignments" {
    local sessdir="$LMD_INSTALL/sess"
    echo 'email_alert=1' > "$sessdir/.import_conf.cache"
    echo 'scan_max_filesize=768k' >> "$sessdir/.import_conf.cache"
    echo "999999999" > "$sessdir/.import_conf.utime"
    lmd_set_config import_config_url "http://127.0.0.1/fake"
    _source_lmd_stack
    import_conf
    [ "$email_alert" = "1" ]
    [ "$scan_max_filesize" = "768k" ]
}

@test "_safe_source_conf skips comments and blank lines" {
    local tmpfile
    tmpfile=$(mktemp)
    printf '# comment\n\nemail_alert=1\n' > "$tmpfile"
    _source_lmd_stack
    _safe_source_conf "$tmpfile"
    [ "$email_alert" = "1" ]
    rm -f "$tmpfile"
}

# F-004: _safe_source_conf blocks dangerous environment variable overrides
@test "_safe_source_conf rejects PATH override from remote config" {
    local tmpfile
    tmpfile=$(mktemp)
    local orig_path="$PATH"
    printf 'PATH=/attacker/bin\nemail_alert=1\n' > "$tmpfile"
    _source_lmd_stack
    _safe_source_conf "$tmpfile"
    # PATH must NOT be overwritten
    [ "$PATH" = "$orig_path" ]
    # Normal variable must still work
    [ "$email_alert" = "1" ]
    rm -f "$tmpfile"
}

@test "_safe_source_conf rejects LD_PRELOAD override from remote config" {
    local tmpfile
    tmpfile=$(mktemp)
    printf 'LD_PRELOAD=/evil.so\nscan_max_filesize=768k\n' > "$tmpfile"
    _source_lmd_stack
    _safe_source_conf "$tmpfile"
    # LD_PRELOAD must NOT be set
    [ -z "$LD_PRELOAD" ]
    # Normal variable must still work
    [ "$scan_max_filesize" = "768k" ]
    rm -f "$tmpfile"
}

@test "_safe_source_conf rejects BASH_ENV and IFS overrides" {
    local tmpfile
    tmpfile=$(mktemp)
    local orig_ifs="$IFS"
    printf 'BASH_ENV=/evil.sh\nIFS=x\nemail_alert=1\n' > "$tmpfile"
    _source_lmd_stack
    _safe_source_conf "$tmpfile"
    # BASH_ENV must NOT be set
    [ -z "$BASH_ENV" ]
    # IFS must NOT be changed
    [ "$IFS" = "$orig_ifs" ]
    # Normal variable must still work
    [ "$email_alert" = "1" ]
    rm -f "$tmpfile"
}

# F-033: restore path traversal validation
@test "restore rejects path with .. traversal in .info" {
    lmd_set_config quarantine_hits 1
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    local scanid
    scanid=$(get_last_scanid)
    # Find the .info file and inject a traversal path
    local info_file
    info_file=$(ls "$LMD_INSTALL/quarantine/"*.info 2>/dev/null | head -1)
    [ -n "$info_file" ]
    # Replace the path (field 9) with a traversal path
    local original
    original=$(grep -E -v '^\#' "$info_file")
    local prefix
    prefix=$(echo "$original" | cut -d: -f1-8)
    echo "# owner:group:mode:size(b):md5:atime(epoch):mtime(epoch):ctime(epoch):file(path)" > "$info_file"
    echo "${prefix}:/tmp/../tmp/lmd-traversal-test" >> "$info_file"
    local qfile
    qfile=$(basename "${info_file%.info}")
    run maldet -s "$qfile"
    # The traversal path should NOT have been created
    [ ! -f "/tmp/lmd-traversal-test" ]
}

# F-052: chown uses POSIX ':' separator (not deprecated '.')
@test "functions uses POSIX chown user:group separator not deprecated dot" {
    local func_file="$LMD_INSTALL/internals/lmd.lib.sh"
    # grep for chown with '.' separator — should find zero matches
    # Pattern: chown followed by word.word (not :)
    # Exclude lines with $quardir/$file_name.$rnd (that dot is filename, not separator)
    run bash -c "grep -n 'chown.*[a-z}]\.[a-z}]' \"$func_file\" | grep -v 'file_name\.\$rnd' | grep -v '^\s*#'"
    # No matches means the deprecated separator is gone
    assert_failure
}

# F-046: sed uses -E not -r
@test "functions uses sed -E not deprecated sed -r" {
    local func_file="$LMD_INSTALL/internals/lmd.lib.sh"
    run grep -n 'sed -r' "$func_file"
    assert_failure
}

# S-002: F-007 combined scenario — -co override survives import_config_url re-source
# Without the _lmd_cli_co_applied guard, import_conf re-sources base config
# (internals.conf + conf.maldet), resetting ALL variables to defaults before
# applying the remote config cache. This destroys any -co overrides for variables
# NOT mentioned in the remote config. The guard skips base re-source when -co
# was used, so -co values survive for variables the remote config does not set.
@test "import_conf preserves -co override when import_config_url cache exists" {
    _source_lmd_stack
    local sessdir="$LMD_INSTALL/sess"
    # Remote config cache sets email_alert=1 but does NOT mention scan_cpunice
    echo 'email_alert=1' > "$sessdir/.import_conf.cache"
    echo "999999999" > "$sessdir/.import_conf.utime"
    # Set import_config_url so import_conf processes the cache
    import_config_url="http://127.0.0.1/fake"
    # Simulate -co override: user set scan_cpunice=10 via CLI
    _lmd_cli_co_applied=1
    scan_cpunice=10
    # Call import_conf — with guard, base config is NOT re-sourced,
    # so scan_cpunice stays 10. Without guard, base re-source would
    # reset scan_cpunice to conf.maldet default (19).
    import_conf
    [ "$scan_cpunice" = "10" ]
}

@test "restore succeeds with valid .info path" {
    lmd_set_config quarantine_hits 1
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/test-restore-valid.txt"
    run maldet -a "$TEST_SCAN_DIR"
    local qfile
    qfile=$(ls "$LMD_INSTALL/quarantine/" 2>/dev/null | grep -v '\.info$' | head -1)
    [ -n "$qfile" ]
    run maldet -s "$qfile"
    # File should be restored (normal behavior still works)
    assert_output --partial "restored"
}

# PR-006: _safe_source_conf rejects arbitrary unknown variables
@test "_safe_source_conf rejects unknown variable while accepting known" {
    local tmpfile
    tmpfile=$(mktemp)
    printf 'MY_UNKNOWN_VAR=pwned\nemail_alert=1\n' > "$tmpfile"
    _source_lmd_stack
    unset MY_UNKNOWN_VAR 2>/dev/null || true
    _safe_source_conf "$tmpfile"
    # Unknown variable must NOT be set
    [ -z "${MY_UNKNOWN_VAR:-}" ]
    # Known variable must be applied
    [ "$email_alert" = "1" ]
    rm -f "$tmpfile"
}

# PR-004: -co handler rejects non-conf.maldet variable via allowlist
@test "-co rejects non-allowlisted variable name" {
    mkdir -p /tmp/lmd-co-test
    echo "clean" > /tmp/lmd-co-test/file.txt
    local log="$LMD_INSTALL/logs/event_log"
    run maldet -co MY_EVIL_VAR=test -e list
    # _safe_source_conf rejects the unknown variable; warning goes to event_log
    run grep "rejected unknown variable" "$log"
    assert_success
    rm -rf /tmp/lmd-co-test
}

@test "hash scanner detects malware in file with backslash in name" {
    local tdir malfile hash
    tdir=$(mktemp -d)
    # Create file with backslash in name (32+ bytes to pass scan_min_filesize)
    malfile="${tdir}/evil\\hack.php"
    printf '%032d' 0 > "$malfile"
    # md5sum on escaped filenames outputs \HASH  path — strip leading \ with sed
    hash=$(md5sum "$malfile" | awk '{print $1}' | sed 's/^\\//')
    echo "${hash}:32:{MD5}test.backslash.plan.1" >> "$LMD_INSTALL/sigs/custom.md5.dat"
    run maldet -co "scan_hashtype=md5" -co "scan_min_filesize=30" -a "$tdir"
    # exit 2 = malware found
    [ "$status" -eq 2 ]
    # Verify signame in session hits file (not stdout — scan reports summary only)
    local scanid hitsfile
    scanid=$(get_last_scanid)
    hitsfile=$(get_session_hits_file "$scanid")
    [ -n "$hitsfile" ]
    run grep "test.backslash.plan.1" "$hitsfile"
    assert_success
    sed -i "/test.backslash.plan.1/d" "$LMD_INSTALL/sigs/custom.md5.dat"
    rm -rf "$tdir"
}
