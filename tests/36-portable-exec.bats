#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

LMD_INSTALL="/usr/local/maldetect"

# --- Source-tree auto-detect ---

@test "portable: internals.conf uses conditional inspath assignment" {
    grep -q 'inspath="\${inspath:-/usr/local/maldetect}"' "$LMD_INSTALL/internals/internals.conf"
}

@test "portable: maldet resolves inspath from own directory" {
    # When invoked via absolute path, auto-detect finds internals/ beside the script
    run bash -c '_self=$(readlink -f "'"$LMD_INSTALL/maldet"'" 2>/dev/null); _selfdir="${_self%/*}"; [ -f "$_selfdir/internals/internals.conf" ] && echo "found" || echo "missing"'
    assert_output "found"
}

@test "portable: default inspath resolves to /usr/local/maldetect" {
    run maldet --version
    assert_success
    assert_output --partial "Linux Malware Detect"
}

# --- LMD_BASEDIR env override ---

@test "portable: LMD_BASEDIR overrides inspath" {
    run env LMD_BASEDIR="$LMD_INSTALL" maldet --version
    assert_success
    assert_output --partial "Linux Malware Detect"
}

@test "portable: LMD_BASEDIR with invalid path fails gracefully" {
    run env LMD_BASEDIR="/nonexistent" maldet --version
    assert_failure
    assert_output --partial "intcnf not found"
}

@test "portable: LMD_BASEDIR is unset after consumption" {
    # LMD_BASEDIR should not leak to child processes
    grep -q 'unset LMD_BASEDIR' "$LMD_INSTALL/maldet"
}

# --- Symlink resolution ---

@test "portable: symlink to maldet resolves to real path" {
    local _tmplink
    _tmplink=$(mktemp -u /tmp/maldet-symlink-XXXXXX)
    ln -s "$LMD_INSTALL/maldet" "$_tmplink"
    run "$_tmplink" --version
    rm -f "$_tmplink"
    assert_success
    assert_output --partial "Linux Malware Detect"
}

# --- Regression: installed path unaffected ---

@test "portable: installed maldet still uses /usr/local/maldetect paths" {
    # Verify that session dir resolves under the install path
    run bash -c 'source '"$LMD_INSTALL"'/internals/internals.conf; echo "$sessdir"'
    assert_output "/usr/local/maldetect/sess"
}

@test "portable: internals.conf preserves pre-set inspath" {
    run bash -c 'inspath="/custom/path"; source '"$LMD_INSTALL"'/internals/internals.conf; echo "$inspath"'
    assert_output "/custom/path"
}

@test "portable: internals.conf defaults when inspath is unset" {
    run bash -c 'unset inspath; source '"$LMD_INSTALL"'/internals/internals.conf; echo "$inspath"'
    assert_output "/usr/local/maldetect"
}
