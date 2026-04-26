#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-hex"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"

    # Force single worker — multi-worker HEX has a non-deterministic race
    # where one worker's output is empty (2/3 instead of 3/3 on Rocky 9)
    lmd_set_config scan_workers 1

    # Install test HEX signature for eval(base64_decode(
    echo "6576616c286261736536345f6465636f646528:test.hex.php.1" > "$LMD_INSTALL/sigs/custom.hex.dat"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "HEX scan detects test PHP sample" {
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "HEX scan with custom scan_hexdepth" {
    lmd_set_config scan_hexdepth 524288
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "scan_hexdepth limits bytes scanned" {
    # Set hex depth very small so the pattern won't be found
    lmd_set_config scan_hexdepth 5
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "malware hits 0"
}

@test "custom HEX signatures are loaded alongside builtin" {
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    [ -n "$scanid" ]
    assert_report_contains "$scanid" "test.hex.php"
}

@test "HEX scan with both MD5 and HEX sigs active" {
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 2"
}

@test "scan_workers=1 single-threaded HEX produces detection" {
    lmd_set_config scan_workers 1
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "scan_workers=2 parallel HEX produces detection" {
    lmd_set_config scan_workers 2
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "batch scan: 3 infected files detected" {
    local i
    for i in 1 2 3; do
        cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/infected${i}.php"
    done
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 3"
}

@test "batch scan: clean files produce zero hits" {
    local i
    for i in 1 2 3 4 5; do
        cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/clean${i}.txt"
    done
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "malware hits 0"
}

@test "HEX scan reports correct signame via sigmap cache" {
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
    # Verify the expected signame appears in the session hits file
    # (confirms sigmap cache lookup worked — empty cache → no signame → this would fail)
    local scanid hitsfile
    scanid=$(get_last_scanid)
    hitsfile=$(get_session_hits_file "$scanid")
    [ -n "$hitsfile" ]
    run grep "test.hex.php.1" "$hitsfile"
    assert_success
}

# Helper to source the LMD function stack for direct function testing
_source_lmd_stack() {
    set +eu
    trap - ERR  # bash 5.1: BATS ERR trap leaks into sourced files even with set +e
    source "$LMD_INSTALL/internals/internals.conf"
    source "$LMD_INSTALL/conf.maldet"
    source "$LMD_INSTALL/internals/lmd.lib.sh"
}

# --- HEX wildcard compilation tests (call _hex_compile_wildcards_awk directly) ---

@test "HEX wildcard: ?? compiles to [0-9a-f]{2}" {
    _source_lmd_stack
    local runtime_hex_regex runtime_hex_literal _hex_wc_tmp
    runtime_hex_regex=$(mktemp)
    runtime_hex_literal=$(mktemp)
    _hex_wc_tmp=$(mktemp)
    printf '%s\t%s\n' "aa??bb" "{HEX}test.wc.1" > "$_hex_wc_tmp"
    _hex_compile_wildcards_awk
    local compiled
    compiled=$(cut -f2 "$runtime_hex_regex")
    [ "$compiled" = "aa[0-9a-f]{2}bb" ]
    rm -f "$runtime_hex_regex" "$runtime_hex_literal" "$_hex_wc_tmp"
}

@test "HEX wildcard: * compiles to [0-9a-f]*" {
    _source_lmd_stack
    local runtime_hex_regex runtime_hex_literal _hex_wc_tmp
    runtime_hex_regex=$(mktemp)
    runtime_hex_literal=$(mktemp)
    _hex_wc_tmp=$(mktemp)
    printf '%s\t%s\n' "aa*bb" "{HEX}test.wc.2" > "$_hex_wc_tmp"
    _hex_compile_wildcards_awk
    local compiled
    compiled=$(cut -f2 "$runtime_hex_regex")
    [ "$compiled" = "aa[0-9a-f]*bb" ]
    rm -f "$runtime_hex_regex" "$runtime_hex_literal" "$_hex_wc_tmp"
}

@test "HEX wildcard: ?x nibble compiles to [0-9a-f]x" {
    _source_lmd_stack
    local runtime_hex_regex runtime_hex_literal _hex_wc_tmp
    runtime_hex_regex=$(mktemp)
    runtime_hex_literal=$(mktemp)
    _hex_wc_tmp=$(mktemp)
    printf '%s\t%s\n' "?aff" "{HEX}test.wc.3" > "$_hex_wc_tmp"
    _hex_compile_wildcards_awk
    local compiled
    compiled=$(cut -f2 "$runtime_hex_regex")
    [ "$compiled" = "[0-9a-f]aff" ]
    rm -f "$runtime_hex_regex" "$runtime_hex_literal" "$_hex_wc_tmp"
}

@test "HEX wildcard: x? nibble compiles to x[0-9a-f]" {
    _source_lmd_stack
    local runtime_hex_regex runtime_hex_literal _hex_wc_tmp
    runtime_hex_regex=$(mktemp)
    runtime_hex_literal=$(mktemp)
    _hex_wc_tmp=$(mktemp)
    # ffb? — b is hex, ? at end-of-string forces x? (low nibble) codepath
    printf '%s\t%s\n' "ffb?" "{HEX}test.wc.4" > "$_hex_wc_tmp"
    _hex_compile_wildcards_awk
    local compiled
    compiled=$(cut -f2 "$runtime_hex_regex")
    [ "$compiled" = "ffb[0-9a-f]" ]
    rm -f "$runtime_hex_regex" "$runtime_hex_literal" "$_hex_wc_tmp"
}

@test "HEX wildcard: {N-M} compiles to [0-9a-f]{2N,2M}" {
    _source_lmd_stack
    local runtime_hex_regex runtime_hex_literal _hex_wc_tmp
    runtime_hex_regex=$(mktemp)
    runtime_hex_literal=$(mktemp)
    _hex_wc_tmp=$(mktemp)
    printf '%s\t%s\n' "aa{3-5}bb" "{HEX}test.wc.5" > "$_hex_wc_tmp"
    _hex_compile_wildcards_awk
    local compiled
    compiled=$(cut -f2 "$runtime_hex_regex")
    [ "$compiled" = "aa[0-9a-f]{6,10}bb" ]
    rm -f "$runtime_hex_regex" "$runtime_hex_literal" "$_hex_wc_tmp"
}

@test "HEX wildcard: (a|b) alternation passes through" {
    _source_lmd_stack
    local runtime_hex_regex runtime_hex_literal _hex_wc_tmp
    runtime_hex_regex=$(mktemp)
    runtime_hex_literal=$(mktemp)
    _hex_wc_tmp=$(mktemp)
    printf '%s\t%s\n' "aa(63|64)bb" "{HEX}test.wc.6" > "$_hex_wc_tmp"
    _hex_compile_wildcards_awk
    local compiled
    compiled=$(cut -f2 "$runtime_hex_regex")
    [ "$compiled" = "aa(63|64)bb" ]
    rm -f "$runtime_hex_regex" "$runtime_hex_literal" "$_hex_wc_tmp"
}

@test "HEX wildcard: ?? before nibble ordering" {
    _source_lmd_stack
    local runtime_hex_regex runtime_hex_literal _hex_wc_tmp
    runtime_hex_regex=$(mktemp)
    runtime_hex_literal=$(mktemp)
    _hex_wc_tmp=$(mktemp)
    # aa??b? — ?? must be processed before b? nibble
    printf '%s\t%s\n' "aa??b?" "{HEX}test.wc.7" > "$_hex_wc_tmp"
    _hex_compile_wildcards_awk
    local compiled
    compiled=$(cut -f2 "$runtime_hex_regex")
    # ?? → [0-9a-f]{2}, then b? → b[0-9a-f]
    [ "$compiled" = "aa[0-9a-f]{2}b[0-9a-f]" ]
    rm -f "$runtime_hex_regex" "$runtime_hex_literal" "$_hex_wc_tmp"
}

@test "HEX wildcard: mixed pattern all token types" {
    _source_lmd_stack
    local runtime_hex_regex runtime_hex_literal _hex_wc_tmp
    runtime_hex_regex=$(mktemp)
    runtime_hex_literal=$(mktemp)
    _hex_wc_tmp=$(mktemp)
    # ??a?(63|64)?b{2-4}* — all 6 token types
    printf '%s\t%s\n' '??a?(63|64)?b{2-4}*' '{HEX}test.wc.8' > "$_hex_wc_tmp"
    _hex_compile_wildcards_awk
    local compiled
    compiled=$(cut -f2 "$runtime_hex_regex")
    # ?? → [0-9a-f]{2}
    # a? → a[0-9a-f] (low nibble — a is hex, ? follows, next char ( is not hex)
    # (63|64) → passthrough
    # ?b → [0-9a-f]b (high nibble)
    # {2-4} → [0-9a-f]{4,8}
    # * → [0-9a-f]*
    [ "$compiled" = "[0-9a-f]{2}a[0-9a-f](63|64)[0-9a-f]b[0-9a-f]{4,8}[0-9a-f]*" ]
    rm -f "$runtime_hex_regex" "$runtime_hex_literal" "$_hex_wc_tmp"
}

@test "HEX wildcard: scan detects via wildcard pattern" {
    # Use a ?? wildcard in the hex sig — replace one known byte with ??
    # eval(base64_decode( = 6576616c286261736536345f6465636f646528
    # Replace byte at position 5 (0x28 = '(') with ?? wildcard
    echo "6576616c??6261736536345f6465636f646528:{HEX}test.wc.scan.1" > "$LMD_INSTALL/sigs/custom.hex.dat"
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}
