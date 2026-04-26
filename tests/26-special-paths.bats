#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-special"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"

    # Force MD5 mode — eicar.com is only in MD5 sigs; SHA-NI auto-selects sha256
    lmd_set_config scan_hashtype md5

    # Install test HEX signature for eval(base64_decode(
    echo "6576616c286261736536345f6465636f646528:test.hex.php.1" > "$LMD_INSTALL/sigs/custom.hex.dat"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

# ── Category 1: Scan detection with special-char names ──────────────────

@test "scan detects malware in directory with spaces" {
    mkdir -p "$TEST_SCAN_DIR/sub dir"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/sub dir/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "scan detects malware in file with spaces in name" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/my malware.php"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "scan detects malware in file with parentheses" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/file (copy).php"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "scan detects malware in file with brackets" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/backup[1].php"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "scan detects malware in file with single quotes" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/user's file.php"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "scan handles multiple special-char files in batch" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/my file.php"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/file (2).php"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/backup[3].php"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 3"
}

# ── Category 2: Quarantine and restore with special-char paths ──────────

@test "quarantine file from directory with spaces" {
    mkdir -p "$TEST_SCAN_DIR/sub dir"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/sub dir/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -q "$scanid"
    assert_success
    [ ! -f "$TEST_SCAN_DIR/sub dir/eicar.com" ]
}

@test "quarantine file with parentheses in name" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/file (copy).php"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -q "$scanid"
    assert_success
    [ ! -f "$TEST_SCAN_DIR/file (copy).php" ]
}

@test "restore file to directory with spaces" {
    mkdir -p "$TEST_SCAN_DIR/sub dir"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/sub dir/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    maldet -q "$scanid"
    [ ! -f "$TEST_SCAN_DIR/sub dir/eicar.com" ]
    run maldet -s "$scanid"
    assert_success
    [ -f "$TEST_SCAN_DIR/sub dir/eicar.com" ]
}

@test "quarantine hist preserves full path with spaces" {
    mkdir -p "$TEST_SCAN_DIR/sub dir"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/sub dir/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    maldet -q "$scanid"
    run grep "sub dir/eicar.com" "$LMD_INSTALL/sess/quarantine.hist"
    assert_success
}

@test "batch quarantine handles mixed special-char filenames" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/my file.php"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/file (2).php"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -q "$scanid"
    assert_success
    [ ! -f "$TEST_SCAN_DIR/my file.php" ]
    [ ! -f "$TEST_SCAN_DIR/file (2).php" ]
}

# ── Category 3: Glob/wildcard path expansion ────────────────────────────

@test "single ? expands to single-char directories" {
    mkdir -p "$TEST_SCAN_DIR/a/pub" "$TEST_SCAN_DIR/b/pub"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/a/pub/"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/b/pub/"
    run maldet -a "$TEST_SCAN_DIR/?/pub/"
    assert_scan_completed
    assert_output --partial "malware hits 2"
}

@test "nested ? patterns expand for panel-style paths" {
    mkdir -p "$TEST_SCAN_DIR/home1/u1/domains/s1/public_html"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/home1/u1/domains/s1/public_html/"
    run maldet -a "$TEST_SCAN_DIR/home?/??/domains/??/public_html/"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "comma-separated paths scan multiple directories" {
    mkdir -p "$TEST_SCAN_DIR/dir1" "$TEST_SCAN_DIR/dir2"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/dir1/"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/dir2/"
    run maldet -a "$TEST_SCAN_DIR/dir1/,$TEST_SCAN_DIR/dir2/"
    assert_scan_completed
    assert_output --partial "malware hits 2"
}

@test "? pattern with no matches exits 1 (non-existent path)" {
    run maldet -a "$TEST_SCAN_DIR/nonexistent?/"
    # exit 1: all scan paths do not exist (post-G2 fix); no malware (exit 2 absent)
    [ "$status" -eq 1 ]
    assert_output --partial "empty file list"
}

# ── Category 4: HEX scan and ignore with special paths ──────────────────

@test "HEX scan detects match in file within spaced directory" {
    mkdir -p "$TEST_SCAN_DIR/sub dir"
    cp "$SAMPLES_DIR/test-hex-match.php" "$TEST_SCAN_DIR/sub dir/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

@test "string length scan works on file in spaced directory" {
    lmd_set_config string_length_scan 1
    lmd_set_config string_length 500
    mkdir -p "$TEST_SCAN_DIR/sub dir"
    # Create a text file with a long unbroken string
    printf 'AAAA' > "$TEST_SCAN_DIR/sub dir/obfuscated.txt"
    head -c 600 /dev/urandom | base64 | tr -d '\n' >> "$TEST_SCAN_DIR/sub dir/obfuscated.txt"
    > "$LMD_INSTALL/logs/event_log"
    maldet -a "$TEST_SCAN_DIR" || true
    run grep "{strlen}" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "ignore path with spaces excludes files from scan" {
    mkdir -p "$TEST_SCAN_DIR/safe dir" "$TEST_SCAN_DIR/unsafe"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/safe dir/"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/unsafe/"
    echo "$TEST_SCAN_DIR/safe dir" > "$LMD_INSTALL/ignore_paths"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "malware hits 1"
}

# ── Category 5: Regex metacharacters in filenames (F-003) ────────────

@test "quarantine and restore file with regex metacharacters in name" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/file+copy[1].php"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    maldet -q "$scanid"
    [ ! -f "$TEST_SCAN_DIR/file+copy[1].php" ]
    run maldet -s "$scanid"
    assert_success
    [ -f "$TEST_SCAN_DIR/file+copy[1].php" ]
}

@test "quarantine and clean file with regex metacharacters in name" {
    lmd_set_config quarantine_clean 1
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/data.bak+test[2].php"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -n "$scanid"
    assert_success
}

# ── Category 6: Colon-containing paths (F-002) ──────────────────────

@test "quarantine file with colon in directory name" {
    mkdir -p "$TEST_SCAN_DIR/dir:name"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/dir:name/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    run maldet -q "$scanid"
    assert_success
    [ ! -f "$TEST_SCAN_DIR/dir:name/eicar.com" ]
}

@test "restore file with colon in path" {
    mkdir -p "$TEST_SCAN_DIR/dir:name"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/dir:name/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    maldet -q "$scanid"
    [ ! -f "$TEST_SCAN_DIR/dir:name/eicar.com" ]
    run maldet -s "$scanid"
    assert_success
    [ -f "$TEST_SCAN_DIR/dir:name/eicar.com" ]
}

@test "quarantine.hist records full colon-containing path" {
    mkdir -p "$TEST_SCAN_DIR/dir:name"
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/dir:name/"
    maldet -a "$TEST_SCAN_DIR" || true
    local scanid
    scanid=$(get_last_scanid)
    maldet -q "$scanid"
    run grep "dir:name/eicar.com" "$LMD_INSTALL/sess/quarantine.hist"
    assert_success
}
