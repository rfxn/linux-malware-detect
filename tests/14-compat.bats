#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-compat"

setup_file() {
    source /opt/tests/helpers/reset-lmd.sh
}

setup() {
    mkdir -p "$TEST_SCAN_DIR"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

# Helper: source compat.conf safely (it expects conf.maldet vars to exist)
_source_compat() {
    set +u
    source "$LMD_INSTALL/internals/compat.conf"
    set -u
}

@test "all simple 1:1 deprecated vars migrate correctly" {
    # Each entry: "old_var new_var test_value"
    # read -r puts remainder (including spaces) into test_val
    local mappings=(
        "maxdepth scan_max_depth 5"
        "quar_clean quarantine_clean 1"
        "quar_susp quarantine_suspend_user 1"
        "scan_nice scan_cpunice 15"
        "inotify_stime inotify_sleep 30"
        "inotify_webdir inotify_docroot public_html"
        "clamav_scan scan_clamscan 1"
        "suppress_cleanhit email_ignore_clean 1"
        "minfilesize scan_min_filesize 1024"
        "maxfilesize scan_max_filesize 2048000"
        "hexdepth scan_hexdepth 65536"
        "tmpdir_paths scan_tmpdir_paths /tmp /var/tmp"
        "scan_hex_workers scan_workers 3"
        "pubuser_minuid scan_user_access_minuid 500"
        "import_custsigs_md5_url sig_import_md5_url https://example.com/custom-md5.dat"
        "import_custsigs_hex_url sig_import_hex_url https://example.com/custom-hex.dat"
        "import_custsigs_yara_url sig_import_yara_url https://example.com/custom-yara.yar"
        "import_custsigs_sha256_url sig_import_sha256_url https://example.com/custom-sha256.dat"
        "import_custsigs_csig_url sig_import_csig_url https://example.com/custom-csig.dat"
    )
    local entry old_var new_var test_val
    for entry in "${mappings[@]}"; do
        read -r old_var new_var test_val <<< "$entry"
        unset "$new_var" "$old_var" 2>/dev/null || true
        eval "$old_var=\"$test_val\""
        _source_compat
        [ "${!new_var}" = "$test_val" ] || {
            echo "FAIL: $old_var=$test_val did not migrate to $new_var (got: ${!new_var:-<unset>})"
            return 1
        }
    done
}

@test "deprecated hex_fifo_depth migrates to scan_hexdepth via scan_hexfifo" {
    scan_hexfifo=1
    scan_hexfifo_depth=1048576
    _source_compat
    [ "$scan_hexdepth" = "1048576" ]
}

@test "new variable takes priority over deprecated" {
    scan_max_depth=10
    maxdepth=5
    _source_compat
    [ "$scan_max_depth" = "10" ]
}

@test "multiple deprecated vars work together" {
    unset quarantine_clean scan_cpunice
    quar_clean=1
    scan_nice=15
    _source_compat
    [ "$quarantine_clean" = "1" ]
    [ "$scan_cpunice" = "15" ]
}

@test "scan_hex_workers overrides default scan_workers value" {
    scan_workers="0"
    scan_hex_workers=4
    _source_compat
    [ "$scan_workers" = "4" ]
}

@test "compat.conf sourced after conf.maldet in source chain" {
    # After library decomposition, cnf and compatcnf are both sourced from lmd.lib.sh
    local libhub="$LMD_INSTALL/internals/lmd.lib.sh"
    run grep -n 'source.*compatcnf' "$libhub"
    assert_success
    local compat_line
    compat_line=$(echo "$output" | head -1 | cut -d: -f1)
    run grep -n 'source.*cnf' "$libhub"
    assert_success
    local cnf_line
    cnf_line=$(echo "$output" | head -1 | cut -d: -f1)
    [ "$compat_line" -gt "$cnf_line" ]
}

@test "scan_clamscan=1 from old config resolves correctly after upgrade" {
    lmd_set_config scan_clamscan 1
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    refute_output --partial "invalid scan_clamscan"
}
