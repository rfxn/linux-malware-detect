#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-scan.bash
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-sigs"

setup() {
    RESET_FULL=1
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "empty custom signature files do not cause errors" {
    > "$LMD_INSTALL/sigs/custom.md5.dat"
    > "$LMD_INSTALL/sigs/custom.hex.dat"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
}

@test "missing custom signature files do not cause errors" {
    rm -f "$LMD_INSTALL/sigs/custom.md5.dat" "$LMD_INSTALL/sigs/custom.hex.dat"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
}

@test "signature version file is not modified by scan" {
    echo "20250101" > "$LMD_INSTALL/sigs/maldet.sigs.ver"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    maldet -a "$TEST_SCAN_DIR"
    run cat "$LMD_INSTALL/sigs/maldet.sigs.ver"
    assert_output "20250101"
}

@test "scan output reports signature counts" {
    cp "$SAMPLES_DIR/eicar.com" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_scan_completed
    assert_output --partial "signatures ready"
}

@test "sha256v2.dat absence is non-fatal (upgrade path)" {
    rm -f "$LMD_INSTALL/sigs/sha256v2.dat"
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
}

@test "signature count output uses deduplicated MD5/SHA format" {
    lmd_set_config scan_clamscan 0
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -co scan_hashtype=both -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "MD5/SHA"
    refute_output --regexp "[0-9]+ MD5 \|.*[0-9]+ SHA256"
}

@test "signature count output uses comma-formatted numbers" {
    lmd_set_config scan_clamscan 0
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --regexp "[0-9]+,[0-9]{3}"
}

@test "YARA(no engine) label when no ClamAV or YARA binary" {
    lmd_set_config scan_clamscan 0
    lmd_set_config scan_yara 0
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "YARA(no engine)"
}

@test "stage list omits yara(cav) when ClamAV disabled" {
    lmd_set_config scan_clamscan 0
    lmd_set_config scan_yara 0
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    refute_output --partial "yara(cav)"
}
