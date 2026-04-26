#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"
SAMPLES_DIR="/opt/tests/samples"
TEST_SCAN_DIR="/tmp/lmd-test-resource"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    mkdir -p "$TEST_SCAN_DIR"
}

teardown() {
    rm -rf "$TEST_SCAN_DIR"
}

@test "nice binary exists on system" {
    command -v nice
}

@test "ionice binary exists on system" {
    command -v ionice || skip "ionice not available on this OS"
}

@test "internals.conf discovers nice via command -v" {
    run grep 'nice=.*command -v nice' "$LMD_INSTALL/internals/internals.conf"
    assert_success
}

@test "internals.conf discovers ionice via command -v" {
    run grep 'ionice=.*command -v ionice' "$LMD_INSTALL/internals/internals.conf"
    assert_success
}

@test "scan_cpunice defaults to 19" {
    source "$LMD_INSTALL/conf.maldet"
    [ "$scan_cpunice" = "19" ]
}

@test "scan_ionice defaults to 6" {
    source "$LMD_INSTALL/conf.maldet"
    [ "$scan_ionice" = "6" ]
}

@test "scan reports nice scheduler priorities" {
    cp "$SAMPLES_DIR/clean-file.txt" "$TEST_SCAN_DIR/"
    run maldet -a "$TEST_SCAN_DIR"
    assert_success
    assert_output --partial "nice scheduler priorities"
}

@test "scan_cpulimit=0 means cpulimit disabled" {
    source "$LMD_INSTALL/conf.maldet"
    [ "$scan_cpulimit" = "0" ]
}
