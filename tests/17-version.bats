#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

LMD_INSTALL="/usr/local/maldetect"

setup_file() {
    source /opt/tests/helpers/reset-lmd.sh
}

@test "VERSION file contains current version" {
    run cat "$LMD_INSTALL/VERSION"
    assert_output --partial "2.0.1"
}

@test "maldet reports correct version" {
    run maldet --help
    assert_success
    assert_output --partial "v2.0.1"
}

