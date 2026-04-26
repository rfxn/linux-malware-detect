#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

LMD_INSTALL="/usr/local/maldetect"

setup_file() {
    source /opt/tests/helpers/reset-lmd.sh
}

@test "--all flag appears in short usage" {
    run maldet
    assert_success
    assert_output --partial "--all"
}

@test "--all flag appears in long usage (--help)" {
    run maldet --help
    assert_success
    assert_output --partial "--all"
}

@test "--all long usage describes -e list context" {
    run maldet --help
    assert_success
    assert_output --partial "list --all"
}


