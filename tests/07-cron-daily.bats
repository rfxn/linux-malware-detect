#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

LMD_INSTALL="/usr/local/maldetect"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
}

@test "cron.daily script exists" {
    [ -d /etc/cron.daily ] || skip "no /etc/cron.daily on this OS"
    [ -f /etc/cron.daily/maldet ]
}

@test "cron.daily script is executable" {
    [ -d /etc/cron.daily ] || skip "no /etc/cron.daily on this OS"
    [ -x /etc/cron.daily/maldet ]
}

@test "cron.daily syntax check passes" {
    [ -d /etc/cron.daily ] || skip "no /etc/cron.daily on this OS"
    run bash -n /etc/cron.daily/maldet
    assert_success
}

@test "maldet script syntax check passes" {
    run bash -n "$LMD_INSTALL/maldet"
    assert_success
}

@test "lmd.lib.sh syntax check passes" {
    run bash -n "$LMD_INSTALL/internals/lmd.lib.sh"
    assert_success
}

@test "internals.conf syntax check passes" {
    run bash -n "$LMD_INSTALL/internals/internals.conf"
    assert_success
}

@test "maldet.sh init script syntax check passes" {
    run bash -n "$LMD_INSTALL/service/maldet.sh"
    assert_success
}

@test "hookscan.sh syntax check passes" {
    run bash -n "$LMD_INSTALL/hookscan.sh"
    assert_success
}

@test "compat.conf syntax check passes" {
    run bash -n "$LMD_INSTALL/internals/compat.conf"
    assert_success
}

@test "tlog_lib.sh syntax check passes" {
    run bash -n "$LMD_INSTALL/internals/tlog_lib.sh"
    assert_success
}

@test "cron.watchdog syntax check passes" {
    [ -f /etc/cron.weekly/maldet-watchdog ] || skip "cron.watchdog not installed"
    run bash -n /etc/cron.weekly/maldet-watchdog
    assert_success
}

@test "uninstall.sh syntax check passes" {
    run bash -n "$LMD_INSTALL/uninstall.sh"
    assert_success
}
