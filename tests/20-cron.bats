#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/lmd-config.sh
source /opt/tests/helpers/cron-helpers.sh

LMD_INSTALL="/usr/local/maldetect"
CRON_MALDET_LOG="/tmp/cron-maldet.log"

setup() {
    [ -f /etc/cron.daily/maldet ] || skip "no /etc/cron.daily/maldet on this OS"
    source /opt/tests/helpers/reset-lmd.sh
    rm -f "$CRON_MALDET_LOG"

    # Disable autoupdates (default in test config, but be explicit)
    lmd_set_config autoupdate_version 0
    lmd_set_config autoupdate_signatures 0

    # Clean up any mock panel dirs from prior tests
    rm -rf /usr/local/cpanel.mock /etc/psa.mock /var/lib/psa.mock \
           /usr/local/directadmin.mock /opt/webdir.mock /etc/nginx/bx.mock
}

teardown() {
    # Restore real maldet if we replaced it
    if [ -f "$LMD_INSTALL/maldet.real" ]; then
        mv "$LMD_INSTALL/maldet.real" "$LMD_INSTALL/maldet"
    fi
    rm -f "$CRON_MALDET_LOG"
    # Clean up mock panel dirs
    rm -rf /usr/local/cpanel /etc/psa /var/lib/psa \
           /usr/local/directadmin /opt/webdir /etc/nginx/bx \
           /var/www/clients /etc/webmin/virtual-server \
           /usr/local/ispmgr /usr/local/mgr5 \
           /var/customers/webs /usr/local/vesta /usr/local/hestia \
           /usr/share/dtc /home/virtual /usr/lib/opcenter
    rm -f "$LMD_INSTALL/tmp/.cron.lock"
    # Clean up custom cron config test artifacts (R-14)
    rm -f /tmp/cron-custom-marker
    rm -rf "$LMD_INSTALL/cron"
}

@test "cron prunes quarantine files older than cron_prune_days" {
    lmd_set_config cron_prune_days 21
    lmd_set_config cron_daily_scan 0
    # Create an old file in quarantine
    touch -d '30 days ago' "$LMD_INSTALL/quarantine/old-quar-file"
    [ -f "$LMD_INSTALL/quarantine/old-quar-file" ]
    bash /etc/cron.daily/maldet
    [ ! -f "$LMD_INSTALL/quarantine/old-quar-file" ]
}

@test "cron prunes session files older than cron_prune_days" {
    lmd_set_config cron_prune_days 21
    lmd_set_config cron_daily_scan 0
    touch -d '30 days ago' "$LMD_INSTALL/sess/old-session-file"
    [ -f "$LMD_INSTALL/sess/old-session-file" ]
    bash /etc/cron.daily/maldet
    [ ! -f "$LMD_INSTALL/sess/old-session-file" ]
}

@test "cron prunes temp files older than cron_prune_days" {
    lmd_set_config cron_prune_days 21
    lmd_set_config cron_daily_scan 0
    touch -d '30 days ago' "$LMD_INSTALL/tmp/old-tmp-file"
    [ -f "$LMD_INSTALL/tmp/old-tmp-file" ]
    bash /etc/cron.daily/maldet
    [ ! -f "$LMD_INSTALL/tmp/old-tmp-file" ]
}

@test "cron preserves files within cron_prune_days threshold" {
    lmd_set_config cron_prune_days 21
    lmd_set_config cron_daily_scan 0
    touch -d '10 days ago' "$LMD_INSTALL/quarantine/recent-quar-file"
    bash /etc/cron.daily/maldet
    [ -f "$LMD_INSTALL/quarantine/recent-quar-file" ]
}

@test "cron detects cPanel by /usr/local/cpanel directory" {
    mkdir -p /usr/local/cpanel
    install_mock_maldet
    lmd_set_config cron_daily_scan 1
    run bash /etc/cron.daily/maldet
    assert_success
    # Default/cPanel path includes /home?/?/public_html/
    run grep "public_html" "$CRON_MALDET_LOG"
    assert_success
}

@test "cron detects Plesk by /etc/psa directory" {
    mkdir -p /etc/psa /var/lib/psa
    install_mock_maldet
    lmd_set_config cron_daily_scan 1
    run bash /etc/cron.daily/maldet
    assert_success
    run grep "vhosts" "$CRON_MALDET_LOG"
    assert_success
}

@test "cron detects DirectAdmin" {
    mkdir -p /usr/local/directadmin
    install_mock_maldet
    lmd_set_config cron_daily_scan 1
    run bash /etc/cron.daily/maldet
    assert_success
    run grep "domains" "$CRON_MALDET_LOG"
    assert_success
}

@test "cron detects Bitrix by /opt/webdir and /etc/nginx/bx" {
    mkdir -p /opt/webdir /etc/nginx/bx
    install_mock_maldet
    lmd_set_config cron_daily_scan 1
    run bash /etc/cron.daily/maldet
    assert_success
    run grep "bitrix" "$CRON_MALDET_LOG"
    assert_success
}

@test "cron falls back to default paths when no panel detected" {
    # Ensure no panel dirs exist
    install_mock_maldet
    lmd_set_config cron_daily_scan 1
    run bash /etc/cron.daily/maldet
    assert_success
    # Default path includes /home?/?/public_html/
    run grep "public_html" "$CRON_MALDET_LOG"
    assert_success
}

@test "cron skips scan when cron_daily_scan=0" {
    install_mock_maldet
    lmd_set_config cron_daily_scan 0
    run bash /etc/cron.daily/maldet
    assert_success
    # No scan calls should appear (--maintenance is housekeeping, always runs)
    if [ -f "$CRON_MALDET_LOG" ]; then
        run grep -c -- ' -b ' "$CRON_MALDET_LOG"
        [ "$output" = "0" ]
    fi
}

@test "cron lockfile prevents overlapping runs" {
    lmd_set_config cron_daily_scan 0
    # Hold the lock in background
    exec 8>"$LMD_INSTALL/tmp/.cron.lock"
    flock -n 8
    # Second cron run should exit immediately
    run bash /etc/cron.daily/maldet
    assert_success
    # Release lock
    exec 8>&-
}

@test "cron lock uses CLOEXEC command form (no fd leak)" {
    # Verify cron.daily uses flock command form (_CRON_FLOCK guard)
    run grep '_CRON_FLOCK' /etc/cron.daily/maldet
    assert_success
    # Verify no exec 9> fd-based locking (old pattern that leaked to children)
    run grep 'exec 9>' /etc/cron.daily/maldet
    assert_failure
}

# Helper: install mock maldet that logs args and exits with failure
install_failing_mock_maldet() {
    cp "$LMD_INSTALL/maldet" "$LMD_INSTALL/maldet.real"
    cat > "$LMD_INSTALL/maldet" <<'MOCK'
#!/usr/bin/env bash
echo "MALDET_CALL: $@" >> /tmp/cron-maldet.log
exit 1
MOCK
    chmod 755 "$LMD_INSTALL/maldet"
}

@test "cron logs failure when version update fails" {
    lmd_set_config autoupdate_version 1
    lmd_set_config cron_daily_scan 0
    install_failing_mock_maldet
    run_cron_daily
    run grep "version update) failed" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "cron logs failure when signature update fails" {
    lmd_set_config autoupdate_signatures 1
    lmd_set_config cron_daily_scan 0
    install_failing_mock_maldet
    run_cron_daily
    run grep "signature update) failed" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "cron sources custom config file" {
    lmd_set_config cron_daily_scan 0
    mkdir -p "$LMD_INSTALL/cron"
    echo 'TEST_CRON_SOURCED=1' > "$LMD_INSTALL/cron/conf.maldet.cron"
    cat > "$LMD_INSTALL/cron/custom.cron" <<'EOF'
if [ "$TEST_CRON_SOURCED" = "1" ]; then
    touch /tmp/cron-custom-marker
fi
EOF
    run bash /etc/cron.daily/maldet
    assert_success
    [ -f /tmp/cron-custom-marker ]
}
