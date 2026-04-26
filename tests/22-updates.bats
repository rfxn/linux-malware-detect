#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/lmd-config.sh
source /opt/tests/helpers/cron-helpers.sh

LMD_INSTALL="/usr/local/maldetect"
CRON_MALDET_LOG="/tmp/cron-maldet.log"

setup() {
    RESET_FULL=1
    source /opt/tests/helpers/reset-lmd.sh
    source /opt/tests/helpers/mock-update-server.sh
    setup_mock_update_server
    rm -f "$CRON_MALDET_LOG"
    rm -f /tmp/lmd-mock-install-ran

    # Save original PATH for later restoration
    export ORIG_PATH_BACKUP="$PATH"
}

teardown() {
    # Restore real maldet if we replaced it
    if [ -f "$LMD_INSTALL/maldet.real" ]; then
        mv "$LMD_INSTALL/maldet.real" "$LMD_INSTALL/maldet"
    fi
    # Restore curl if hidden by wget fallback test (R-10 safety net)
    if [ -f /usr/bin/curl.hidden ]; then
        mv /usr/bin/curl.hidden /usr/bin/curl
    fi
    rm -f "$CRON_MALDET_LOG"
    rm -f /tmp/lmd-mock-install-ran
    rm -f "$LMD_INSTALL/tmp/.cron.lock"
    source /opt/tests/helpers/mock-update-server.sh
    cleanup_mock_update_server
    export PATH="$ORIG_PATH_BACKUP"
}


# ============================================================
# get_remote_file() tests
# ============================================================

@test "get_remote_file downloads file via curl" {
    set_fixture "testfile.dat" "hello from fixture"

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        web_proxy=""
        get_proxy_arg=""
        get_remote_file "https://cdn.rfxn.com/downloads/testfile.dat" "test" "1" ""
        [ -n "$return_file" ] && [ -f "$return_file" ] && cat "$return_file"
    '
    assert_success
    assert_output --partial "hello from fixture"
}

@test "get_remote_file sets return_file empty on download failure" {
    # No fixture set — mock curl will create an empty file

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        web_proxy=""
        get_proxy_arg=""
        get_remote_file "https://cdn.rfxn.com/downloads/nonexistent.dat" "test" "1" ""
        if [ -z "$return_file" ]; then echo "RETURN_FILE_EMPTY"; fi
    '
    assert_success
    assert_output --partial "RETURN_FILE_EMPTY"
    run grep "could not download" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "get_remote_file falls back to wget when curl absent" {
    set_fixture "testfile.dat" "wget served this"

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        # Remove mock curl so wget is used
        rm -f /tmp/lmd-mock-update/bin/curl
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        # Force curl to empty so get_remote_file uses wget
        curl=""
        # Temporarily hide real curl
        if [ -f /usr/bin/curl ]; then mv /usr/bin/curl /usr/bin/curl.hidden; fi
        web_proxy=""
        get_proxy_arg=""
        get_remote_file "https://cdn.rfxn.com/downloads/testfile.dat" "test" "1" ""
        rc=$?
        if [ -f /usr/bin/curl.hidden ]; then mv /usr/bin/curl.hidden /usr/bin/curl; fi
        [ -n "$return_file" ] && cat "$return_file"
        exit $rc
    '
    assert_success
    assert_output --partial "wget served this"
    # Verify wget was used
    run grep "WGET:" /tmp/mock-curl-update.log
    assert_success
}


# ============================================================
# sigup() tests
# ============================================================

@test "sigup detects new signature version and downloads" {
    # Set current installed version
    echo "2024010100000" > "$LMD_INSTALL/sigs/maldet.sigs.ver"

    # Create mock sigpack with newer version
    create_mock_sigpack "2025010100000"
    create_mock_cleanpack

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        import_config_url=""
        sig_import_md5_url=""
        sig_import_hex_url=""
        web_proxy=""
        get_proxy_arg=""
        echo "2024010100000" > "'"$LMD_INSTALL"'/sigs/maldet.sigs.ver"
        sig_version="2024010100000"
        sigup
    '
    assert_success
    # Check that event_log records the update
    run grep "new signature set" "$LMD_INSTALL/logs/event_log"
    assert_success
    run grep "signature set update completed" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "sigup skips update when version matches" {
    # Create matching sigpack version
    create_mock_sigpack "2024010100000"
    create_mock_cleanpack

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        import_config_url=""
        sig_import_md5_url=""
        sig_import_hex_url=""
        web_proxy=""
        get_proxy_arg=""
        echo "2024010100000" > "'"$LMD_INSTALL"'/sigs/maldet.sigs.ver"
        sig_version="2024010100000"
        sigup
    '
    assert_success
    run grep "latest signature set already installed" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "sigup rejects sigpack with bad hash" {
    create_mock_sigpack "2025010100000"
    create_mock_cleanpack
    # Corrupt the sha256 sidecar
    echo "0000000000000000000000000000000000000000000000000000000000bad000" > "$MOCK_FIXTURES/maldet-sigpack.tgz.sha256"

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        import_config_url=""
        sig_import_md5_url=""
        sig_import_hex_url=""
        web_proxy=""
        get_proxy_arg=""
        echo "2024010100000" > "'"$LMD_INSTALL"'/sigs/maldet.sigs.ver"
        sig_version="2024010100000"
        sigup
    '
    assert_failure
    run grep "unable to verify sha256sum" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "sigup forces update when signature files are missing" {
    create_mock_sigpack "2024010100000"
    create_mock_cleanpack

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        import_config_url=""
        sig_import_md5_url=""
        sig_import_hex_url=""
        web_proxy=""
        get_proxy_arg=""
        # Set matching version — normally would skip
        echo "2024010100000" > "'"$LMD_INSTALL"'/sigs/maldet.sigs.ver"
        sig_version="2024010100000"
        # But delete sig files to force update
        rm -f "'"$LMD_INSTALL"'/sigs/md5v2.dat"
        sigup
    '
    assert_success
    run grep "signature files missing" "$LMD_INSTALL/logs/event_log"
    assert_success
    run grep "signature set update completed" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "sigup forces update when signature files are undersized" {
    create_mock_sigpack "2024010100000"
    create_mock_cleanpack

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        import_config_url=""
        sig_import_md5_url=""
        sig_import_hex_url=""
        web_proxy=""
        get_proxy_arg=""
        # Set matching version
        echo "2024010100000" > "'"$LMD_INSTALL"'/sigs/maldet.sigs.ver"
        sig_version="2024010100000"
        # Truncate hex.dat below 1000 lines
        head -100 "'"$LMD_INSTALL"'/sigs/hex.dat" > "'"$LMD_INSTALL"'/sigs/hex.dat.tmp"
        mv "'"$LMD_INSTALL"'/sigs/hex.dat.tmp" "'"$LMD_INSTALL"'/sigs/hex.dat"
        sigup
    '
    assert_success
    run grep "signature files corrupted" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "sigup preserves custom signatures across update" {
    create_mock_sigpack "2025010100000"
    create_mock_cleanpack
    # Add a custom signature before update
    echo "deadbeef12345678:{HEX}custom.test.1" > "$LMD_INSTALL/sigs/custom.hex.dat"

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        import_config_url=""
        sig_import_md5_url=""
        sig_import_hex_url=""
        web_proxy=""
        get_proxy_arg=""
        echo "2024010100000" > "'"$LMD_INSTALL"'/sigs/maldet.sigs.ver"
        sig_version="2024010100000"
        sigup
    '
    assert_success
    # Custom sig file should still exist and contain our signature
    [ -f "$LMD_INSTALL/sigs/custom.hex.dat" ]
    run grep "custom.test.1" "$LMD_INSTALL/sigs/custom.hex.dat"
    assert_success
}


# ============================================================
# lmdup() tests
# ============================================================

@test "lmdup detects newer upstream version" {
    create_mock_tarball "2.0.2"

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        import_config_url=""
        web_proxy=""
        get_proxy_arg=""
        lmd_version="2.0.1"
        lmdup
    '
    # lmdup will try to run install.sh from the tarball
    run grep "new version" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "lmdup skips when already at latest version" {
    # Set upstream version to match installed
    set_fixture "maldet.current.ver" "2.0.1"

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        import_config_url=""
        web_proxy=""
        get_proxy_arg=""
        lmd_version="2.0.1"
        autoupdate_version_hashed="0"
        lmdup
    '
    assert_success
    run grep "latest version already installed" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "lmdup forces update with --force even when version matches" {
    set_fixture "maldet.current.ver" "2.0.1"
    create_mock_tarball "2.0.1"

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        import_config_url=""
        web_proxy=""
        get_proxy_arg=""
        lmd_version="2.0.1"
        autoupdate_version_hashed="0"
        lmdup_force=1
        lmdup
    '
    run grep "version update with --force requested" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "lmdup rejects tarball with bad hash" {
    create_mock_tarball "2.0.2"
    # Corrupt the sha256 sidecar
    echo "0000000000000000000000000000000000000000000000000000000000bad000" > "$MOCK_FIXTURES/maldetect-current.tar.gz.sha256"

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        import_config_url=""
        web_proxy=""
        get_proxy_arg=""
        lmd_version="2.0.1"
        lmdup
    '
    assert_failure
    run grep "unable to verify sha256sum" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "lmdup hash check triggers update when files differ" {
    create_mock_tarball "2.0.1"
    # Set upstream hash that differs from local
    set_fixture "maldet.current.ver" "2.0.1"
    set_fixture "maldet.current.hash.sha256" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccc"

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        import_config_url=""
        web_proxy=""
        get_proxy_arg=""
        lmd_version="2.0.1"
        autoupdate_version_hashed="1"
        lmdup
    '
    run grep "hash check failed, forcing update" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "lmdup hash check passes when files match" {
    set_fixture "maldet.current.ver" "2.0.1"
    # Compute real hash of installed files
    local_hash=$(sha256sum "$LMD_INSTALL/maldet" "$LMD_INSTALL/internals/lmd.lib.sh" | awk '{print$1}' | tr '\n' ' ' | tr -d ' ')
    set_fixture "maldet.current.hash.sha256" "$local_hash"

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        import_config_url=""
        web_proxy=""
        get_proxy_arg=""
        lmd_version="2.0.1"
        autoupdate_version_hashed="1"
        lmdup
    '
    assert_success
    run grep "latest version already installed" "$LMD_INSTALL/logs/event_log"
    assert_success
}


# ============================================================
# Cron update integration tests
# ============================================================

@test "cron calls maldet -d when autoupdate_version=1" {
    [ -f /etc/cron.daily/maldet ] || skip "no /etc/cron.daily/maldet on this OS"
    install_mock_maldet
    lmd_set_config autoupdate_version 1
    lmd_set_config autoupdate_signatures 0
    lmd_set_config cron_daily_scan 0

    run_cron_daily

    [ -f "$CRON_MALDET_LOG" ]
    run grep "MALDET_CALL:.*-d" "$CRON_MALDET_LOG"
    assert_success
}

@test "cron calls maldet -u when autoupdate_signatures=1" {
    [ -f /etc/cron.daily/maldet ] || skip "no /etc/cron.daily/maldet on this OS"
    install_mock_maldet
    lmd_set_config autoupdate_version 0
    lmd_set_config autoupdate_signatures 1
    lmd_set_config cron_daily_scan 0

    run_cron_daily

    [ -f "$CRON_MALDET_LOG" ]
    run grep "MALDET_CALL:.*-u" "$CRON_MALDET_LOG"
    assert_success
}

@test "cron skips updates when autoupdate disabled" {
    [ -f /etc/cron.daily/maldet ] || skip "no /etc/cron.daily/maldet on this OS"
    install_mock_maldet
    lmd_set_config autoupdate_version 0
    lmd_set_config autoupdate_signatures 0
    lmd_set_config cron_daily_scan 0

    run_cron_daily

    if [ -f "$CRON_MALDET_LOG" ]; then
        # --maintenance is housekeeping (always runs); verify no update calls (-d, -u)
        run bash -c "grep -cE ' -(d|u) ' '$CRON_MALDET_LOG'"
        [ "$output" = "0" ]
    fi
}

@test "cron runs version update before signature update" {
    [ -f /etc/cron.daily/maldet ] || skip "no /etc/cron.daily/maldet on this OS"
    install_mock_maldet
    lmd_set_config autoupdate_version 1
    lmd_set_config autoupdate_signatures 1
    lmd_set_config cron_daily_scan 0

    run_cron_daily

    [ -f "$CRON_MALDET_LOG" ]
    # -d should appear before -u in the log
    d_line=$(grep -n "MALDET_CALL:.*-d" "$CRON_MALDET_LOG" | head -1 | cut -d: -f1)
    u_line=$(grep -n "MALDET_CALL:.*-u" "$CRON_MALDET_LOG" | head -1 | cut -d: -f1)
    [ -n "$d_line" ]
    [ -n "$u_line" ]
    [ "$d_line" -lt "$u_line" ]
}


# ============================================================
# Watchdog tests
# ============================================================

@test "watchdog exits cleanly when signatures are fresh" {
    [ -f /etc/cron.weekly/maldet-watchdog ] || skip "watchdog not installed"
    # Touch sig version file recently
    touch "$LMD_INSTALL/sigs/maldet.sigs.ver"
    install_mock_maldet

    run bash /etc/cron.weekly/maldet-watchdog

    assert_success
    # Should NOT have called maldet
    if [ -f "$CRON_MALDET_LOG" ]; then
        run grep -c "MALDET_CALL:" "$CRON_MALDET_LOG"
        [ "$output" = "0" ]
    fi
}

@test "watchdog triggers emergency update when signatures are stale" {
    [ -f /etc/cron.weekly/maldet-watchdog ] || skip "watchdog not installed"
    # Make sig version file 10 days old
    touch -d '10 days ago' "$LMD_INSTALL/sigs/maldet.sigs.ver"
    install_mock_maldet

    run bash /etc/cron.weekly/maldet-watchdog

    assert_success
    # Should have called both maldet -u and maldet -d
    [ -f "$CRON_MALDET_LOG" ]
    run grep "MALDET_CALL:.*-u" "$CRON_MALDET_LOG"
    assert_success
    run grep "MALDET_CALL:.*-d" "$CRON_MALDET_LOG"
    assert_success
}

@test "watchdog runs version update even when signature update fails" {
    [ -f /etc/cron.weekly/maldet-watchdog ] || skip "watchdog not installed"
    touch -d '10 days ago' "$LMD_INSTALL/sigs/maldet.sigs.ver"
    # Install mock maldet that fails on -u but succeeds on -d
    cp "$LMD_INSTALL/maldet" "$LMD_INSTALL/maldet.real"
    cat > "$LMD_INSTALL/maldet" <<'MOCK'
#!/usr/bin/env bash
echo "MALDET_CALL: $@" >> /tmp/cron-maldet.log
case "$1" in
    -u) exit 1 ;;
    *)  exit 0 ;;
esac
MOCK
    chmod 755 "$LMD_INSTALL/maldet"

    run bash /etc/cron.weekly/maldet-watchdog

    assert_success
    [ -f "$CRON_MALDET_LOG" ]
    # Both -u and -d should have been called despite -u failure
    run grep "MALDET_CALL:.*-u" "$CRON_MALDET_LOG"
    assert_success
    run grep "MALDET_CALL:.*-d" "$CRON_MALDET_LOG"
    assert_success
}

@test "watchdog logs staleness warning to event_log" {
    [ -f /etc/cron.weekly/maldet-watchdog ] || skip "watchdog not installed"
    touch -d '10 days ago' "$LMD_INSTALL/sigs/maldet.sigs.ver"
    install_mock_maldet

    bash /etc/cron.weekly/maldet-watchdog

    run grep "maldet-watchdog: signatures are" "$LMD_INSTALL/logs/event_log"
    assert_success
    run grep "emergency update" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "watchdog survives missing internals.conf" {
    [ -f /etc/cron.weekly/maldet-watchdog ] || skip "watchdog not installed"
    mv "$LMD_INSTALL/internals/internals.conf" "$LMD_INSTALL/internals/internals.conf.bak"

    run bash /etc/cron.weekly/maldet-watchdog

    assert_success
    # Restore
    mv "$LMD_INSTALL/internals/internals.conf.bak" "$LMD_INSTALL/internals/internals.conf"
}


# ============================================================
# import_user_sigs() YARA validation tests
# ============================================================

@test "import_user_sigs installs valid YARA rules" {
    command -v yara >/dev/null 2>&1 || command -v yr >/dev/null 2>&1 || skip "no yara or yr binary"

    # Create valid YARA rule as fixture
    local rule_content='rule test_yara_marker { strings: $marker = "YARATEST_MARKER_STRING_1234567890" condition: $marker }'
    set_fixture "custom_yara_rules.yar" "$rule_content"

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        sig_import_md5_url=""
        sig_import_hex_url=""
        import_config_url=""
        web_proxy=""
        get_proxy_arg=""
        sig_import_yara_url="https://cdn.rfxn.com/downloads/custom_yara_rules.yar"
        import_user_sigs
    '
    assert_success
    run grep "test_yara_marker" "$LMD_INSTALL/sigs/custom.yara"
    assert_success
    run grep "imported custom YARA rules from" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "import_user_sigs rejects malformed YARA rules" {
    command -v yara >/dev/null 2>&1 || command -v yr >/dev/null 2>&1 || skip "no yara or yr binary"

    set_fixture "bad_yara_rules.yar" "rule broken {{{"

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        sig_import_md5_url=""
        sig_import_hex_url=""
        import_config_url=""
        web_proxy=""
        get_proxy_arg=""
        sig_import_yara_url="https://cdn.rfxn.com/downloads/bad_yara_rules.yar"
        import_user_sigs
    '
    assert_success
    # custom.yara should remain empty (reset-lmd.sh truncated it)
    [ ! -s "$LMD_INSTALL/sigs/custom.yara" ]
    run grep "WARNING: downloaded YARA rules from" "$LMD_INSTALL/logs/event_log"
    assert_success
    run grep "failed syntax check, skipping import" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "import_user_sigs preserves existing custom.yara on validation failure" {
    command -v yara >/dev/null 2>&1 || command -v yr >/dev/null 2>&1 || skip "no yara or yr binary"

    # Pre-populate custom.yara with a valid rule
    cat > "$LMD_INSTALL/sigs/custom.yara" <<'RULE'
rule pre_existing_rule { strings: $s = "PREEXISTING_MARKER" condition: $s }
RULE

    set_fixture "bad_yara_rules.yar" "rule broken {{{"

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        sig_import_md5_url=""
        sig_import_hex_url=""
        import_config_url=""
        web_proxy=""
        get_proxy_arg=""
        sig_import_yara_url="https://cdn.rfxn.com/downloads/bad_yara_rules.yar"
        import_user_sigs
    '
    assert_success
    # Original rule should still be there
    run grep "pre_existing_rule" "$LMD_INSTALL/sigs/custom.yara"
    assert_success
    run grep "WARNING: downloaded YARA rules from" "$LMD_INSTALL/logs/event_log"
    assert_success
}


# ============================================================
# import_user_sigs() csig URL tests
# ============================================================

@test "import_user_sigs imports csig data from sig_import_csig_url" {
    # Create a local csig fixture file
    set_fixture "custom_csig_rules.dat" "435349475f554e495155455f4d41524b45525f53494e474c45:{CSIG}test.csig.import.1"

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        sig_import_md5_url=""
        sig_import_hex_url=""
        sig_import_yara_url=""
        sig_import_sha256_url=""
        import_config_url=""
        web_proxy=""
        get_proxy_arg=""
        sig_import_csig_url="https://cdn.rfxn.com/downloads/custom_csig_rules.dat"
        import_user_sigs
    '
    assert_success
    run grep "test.csig.import.1" "$LMD_INSTALL/sigs/custom.csig.dat"
    assert_success
    run grep "imported custom compound signature data from" "$LMD_INSTALL/logs/event_log"
    assert_success
}


# ============================================================
# SHA-256 / MD5 fallback tests
# ============================================================

@test "sigup falls back to md5 when sha256sum unavailable" {
    create_mock_sigpack "2025010100000"
    create_mock_cleanpack

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        import_config_url=""
        sig_import_md5_url=""
        sig_import_hex_url=""
        web_proxy=""
        get_proxy_arg=""
        # Force sha256sum unavailable
        sha256sum=""
        echo "2024010100000" > "'"$LMD_INSTALL"'/sigs/maldet.sigs.ver"
        sig_version="2024010100000"
        sigup
    '
    assert_success
    run grep "sha256sum not available, falling back to md5" "$LMD_INSTALL/logs/event_log"
    assert_success
    run grep "verified md5sum" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "lmdup falls back to md5 for tarball when sha256sum unavailable" {
    create_mock_tarball "2.0.2"

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        import_config_url=""
        web_proxy=""
        get_proxy_arg=""
        sha256sum=""
        lmd_version="2.0.1"
        lmdup
    '
    run grep "sha256sum not available, falling back to md5" "$LMD_INSTALL/logs/event_log"
    assert_success
    run grep "verified md5sum" "$LMD_INSTALL/logs/event_log"
    assert_success
}

@test "lmdup hash check falls back to md5 URL when sha256sum unavailable" {
    set_fixture "maldet.current.ver" "2.0.1"
    # Compute real MD5 hash of installed files (sha256sum unavailable)
    local_hash=$(md5sum "$LMD_INSTALL/maldet" "$LMD_INSTALL/internals/lmd.lib.sh" | awk '{print$1}' | tr '\n' ' ' | tr -d ' ')
    set_fixture "maldet.current.hash" "$local_hash"

    run bash -c '
        source /opt/tests/helpers/mock-update-server.sh
        setup_mock_update_server
        source "'"$LMD_INSTALL"'/internals/internals.conf"
        source "'"$LMD_INSTALL"'/conf.maldet"
        if [ -f "$compatcnf" ]; then source "$compatcnf"; fi
        source "'"$LMD_INSTALL"'/internals/lmd.lib.sh"
        import_config_url=""
        web_proxy=""
        get_proxy_arg=""
        sha256sum=""
        lmd_version="2.0.1"
        autoupdate_version_hashed="1"
        lmdup
    '
    assert_success
    run grep "sha256sum not available, falling back to md5" "$LMD_INSTALL/logs/event_log"
    assert_success
    run grep "latest version already installed" "$LMD_INSTALL/logs/event_log"
    assert_success
}
