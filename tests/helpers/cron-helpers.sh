#!/usr/bin/env bash
# Shared helpers for cron.daily tests (used by 20-cron.bats and 22-updates.bats)

LMD_INSTALL="${LMD_INSTALL:-/usr/local/maldetect}"
CRON_MALDET_LOG="${CRON_MALDET_LOG:-/tmp/cron-maldet.log}"

# Install mock maldet that logs args
install_mock_maldet() {
    cp "$LMD_INSTALL/maldet" "$LMD_INSTALL/maldet.real"
    cat > "$LMD_INSTALL/maldet" <<'MOCK'
#!/usr/bin/env bash
echo "MALDET_CALL: $@" >> /tmp/cron-maldet.log
MOCK
    chmod 755 "$LMD_INSTALL/maldet"
}

# Run cron.daily with sleep disabled to avoid random delay
run_cron_daily() {
    local tmpscript
    tmpscript=$(mktemp /tmp/cron-daily-nosleep.XXXXXX)
    sed 's/sleep $(echo $RANDOM/sleep 0 #/' /etc/cron.daily/maldet > "$tmpscript"
    chmod 755 "$tmpscript"
    bash "$tmpscript"
    local rc=$?
    rm -f "$tmpscript"
    return $rc
}
