#!/usr/bin/env bash
# Helper to set LMD config values for tests
# Usage: lmd_set_config VAR VAL

LMD_INSTALL="${LMD_INSTALL:-/usr/local/maldetect}"

lmd_set_config() {
    local var="$1"
    local val="$2"
    local conf="$LMD_INSTALL/conf.maldet"
    if grep -q "^${var}=" "$conf"; then
        sed -i "s|^${var}=.*|${var}=\"${val}\"|" "$conf"
    else
        echo "${var}=\"${val}\"" >> "$conf"
    fi
}
