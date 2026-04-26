#!/usr/bin/env bash
# Custom BATS assertions for LMD scan results

LMD_INSTALL="${LMD_INSTALL:-/usr/local/maldetect}"

# Assert scan completed (exit 0=no hits, 2=hits found, both are valid)
# Usage: run maldet -a PATH; assert_scan_completed
assert_scan_completed() {
    if [ "$status" -ne 0 ] && [ "$status" -ne 2 ]; then
        echo "# maldet scan failed with unexpected status $status" >&2
        echo "# output: $output" >&2
        return 1
    fi
}

# Assert that a file has been quarantined
# Usage: assert_quarantined FILE
assert_quarantined() {
    local file="$1"
    if [ -f "$file" ]; then
        echo "# File still exists (not quarantined): $file" >&2
        return 1
    fi
    if ! grep -q "$file" "$LMD_INSTALL/sess/quarantine.hist" 2>/dev/null; then
        echo "# File not found in quarantine history: $file" >&2
        return 1
    fi
}

# Assert that a scan report contains a pattern
# Checks TSV session file first, falls back to legacy plaintext.
# Usage: assert_report_contains SCANID PATTERN
assert_report_contains() {
    local scanid="$1"
    local pattern="$2"
    local report
    report=$(get_session_report_file "$scanid")
    if [ -z "$report" ] || [ ! -f "$report" ]; then
        echo "# Report not found for scanid: $scanid" >&2
        return 1
    fi
    if ! grep -qi "$pattern" "$report"; then
        echo "# Pattern '$pattern' not found in report $scanid" >&2
        return 1
    fi
}

# Resolve session report file (TSV, legacy plaintext, or legacy hits)
# Checks session.tsv.$scanid first, then session.$scanid, then session.hits.$scanid
# Usage: local report; report=$(get_session_report_file "$scanid")
get_session_report_file() {
    local _sid="$1"
    if [ -f "$LMD_INSTALL/sess/session.tsv.${_sid}" ]; then
        echo "$LMD_INSTALL/sess/session.tsv.${_sid}"
    elif [ -f "$LMD_INSTALL/sess/session.${_sid}" ]; then
        echo "$LMD_INSTALL/sess/session.${_sid}"
    elif [ -f "$LMD_INSTALL/sess/session.hits.${_sid}" ]; then
        echo "$LMD_INSTALL/sess/session.hits.${_sid}"
    fi
}

# Assert malware was found (exit code 2)
# Usage: run maldet -a PATH; assert_malware_found
assert_malware_found() {
    if [ "$status" -ne 2 ]; then
        echo "# expected exit code 2 (malware found), got $status" >&2
        echo "# output: $output" >&2
        return 1
    fi
}

# Assert scan was clean (exit code 0)
# Usage: run maldet -a PATH; assert_scan_clean
assert_scan_clean() {
    if [ "$status" -ne 0 ]; then
        echo "# expected exit code 0 (clean scan), got $status" >&2
        echo "# output: $output" >&2
        return 1
    fi
}

# Resolve session data file (TSV or legacy hits) for a scan ID
# Usage: local hitsfile; hitsfile=$(get_session_hits_file "$scanid")
get_session_hits_file() {
    local _sid="$1"
    if [ -f "$LMD_INSTALL/sess/session.tsv.${_sid}" ]; then
        echo "$LMD_INSTALL/sess/session.tsv.${_sid}"
    elif [ -f "$LMD_INSTALL/sess/session.hits.${_sid}" ]; then
        echo "$LMD_INSTALL/sess/session.hits.${_sid}"
    fi
}

# Get the most recent scan ID
# Usage: scanid=$(get_last_scanid)
get_last_scanid() {
    if [ -f "$LMD_INSTALL/sess/session.last" ]; then
        cat "$LMD_INSTALL/sess/session.last"
    else
        echo ""
    fi
}
