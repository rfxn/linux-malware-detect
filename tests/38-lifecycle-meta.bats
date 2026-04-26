#!/usr/bin/env bats

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/lmd-config.sh

LMD_INSTALL="/usr/local/maldetect"

setup() {
    source /opt/tests/helpers/reset-lmd.sh
    TEST_DIR=$(mktemp -d)
}

teardown() {
    rm -rf "$TEST_DIR"
}

# --- Helper: source LMD stack to get lifecycle functions ---
_source_lmd_stack() {
    set +eu
    trap - ERR  # bash 5.1: BATS ERR trap leaks into sourced files even with set +e
    export inspath="$LMD_INSTALL"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/internals.conf"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/conf.maldet"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/tlog_lib.sh"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/elog_lib.sh"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/alert_lib.sh"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/lmd_alert.sh"
    # shellcheck disable=SC1090,SC1091
    source "$LMD_INSTALL/internals/lmd.lib.sh"
    set -eu
}

# ========================================================================
# _lifecycle_write_meta tests
# ========================================================================

@test "_lifecycle_write_meta creates scan.meta file with #LMD_META:v1 header" {
    _source_lmd_stack
    local scanid="260328-1500.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home/testuser" "1000" "4" "native" "md5" "md5,hex" "scan_clamscan=0"
    [ -f "$sessdir/scan.meta.$scanid" ]
    head -1 "$sessdir/scan.meta.$scanid" | grep -q '^#LMD_META:v1$'
}

@test "_lifecycle_write_meta writes correct pid and ppid" {
    _source_lmd_stack
    local scanid="260328-1501.$$"
    _lifecycle_write_meta "$scanid" "12345" "12300" "/home/user" "500" "2" "native" "sha256" "md5" ""
    grep -q '^pid=12345$' "$sessdir/scan.meta.$scanid"
    grep -q '^ppid=12300$' "$sessdir/scan.meta.$scanid"
}

@test "_lifecycle_write_meta writes started epoch and human-readable timestamp" {
    _source_lmd_stack
    local scanid="260328-1502.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home/user" "100" "1" "native" "md5" "md5" ""
    # started should be a numeric epoch
    grep -E '^started=[0-9]+$' "$sessdir/scan.meta.$scanid"
    # started_hr should have a date-like format
    grep -E '^started_hr=.+ [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}' "$sessdir/scan.meta.$scanid"
}

@test "_lifecycle_write_meta writes path and file count" {
    _source_lmd_stack
    local scanid="260328-1503.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/var/www/html" "5748092" "8" "native" "md5" "md5,hex" ""
    grep -q '^path=/var/www/html$' "$sessdir/scan.meta.$scanid"
    grep -q '^total_files=5748092$' "$sessdir/scan.meta.$scanid"
}

@test "_lifecycle_write_meta writes engine, hashtype, stages, workers" {
    _source_lmd_stack
    local scanid="260328-1504.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "4" "clamav" "sha256" "md5,hex,yara" "quarantine_hits=1"
    grep -q '^engine=clamav$' "$sessdir/scan.meta.$scanid"
    grep -q '^hashtype=sha256$' "$sessdir/scan.meta.$scanid"
    grep -q '^stages=md5,hex,yara$' "$sessdir/scan.meta.$scanid"
    grep -q '^workers=4$' "$sessdir/scan.meta.$scanid"
}

@test "_lifecycle_write_meta writes sig_version from maldet.sigs.ver" {
    _source_lmd_stack
    # Set a known sig version
    echo "2026032801" > "$sigdir/maldet.sigs.ver"
    local scanid="260328-1505.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    grep -q '^sig_version=2026032801$' "$sessdir/scan.meta.$scanid"
}

@test "_lifecycle_write_meta writes unknown sig_version when sigs.ver missing" {
    _source_lmd_stack
    rm -f "$sigdir/maldet.sigs.ver"
    local scanid="260328-1506.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    grep -q '^sig_version=unknown$' "$sessdir/scan.meta.$scanid"
}

@test "_lifecycle_write_meta writes options and state=running" {
    _source_lmd_stack
    local scanid="260328-1507.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" "scan_clamscan=0,scan_yara=0"
    grep -q '^options=scan_clamscan=0,scan_yara=0$' "$sessdir/scan.meta.$scanid"
    grep -q '^state=running$' "$sessdir/scan.meta.$scanid"
}

@test "_lifecycle_write_meta uses atomic write (tmp then mv)" {
    _source_lmd_stack
    local scanid="260328-1508.$$"
    # If atomic, no .tmp file should remain after completion
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    [ ! -f "$sessdir/scan.meta.$scanid.tmp" ]
    [ -f "$sessdir/scan.meta.$scanid" ]
}

# ========================================================================
# _lifecycle_update_meta tests
# ========================================================================

@test "_lifecycle_update_meta appends key=value to existing meta file" {
    _source_lmd_stack
    local scanid="260328-1510.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "stage" "hex"
    tail -1 "$sessdir/scan.meta.$scanid" | grep -q '^stage=hex$'
}

@test "_lifecycle_update_meta supports last-value-wins for duplicate keys" {
    _source_lmd_stack
    local scanid="260328-1511.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "paused"
    _lifecycle_update_meta "$scanid" "state" "running"
    # Both lines exist in the file
    local count
    count=$(grep -c '^state=' "$sessdir/scan.meta.$scanid")
    [ "$count" -ge 2 ]
}

@test "_lifecycle_update_meta returns 1 for missing meta file" {
    _source_lmd_stack
    run _lifecycle_update_meta "nonexistent.999" "key" "val"
    [ "$status" -ne 0 ]
}

# ========================================================================
# _lifecycle_read_meta tests
# ========================================================================

@test "_lifecycle_read_meta populates _meta_pid and _meta_ppid" {
    _source_lmd_stack
    local scanid="260328-1520.$$"
    _lifecycle_write_meta "$scanid" "12345" "12300" "/home" "500" "2" "native" "md5" "md5" ""
    _lifecycle_read_meta "$scanid"
    [ "$_meta_pid" = "12345" ]
    [ "$_meta_ppid" = "12300" ]
}

@test "_lifecycle_read_meta populates _meta_path and _meta_total_files" {
    _source_lmd_stack
    local scanid="260328-1521.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/var/www/html" "9999" "4" "native" "md5" "md5" ""
    _lifecycle_read_meta "$scanid"
    [ "$_meta_path" = "/var/www/html" ]
    [ "$_meta_total_files" = "9999" ]
}

@test "_lifecycle_read_meta uses last-value-wins for updated keys" {
    _source_lmd_stack
    local scanid="260328-1522.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "completed"
    _lifecycle_update_meta "$scanid" "hits" "5"
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "completed" ]
    [ "$_meta_hits" = "5" ]
}

@test "_lifecycle_read_meta returns 1 for missing meta file" {
    _source_lmd_stack
    run _lifecycle_read_meta "nonexistent.999"
    [ "$status" -eq 1 ]
}

@test "_lifecycle_read_meta handles options with embedded equals signs" {
    _source_lmd_stack
    local scanid="260328-1523.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" "scan_clamscan=0,scan_yara=0,quarantine_hits=0"
    _lifecycle_read_meta "$scanid"
    [ "$_meta_options" = "scan_clamscan=0,scan_yara=0,quarantine_hits=0" ]
}

@test "_lifecycle_read_meta populates engine and hashtype" {
    _source_lmd_stack
    local scanid="260328-1524.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "clamav" "sha256" "md5,hex,yara" ""
    _lifecycle_read_meta "$scanid"
    [ "$_meta_engine" = "clamav" ]
    [ "$_meta_hashtype" = "sha256" ]
    [ "$_meta_stages" = "md5,hex,yara" ]
}

# ========================================================================
# _lifecycle_detect_state tests
# ========================================================================

@test "_lifecycle_detect_state returns 'completed' for completed scan" {
    _source_lmd_stack
    local scanid="260328-1530.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "completed"
    run _lifecycle_detect_state "$scanid"
    assert_success
    assert_output "completed"
}

@test "_lifecycle_detect_state returns 'killed' for killed scan" {
    _source_lmd_stack
    local scanid="260328-1531.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "killed"
    run _lifecycle_detect_state "$scanid"
    assert_success
    assert_output "killed"
}

@test "_lifecycle_detect_state returns 'stopped' for stopped scan" {
    _source_lmd_stack
    local scanid="260328-1532.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "stopped"
    run _lifecycle_detect_state "$scanid"
    assert_success
    assert_output "stopped"
}

@test "_lifecycle_detect_state returns 'stale' when pid is dead" {
    _source_lmd_stack
    local scanid="260328-1533.$$"
    # Use a PID that definitely doesn't exist
    _lifecycle_write_meta "$scanid" "99999" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    run _lifecycle_detect_state "$scanid"
    assert_success
    assert_output "stale"
}

@test "_lifecycle_detect_state returns 'running' for live process" {
    _source_lmd_stack
    local scanid="260328-1534.$$"
    # Use our own PID which is alive
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    run _lifecycle_detect_state "$scanid"
    assert_success
    assert_output "running"
}

@test "_lifecycle_detect_state returns 'paused' for live process with pause sentinel" {
    _source_lmd_stack
    local scanid="260328-1535.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    # Create the pause sentinel file
    touch "$tmpdir/.pause.$scanid"
    run _lifecycle_detect_state "$scanid"
    assert_success
    assert_output "paused"
    rm -f "$tmpdir/.pause.$scanid"
}

@test "_lifecycle_detect_state returns 1 for nonexistent scan" {
    _source_lmd_stack
    run _lifecycle_detect_state "nonexistent.999"
    [ "$status" -eq 1 ]
}
