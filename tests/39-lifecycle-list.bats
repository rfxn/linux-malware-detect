#!/usr/bin/env bats
# 39-lifecycle-list.bats — Unit tests for active scan listing and state-aware report

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

# --- Helper: create a meta file for a scan with specified state ---
_create_meta_file() {
    local _scanid="$1" _pid="$2" _state="$3" _path="$4"
    local _total="${5:-1000}" _workers="${6:-4}" _engine="${7:-native}"
    local _meta_file="$sessdir/scan.meta.$_scanid"
    cat > "$_meta_file" <<EOF
#LMD_META:v1
pid=$_pid
ppid=$PPID
started=$(date +%s)
started_hr=$(date "+%b %d %Y %H:%M:%S %z")
path=$_path
total_files=$_total
workers=$_workers
engine=$_engine
hashtype=md5
stages=md5,hex
sig_version=2026032801
options=
state=$_state
hits=3
progress_pos=500
progress_total=$_total
elapsed=120
EOF
}

# ========================================================================
# _lifecycle_list_active — no active scans
# ========================================================================

@test "lifecycle list: returns 1 and stderr message when no meta files exist" {
    _source_lmd_stack
    # Ensure no meta files exist
    rm -f "$sessdir"/scan.meta.*
    run _lifecycle_list_active "text" "0"
    [ "$status" -eq 1 ]
    assert_output --partial "No active scans"
}

@test "lifecycle list: returns 1 when only completed scans exist" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1600.11111" "99999" "completed" "/home"
    run _lifecycle_list_active "text" "0"
    [ "$status" -eq 1 ]
    assert_output --partial "No active scans"
}

@test "lifecycle list: returns 1 when only killed scans exist" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1601.22222" "99999" "killed" "/var/www"
    run _lifecycle_list_active "text" "0"
    [ "$status" -eq 1 ]
    assert_output --partial "No active scans"
}

# ========================================================================
# _lifecycle_list_active — text format
# ========================================================================

@test "lifecycle list: text format shows running scan with header row" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    # Use our own PID so it appears as "running"
    _create_meta_file "260328-1610.$$" "$$" "running" "/home/testuser" "5000" "8" "native"
    run _lifecycle_list_active "text" "0"
    [ "$status" -eq 0 ]
    assert_output --partial "Active scans ("
    assert_output --partial "SCANID"
    assert_output --partial "STATE"
    assert_output --partial "260328-1610.$$"
    assert_output --partial "running"
}

@test "lifecycle list: text format shows stale scan (dead pid)" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1611.99998" "99998" "running" "/var/www" "2000"
    run _lifecycle_list_active "text" "0"
    [ "$status" -eq 0 ]
    assert_output --partial "stale"
}

@test "lifecycle list: text format excludes completed scans" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1612.$$" "$$" "running" "/home" "1000"
    _create_meta_file "260328-1613.11111" "11111" "completed" "/var"
    run _lifecycle_list_active "text" "0"
    [ "$status" -eq 0 ]
    assert_output --partial "260328-1612.$$"
    refute_output --partial "260328-1613.11111"
}

@test "lifecycle list: text verbose shows workers and sig_version" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1614.$$" "$$" "running" "/home" "5000" "8" "native"
    run _lifecycle_list_active "text" "1"
    [ "$status" -eq 0 ]
    assert_output --partial "8"
    assert_output --partial "2026032801"
}

# ========================================================================
# _lifecycle_list_active — JSON format
# ========================================================================

@test "lifecycle list: json format produces valid JSON structure" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    local _test_scanid="260328-1620.$$"
    _create_meta_file "$_test_scanid" "$$" "running" "/home/user" "3000" "4" "native"
    run _lifecycle_list_active "json" "0"
    [ "$status" -eq 0 ]
    # Check JSON structure
    assert_output --partial '"active_scans"'
    assert_output --partial '"scanid"'
    assert_output --partial "\"$_test_scanid\""
    assert_output --partial '"state"'
    assert_output --partial '"running"'
}

@test "lifecycle list: json format has unquoted integers for pid and total_files" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1621.$$" "$$" "running" "/home" "5000" "4" "native"
    run _lifecycle_list_active "json" "0"
    [ "$status" -eq 0 ]
    # pid should be unquoted integer
    assert_output --partial "\"pid\": $$"
    # total_files should be unquoted integer
    assert_output --partial '"total_files": 5000'
}

@test "lifecycle list: json format includes progress object" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1622.$$" "$$" "running" "/home" "5000" "4" "native"
    run _lifecycle_list_active "json" "0"
    [ "$status" -eq 0 ]
    assert_output --partial '"progress"'
    assert_output --partial '"position"'
    assert_output --partial '"total"'
}

@test "lifecycle list: json no active scans returns error JSON to stderr" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    run _lifecycle_list_active "json" "0"
    [ "$status" -eq 1 ]
    assert_output --partial "No active scans"
}

# ========================================================================
# _lifecycle_list_active — TSV format
# ========================================================================

@test "lifecycle list: tsv format has #LMD_SCANLIST:v1 header" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1630.$$" "$$" "running" "/home" "1000" "2" "native"
    run _lifecycle_list_active "tsv" "0"
    [ "$status" -eq 0 ]
    # First line should be the TSV header
    local first_line
    first_line=$(echo "$output" | head -1)
    [ "$first_line" = "#LMD_SCANLIST:v1" ]
}

@test "lifecycle list: tsv format has column header as second line" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1631.$$" "$$" "running" "/home" "1000" "2" "native"
    run _lifecycle_list_active "tsv" "0"
    [ "$status" -eq 0 ]
    local second_line
    second_line=$(echo "$output" | sed -n '2p')
    echo "$second_line" | grep -q 'scanid'
    echo "$second_line" | grep -q 'state'
    echo "$second_line" | grep -q 'pid'
}

@test "lifecycle list: tsv format data rows are tab-separated" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1632.$$" "$$" "running" "/home" "1000" "2" "native"
    run _lifecycle_list_active "tsv" "0"
    [ "$status" -eq 0 ]
    # Third line (first data row) should be tab-separated
    local data_line
    data_line=$(echo "$output" | sed -n '3p')
    # Count tabs — should be at least 7 (8 fields = 7 tabs)
    local tab_count
    tab_count=$(echo "$data_line" | tr -cd '\t' | wc -c)
    [ "$tab_count" -ge 7 ]
}

# ========================================================================
# _lifecycle_list_active — single scanid mode
# ========================================================================

@test "lifecycle list: single scanid mode returns only that scan" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1640.$$" "$$" "running" "/home" "1000"
    _create_meta_file "260328-1641.$$" "$$" "running" "/var" "2000"
    run _lifecycle_list_active "text" "0" "260328-1640.$$"
    [ "$status" -eq 0 ]
    assert_output --partial "260328-1640.$$"
    refute_output --partial "260328-1641.$$"
}

@test "lifecycle list: single scanid returns 1 for nonexistent scan" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    run _lifecycle_list_active "text" "0" "nonexistent.999"
    [ "$status" -eq 1 ]
}

@test "lifecycle list: single scanid json outputs single scan object" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    local _test_scanid="260328-1642.$$"
    _create_meta_file "$_test_scanid" "$$" "running" "/home" "3000" "4" "native"
    run _lifecycle_list_active "json" "0" "$_test_scanid"
    [ "$status" -eq 0 ]
    assert_output --partial '"active_scans"'
    assert_output --partial "\"$_test_scanid\""
}

# ========================================================================
# _lifecycle_render_text_active — elapsed formatting
# ========================================================================

@test "lifecycle list: elapsed renders as human-readable time" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1650.$$" "$$" "running" "/home" "1000"
    # Override elapsed to a known value (2 hours = 7200 seconds)
    echo "elapsed=7200" >> "$sessdir/scan.meta.260328-1650.$$"
    run _lifecycle_list_active "text" "0"
    [ "$status" -eq 0 ]
    # Should contain human-readable elapsed time
    assert_output --partial "2h"
}

# ========================================================================
# --format tsv validator
# ========================================================================

@test "CLI: --format tsv is accepted for active list" {
    run "$LMD_INSTALL/maldet" --format tsv --report active 2>&1
    # Should NOT get "ERROR: --format requires text, json, or html"
    refute_output --partial "ERROR: --format requires"
}

@test "CLI: --format tsv rejected for report list" {
    run "$LMD_INSTALL/maldet" --format tsv --report list 2>&1
    assert_output --partial "TSV format is only supported"
}

@test "CLI: --format invalid is rejected" {
    run "$LMD_INSTALL/maldet" --format xml --report list 2>&1
    [ "$status" -ne 0 ]
    assert_output --partial "ERROR: --format requires"
}

# ========================================================================
# -L / --list-active CLI handler
# ========================================================================

@test "CLI: -L outputs no active scans message when none exist" {
    run "$LMD_INSTALL/maldet" -L 2>&1
    # Should contain "No active scans" (return code may be non-zero)
    assert_output --partial "No active scans"
}

@test "CLI: --list-active is synonym for -L" {
    run "$LMD_INSTALL/maldet" --list-active 2>&1
    assert_output --partial "No active scans"
}

@test "CLI: -L with --format json produces JSON-like output" {
    # Create a meta file for a running scan (use init PID which is always alive)
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1700.1" "1" "running" "/home" "1000" "2" "native"
    run "$LMD_INSTALL/maldet" --format json -L 2>&1
    [ "$status" -eq 0 ]
    assert_output --partial '"active_scans"'
}

@test "CLI: -L with --format tsv produces TSV output" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1701.1" "1" "running" "/home" "1000" "2" "native"
    run "$LMD_INSTALL/maldet" --format tsv -L 2>&1
    [ "$status" -eq 0 ]
    assert_output --partial "#LMD_SCANLIST:v1"
}

# ========================================================================
# --report active CLI handler
# ========================================================================

@test "CLI: --report active outputs no active scans message when none exist" {
    run "$LMD_INSTALL/maldet" --report active 2>&1
    assert_output --partial "No active scans"
}

@test "CLI: --report active with --format json outputs JSON" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1710.1" "1" "running" "/home" "1000" "2" "native"
    run "$LMD_INSTALL/maldet" --format json --report active 2>&1
    [ "$status" -eq 0 ]
    assert_output --partial '"active_scans"'
}

# ========================================================================
# State-aware --report SCANID
# ========================================================================

@test "CLI: --report SCANID shows active scan info when scan is running" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    local scanid="260328-1720.1"
    _create_meta_file "$scanid" "1" "running" "/home" "5000" "4" "native"
    run "$LMD_INSTALL/maldet" --report "$scanid" 2>&1
    [ "$status" -eq 0 ]
    # Should show active scan info (state-aware), not "no report found"
    assert_output --partial "$scanid"
    assert_output --partial "running"
}

@test "CLI: --report SCANID for completed scan falls through to normal report" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    local scanid="260328-1721.99999"
    _create_meta_file "$scanid" "99999" "completed" "/home" "1000"
    # No session file exists, so it should fall through and report "no report found"
    run "$LMD_INSTALL/maldet" --report "$scanid" 2>&1
    # Should NOT show active scan info
    refute_output --partial "Active scans ("
}

# ========================================================================
# Structured output suppresses header()
# ========================================================================

@test "lifecycle list: json output does not contain copyright banner" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1730.$$" "$$" "running" "/home" "1000"
    run _lifecycle_list_active "json" "0"
    [ "$status" -eq 0 ]
    refute_output --partial "GNU GPL"
    refute_output --partial "Linux Malware Detect"
}

@test "lifecycle list: tsv output does not contain copyright banner" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1731.$$" "$$" "running" "/home" "1000"
    run _lifecycle_list_active "tsv" "0"
    [ "$status" -eq 0 ]
    refute_output --partial "GNU GPL"
    refute_output --partial "Linux Malware Detect"
}

# ========================================================================
# Active scan heading: count and formatting
# ========================================================================

@test "lifecycle render text: heading includes count for single scan" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1800.$$" "$$" "running" "/home" "1000"
    run _lifecycle_render_text_active "0" "260328-1800.$$"
    [ "$status" -eq 0 ]
    assert_output --partial "Active scans (1):"
}

@test "lifecycle render text: heading includes count for multiple scans" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1801.$$" "$$" "running" "/home" "1000"
    _create_meta_file "260328-1802.$$" "$$" "running" "/var" "2000"
    local _ids
    _ids=$(printf '%s\n' "260328-1801.$$" "260328-1802.$$")
    run _lifecycle_render_text_active "0" "$_ids"
    [ "$status" -eq 0 ]
    assert_output --partial "Active scans (2):"
}

@test "lifecycle render text: heading shows count 0 for empty ids" {
    _source_lmd_stack
    run _lifecycle_render_text_active "0" ""
    [ "$status" -eq 0 ]
    assert_output --partial "Active scans (0):"
}

@test "lifecycle render text: no leading blank line before heading" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.*
    _create_meta_file "260328-1803.$$" "$$" "running" "/home" "1000"
    run _lifecycle_render_text_active "0" "260328-1803.$$"
    [ "$status" -eq 0 ]
    # First line of output should start with Active, not be blank
    local first_line
    first_line=$(echo "$output" | head -1)
    [[ "$first_line" == Active* ]]
}

# ========================================================================
# _lifecycle_list_stopped — no stopped scans
# ========================================================================

@test "lifecycle list_stopped: returns 1 when no meta files exist" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.* "$sessdir"/scan.checkpoint.*
    run _lifecycle_list_stopped
    [ "$status" -eq 1 ]
    [ -z "$output" ]
}

@test "lifecycle list_stopped: returns 1 when only running scans exist" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.* "$sessdir"/scan.checkpoint.*
    _create_meta_file "260328-1900.$$" "$$" "running" "/home"
    run _lifecycle_list_stopped
    [ "$status" -eq 1 ]
}

@test "lifecycle list_stopped: returns 1 when stopped scan has no checkpoint file" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.* "$sessdir"/scan.checkpoint.*
    _create_meta_file "260328-1901.99999" "99999" "stopped" "/home"
    # No checkpoint file created — should not appear
    run _lifecycle_list_stopped
    [ "$status" -eq 1 ]
}

# ========================================================================
# _lifecycle_list_stopped — with stopped scans
# ========================================================================

@test "lifecycle list_stopped: shows stopped scan with checkpoint" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.* "$sessdir"/scan.checkpoint.*
    local scanid="260328-1910.99999"
    _create_meta_file "$scanid" "99999" "stopped" "/home/user" "5000" "4"
    # Add stopped metadata
    echo "stopped=$(date +%s)" >> "$sessdir/scan.meta.$scanid"
    echo "stopped_hr=$(date '+%b %d %Y %H:%M:%S %z')" >> "$sessdir/scan.meta.$scanid"
    echo "stage=hex" >> "$sessdir/scan.meta.$scanid"
    # Create checkpoint file
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    run _lifecycle_list_stopped
    [ "$status" -eq 0 ]
    assert_output --partial "Stopped scans (1):"
    assert_output --partial "$scanid"
    assert_output --partial "resume: maldet --continue"
}

@test "lifecycle list_stopped: shows correct column headers" {
    _source_lmd_stack
    rm -f "$sessdir"/scan.meta.* "$sessdir"/scan.checkpoint.*
    local scanid="260328-1911.99999"
    _create_meta_file "$scanid" "99999" "stopped" "/var/www"
    echo "stage=md5" >> "$sessdir/scan.meta.$scanid"
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=md5\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    run _lifecycle_list_stopped
    [ "$status" -eq 0 ]
    assert_output --partial "SCANID"
    assert_output --partial "STAGE"
    assert_output --partial "FILES"
    assert_output --partial "HITS"
    assert_output --partial "STOPPED"
    assert_output --partial "PATH"
}
