#!/usr/bin/env bats
# 42-lifecycle-stop.bats — Tests for stop/continue: checkpoint at stage boundary and resume

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
    # Kill any leftover sleep processes from tests
    kill %1 2>/dev/null || true
    wait 2>/dev/null || true
}

# --- Helper: source LMD stack to get lifecycle functions ---
_source_lmd_stack() {
    local _old_opts
    _old_opts=$(set +o)
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
    eval "$_old_opts"
    return 0
}

# ========================================================================
# _lifecycle_stop tests — error rejection
# ========================================================================

@test "lifecycle_stop: rejects completed scan" {
    _source_lmd_stack
    local scanid="260328-4000.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "completed"
    run _lifecycle_stop "$scanid"
    [ "$status" -ne 0 ]
    assert_output --partial "not running"
}

@test "lifecycle_stop: rejects killed scan" {
    _source_lmd_stack
    local scanid="260328-4001.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "killed"
    run _lifecycle_stop "$scanid"
    [ "$status" -ne 0 ]
    assert_output --partial "not running"
}

@test "lifecycle_stop: rejects already stopped scan" {
    _source_lmd_stack
    local scanid="260328-4002.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "state" "stopped"
    run _lifecycle_stop "$scanid"
    [ "$status" -ne 0 ]
    assert_output --partial "already stopped"
}

@test "lifecycle_stop: rejects nonexistent scanid" {
    _source_lmd_stack
    run _lifecycle_stop "nonexistent.999"
    [ "$status" -ne 0 ]
    assert_output --partial "not found"
}

@test "lifecycle_stop: rejects daemon clamdscan engine" {
    _source_lmd_stack
    local scanid="260328-4003.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "clamdscan" "md5" "clamav" ""
    run _lifecycle_stop "$scanid"
    [ "$status" -ne 0 ]
    assert_output --partial "cannot checkpoint daemon"
}

# ========================================================================
# _lifecycle_stop tests — checkpoint writing (use run to capture)
# ========================================================================

@test "lifecycle_stop: writes checkpoint file with v1 header" {
    _source_lmd_stack
    sleep 300 &
    local bg_pid=$!
    local scanid="260328-4004.$bg_pid"
    _lifecycle_write_meta "$scanid" "$bg_pid" "$$" "/home" "5000" "4" "native" "md5" "md5,hex,yara" "scan_clamscan=0,quarantine_hits=0"
    _lifecycle_update_meta "$scanid" "stage" "hex"
    _lifecycle_update_meta "$scanid" "hits" "12"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"

    run _lifecycle_stop "$scanid"
    [ "$status" -eq 0 ]
    [ -f "$sessdir/scan.checkpoint.$scanid" ]
    run head -1 "$sessdir/scan.checkpoint.$scanid"
    assert_output '#LMD_CHECKPOINT:v1'
    run grep "^scanid=$scanid" "$sessdir/scan.checkpoint.$scanid"
    [ "$status" -eq 0 ]
    run grep "^stage=hex" "$sessdir/scan.checkpoint.$scanid"
    [ "$status" -eq 0 ]
    run grep "^sig_version=2026032601" "$sessdir/scan.checkpoint.$scanid"
    [ "$status" -eq 0 ]
    run grep "^total_files=5000" "$sessdir/scan.checkpoint.$scanid"
    [ "$status" -eq 0 ]
    run grep "^hits_so_far=12" "$sessdir/scan.checkpoint.$scanid"
    [ "$status" -eq 0 ]
    run grep "^workers=4" "$sessdir/scan.checkpoint.$scanid"
    [ "$status" -eq 0 ]
    run grep "^options=scan_clamscan=0,quarantine_hits=0" "$sessdir/scan.checkpoint.$scanid"
    [ "$status" -eq 0 ]
    kill "$bg_pid" 2>/dev/null; wait "$bg_pid" 2>/dev/null || true
}

@test "lifecycle_stop: updates meta state to stopped" {
    _source_lmd_stack
    sleep 300 &
    local bg_pid=$!
    local scanid="260328-4005.$bg_pid"
    _lifecycle_write_meta "$scanid" "$bg_pid" "$$" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "stage" "md5"

    run _lifecycle_stop "$scanid"
    [ "$status" -eq 0 ]
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "stopped" ]
    kill "$bg_pid" 2>/dev/null; wait "$bg_pid" 2>/dev/null || true
}

@test "lifecycle_stop: cleans abort and pause sentinels" {
    _source_lmd_stack
    sleep 300 &
    local bg_pid=$!
    local scanid="260328-4006.$bg_pid"
    _lifecycle_write_meta "$scanid" "$bg_pid" "$$" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "stage" "md5"

    run _lifecycle_stop "$scanid"
    [ "$status" -eq 0 ]
    [ ! -f "$tmpdir/.abort.$scanid" ]
    [ ! -f "$tmpdir/.pause.$scanid" ]
    kill "$bg_pid" 2>/dev/null; wait "$bg_pid" 2>/dev/null || true
}

@test "lifecycle_stop: works on paused scan (SIGCONT then stop)" {
    _source_lmd_stack
    sleep 300 &
    local bg_pid=$!
    local scanid="260328-4007.$bg_pid"
    _lifecycle_write_meta "$scanid" "$bg_pid" "$$" "/home" "100" "1" "native" "md5" "md5" ""
    printf 'epoch=%s\nduration=0\n' "$(date +%s)" > "$tmpdir/.pause.$scanid"
    _lifecycle_update_meta "$scanid" "state" "paused"
    _lifecycle_update_meta "$scanid" "stage" "hex"

    run _lifecycle_stop "$scanid"
    [ "$status" -eq 0 ]
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "stopped" ]
    [ -f "$sessdir/scan.checkpoint.$scanid" ]
    kill "$bg_pid" 2>/dev/null; wait "$bg_pid" 2>/dev/null || true
}

@test "lifecycle_stop: checkpoint has stopped timestamp" {
    _source_lmd_stack
    sleep 300 &
    local bg_pid=$!
    local scanid="260328-4008.$bg_pid"
    _lifecycle_write_meta "$scanid" "$bg_pid" "$$" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "stage" "md5"

    run _lifecycle_stop "$scanid"
    [ "$status" -eq 0 ]
    run grep "^stopped=" "$sessdir/scan.checkpoint.$scanid"
    [ "$status" -eq 0 ]
    run grep "^stopped_hr=" "$sessdir/scan.checkpoint.$scanid"
    [ "$status" -eq 0 ]
    kill "$bg_pid" 2>/dev/null; wait "$bg_pid" 2>/dev/null || true
}

@test "lifecycle_stop: logs eout message with lifecycle prefix" {
    _source_lmd_stack
    sleep 300 &
    local bg_pid=$!
    local scanid="260328-4009.$bg_pid"
    _lifecycle_write_meta "$scanid" "$bg_pid" "$$" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "stage" "hex"

    run _lifecycle_stop "$scanid"
    [ "$status" -eq 0 ]
    assert_output --partial "{lifecycle}"
    assert_output --partial "stopped"
    kill "$bg_pid" 2>/dev/null; wait "$bg_pid" 2>/dev/null || true
}

@test "lifecycle_stop: meta records stopped timestamp" {
    _source_lmd_stack
    sleep 300 &
    local bg_pid=$!
    local scanid="260328-4010.$bg_pid"
    _lifecycle_write_meta "$scanid" "$bg_pid" "$$" "/home" "100" "1" "native" "md5" "md5" ""
    _lifecycle_update_meta "$scanid" "stage" "md5"

    run _lifecycle_stop "$scanid"
    [ "$status" -eq 0 ]
    _lifecycle_read_meta "$scanid"
    [ -n "$_meta_stopped" ]
    [ -n "$_meta_stopped_hr" ]
    kill "$bg_pid" 2>/dev/null; wait "$bg_pid" 2>/dev/null || true
}

# ========================================================================
# _lifecycle_continue tests
# ========================================================================

@test "lifecycle_continue: rejects nonexistent checkpoint" {
    _source_lmd_stack
    run _lifecycle_continue "nonexistent.999"
    [ "$status" -ne 0 ]
    assert_output --partial "checkpoint not found"
}

@test "lifecycle_continue: rejects corrupted checkpoint (bad header)" {
    _source_lmd_stack
    local scanid="260328-4020.$$"
    echo "GARBAGE_HEADER" > "$sessdir/scan.checkpoint.$scanid"
    echo "scanid=$scanid" >> "$sessdir/scan.checkpoint.$scanid"
    run _lifecycle_continue "$scanid"
    [ "$status" -ne 0 ]
    assert_output --partial "corrupt"
}

@test "lifecycle_continue: validates checkpoint v1 header" {
    _source_lmd_stack
    local scanid="260328-4021.$$"
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\nsig_version=2026032601\nworkers=4\ntotal_files=100\nhits_so_far=0\noptions=\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"
    run _lifecycle_continue "$scanid"
    [ "$status" -eq 0 ]
    refute_output --partial "corrupt"
}

@test "lifecycle_continue: warns on sig version drift" {
    _source_lmd_stack
    local scanid="260328-4022.$$"
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\nsig_version=2026032500\nworkers=4\ntotal_files=100\nhits_so_far=0\noptions=\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"
    run _lifecycle_continue "$scanid"
    assert_output --partial "signature version changed"
}

@test "lifecycle_continue: rejects when scan is paused (not stopped)" {
    _source_lmd_stack
    sleep 300 &
    local bg_pid=$!
    local scanid="260328-4023.$bg_pid"
    _lifecycle_write_meta "$scanid" "$bg_pid" "$$" "/home" "100" "1" "native" "md5" "md5" ""
    printf 'epoch=%s\nduration=0\n' "$(date +%s)" > "$tmpdir/.pause.$scanid"
    _lifecycle_update_meta "$scanid" "state" "paused"
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\nsig_version=2026032601\nworkers=4\ntotal_files=100\nhits_so_far=0\noptions=\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"

    run _lifecycle_continue "$scanid"
    [ "$status" -ne 0 ]
    assert_output --partial "paused"
    kill "$bg_pid" 2>/dev/null; wait "$bg_pid" 2>/dev/null || true
    rm -f "$tmpdir/.pause.$scanid"
}

@test "lifecycle_continue: parses checkpoint options into env" {
    _source_lmd_stack
    local scanid="260328-4024.$$"
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\nsig_version=2026032601\nworkers=4\ntotal_files=100\nhits_so_far=0\noptions=scan_clamscan=0,scan_yara=0,quarantine_hits=0\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"
    run _lifecycle_continue "$scanid"
    [ "$status" -eq 0 ]
    refute_output --partial "corrupt"
}

@test "lifecycle_continue: exports stage for scan orchestration" {
    _source_lmd_stack
    local scanid="260328-4025.$$"
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=yara\nsig_version=2026032601\nworkers=4\ntotal_files=100\nhits_so_far=5\noptions=\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"
    _lifecycle_continue "$scanid"
    [ "$_continue_stage" = "yara" ]
    [ "$_continue_scanid" = "$scanid" ]
    [ "$_continue_hits_so_far" = "5" ]
}

@test "lifecycle_continue: logs resuming message" {
    _source_lmd_stack
    local scanid="260328-4026.$$"
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\nsig_version=2026032601\nworkers=4\ntotal_files=100\nhits_so_far=3\noptions=\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"
    run _lifecycle_continue "$scanid"
    [ "$status" -eq 0 ]
    assert_output --partial "resuming scan"
    assert_output --partial "from stage hex"
}

@test "lifecycle_continue: no sig drift warning when versions match" {
    _source_lmd_stack
    local scanid="260328-4027.$$"
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=md5\nsig_version=2026032601\nworkers=4\ntotal_files=100\nhits_so_far=0\noptions=\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"
    run _lifecycle_continue "$scanid"
    [ "$status" -eq 0 ]
    refute_output --partial "signature version changed"
}

# ========================================================================
# _scan_cleanup stop mode tests
# ========================================================================

@test "scan_cleanup: preserves session files in stop mode" {
    _source_lmd_stack
    local scanid="260328-4030.$$"
    scan_session="$tmpdir/.sess.test_stop"
    touch "$scan_session"
    echo "test hit data" > "$scan_session"
    _scan_stop_mode=1
    find_results="$tmpdir/.find.test_stop"
    touch "$find_results"
    runtime_ndb="$tmpdir/.runtime_ndb_test"
    runtime_hdb="$tmpdir/.runtime_hdb_test"
    runtime_hexstrings="$tmpdir/.runtime_hex_test"
    runtime_md5="$tmpdir/.runtime_md5_test"
    runtime_sha256="$tmpdir/.runtime_sha256_test"
    runtime_hsb="$tmpdir/.runtime_hsb_test"
    clamscan_results="$tmpdir/.clamscan_test"
    runtime_hex_literal="$tmpdir/.runtime_hex_literal_test"
    runtime_hex_regex="$tmpdir/.runtime_hex_regex_test"
    runtime_hex_sigmap="$tmpdir/.runtime_hex_sigmap_test"
    runtime_csig_batch_compiled="$tmpdir/.runtime_csig_compiled_test"
    runtime_csig_literals="$tmpdir/.runtime_csig_literals_test"
    runtime_csig_wildcards="$tmpdir/.runtime_csig_wildcards_test"
    runtime_csig_universals="$tmpdir/.runtime_csig_universals_test"
    _scan_cleanup
    [ -f "$scan_session" ]
    [ ! -f "$find_results" ]
    _scan_stop_mode=0
    rm -f "$scan_session"
}

@test "scan_cleanup: deletes session files in normal mode" {
    _source_lmd_stack
    local scanid="260328-4031.$$"
    scan_session="$tmpdir/.sess.test_normal"
    touch "$scan_session"
    echo "test hit data" > "$scan_session"
    _scan_stop_mode=0
    find_results="$tmpdir/.find.test_normal"
    touch "$find_results"
    runtime_ndb="$tmpdir/.runtime_ndb_test2"
    runtime_hdb="$tmpdir/.runtime_hdb_test2"
    runtime_hexstrings="$tmpdir/.runtime_hex_test2"
    runtime_md5="$tmpdir/.runtime_md5_test2"
    runtime_sha256="$tmpdir/.runtime_sha256_test2"
    runtime_hsb="$tmpdir/.runtime_hsb_test2"
    clamscan_results="$tmpdir/.clamscan_test2"
    runtime_hex_literal="$tmpdir/.runtime_hex_literal_test2"
    runtime_hex_regex="$tmpdir/.runtime_hex_regex_test2"
    runtime_hex_sigmap="$tmpdir/.runtime_hex_sigmap_test2"
    runtime_csig_batch_compiled="$tmpdir/.runtime_csig_compiled_test2"
    runtime_csig_literals="$tmpdir/.runtime_csig_literals_test2"
    runtime_csig_wildcards="$tmpdir/.runtime_csig_wildcards_test2"
    runtime_csig_universals="$tmpdir/.runtime_csig_universals_test2"
    _scan_cleanup
    [ ! -f "$scan_session" ]
}

# ========================================================================
# CLI --stop / --continue handler tests
# ========================================================================

@test "CLI --stop: requires SCANID argument" {
    run "$LMD_INSTALL/maldet" --stop
    [ "$status" -ne 0 ]
    assert_output --partial "requires a SCANID"
}

@test "CLI --continue: requires SCANID argument" {
    run "$LMD_INSTALL/maldet" --continue
    [ "$status" -ne 0 ]
    assert_output --partial "requires a SCANID"
}

@test "CLI --stop: passes scanid to lifecycle_stop" {
    run "$LMD_INSTALL/maldet" --stop "999999-9999.99999"
    [ "$status" -ne 0 ]
    assert_output --partial "not found"
}

@test "CLI --continue: passes scanid to lifecycle_continue" {
    run "$LMD_INSTALL/maldet" --continue "999999-9999.99999"
    [ "$status" -ne 0 ]
    assert_output --partial "checkpoint not found"
}

# ========================================================================
# Stop mode: trap_exit sentinel detection
# ========================================================================

@test "trap_exit: stop sentinel sets _scan_stop_mode=1 and preserves hits" {
    _source_lmd_stack
    local scanid="260328-5000.$$"
    # Simulate in-flight scan state
    scan_session=$(mktemp "$tmpdir/.sess.XXXXXX")
    printf 'sig1\t/test/file1.php\t12345\tmd5\n' > "$scan_session"
    svc=a
    _scan_aborting=0
    _scan_stop_mode=0
    scan_start=$(date +%s)
    progress_hits=1
    progress_cleaned=0
    # Create stop sentinel
    printf 'stop\n' > "$tmpdir/.abort.$scanid"
    # Create dummy runtime vars for _scan_cleanup
    find_results="$tmpdir/.find.trap_test"
    touch "$find_results"
    runtime_ndb="" runtime_hdb="" runtime_hexstrings=""
    runtime_md5="" runtime_sha256="" runtime_hsb=""
    clamscan_results=""
    runtime_hex_literal="" runtime_hex_regex="" runtime_hex_sigmap=""
    runtime_csig_batch_compiled="" runtime_csig_literals=""
    runtime_csig_wildcards="" runtime_csig_universals=""
    tmpf=""

    # Run trap_exit — it should detect stop and preserve session.hits
    run trap_exit
    [ "$status" -eq 0 ]
    [ -f "$sessdir/session.hits.$scanid" ]
    grep -q "sig1" "$sessdir/session.hits.$scanid"
    rm -f "$sessdir/session.hits.$scanid"
}

@test "trap_exit: abort sentinel marks meta killed (not stopped)" {
    _source_lmd_stack
    local scanid="260328-5001.$$"
    scan_session=$(mktemp "$tmpdir/.sess.XXXXXX")
    printf 'sig1\t/test/file1.php\n' > "$scan_session"
    svc=a
    _scan_aborting=0
    _scan_stop_mode=0
    scan_start=$(date +%s)
    progress_hits=0
    progress_cleaned=0
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "10" "1" "native" "md5" "md5" ""
    printf 'abort\n' > "$tmpdir/.abort.$scanid"
    find_results="" runtime_ndb="" runtime_hdb="" runtime_hexstrings=""
    runtime_md5="" runtime_sha256="" runtime_hsb=""
    clamscan_results=""
    runtime_hex_literal="" runtime_hex_regex="" runtime_hex_sigmap=""
    runtime_csig_batch_compiled="" runtime_csig_literals=""
    runtime_csig_wildcards="" runtime_csig_universals=""
    tmpf=""

    run trap_exit
    [ "$status" -eq 1 ]
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "killed" ]
    # session.hits should NOT be preserved for kill
    [ ! -f "$sessdir/session.hits.$scanid" ]
    rm -f "$tmpdir/.abort.$scanid"
}

# ========================================================================
# Hash worker exit 4 on stop sentinel
# ========================================================================

@test "hash worker: exits 4 on stop sentinel (Linux)" {
    _source_lmd_stack
    local scanid="260328-5010.$$"
    printf 'stop\n' > "$tmpdir/.abort.$scanid"
    # Create minimal inputs for _hash_batch_worker
    local chunk hash_sigs
    chunk=$(mktemp "$tmpdir/.chunk.XXXXXX")
    hash_sigs=$(mktemp "$tmpdir/.sigs.XXXXXX")
    echo "/nonexistent/file.txt" > "$chunk"
    echo "d41d8cd98f00b204e9800998ecf8427e:0:{MD5}test.sig.1" > "$hash_sigs"
    # Run in subshell to capture exit code
    run bash -c "
        source '$LMD_INSTALL/internals/internals.conf'
        source '$LMD_INSTALL/conf.maldet'
        source '$LMD_INSTALL/internals/lmd.lib.sh'
        _hash_batch_worker '$md5sum' 'md5' '$chunk' '$hash_sigs' '' '$scanid'
    "
    [ "$status" -eq 4 ]
    rm -f "$tmpdir/.abort.$scanid" "$chunk" "$hash_sigs"
}

# ========================================================================
# Lifecycle check_sentinels: distinguishes stop from abort
# ========================================================================

@test "check_sentinels: returns 4 for stop sentinel" {
    _source_lmd_stack
    local scanid="260328-5020.$$"
    printf 'stop\n' > "$tmpdir/.abort.$scanid"
    _lifecycle_check_sentinels "$scanid"
    local rc=$?
    [ "$rc" -eq 4 ]
    rm -f "$tmpdir/.abort.$scanid"
}

@test "check_sentinels: returns 1 for abort sentinel" {
    _source_lmd_stack
    local scanid="260328-5021.$$"
    printf 'abort\n' > "$tmpdir/.abort.$scanid"
    _lifecycle_check_sentinels "$scanid"
    local rc=$?
    [ "$rc" -eq 1 ]
    rm -f "$tmpdir/.abort.$scanid"
}

# ========================================================================
# Session finalization uses $scanid
# ========================================================================

@test "finalize_session: uses scanid for session.tsv naming" {
    _source_lmd_stack
    # Set scanid to a value that differs from datestamp.$$ — must be exported
    # so _scan_finalize_session can see it (it reads $scanid global)
    scanid="260101-0000.99999"
    export scanid
    scan_session=$(mktemp "$tmpdir/.sess.XXXXXX")
    printf 'sig1\t/test/file.php\t12345\tmd5\n' > "$scan_session"
    scan_start=$(date +%s)
    scan_start_hr="Jan 01 2026 00:00:00 +0000"
    scan_et=10
    tot_files=1
    tot_hits=1
    tot_cl=0
    hrspath="/test"
    _scan_finalize_session
    # Verify the session file uses $scanid, not $datestamp.$$
    [ -f "$sessdir/session.tsv.$scanid" ]
    rm -f "$sessdir/session.tsv.$scanid" "$sessdir/session.$scanid" "$sessdir/session.last"
}

# ========================================================================
# Orphan sweep temp file cleanup
# ========================================================================

@test "orphan_sweep: cleans temp files for stale scans" {
    _source_lmd_stack
    # Use a PID that doesn't exist
    local stale_pid=99998
    local scanid="260328-5030.$stale_pid"
    _lifecycle_write_meta "$scanid" "$stale_pid" "$$" "/home" "100" "1" "native" "md5" "md5" ""
    # Create orphaned temp files
    touch "$tmpdir/.hcb.$stale_pid.chunk0"
    touch "$tmpdir/.hex_worker.$stale_pid.0"
    touch "$tmpdir/.md5_worker.$stale_pid.0"
    printf 'abort\n' > "$tmpdir/.abort.$scanid"
    touch "$tmpdir/.clamscan_pid.$scanid"
    # Run orphan sweep
    _lifecycle_orphan_sweep
    # Verify temp files and sentinels are cleaned
    [ ! -f "$tmpdir/.hcb.$stale_pid.chunk0" ]
    [ ! -f "$tmpdir/.hex_worker.$stale_pid.0" ]
    [ ! -f "$tmpdir/.md5_worker.$stale_pid.0" ]
    [ ! -f "$tmpdir/.abort.$scanid" ]
    [ ! -f "$tmpdir/.clamscan_pid.$scanid" ]
    # Verify meta was marked stale
    _lifecycle_read_meta "$scanid"
    [ "$_meta_state" = "stale" ]
}

@test "orphan_sweep: preserves temp files for running scans" {
    _source_lmd_stack
    # Use a PID that IS alive (our own process)
    local scanid="260328-5031.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "native" "md5" "md5" ""
    touch "$tmpdir/.hex_worker.$$.0"
    _lifecycle_orphan_sweep
    # File should still exist (scan is running)
    [ -f "$tmpdir/.hex_worker.$$.0" ]
    rm -f "$tmpdir/.hex_worker.$$.0"
}

# ========================================================================
# Continue mode: scanid override
# ========================================================================

@test "lifecycle_continue: exports chunk_skips for hex stage" {
    _source_lmd_stack
    local scanid="260328-5040.$$"
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\nsig_version=2026032601\nworkers=2\ntotal_files=100\nhits_so_far=0\noptions=\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"
    # Create per-worker checkpoint files
    printf '#LMD_WP:v1\nchunks_completed=5\n' > "$sessdir/scan.wp.$scanid.0"
    printf '#LMD_WP:v1\nchunks_completed=3\n' > "$sessdir/scan.wp.$scanid.1"
    _lifecycle_continue "$scanid"
    [ "$_continue_chunk_skips" = "5 3" ]
    rm -f "$sessdir/scan.checkpoint.$scanid" "$sessdir"/scan.wp."$scanid".*
}

# ========================================================================
# MUST-FIX 1: progress_hits must survive continue-mode pre-seed
# ========================================================================

@test "scan: progress_hits=0 is guarded by continue-mode check" {
    _source_lmd_stack
    local scan_src="$LMD_INSTALL/internals/lmd_scan.sh"
    # The bare 'progress_hits=0' without a continue guard would clobber
    # the pre-seeded value from checkpoint. After the fix, bare
    # 'progress_hits=0' should not appear — it must be inside a
    # conditional that checks _continue_scanid.
    # A bare instance means: a line matching ^\tprogress_hits=0$ at the
    # scan() function's indentation level (single tab).
    local bare_count
    bare_count=$(grep -cP '^\tprogress_hits=0$' "$scan_src" || echo 0)
    [ "$bare_count" -eq 0 ]
}

# ========================================================================
# MUST-FIX 2: scan completion messages must use $scanid
# ========================================================================

@test "scan: completion eout uses scanid not datestamp.pid" {
    _source_lmd_stack
    local scan_src="$LMD_INSTALL/internals/lmd_scan.sh"
    # The report path in completion messages must use $scanid.
    # Check for the literal string 'datestamp.$$' in report/quarantine lines.
    # Use fgrep with a literal pattern to avoid shell expansion issues.
    local pat='$datestamp.$$'
    local match_count
    match_count=$(grep -Fc "$pat" "$scan_src" 2>/dev/null || echo 0)
    # Hook scan lines legitimately use datestamp.$$ — only non-hook lines matter.
    # Non-hook completion lines are the ones with "maldet --report" or "maldet -q"
    local bad_count
    bad_count=$(grep -F "$pat" "$scan_src" | grep -cE '(maldet --report|maldet -q)' 2>/dev/null || echo 0)
    [ "$bad_count" -eq 0 ]
}

# ========================================================================
# SHOULD-FIX 1: skip-hex path excludes prior hits from file list
# ========================================================================

@test "scan: skip-hex else branch excludes prior hits from file list" {
    _source_lmd_stack
    local scan_src="$LMD_INSTALL/internals/lmd_scan.sh"
    # When _skip_hex=1, the else branch that builds _hex_filelist for
    # downstream stages (YARA, strlen) must exclude files already in
    # scan_session, using the same grep -vFxf pattern as the normal path.
    # Check that the else branch (after "continue mode: rebuilding") has
    # hit-exclusion logic (grep -vFxf).
    local block
    block=$(awk '/continue mode: rebuilding/{f=1} f{print; if(/rm -f.*_hash_hit_paths/) exit}' "$scan_src")
    echo "$block" | grep -q 'grep -vFxf'
}

# ========================================================================
# SHOULD-FIX 2: ClamAV daemon engine type recorded as clamdscan
# ========================================================================

@test "lifecycle_stop: daemon gate matches actual meta engine value" {
    _source_lmd_stack
    # When meta records engine=clamdscan, the daemon gate should fire
    local scanid="260328-6000.$$"
    _lifecycle_write_meta "$scanid" "$$" "$PPID" "/home" "100" "1" "clamdscan" "md5" "clamav" ""
    run _lifecycle_stop "$scanid"
    [ "$status" -ne 0 ]
    assert_output --partial "cannot checkpoint daemon"
}

@test "scan: engine_type distinguishes clamdscan from clamscan" {
    _source_lmd_stack
    local scan_src="$LMD_INSTALL/internals/lmd_scan.sh"
    # The _engine_type assignment should check $clamd to distinguish daemon
    # from standalone ClamAV — look for clamdscan in the assignment block
    local found
    found=$(grep -A5 '_engine_type="clamav"' "$scan_src" | grep -c 'clamdscan' || echo 0)
    [ "$found" -gt 0 ]
}

# ========================================================================
# _lifecycle_continue — allowlist rejection (security)
# ========================================================================

@test "lifecycle_continue: rejects PATH in checkpoint options" {
    _source_lmd_stack
    local scanid="260328-4050.$$"
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\nsig_version=2026032601\nworkers=4\ntotal_files=100\nhits_so_far=0\noptions=PATH=/evil/bin,scan_yara=0\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"
    run _lifecycle_continue "$scanid"
    [ "$status" -eq 0 ]
    assert_output --partial "rejected unknown checkpoint option: PATH"
}

@test "lifecycle_continue: rejects IFS in checkpoint options" {
    _source_lmd_stack
    local scanid="260328-4051.$$"
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\nsig_version=2026032601\nworkers=4\ntotal_files=100\nhits_so_far=0\noptions=IFS=x,scan_clamscan=0\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"
    run _lifecycle_continue "$scanid"
    [ "$status" -eq 0 ]
    assert_output --partial "rejected unknown checkpoint option: IFS"
}

@test "lifecycle_continue: rejects LD_PRELOAD in checkpoint options" {
    _source_lmd_stack
    local scanid="260328-4052.$$"
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\nsig_version=2026032601\nworkers=4\ntotal_files=100\nhits_so_far=0\noptions=LD_PRELOAD=/evil.so,quarantine_hits=1\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"
    run _lifecycle_continue "$scanid"
    [ "$status" -eq 0 ]
    assert_output --partial "rejected unknown checkpoint option: LD_PRELOAD"
}

@test "lifecycle_continue: rejects inspath in checkpoint options" {
    _source_lmd_stack
    local scanid="260328-4053.$$"
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\nsig_version=2026032601\nworkers=4\ntotal_files=100\nhits_so_far=0\noptions=inspath=/tmp/evil\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"
    run _lifecycle_continue "$scanid"
    [ "$status" -eq 0 ]
    assert_output --partial "rejected unknown checkpoint option: inspath"
}

@test "lifecycle_continue: accepts allowlisted option alongside rejected one" {
    _source_lmd_stack
    local scanid="260328-4054.$$"
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\nsig_version=2026032601\nworkers=4\ntotal_files=100\nhits_so_far=0\noptions=scan_clamscan=1,BASH_ENV=/evil,quarantine_hits=0\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"
    run _lifecycle_continue "$scanid"
    [ "$status" -eq 0 ]
    assert_output --partial "rejected unknown checkpoint option: BASH_ENV"
    assert_output --partial "resuming scan"
}
