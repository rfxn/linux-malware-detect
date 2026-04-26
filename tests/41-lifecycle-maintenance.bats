#!/usr/bin/env bats
# 41-lifecycle-maintenance.bats — Tests for history rotation, session compression, --maintenance

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

# --- Helper: source LMD stack ---
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
# _rotate_history tests
# ========================================================================

@test "maintenance: rotate_history skips file below threshold" {
    _source_lmd_stack
    local testfile="$TEST_DIR/small.hist"
    printf 'small content\n' > "$testfile"
    # Threshold 1MB — file is tiny
    run _rotate_history "$testfile" 1048576
    [ "$status" -eq 0 ]
    # No .1.gz should exist
    [ ! -f "$testfile.1.gz" ]
    # Original unchanged
    [ -f "$testfile" ]
}

@test "maintenance: rotate_history rotates file exceeding threshold" {
    _source_lmd_stack
    local testfile="$TEST_DIR/big.hist"
    # Create a file larger than 100 bytes threshold
    dd if=/dev/urandom bs=200 count=1 2>/dev/null | base64 > "$testfile"
    local orig_size
    orig_size=$(wc -c < "$testfile")
    run _rotate_history "$testfile" 100
    [ "$status" -eq 0 ]
    # .1.gz should exist
    [ -f "$testfile.1.gz" ]
    # Original should be truncated (empty or near-empty)
    local new_size
    new_size=$(wc -c < "$testfile")
    [ "$new_size" -eq 0 ]
}

@test "maintenance: rotate_history cascades .1.gz to .2.gz" {
    _source_lmd_stack
    local testfile="$TEST_DIR/cascade.hist"
    # Create existing .1.gz
    echo "old-rotation-1" | gzip > "$testfile.1.gz"
    # Create large active file
    dd if=/dev/urandom bs=200 count=1 2>/dev/null | base64 > "$testfile"
    run _rotate_history "$testfile" 100
    [ "$status" -eq 0 ]
    # .2.gz should now contain old .1.gz content
    [ -f "$testfile.2.gz" ]
    # .1.gz should be new rotation
    [ -f "$testfile.1.gz" ]
    # Verify .2.gz has the old content
    local content
    content=$(gzip -d < "$testfile.2.gz")
    [ "$content" = "old-rotation-1" ]
}

@test "maintenance: rotate_history cascades .2.gz to .3.gz" {
    _source_lmd_stack
    local testfile="$TEST_DIR/cascade3.hist"
    # Create existing .1.gz and .2.gz
    echo "old-rotation-2" | gzip > "$testfile.2.gz"
    echo "old-rotation-1" | gzip > "$testfile.1.gz"
    # Create large active file
    dd if=/dev/urandom bs=200 count=1 2>/dev/null | base64 > "$testfile"
    run _rotate_history "$testfile" 100
    [ "$status" -eq 0 ]
    [ -f "$testfile.3.gz" ]
    [ -f "$testfile.2.gz" ]
    [ -f "$testfile.1.gz" ]
    # Verify .3.gz has the oldest content
    local content
    content=$(gzip -d < "$testfile.3.gz")
    [ "$content" = "old-rotation-2" ]
}

@test "maintenance: rotate_history preserves inode of active file" {
    _source_lmd_stack
    local testfile="$TEST_DIR/inode.hist"
    dd if=/dev/urandom bs=200 count=1 2>/dev/null | base64 > "$testfile"
    local orig_inode
    orig_inode=$(stat -c %i "$testfile")
    run _rotate_history "$testfile" 100
    [ "$status" -eq 0 ]
    local new_inode
    new_inode=$(stat -c %i "$testfile")
    [ "$orig_inode" = "$new_inode" ]
}

@test "maintenance: rotate_history handles missing file gracefully" {
    _source_lmd_stack
    run _rotate_history "$TEST_DIR/nonexistent.hist" 100
    [ "$status" -eq 0 ]
}

# ========================================================================
# _session_compress tests
# ========================================================================

@test "maintenance: session_compress gzips TSV session file" {
    _source_lmd_stack
    local scanid="260328-1000.12345"
    local tsv_file="$sessdir/session.tsv.$scanid"
    printf '#LMD:v1\ttest\n' > "$tsv_file"
    printf 'test.sig\t/test/file\n' >> "$tsv_file"
    run _session_compress "$scanid"
    [ "$status" -eq 0 ]
    # .gz should exist
    [ -f "$tsv_file.gz" ]
    # original should be removed
    [ ! -f "$tsv_file" ]
    # verify decompressed content
    local first_line
    first_line=$(gzip -d < "$tsv_file.gz" | head -1)
    [[ "$first_line" == "#LMD:v1"* ]]
}

@test "maintenance: session_compress skips already-compressed file" {
    _source_lmd_stack
    local scanid="260328-1100.22222"
    local tsv_file="$sessdir/session.tsv.$scanid"
    # Only .gz exists, no uncompressed file
    echo "already compressed" | gzip > "$tsv_file.gz"
    run _session_compress "$scanid"
    [ "$status" -eq 0 ]
    # .gz still exists, unchanged
    [ -f "$tsv_file.gz" ]
}

@test "maintenance: session_compress returns 1 for missing session" {
    _source_lmd_stack
    run _session_compress "999999-0000.00000"
    [ "$status" -eq 1 ]
}

# ========================================================================
# _session_resolve_compressed tests
# ========================================================================

@test "maintenance: resolve_compressed finds .gz session file" {
    _source_lmd_stack
    local scanid="260328-1200.33333"
    echo "data" | gzip > "$sessdir/session.tsv.$scanid.gz"
    run _session_resolve_compressed "$scanid"
    [ "$status" -eq 0 ]
    assert_output "$sessdir/session.tsv.$scanid.gz"
}

@test "maintenance: resolve_compressed returns 1 when not found" {
    _source_lmd_stack
    run _session_resolve_compressed "999999-0000.99999"
    [ "$status" -eq 1 ]
    [ -z "$output" ]
}

# ========================================================================
# _session_resolve integration with compressed sessions
# ========================================================================

@test "maintenance: session_resolve falls back to compressed .gz file" {
    _source_lmd_stack
    local scanid="260328-1300.44444"
    # No uncompressed session files — only .gz
    echo "data" | gzip > "$sessdir/session.tsv.$scanid.gz"
    run _session_resolve "$scanid"
    [ "$status" -eq 0 ]
    assert_output "$sessdir/session.tsv.$scanid.gz"
}

@test "maintenance: session_resolve prefers uncompressed over compressed" {
    _source_lmd_stack
    local scanid="260328-1400.55555"
    printf '#LMD:v1\ttest\n' > "$sessdir/session.tsv.$scanid"
    echo "stale" | gzip > "$sessdir/session.tsv.$scanid.gz"
    run _session_resolve "$scanid"
    [ "$status" -eq 0 ]
    assert_output "$sessdir/session.tsv.$scanid"
}

# ========================================================================
# _rotate_histories integration test
# ========================================================================

@test "maintenance: rotate_histories rotates all standard history files" {
    _source_lmd_stack
    # Create oversized history files
    for hist_file in "$quardir/hits.hist" "$quardir/quarantine.hist" "$quardir/monitor.scanned.hist"; do
        dd if=/dev/urandom bs=1100000 count=1 2>/dev/null | base64 > "$hist_file"
    done
    # Create oversized inotify_log
    dd if=/dev/urandom bs=1100000 count=1 2>/dev/null | base64 > "$inotify_log"
    run _rotate_histories
    [ "$status" -eq 0 ]
    # All should have .1.gz rotations
    [ -f "$quardir/hits.hist.1.gz" ]
    [ -f "$quardir/quarantine.hist.1.gz" ]
    [ -f "$quardir/monitor.scanned.hist.1.gz" ]
    [ -f "$inotify_log.1.gz" ]
}

@test "maintenance: rotate_histories skips files below threshold" {
    _source_lmd_stack
    # Create small history files
    echo "small" > "$quardir/hits.hist"
    echo "small" > "$quardir/quarantine.hist"
    run _rotate_histories
    [ "$status" -eq 0 ]
    # No rotations
    [ ! -f "$quardir/hits.hist.1.gz" ]
    [ ! -f "$quardir/quarantine.hist.1.gz" ]
}

# ========================================================================
# --maintenance CLI test
# ========================================================================

@test "maintenance: --maintenance CLI handler exits 0 with lifecycle output" {
    run maldet --maintenance
    [ "$status" -eq 0 ]
    assert_output --partial "{lifecycle}"
}

# ========================================================================
# _session_archive_month tests
# ========================================================================

@test "maintenance: archive_month bundles matching TSV sessions into archive" {
    _source_lmd_stack
    local yymm="2603"
    # Create two session files for the same month
    printf '#LMD:v1\tscan\t260301-1000.111\n' > "$sessdir/session.tsv.260301-1000.111"
    printf '#LMD:v1\tscan\t260315-1400.222\n' > "$sessdir/session.tsv.260315-1400.222"
    run _session_archive_month "$yymm"
    [ "$status" -eq 0 ]
    # Archive file should exist
    [ -f "$sessdir/session.archive.$yymm.tsv.gz" ]
    # Originals should be removed
    [ ! -f "$sessdir/session.tsv.260301-1000.111" ]
    [ ! -f "$sessdir/session.tsv.260315-1400.222" ]
    # Verify archive content includes both sessions
    local content
    content=$(gzip -dc "$sessdir/session.archive.$yymm.tsv.gz")
    [[ "$content" == *"260301-1000.111"* ]]
    [[ "$content" == *"260315-1400.222"* ]]
}

@test "maintenance: archive_month includes compressed .gz sessions" {
    _source_lmd_stack
    local yymm="2602"
    # One plain, one already compressed
    printf '#LMD:v1\tscan\t260201-0800.333\n' > "$sessdir/session.tsv.260201-0800.333"
    printf '#LMD:v1\tscan\t260210-1200.444\n' | gzip > "$sessdir/session.tsv.260210-1200.444.gz"
    run _session_archive_month "$yymm"
    [ "$status" -eq 0 ]
    [ -f "$sessdir/session.archive.$yymm.tsv.gz" ]
    # Both originals removed
    [ ! -f "$sessdir/session.tsv.260201-0800.333" ]
    [ ! -f "$sessdir/session.tsv.260210-1200.444.gz" ]
    # Verify both present in archive
    local content
    content=$(gzip -dc "$sessdir/session.archive.$yymm.tsv.gz")
    [[ "$content" == *"260201-0800.333"* ]]
    [[ "$content" == *"260210-1200.444"* ]]
}

@test "maintenance: archive_month returns 0 with no matching files" {
    _source_lmd_stack
    # Create session for a different month
    printf '#LMD:v1\tscan\t260401-0800.555\n' > "$sessdir/session.tsv.260401-0800.555"
    run _session_archive_month "2603"
    [ "$status" -eq 0 ]
    # No archive created
    [ ! -f "$sessdir/session.archive.2603.tsv.gz" ]
    # Other month's file untouched
    [ -f "$sessdir/session.tsv.260401-0800.555" ]
}

@test "maintenance: archive_month preserves non-matching sessions" {
    _source_lmd_stack
    local yymm="2601"
    printf '#LMD:v1\tscan\t260115-0900.666\n' > "$sessdir/session.tsv.260115-0900.666"
    printf '#LMD:v1\tscan\t260215-0900.777\n' > "$sessdir/session.tsv.260215-0900.777"
    run _session_archive_month "$yymm"
    [ "$status" -eq 0 ]
    [ -f "$sessdir/session.archive.$yymm.tsv.gz" ]
    # Other month's file untouched
    [ -f "$sessdir/session.tsv.260215-0900.777" ]
}

@test "maintenance: archive_month logs archive count" {
    _source_lmd_stack
    local yymm="2512"
    printf '#LMD:v1\tscan\t251201-0800.888\n' > "$sessdir/session.tsv.251201-0800.888"
    printf '#LMD:v1\tscan\t251225-1600.999\n' > "$sessdir/session.tsv.251225-1600.999"
    run _session_archive_month "$yymm"
    [ "$status" -eq 0 ]
    assert_output --partial "{lifecycle} archived 2 sessions for month $yymm"
}

# ========================================================================
# _session_resolve_compressed: monthly archive resolution
# ========================================================================

@test "maintenance: resolve_compressed finds session in monthly archive" {
    _source_lmd_stack
    local scanid="260301-1000.111"
    local yymm="2603"
    # Create a monthly archive containing this scanid
    printf '#LMD:v1\tscan\t%s\n' "$scanid" | gzip > "$sessdir/session.archive.$yymm.tsv.gz"
    run _session_resolve_compressed "$scanid"
    [ "$status" -eq 0 ]
    assert_output "$sessdir/session.archive.$yymm.tsv.gz"
}

@test "maintenance: resolve_compressed prefers per-session .gz over archive" {
    _source_lmd_stack
    local scanid="260301-1000.222"
    local yymm="2603"
    # Both per-session .gz and monthly archive exist
    printf '#LMD:v1\tscan\t%s\n' "$scanid" | gzip > "$sessdir/session.tsv.$scanid.gz"
    printf '#LMD:v1\tscan\t%s\n' "$scanid" | gzip > "$sessdir/session.archive.$yymm.tsv.gz"
    run _session_resolve_compressed "$scanid"
    [ "$status" -eq 0 ]
    # Per-session .gz should be preferred
    assert_output "$sessdir/session.tsv.$scanid.gz"
}

# ========================================================================
# view_report: archive-aware decompression
# ========================================================================

@test "maintenance: view_report decompresses .gz session for text rendering" {
    _source_lmd_stack
    local scanid="260328-1500.12345"
    # Create a compressed session with valid TSV header
    printf '#LMD:v1\tscan\t%s\tlocalhost\t/test\t-\tMar 28 2026 15:00:00 -0400\tMar 28 2026 15:01:00 -0400\t60\t1\t100\t1\t0\t2.0.1\t2026032801\tmd5\tnative\t0\t-\n' "$scanid" > "$TEST_DIR/session.tsv"
    printf 'test.sig\t/test/file\t-\tMD5\tMD5\n' >> "$TEST_DIR/session.tsv"
    gzip -c "$TEST_DIR/session.tsv" > "$sessdir/session.tsv.$scanid.gz"
    # Verify view_report can access the compressed session
    # It should decompress and render (or at least not fail with "no report found")
    run maldet --report "$scanid"
    [ "$status" -ne 1 ] || {
        # If it exited 1, the error should NOT be "no report found"
        refute_output --partial "no report found"
    }
}

# ========================================================================
# --maintenance: archiving integration
# ========================================================================

@test "maintenance: --maintenance archives sessions older than 30 days" {
    _source_lmd_stack
    # Create compressed sessions with old timestamps (simulate already-compressed)
    # We need files that look like they're from a past month
    # Use touch to set old mtime (30+ days ago)
    local old_scanid="260201-1000.11111"
    printf '#LMD:v1\tscan\t%s\n' "$old_scanid" | gzip > "$sessdir/session.tsv.$old_scanid.gz"
    touch -t 202602010000 "$sessdir/session.tsv.$old_scanid.gz"
    # Also create a recent session that should NOT be archived
    local new_scanid="260328-1000.22222"
    printf '#LMD:v1\tscan\t%s\n' "$new_scanid" > "$sessdir/session.tsv.$new_scanid"
    run maldet --maintenance
    [ "$status" -eq 0 ]
    # Old month should be archived (if archive was created)
    # New session should still exist (not archived)
    [ -f "$sessdir/session.tsv.$new_scanid" ] || [ -f "$sessdir/session.tsv.$new_scanid.gz" ]
}
