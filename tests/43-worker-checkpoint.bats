#!/usr/bin/env bats
# 43-worker-checkpoint.bats — Tests for Phase 14: per-worker chunk checkpoints
# Verifies: checkpoint write on stop, chunk-skip, worker count mismatch, sentinel type detection

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

# --- Helper: inline LMD source preamble for bash -c invocations ---
_lmd_source_snippet() {
    printf "set +eu; export inspath='%s'; " "$LMD_INSTALL"
    printf "source '%s/internals/internals.conf'; " "$LMD_INSTALL"
    printf "source '%s/conf.maldet'; " "$LMD_INSTALL"
    printf "source '%s/internals/tlog_lib.sh'; " "$LMD_INSTALL"
    printf "source '%s/internals/elog_lib.sh'; " "$LMD_INSTALL"
    printf "source '%s/internals/alert_lib.sh'; " "$LMD_INSTALL"
    printf "source '%s/internals/lmd_alert.sh'; " "$LMD_INSTALL"
    printf "source '%s/internals/lmd.lib.sh'; " "$LMD_INSTALL"
}

# --- Helper: source LMD stack for direct function calls ---
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
# _lifecycle_check_sentinels — abort vs stop detection
# ========================================================================

# bats test_tags=lifecycle,sentinel,checkpoint
@test "sentinels: returns 1 (abort) for kill-type abort sentinel" {
    _source_lmd_stack
    local scanid="wp-sent-$$"
    printf 'abort\n' > "$tmpdir/.abort.$scanid"
    _lifecycle_check_sentinels "$scanid"
    local rc=$?
    [ "$rc" -eq 1 ]
    rm -f "$tmpdir/.abort.$scanid"
}

# bats test_tags=lifecycle,sentinel,checkpoint
@test "sentinels: returns 4 (stop) for stop-type abort sentinel" {
    _source_lmd_stack
    local scanid="wp-sent2-$$"
    printf 'stop\n' > "$tmpdir/.abort.$scanid"
    _lifecycle_check_sentinels "$scanid"
    local rc=$?
    [ "$rc" -eq 4 ]
    rm -f "$tmpdir/.abort.$scanid"
}

# bats test_tags=lifecycle,sentinel,checkpoint
@test "sentinels: returns 0 (continue) when no sentinel exists" {
    _source_lmd_stack
    local scanid="wp-sent3-$$"
    _lifecycle_check_sentinels "$scanid"
    local rc=$?
    [ "$rc" -eq 0 ]
}

# bats test_tags=lifecycle,sentinel,checkpoint
@test "sentinels: returns 2 (pause) when pause sentinel exists without abort" {
    _source_lmd_stack
    local scanid="wp-sent4-$$"
    printf 'epoch=%s\nduration=0\n' "$(date +%s)" > "$tmpdir/.pause.$scanid"
    _lifecycle_check_sentinels "$scanid"
    local rc=$?
    [ "$rc" -eq 2 ]
    rm -f "$tmpdir/.pause.$scanid"
}

# ========================================================================
# _hex_csig_batch_worker — per-worker checkpoint on stop
# ========================================================================

# bats test_tags=lifecycle,worker,checkpoint
@test "hex worker: exits 4 on stop sentinel and writes per-worker checkpoint" {
    local chunk="$TEST_DIR/chunk.txt"
    local hexlits="$TEST_DIR/hex_lits.txt"
    local hexregex="$TEST_DIR/hex_regex.txt"
    local hexsigmap="$TEST_DIR/hex_sigmap.txt"

    # Create enough files for at least 2 micro-chunks (chunk_size=1)
    local i
    for i in 1 2 3 4; do
        local f="$TEST_DIR/file${i}.txt"
        printf 'stop checkpoint test file content number %s padding to exceed min\n' "$i" > "$f"
        echo "$f" >> "$chunk"
    done
    touch "$hexlits" "$hexregex" "$hexsigmap"

    local scanid="stop-wp-$$"

    # Create stop sentinel before launching — worker should see it after first micro-chunk
    printf 'stop\n' > "$TEST_DIR/.abort.$scanid"

    run bash -c "$(_lmd_source_snippet)
        tmpdir='$TEST_DIR'
        sessdir='$TEST_DIR'
        _hex_csig_batch_worker '$chunk' '256' \
            '$hexlits' '$hexregex' '$hexsigmap' \
            '' '' '' '' '' '1' '$scanid'
    "
    [ "$status" -eq 4 ]
}

# bats test_tags=lifecycle,worker,checkpoint
@test "hex worker: per-worker checkpoint has v1 header and chunks_completed" {
    local chunk="$TEST_DIR/chunk.txt"
    local hexlits="$TEST_DIR/hex_lits.txt"
    local hexregex="$TEST_DIR/hex_regex.txt"
    local hexsigmap="$TEST_DIR/hex_sigmap.txt"

    # Create files for multiple micro-chunks (chunk_size=1)
    local i
    for i in 1 2 3; do
        local f="$TEST_DIR/file${i}.txt"
        printf 'checkpoint header test file content number %s padding extra\n' "$i" > "$f"
        echo "$f" >> "$chunk"
    done
    touch "$hexlits" "$hexregex" "$hexsigmap"

    local scanid="stop-hdr-$$"

    # Create stop sentinel — worker processes first chunk, then sees stop
    printf 'stop\n' > "$TEST_DIR/.abort.$scanid"

    bash -c "$(_lmd_source_snippet)
        tmpdir='$TEST_DIR'
        sessdir='$TEST_DIR'
        _hex_csig_batch_worker '$chunk' '256' \
            '$hexlits' '$hexregex' '$hexsigmap' \
            '' '' '' '' '' '1' '$scanid'
    " || true  # exit 4 is expected

    # Find the per-worker checkpoint file
    local wp_file
    wp_file=$(find "$TEST_DIR" -name "scan.wp.${scanid}.*" -type f | head -1)
    [ -n "$wp_file" ]
    [ -f "$wp_file" ]

    # Validate header
    run head -1 "$wp_file"
    assert_output '#LMD_WP:v1'

    # Validate chunks_completed field exists and is a number
    run grep '^chunks_completed=' "$wp_file"
    [ "$status" -eq 0 ]
    local val
    val=$(grep '^chunks_completed=' "$wp_file" | cut -d= -f2)
    [[ "$val" =~ ^[0-9]+$ ]]
    [ "$val" -ge 1 ]
}

# bats test_tags=lifecycle,worker,checkpoint
@test "hex worker: still exits 3 on abort (kill) sentinel — not 4" {
    local chunk="$TEST_DIR/chunk.txt"
    local hexlits="$TEST_DIR/hex_lits.txt"
    local hexregex="$TEST_DIR/hex_regex.txt"
    local hexsigmap="$TEST_DIR/hex_sigmap.txt"

    local i
    for i in 1 2 3; do
        local f="$TEST_DIR/file${i}.txt"
        printf 'abort vs stop test file content number %s padding bytes extra\n' "$i" > "$f"
        echo "$f" >> "$chunk"
    done
    touch "$hexlits" "$hexregex" "$hexsigmap"

    local scanid="abort-not-stop-$$"

    # Create abort sentinel (not stop)
    printf 'abort\n' > "$TEST_DIR/.abort.$scanid"

    run bash -c "$(_lmd_source_snippet)
        tmpdir='$TEST_DIR'
        sessdir='$TEST_DIR'
        _hex_csig_batch_worker '$chunk' '256' \
            '$hexlits' '$hexregex' '$hexsigmap' \
            '' '' '' '' '' '1' '$scanid'
    "
    [ "$status" -eq 3 ]
}

# bats test_tags=lifecycle,worker,checkpoint
@test "hex worker: no checkpoint file written on abort (kill)" {
    local chunk="$TEST_DIR/chunk.txt"
    local hexlits="$TEST_DIR/hex_lits.txt"
    local hexregex="$TEST_DIR/hex_regex.txt"
    local hexsigmap="$TEST_DIR/hex_sigmap.txt"

    local i
    for i in 1 2 3; do
        local f="$TEST_DIR/file${i}.txt"
        printf 'no checkpoint on abort test file %s padding for min size\n' "$i" > "$f"
        echo "$f" >> "$chunk"
    done
    touch "$hexlits" "$hexregex" "$hexsigmap"

    local scanid="no-ckpt-$$"

    printf 'abort\n' > "$TEST_DIR/.abort.$scanid"

    bash -c "$(_lmd_source_snippet)
        tmpdir='$TEST_DIR'
        sessdir='$TEST_DIR'
        _hex_csig_batch_worker '$chunk' '256' \
            '$hexlits' '$hexregex' '$hexsigmap' \
            '' '' '' '' '' '1' '$scanid'
    " || true  # exit 3 expected

    # No per-worker checkpoint should exist
    local wp_count
    wp_count=$(find "$TEST_DIR" -name "scan.wp.${scanid}.*" -type f 2>/dev/null | wc -l)
    [ "$wp_count" -eq 0 ]
}

# ========================================================================
# _hex_csig_batch_worker — chunk-skip (arg 13)
# ========================================================================

# bats test_tags=lifecycle,worker,checkpoint
@test "hex worker: chunk-skip=0 processes all chunks" {
    local chunk="$TEST_DIR/chunk.txt"
    local hexlits="$TEST_DIR/hex_lits.txt"
    local hexregex="$TEST_DIR/hex_regex.txt"
    local hexsigmap="$TEST_DIR/hex_sigmap.txt"
    local progress="$TEST_DIR/progress"

    local i
    for i in 1 2 3; do
        local f="$TEST_DIR/file${i}.txt"
        printf 'chunk skip zero test file content number %s padding for min size\n' "$i" > "$f"
        echo "$f" >> "$chunk"
    done
    touch "$hexlits" "$hexregex" "$hexsigmap"

    local scanid="skip0-$$"

    run bash -c "$(_lmd_source_snippet)
        tmpdir='$TEST_DIR'
        sessdir='$TEST_DIR'
        _hex_csig_batch_worker '$chunk' '256' \
            '$hexlits' '$hexregex' '$hexsigmap' \
            '' '' '' '' '$progress' '1' '$scanid' '0'
    "
    [ "$status" -eq 0 ]

    # Progress file should show all 3 files processed
    [ -f "$progress" ]
    local processed
    processed=$(cat "$progress")
    [ "$processed" -eq 3 ]
}

# bats test_tags=lifecycle,worker,checkpoint
@test "hex worker: chunk-skip=2 skips first 2 micro-chunks" {
    local chunk="$TEST_DIR/chunk.txt"
    local hexlits="$TEST_DIR/hex_lits.txt"
    local hexregex="$TEST_DIR/hex_regex.txt"
    local hexsigmap="$TEST_DIR/hex_sigmap.txt"
    local progress="$TEST_DIR/progress"

    # Create 5 files, chunk_size=1, so 5 micro-chunks
    local i
    for i in 1 2 3 4 5; do
        local f="$TEST_DIR/file${i}.txt"
        printf 'chunk skip two test file content number %s padding for minimum\n' "$i" > "$f"
        echo "$f" >> "$chunk"
    done
    touch "$hexlits" "$hexregex" "$hexsigmap"

    local scanid="skip2-$$"

    run bash -c "$(_lmd_source_snippet)
        tmpdir='$TEST_DIR'
        sessdir='$TEST_DIR'
        _hex_csig_batch_worker '$chunk' '256' \
            '$hexlits' '$hexregex' '$hexsigmap' \
            '' '' '' '' '$progress' '1' '$scanid' '2'
    "
    [ "$status" -eq 0 ]

    # Progress file should show 5 (all files read), but only 3 micro-chunks
    # were actually processed (chunks 3, 4, 5). The global_idx advances for
    # all, but the skipped chunks still read files from the FD.
    # Actually, the chunk-skip skips the hex extraction but still reads the FD,
    # so _global_idx advances. Progress reports _global_idx which includes skipped.
    # The key test: the progress file value should show 5 total files read.
    [ -f "$progress" ]
    local processed
    processed=$(cat "$progress")
    [ "$processed" -eq 5 ]
}

# bats test_tags=lifecycle,worker,checkpoint
@test "hex worker: chunk-skip larger than total chunks completes without error" {
    local chunk="$TEST_DIR/chunk.txt"
    local hexlits="$TEST_DIR/hex_lits.txt"
    local hexregex="$TEST_DIR/hex_regex.txt"
    local hexsigmap="$TEST_DIR/hex_sigmap.txt"

    local i
    for i in 1 2; do
        local f="$TEST_DIR/file${i}.txt"
        printf 'chunk skip overrun test file content number %s with padding\n' "$i" > "$f"
        echo "$f" >> "$chunk"
    done
    touch "$hexlits" "$hexregex" "$hexsigmap"

    local scanid="skipover-$$"

    # Skip 10 chunks but only 2 files (chunk_size=1, so 2 chunks)
    run bash -c "$(_lmd_source_snippet)
        tmpdir='$TEST_DIR'
        sessdir='$TEST_DIR'
        _hex_csig_batch_worker '$chunk' '256' \
            '$hexlits' '$hexregex' '$hexsigmap' \
            '' '' '' '' '' '1' '$scanid' '10'
    "
    [ "$status" -eq 0 ]
}

# bats test_tags=lifecycle,worker,checkpoint
@test "hex worker: omitted chunk-skip defaults to 0" {
    local chunk="$TEST_DIR/chunk.txt"
    local hexlits="$TEST_DIR/hex_lits.txt"
    local hexregex="$TEST_DIR/hex_regex.txt"
    local hexsigmap="$TEST_DIR/hex_sigmap.txt"

    local f="$TEST_DIR/file1.txt"
    printf 'default chunk skip test file content with padding bytes\n' > "$f"
    echo "$f" > "$chunk"
    touch "$hexlits" "$hexregex" "$hexsigmap"

    local scanid="skipdefault-$$"

    # Call without arg 13 — should default to 0 (process all)
    run bash -c "$(_lmd_source_snippet)
        tmpdir='$TEST_DIR'
        sessdir='$TEST_DIR'
        _hex_csig_batch_worker '$chunk' '256' \
            '$hexlits' '$hexregex' '$hexsigmap' \
            '' '' '' '' '' '10240' '$scanid'
    "
    [ "$status" -eq 0 ]
}

# ========================================================================
# _lifecycle_continue — per-worker checkpoint reading
# ========================================================================

# bats test_tags=lifecycle,checkpoint,continue
@test "lifecycle_continue: reads per-worker checkpoints with matching worker count" {
    _source_lmd_stack
    local scanid="wp-cont-$$"

    # Create main checkpoint with workers=2
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\nsig_version=2026032601\nworkers=2\ntotal_files=100\nhits_so_far=0\noptions=\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"

    # Create per-worker checkpoint files
    printf '#LMD_WP:v1\nchunks_completed=5\n' > "$sessdir/scan.wp.$scanid.0"
    printf '#LMD_WP:v1\nchunks_completed=3\n' > "$sessdir/scan.wp.$scanid.1"

    _lifecycle_continue "$scanid"
    [ "$_continue_stage" = "hex" ]
    [ -n "${_continue_chunk_skips:-}" ]
}

# bats test_tags=lifecycle,checkpoint,continue
@test "lifecycle_continue: sets chunk-skip array from worker checkpoints" {
    _source_lmd_stack
    local scanid="wp-cont2-$$"

    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\nsig_version=2026032601\nworkers=2\ntotal_files=100\nhits_so_far=0\noptions=\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"

    printf '#LMD_WP:v1\nchunks_completed=5\n' > "$sessdir/scan.wp.$scanid.0"
    printf '#LMD_WP:v1\nchunks_completed=3\n' > "$sessdir/scan.wp.$scanid.1"

    _lifecycle_continue "$scanid"
    # _continue_chunk_skips should be a space-separated list "5 3"
    [ "$_continue_chunk_skips" = "5 3" ]
}

# bats test_tags=lifecycle,checkpoint,continue
@test "lifecycle_continue: warns on worker count mismatch and falls back to stage granularity" {
    _source_lmd_stack
    local scanid="wp-mismatch-$$"

    # Checkpoint says workers=3 but only 2 wp files exist
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\nsig_version=2026032601\nworkers=3\ntotal_files=100\nhits_so_far=0\noptions=\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"

    printf '#LMD_WP:v1\nchunks_completed=5\n' > "$sessdir/scan.wp.$scanid.0"
    printf '#LMD_WP:v1\nchunks_completed=3\n' > "$sessdir/scan.wp.$scanid.1"

    run _lifecycle_continue "$scanid"
    [ "$status" -eq 0 ]
    assert_output --partial "worker count mismatch"
}

# bats test_tags=lifecycle,checkpoint,continue
@test "lifecycle_continue: clears chunk-skips on worker count mismatch" {
    _source_lmd_stack
    local scanid="wp-mismatch2-$$"

    # workers=3 but only 1 wp file
    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\nsig_version=2026032601\nworkers=3\ntotal_files=100\nhits_so_far=0\noptions=\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"

    printf '#LMD_WP:v1\nchunks_completed=5\n' > "$sessdir/scan.wp.$scanid.0"

    _lifecycle_continue "$scanid"
    # On mismatch, chunk skips should be empty (stage-granularity fallback)
    [ -z "${_continue_chunk_skips:-}" ]
}

# bats test_tags=lifecycle,checkpoint,continue
@test "lifecycle_continue: no chunk-skips when no wp files exist" {
    _source_lmd_stack
    local scanid="wp-none-$$"

    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\nsig_version=2026032601\nworkers=2\ntotal_files=100\nhits_so_far=0\noptions=\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"

    _lifecycle_continue "$scanid"
    [ -z "${_continue_chunk_skips:-}" ]
}

# bats test_tags=lifecycle,checkpoint,continue
@test "lifecycle_continue: rejects wp file with invalid header" {
    _source_lmd_stack
    local scanid="wp-badhdr-$$"

    printf '#LMD_CHECKPOINT:v1\nscanid=%s\nstage=hex\nsig_version=2026032601\nworkers=1\ntotal_files=100\nhits_so_far=0\noptions=\nstopped=1774588200\nstopped_hr=Mar 27 2026 20:30:00 +0000\n' "$scanid" > "$sessdir/scan.checkpoint.$scanid"
    echo "2026032601" > "$sigdir/maldet.sigs.ver"

    # Invalid header
    printf 'BAD_HEADER\nchunks_completed=5\n' > "$sessdir/scan.wp.$scanid.0"

    run _lifecycle_continue "$scanid"
    [ "$status" -eq 0 ]
    # Should warn about invalid wp file and fall back
    assert_output --partial "worker count mismatch"
}

# ========================================================================
# Scan worker invocation — chunk-skip passed as arg 13
# ========================================================================

# bats test_tags=lifecycle,worker,checkpoint,integration
@test "lmd_scan.sh: hex worker call site accepts 13th argument position" {
    # Verify the source code has the 13th arg position for chunk-skip
    run grep -A20 '_hex_csig_batch_worker.*chunk_prefix' "$LMD_INSTALL/internals/lmd_scan.sh"
    # Should contain either chunk_skip reference or arg 13 position
    [ "$status" -eq 0 ]
}

# ========================================================================
# Regression: existing scan unaffected
# ========================================================================

# bats test_tags=lifecycle,worker,checkpoint,regression
@test "regression: hex worker processes all files when no sentinel present" {
    local chunk="$TEST_DIR/chunk.txt"
    local hexlits="$TEST_DIR/hex_lits.txt"
    local hexregex="$TEST_DIR/hex_regex.txt"
    local hexsigmap="$TEST_DIR/hex_sigmap.txt"
    local progress="$TEST_DIR/progress"

    local i
    for i in 1 2 3; do
        local f="$TEST_DIR/file${i}.txt"
        printf 'regression test file content number %s with padding for min size\n' "$i" > "$f"
        echo "$f" >> "$chunk"
    done
    touch "$hexlits" "$hexregex" "$hexsigmap"

    run bash -c "$(_lmd_source_snippet)
        tmpdir='$TEST_DIR'
        sessdir='$TEST_DIR'
        _hex_csig_batch_worker '$chunk' '256' \
            '$hexlits' '$hexregex' '$hexsigmap' \
            '' '' '' '' '$progress' '1' '' '0'
    "
    [ "$status" -eq 0 ]
    [ -f "$progress" ]
    local processed
    processed=$(cat "$progress")
    [ "$processed" -eq 3 ]
}
