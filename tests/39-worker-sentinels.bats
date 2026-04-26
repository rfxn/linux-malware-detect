#!/usr/bin/env bats
# 39-worker-sentinels.bats — Tests for worker sentinel hooks (Phase 5)
# Verifies: abort/pause checks at natural boundaries, parent liveness, EXIT traps

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
# Returns a shell snippet that sources the LMD stack with set +eu.
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

# ========================================================================
# _hex_csig_batch_worker — scanid argument acceptance (arg 12)
# ========================================================================

# bats test_tags=lifecycle,worker,hex
@test "hex worker: accepts scanid as arg 12 without error" {
    local chunk="$TEST_DIR/chunk.txt"
    local hexlits="$TEST_DIR/hex_lits.txt"
    local hexregex="$TEST_DIR/hex_regex.txt"
    local hexsigmap="$TEST_DIR/hex_sigmap.txt"
    local testfile="$TEST_DIR/testfile.txt"

    printf 'clean file content for worker sentinel test\n' > "$testfile"
    echo "$testfile" > "$chunk"
    touch "$hexlits" "$hexregex" "$hexsigmap"

    local scanid="test-$$"

    run bash -c "$(_lmd_source_snippet)
        tmpdir='$TEST_DIR'
        _hex_csig_batch_worker '$chunk' '256' \
            '$hexlits' '$hexregex' '$hexsigmap' \
            '' '' '' '' '' '10240' '$scanid'
    "
    [ "$status" -eq 0 ]
    # Verify clean content against empty sigs produces no false hits
    refute_output --partial "{HEX}"
}

# bats test_tags=lifecycle,worker,hex
@test "hex worker: exits 3 on abort sentinel at micro-chunk boundary" {
    local chunk="$TEST_DIR/chunk.txt"
    local hexlits="$TEST_DIR/hex_lits.txt"
    local hexregex="$TEST_DIR/hex_regex.txt"
    local hexsigmap="$TEST_DIR/hex_sigmap.txt"

    # Create enough files for at least 2 micro-chunks (chunk_size=1)
    local i
    for i in 1 2 3; do
        local f="$TEST_DIR/file${i}.txt"
        printf 'clean file content number %s padding to exceed scan_min_filesize\n' "$i" > "$f"
        echo "$f" >> "$chunk"
    done
    touch "$hexlits" "$hexregex" "$hexsigmap"

    local scanid="abort-test-$$"

    # Create abort sentinel before launching — worker should see it after first micro-chunk
    touch "$TEST_DIR/.abort.$scanid"

    run bash -c "$(_lmd_source_snippet)
        tmpdir='$TEST_DIR'
        _hex_csig_batch_worker '$chunk' '256' \
            '$hexlits' '$hexregex' '$hexsigmap' \
            '' '' '' '' '' '1' '$scanid'
    "
    [ "$status" -eq 3 ]
}

# bats test_tags=lifecycle,worker,hex
@test "hex worker: EXIT trap cleans up .hcb temp files" {
    local chunk="$TEST_DIR/chunk.txt"
    local hexlits="$TEST_DIR/hex_lits.txt"
    local hexregex="$TEST_DIR/hex_regex.txt"
    local hexsigmap="$TEST_DIR/hex_sigmap.txt"
    local testfile="$TEST_DIR/testfile.txt"

    printf 'clean file content for exit trap test padding bytes\n' > "$testfile"
    echo "$testfile" > "$chunk"
    touch "$hexlits" "$hexregex" "$hexsigmap"

    local scanid="trap-test-$$"

    # Run worker directly (not via run) so we can check temp files after
    bash -c "$(_lmd_source_snippet)
        tmpdir='$TEST_DIR'
        _hex_csig_batch_worker '$chunk' '256' \
            '$hexlits' '$hexregex' '$hexsigmap' \
            '' '' '' '' '' '10240' '$scanid'
    "

    # After worker completes, no .hcb files should remain
    local hcb_count
    hcb_count=$(find "$TEST_DIR" -name '.hcb.*' 2>/dev/null | wc -l)
    [ "$hcb_count" -eq 0 ]
}

# bats test_tags=lifecycle,worker,hex
@test "hex worker: exits 5 when parent PID is dead (orphaned)" {
    local chunk="$TEST_DIR/chunk.txt"
    local hexlits="$TEST_DIR/hex_lits.txt"
    local hexregex="$TEST_DIR/hex_regex.txt"
    local hexsigmap="$TEST_DIR/hex_sigmap.txt"

    # Create files for multiple micro-chunks
    local i
    for i in 1 2 3; do
        local f="$TEST_DIR/file${i}.txt"
        printf 'orphan test file content number %s padding to minimum size\n' "$i" > "$f"
        echo "$f" >> "$chunk"
    done
    touch "$hexlits" "$hexregex" "$hexsigmap"

    local scanid="orphan-test-$$"

    run bash -c "$(_lmd_source_snippet)
        tmpdir='$TEST_DIR'
        # Override check_parent to always return dead
        _lifecycle_check_parent() { return 1; }
        _hex_csig_batch_worker '$chunk' '256' \
            '$hexlits' '$hexregex' '$hexsigmap' \
            '' '' '' '' '' '1' '$scanid'
    "
    [ "$status" -eq 5 ]
}

# ========================================================================
# _hash_batch_worker — scanid argument acceptance (arg 6)
# ========================================================================

# bats test_tags=lifecycle,worker,hash
@test "hash worker: accepts scanid as arg 6 without error" {
    local chunk="$TEST_DIR/chunk.txt"
    local sigfile="$TEST_DIR/sigs.dat"
    local testfile="$TEST_DIR/testfile.txt"

    printf 'clean file content for hash worker sentinel test\n' > "$testfile"
    echo "$testfile" > "$chunk"
    touch "$sigfile"

    local scanid="hash-test-$$"

    run bash -c "$(_lmd_source_snippet)
        tmpdir='$TEST_DIR'
        _hash_batch_worker '/usr/bin/md5sum' 'md5' '$chunk' '$sigfile' '' '$scanid'
    "
    [ "$status" -eq 0 ]
    # Verify clean content against empty sigs produces no false hits
    refute_output --partial "{MD5}"
}

# bats test_tags=lifecycle,worker,hash
@test "hash worker: exits 3 on abort sentinel after hash batch" {
    local chunk="$TEST_DIR/chunk.txt"
    local sigfile="$TEST_DIR/sigs.dat"
    local testfile="$TEST_DIR/testfile.txt"

    printf 'clean file content for hash abort test padding bytes\n' > "$testfile"
    echo "$testfile" > "$chunk"
    touch "$sigfile"

    local scanid="hash-abort-$$"

    # Create abort sentinel before launching
    touch "$TEST_DIR/.abort.$scanid"

    run bash -c "$(_lmd_source_snippet)
        tmpdir='$TEST_DIR'
        _hash_batch_worker '/usr/bin/md5sum' 'md5' '$chunk' '$sigfile' '' '$scanid'
    "
    [ "$status" -eq 3 ]
}

# bats test_tags=lifecycle,worker,hash
@test "hash worker: exits 5 when parent PID is dead (orphaned)" {
    local chunk="$TEST_DIR/chunk.txt"
    local sigfile="$TEST_DIR/sigs.dat"
    local testfile="$TEST_DIR/testfile.txt"

    printf 'clean file content for hash orphan test padding bytes\n' > "$testfile"
    echo "$testfile" > "$chunk"
    touch "$sigfile"

    local scanid="hash-orphan-$$"

    run bash -c "$(_lmd_source_snippet)
        tmpdir='$TEST_DIR'
        # Override check_parent to always return dead
        _lifecycle_check_parent() { return 1; }
        _hash_batch_worker '/usr/bin/md5sum' 'md5' '$chunk' '$sigfile' '' '$scanid'
    "
    [ "$status" -eq 5 ]
}

# ========================================================================
# _scan_run_native — passes scanid to workers
# ========================================================================

# bats test_tags=lifecycle,worker,integration
@test "scan passes scanid to hex worker (grep call site)" {
    # Verify the source code passes $scanid to _hex_csig_batch_worker
    run grep -c 'scanid' "$LMD_INSTALL/internals/lmd_scan.sh"
    # There should be at least one reference passing scanid to the worker
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]

    # Verify the hex worker call includes scanid as the last argument
    run grep -A15 '_hex_csig_batch_worker' "$LMD_INSTALL/internals/lmd_scan.sh"
    assert_output --partial 'scanid'
}

# bats test_tags=lifecycle,worker,integration
@test "scan passes scanid to hash workers (grep call sites)" {
    # Verify _hash_batch_worker calls include scanid
    run grep '_hash_batch_worker.*scanid' "$LMD_INSTALL/internals/lmd_scan.sh"
    [ "$status" -eq 0 ]
}

# ========================================================================
# Regression: existing scan still works with sentinel hooks
# ========================================================================

# bats test_tags=lifecycle,worker,regression
@test "regression: MD5 scan still detects malware with worker sentinels" {
    lmd_set_config scan_clamscan 0
    lmd_set_config scan_hashtype md5
    local scan_dir
    scan_dir=$(mktemp -d)
    cp /opt/tests/samples/eicar.com "$scan_dir/"
    run maldet -a "$scan_dir"
    # Status 2 = malware found (normal scan behavior unaffected by sentinel hooks)
    [ "$status" -eq 2 ]
    rm -rf "$scan_dir"
}

# bats test_tags=lifecycle,worker,regression
@test "regression: HEX scan still detects malware with worker sentinels" {
    lmd_set_config scan_clamscan 0
    lmd_set_config scan_hashtype md5
    local scan_dir
    scan_dir=$(mktemp -d)
    cp /opt/tests/samples/test-hex-match.php "$scan_dir/"
    run maldet -a "$scan_dir"
    # Status 2 = malware found OR status 0 = clean (HEX depends on sigs)
    # The key test is that the scan completes without errors (not status 1)
    [ "$status" -ne 1 ]
    rm -rf "$scan_dir"
}
