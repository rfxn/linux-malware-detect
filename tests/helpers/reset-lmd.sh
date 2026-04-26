#!/usr/bin/env bash
# Reset LMD to clean state between test files
#
# Modes:
#   RESET_FULL=1  Full reset — copies entire sigs.clean directory (4MB).
#                 Required for tests that modify main sig files (hex.dat,
#                 md5v2.dat, maldet.sigs.ver) such as 09-signatures.bats
#                 and 22-updates.bats.
#   RESET_FULL=0  Light reset (default) — resets config, custom sigs, ignore
#                 files, and session/quarantine/tmp state. Leaves main sig
#                 files in place for faster test execution.
set -euo pipefail

LMD_INSTALL="${LMD_INSTALL:-/usr/local/maldetect}"

# Restore clean config
cp "$LMD_INSTALL/conf.maldet.clean" "$LMD_INSTALL/conf.maldet"

# Restore internals.conf if a backup exists (from tests that modify it)
if [ -f "$LMD_INSTALL/internals/internals.conf.bak" ]; then
    cp "$LMD_INSTALL/internals/internals.conf.bak" "$LMD_INSTALL/internals/internals.conf"
    rm -f "$LMD_INSTALL/internals/internals.conf.bak"
fi

# Restore signature files — full or light mode
if [ "${RESET_FULL:-0}" = "1" ]; then
    # Full reset: copy entire sigs directory from clean baseline
    if [ -d "$LMD_INSTALL/sigs.clean" ]; then
        rm -rf "$LMD_INSTALL/sigs"
        cp -a "$LMD_INSTALL/sigs.clean" "$LMD_INSTALL/sigs"
    fi
else
    # Light reset: only reset custom sigs and drop-in directory
    # Main sig files (hex.dat, md5v2.dat, rfxn.*, maldet.sigs.ver) stay in place
    > "$LMD_INSTALL/sigs/custom.md5.dat"
    > "$LMD_INSTALL/sigs/custom.hex.dat"
    > "$LMD_INSTALL/sigs/custom.sha256.dat"
    > "$LMD_INSTALL/sigs/custom.csig.dat"
    > "$LMD_INSTALL/sigs/custom.yara"
    rm -rf "$LMD_INSTALL/sigs/custom.yara.d"
    mkdir -p "$LMD_INSTALL/sigs/custom.yara.d"
fi

# Clear session, quarantine, and temp data
rm -rf "$LMD_INSTALL/sess/"*
rm -rf "$LMD_INSTALL/quarantine/"*
rm -rf "$LMD_INSTALL/tmp/"*

# Reset custom signatures (also needed for full mode since cp -a restores
# sigs.clean which has non-empty custom files from install)
if [ "${RESET_FULL:-0}" = "1" ]; then
    > "$LMD_INSTALL/sigs/custom.md5.dat"
    > "$LMD_INSTALL/sigs/custom.hex.dat"
    > "$LMD_INSTALL/sigs/custom.sha256.dat"
    > "$LMD_INSTALL/sigs/custom.csig.dat"
    > "$LMD_INSTALL/sigs/custom.yara"
    rm -rf "$LMD_INSTALL/sigs/custom.yara.d"
    mkdir -p "$LMD_INSTALL/sigs/custom.yara.d"
fi

# Clear ignore files
> "$LMD_INSTALL/ignore_paths"
> "$LMD_INSTALL/ignore_sigs"
> "$LMD_INSTALL/ignore_file_ext"
