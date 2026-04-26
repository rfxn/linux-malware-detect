#!/usr/bin/env bash
# Generate test YARA rules for deterministic testing
set -euo pipefail

LMD_INSTALL="${LMD_INSTALL:-/usr/local/maldetect}"

# Create a custom YARA rule matching the test marker string
cat > "$LMD_INSTALL/sigs/custom.yara" <<'EOF'
rule test_yara_marker
{
    strings:
        $marker = "YARATEST_MARKER_STRING_1234567890"
    condition:
        $marker
}
EOF
