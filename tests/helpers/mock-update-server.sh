#!/usr/bin/env bash
# Mock update server for testing sigup(), lmdup(), get_remote_file()
# Provides mock curl/wget binaries that serve local fixture files
# instead of making real HTTP requests.

MOCK_UPDATE_DIR="/tmp/lmd-mock-update"
MOCK_FIXTURES="$MOCK_UPDATE_DIR/fixtures"
MOCK_BIN="$MOCK_UPDATE_DIR/bin"
MOCK_CURL_LOG="/tmp/mock-curl-update.log"

setup_mock_update_server() {
    mkdir -p "$MOCK_FIXTURES" "$MOCK_BIN"
    rm -f "$MOCK_CURL_LOG"

    # Create mock curl
    cat > "$MOCK_BIN/curl" <<'MOCKCURL'
#!/usr/bin/env bash
# Mock curl — routes requests to local fixture files
FIXTURES="/tmp/lmd-mock-update/fixtures"
LOG="/tmp/mock-curl-update.log"
url=""
output_file=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) shift; output_file="$1" ;;
        http*) url="$1" ;;
    esac
    shift
done
echo "CURL: $url -> $output_file" >> "$LOG"

# Map URL to fixture by filename
basename=$(echo "$url" | sed 's|.*/||')
fixture="$FIXTURES/$basename"
if [ -f "$fixture" ]; then
    if [ -n "$output_file" ]; then
        cp -f "$fixture" "$output_file"
    else
        cat "$fixture"
    fi
    exit 0
else
    # Simulate failure — create empty file if output_file specified
    if [ -n "$output_file" ]; then
        : > "$output_file"
    fi
    exit 22
fi
MOCKCURL
    chmod 755 "$MOCK_BIN/curl"

    # Create mock wget
    cat > "$MOCK_BIN/wget" <<'MOCKWGET'
#!/usr/bin/env bash
# Mock wget — routes requests to local fixture files
FIXTURES="/tmp/lmd-mock-update/fixtures"
LOG="/tmp/mock-curl-update.log"
url=""
output_file=""
while [ $# -gt 0 ]; do
    case "$1" in
        -O) shift; output_file="$1" ;;
        http*) url="$1" ;;
    esac
    shift
done
echo "WGET: $url -> $output_file" >> "$LOG"

basename=$(echo "$url" | sed 's|.*/||')
fixture="$FIXTURES/$basename"
if [ -f "$fixture" ]; then
    if [ -n "$output_file" ]; then
        cp -f "$fixture" "$output_file"
    else
        cat "$fixture"
    fi
    exit 0
else
    if [ -n "$output_file" ]; then
        : > "$output_file"
    fi
    exit 1
fi
MOCKWGET
    chmod 755 "$MOCK_BIN/wget"

    # Prepend mock bin to PATH so command -v finds them first
    export PATH="$MOCK_BIN:$PATH"
}

set_fixture() {
    # Usage: set_fixture FILENAME CONTENT
    local name="$1"
    local content="$2"
    echo "$content" > "$MOCK_FIXTURES/$name"
}

set_fixture_file() {
    # Usage: set_fixture_file FILENAME SOURCE_PATH
    local name="$1"
    local src="$2"
    cp -f "$src" "$MOCK_FIXTURES/$name"
}

create_mock_sigpack() {
    # Create a valid maldet-sigpack.tgz + .md5 with test signature data
    # Usage: create_mock_sigpack [SIG_VERSION]
    local sig_ver="${1:-2099010100000}"
    local tmpd
    tmpd=$(mktemp -d /tmp/mock-sigpack.XXXXXX)
    mkdir -p "$tmpd/sigs"

    # Create minimal but valid signature files (>1000 lines each)
    for i in $(seq 1 1010); do
        echo "$(printf '%032x' $i):{MD5}test.sig.$i" >> "$tmpd/sigs/md5v2.dat"
        echo "$(printf '%032x' $((i + 10000))):{HEX}test.hex.$i" >> "$tmpd/sigs/hex.dat"
    done

    # Version file
    echo "$sig_ver" > "$tmpd/sigs/maldet.sigs.ver"

    # ClamAV-compatible files
    touch "$tmpd/sigs/rfxn.ndb" "$tmpd/sigs/rfxn.hdb"
    touch "$tmpd/sigs/rfxn.yara"

    # Create tarball (paths relative to tmpd so tar extracts to ./sigs/)
    tar czf "$MOCK_FIXTURES/maldet-sigpack.tgz" -C "$tmpd" sigs
    md5sum "$MOCK_FIXTURES/maldet-sigpack.tgz" | awk '{print $1}' > "$MOCK_FIXTURES/maldet-sigpack.tgz.md5"
    sha256sum "$MOCK_FIXTURES/maldet-sigpack.tgz" | awk '{print $1}' > "$MOCK_FIXTURES/maldet-sigpack.tgz.sha256"

    # Set version fixture
    echo "$sig_ver" > "$MOCK_FIXTURES/maldet.sigs.ver"

    rm -rf "$tmpd"
}

create_mock_cleanpack() {
    # Create a valid maldet-cleanv2.tgz + .md5
    local tmpd
    tmpd=$(mktemp -d /tmp/mock-cleanpack.XXXXXX)
    mkdir -p "$tmpd/clean"
    echo '#!/bin/bash' > "$tmpd/clean/base64.inject.unclassed"
    chmod 755 "$tmpd/clean/base64.inject.unclassed"

    tar czf "$MOCK_FIXTURES/maldet-cleanv2.tgz" -C "$tmpd" clean
    md5sum "$MOCK_FIXTURES/maldet-cleanv2.tgz" | awk '{print $1}' > "$MOCK_FIXTURES/maldet-cleanv2.tgz.md5"
    sha256sum "$MOCK_FIXTURES/maldet-cleanv2.tgz" | awk '{print $1}' > "$MOCK_FIXTURES/maldet-cleanv2.tgz.sha256"

    rm -rf "$tmpd"
}

create_mock_tarball() {
    # Create a valid maldetect-current.tar.gz + .md5 with stub install.sh
    # Usage: create_mock_tarball VERSION
    local ver="${1:-2.0.2}"
    local tmpd
    tmpd=$(mktemp -d /tmp/mock-tarball.XXXXXX)
    mkdir -p "$tmpd/maldetect-${ver}"

    # Stub install.sh that just touches a marker file
    cat > "$tmpd/maldetect-${ver}/install.sh" <<'STUB'
#!/usr/bin/env bash
touch /tmp/lmd-mock-install-ran
STUB
    chmod 750 "$tmpd/maldetect-${ver}/install.sh"
    mkdir -p "$tmpd/maldetect-${ver}/files"

    tar czf "$MOCK_FIXTURES/maldetect-current.tar.gz" -C "$tmpd" "maldetect-${ver}"
    md5sum "$MOCK_FIXTURES/maldetect-current.tar.gz" | awk '{print $1}' > "$MOCK_FIXTURES/maldetect-current.tar.gz.md5"
    sha256sum "$MOCK_FIXTURES/maldetect-current.tar.gz" | awk '{print $1}' > "$MOCK_FIXTURES/maldetect-current.tar.gz.sha256"

    # Set version fixture
    echo "$ver" > "$MOCK_FIXTURES/maldet.current.ver"

    rm -rf "$tmpd"
}

cleanup_mock_update_server() {
    rm -rf "$MOCK_UPDATE_DIR"
    rm -f "$MOCK_CURL_LOG"
    # PATH cleanup: remove mock bin dir
    export PATH=$(echo "$PATH" | tr ':' '\n' | grep -v "lmd-mock-update" | tr '\n' ':' | sed 's/:$//')
}
