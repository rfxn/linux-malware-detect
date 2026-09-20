#!/usr/bin/env bash
#
# Build the portable source installer bundle.
# The resulting archive is installed with:
#   tar -xzf maldetect-*-universal.tar.gz
#   cd maldetect-*-universal && sudo ./install.sh
#
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(sed -n 's/^lmd_version="\([^"]*\)".*/\1/p' "$root_dir/install.sh" | head -n 1)"
version="${version:-2.0.1}"
dist_dir="$root_dir/dist"
bundle_name="maldetect-${version}-universal"
stage_dir="$(mktemp -d "${TMPDIR:-/tmp}/${bundle_name}.XXXXXX")"
trap 'rm -rf "$stage_dir"' EXIT

mkdir -p "$stage_dir/$bundle_name"
cd "$root_dir"

# Keep the bundle limited to files consumed by install.sh and the user-facing
# documentation. Runtime state, credentials, tests, VCS metadata, and packages
# for a specific distribution are intentionally excluded.
cp -p install.sh uninstall.sh README README.md CHANGELOG COPYING.GPL "$stage_dir/$bundle_name/"
if [ -d docs ]; then
	cp -a docs "$stage_dir/$bundle_name/docs"
fi
cp -a files "$stage_dir/$bundle_name/files"
if [ -d gui ]; then
	cp -a gui "$stage_dir/$bundle_name/gui"
	find "$stage_dir/$bundle_name/gui" -type d -name __pycache__ -prune -exec rm -rf {} +
	find "$stage_dir/$bundle_name/gui" -type f -name '*.pyc' -delete
fi
chmod 755 "$stage_dir/$bundle_name/install.sh" "$stage_dir/$bundle_name/uninstall.sh"

(
	cd "$stage_dir/$bundle_name"
	find . -type f ! -name SHA256SUMS -print0 |
		sort -z |
	xargs -0 sha256sum
) > "$stage_dir/$bundle_name/SHA256SUMS"

mkdir -p "$dist_dir"
rm -f "$dist_dir/$bundle_name.tar.gz" "$dist_dir/$bundle_name.tar.gz.sha256"
tar -C "$stage_dir" --sort=name --owner=0 --group=0 --numeric-owner \
	-czf "$dist_dir/$bundle_name.tar.gz" "$bundle_name"
sha256sum "$dist_dir/$bundle_name.tar.gz" > "$dist_dir/$bundle_name.tar.gz.sha256"

printf 'Created %s\n' "$dist_dir/$bundle_name.tar.gz"
printf 'Archive SHA256: '
cut -d ' ' -f 1 "$dist_dir/$bundle_name.tar.gz.sha256"
