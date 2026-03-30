#!/bin/bash
#
# Build a Debian package for roam.
#
# Usage: ./build-deb.sh
#
# Requires: cargo, rustc, debhelper, dpkg-dev, make
#
set -euo pipefail

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Missing required command: $1" >&2
        exit 1
    }
}

need_cmd cargo
need_cmd dpkg-buildpackage
need_cmd make
need_cmd rustc

SRCDIR=$(cd "$(dirname "$0")" && pwd)
cd "$SRCDIR"

dpkg-buildpackage -us -uc -b

echo ""
echo "Done. Package:"
ls -1 ../roam_*.deb 2>/dev/null || echo "(check parent directory)"
