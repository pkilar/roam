#!/bin/bash
#
# Build a Debian package for roam.
#
# Usage: ./build-deb.sh
#
# Requires: debhelper, dpkg-dev, gcc, linux-libc-dev
#
set -euo pipefail

SRCDIR=$(cd "$(dirname "$0")" && pwd)
cd "$SRCDIR"

dpkg-buildpackage -us -uc -b

echo ""
echo "Done. Package:"
ls -1 ../roam_*.deb 2>/dev/null || echo "(check parent directory)"
