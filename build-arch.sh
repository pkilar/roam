#!/bin/bash
#
# Build an Arch Linux package for roam.
#
# Usage: ./build-arch.sh
#
# Requires: base-devel, linux-api-headers
#
set -euo pipefail

NAME="roam"
VERSION="1.0.0"
SRCDIR=$(cd "$(dirname "$0")" && pwd)

# Create source tarball for makepkg.
TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT

mkdir -p "${TMPDIR}/${NAME}-${VERSION}"
cp "${SRCDIR}"/{roam.c,Makefile,roam.conf,roam.sudoers,README.md,LICENSE} \
   "${TMPDIR}/${NAME}-${VERSION}/"

BUILDDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}" "${BUILDDIR}"' EXIT

cp "${SRCDIR}/archpkg/PKGBUILD" "${BUILDDIR}/"
tar czf "${BUILDDIR}/${NAME}-${VERSION}.tar.gz" \
    -C "${TMPDIR}" "${NAME}-${VERSION}"

# Update checksums and build.
cd "${BUILDDIR}"
updpkgsums 2>/dev/null || true
makepkg -sf

echo ""
echo "Done. Package:"
ls -1 "${BUILDDIR}"/${NAME}-*.pkg.tar.* 2>/dev/null

# Copy package back to source directory.
cp "${BUILDDIR}"/${NAME}-*.pkg.tar.* "${SRCDIR}/" 2>/dev/null || true
