#!/bin/bash
#
# Build an Arch Linux package for roam.
#
# Usage: ./build-arch.sh
#
# Requires: base-devel, cargo, rust
#
set -euo pipefail

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Missing required command: $1" >&2
        exit 1
    }
}

need_cmd cargo
need_cmd make
need_cmd makepkg
need_cmd rustc
need_cmd tar

NAME="roam"
VERSION="2.0.0"
SRCDIR=$(cd "$(dirname "$0")" && pwd)

# Create source tarball for makepkg.
BUILDDIR=$(mktemp -d)
trap 'rm -rf "${BUILDDIR}"' EXIT

cp "${SRCDIR}/archpkg/PKGBUILD" "${BUILDDIR}/"
tar czf "${BUILDDIR}/${NAME}-${VERSION}.tar.gz" \
    --exclude-vcs \
    --transform "s,^,${NAME}-${VERSION}/," \
    -C "${SRCDIR}" \
    Cargo.toml Cargo.lock Makefile README.md ARCHITECTURE.md LICENSE \
    roam.config.toml roam.policy.toml roam.sudoers \
    build-rpm.sh build-deb.sh build-arch.sh \
    archpkg debian crates shell

# Update checksums and build.
cd "${BUILDDIR}"
updpkgsums 2>/dev/null || true
makepkg -sf

echo ""
echo "Done. Package:"
ls -1 "${BUILDDIR}"/${NAME}-*.pkg.tar.* 2>/dev/null

# Copy package back to source directory.
cp "${BUILDDIR}"/${NAME}-*.pkg.tar.* "${SRCDIR}/" 2>/dev/null || true
