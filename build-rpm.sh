#!/bin/bash
#
# Build an RPM package for roam.
#
# Usage: ./build-rpm.sh
#
# Requires: cargo, rustc, rpm-build, make
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
need_cmd rpmbuild
need_cmd rustc
need_cmd tar

NAME="roam"
VERSION="2.0.0"
TARBALL="${NAME}-${VERSION}.tar.gz"

# Set up rpmbuild directory structure.
RPMBUILD="${HOME}/rpmbuild"
mkdir -p "${RPMBUILD}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Create source tarball with the expected directory prefix.
SRCDIR=$(cd "$(dirname "$0")" && pwd)
tar czf "${RPMBUILD}/SOURCES/${TARBALL}" \
    --exclude-vcs \
    --transform "s,^,${NAME}-${VERSION}/," \
    -C "${SRCDIR}" \
    Cargo.toml Cargo.lock Makefile README.md ARCHITECTURE.md LICENSE \
    roam.config.toml roam.policy.toml roam.sudoers \
    build-rpm.sh build-deb.sh build-arch.sh \
    archpkg debian crates

# Copy spec file.
cp "${SRCDIR}/roam.spec" "${RPMBUILD}/SPECS/"

# Build the RPM.
rpmbuild -ba "${RPMBUILD}/SPECS/roam.spec"

echo ""
echo "Done. Packages:"
find "${RPMBUILD}/RPMS" -name "${NAME}-*.rpm" -print
find "${RPMBUILD}/SRPMS" -name "${NAME}-*.rpm" -print
