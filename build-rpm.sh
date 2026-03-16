#!/bin/bash
#
# Build an RPM package for roam.
#
# Usage: ./build-rpm.sh
#
# Requires: rpm-build, gcc, make, kernel-headers
#
set -euo pipefail

NAME="roam"
VERSION="1.0.0"
TARBALL="${NAME}-${VERSION}.tar.gz"

# Set up rpmbuild directory structure.
RPMBUILD="${HOME}/rpmbuild"
mkdir -p "${RPMBUILD}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Create source tarball with the expected directory prefix.
SRCDIR=$(cd "$(dirname "$0")" && pwd)
TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT

mkdir -p "${TMPDIR}/${NAME}-${VERSION}"
cp "${SRCDIR}"/{roam.c,Makefile,roam.conf,roam.sudoers,README.md,LICENSE} \
   "${TMPDIR}/${NAME}-${VERSION}/"

tar czf "${RPMBUILD}/SOURCES/${TARBALL}" \
    -C "${TMPDIR}" "${NAME}-${VERSION}"

# Copy spec file.
cp "${SRCDIR}/roam.spec" "${RPMBUILD}/SPECS/"

# Build the RPM.
rpmbuild -ba "${RPMBUILD}/SPECS/roam.spec"

echo ""
echo "Done. Packages:"
find "${RPMBUILD}/RPMS" -name "${NAME}-*.rpm" -print
find "${RPMBUILD}/SRPMS" -name "${NAME}-*.rpm" -print
