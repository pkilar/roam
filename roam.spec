Name:           roam
Version:        1.0.0
Release:        1%{?dist}
Summary:        Read-Only Access Mode - safe troubleshooting shell

License:        MIT
URL:            https://github.com/pkilar/roam
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  kernel-headers
Requires:       sudo
Requires(pre):  shadow-utils

%description
roam (Read-Only Access Mode) is a Linux security utility that creates a
sandboxed shell with read-only filesystem access. It runs as a dedicated
non-root user via sudo, uses CAP_DAC_READ_SEARCH to read all files,
Landlock LSM for write protection, and sudo session logging for audit.

Designed for safe troubleshooting on production servers where teams need
to view logs and config files without risk of accidental modification.

%prep
%setup -q

%build
make %{?_smp_mflags} CC=gcc CFLAGS="%{optflags}"

%install
install -Dm0755 roam %{buildroot}%{_sbindir}/roam
install -Dm0644 roam.conf %{buildroot}%{_sysconfdir}/sysconfig/roam
install -Dm0440 roam.sudoers %{buildroot}%{_sysconfdir}/sudoers.d/roam

%pre
getent passwd roam >/dev/null 2>&1 || \
    useradd -r -m -s /sbin/nologin -c "Read-Only Access Mode" roam

%post
# Set file capabilities on the binary.
# Must be done in %%post because rpmbuild strips xattrs during packaging.
setcap cap_dac_read_search,cap_setpcap+eip %{_sbindir}/roam || \
    echo "WARNING: failed to set file capabilities on %{_sbindir}/roam" >&2

%verifyscript
# Verify file capabilities are intact.
getcap %{_sbindir}/roam | grep -q cap_dac_read_search || \
    echo "WARNING: file capabilities missing on %{_sbindir}/roam — run: setcap cap_dac_read_search,cap_setpcap+eip %{_sbindir}/roam" >&2

%files
%license LICENSE
%doc README.md
%attr(0755,root,root) %{_sbindir}/roam
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/sysconfig/roam
%config(noreplace) %attr(0440,root,root) %{_sysconfdir}/sudoers.d/roam

%changelog
* Sun Mar 16 2025 Paul Kilar <pkilar@gmail.com> - 1.0.0-1
- Initial package
