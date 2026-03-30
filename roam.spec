Name:           roam
Version:        2.0.0
Release:        1%{?dist}
Summary:        Read-Only Access Mode - safe troubleshooting shell

License:        MIT
URL:            https://github.com/pkilar/roam
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  make
BuildRequires:  rust
Requires:       sudo
Requires(pre):  shadow-utils

%description
roam (Read-Only Access Mode) is a Linux security utility that creates a
sandboxed troubleshooting shell with a root launcher, a read-only
session running as the dedicated roam user, and a per-session privileged
broker for approved edits, exec profiles, service actions, and optional
sudo passthrough. It uses CAP_DAC_READ_SEARCH to read system files,
Landlock LSM for write protection, blacklist overmounts for sensitive
paths, and sudo session logging for audit.

Designed for safe troubleshooting on production servers where teams need
to view logs and config files without risk of accidental modification.

%prep
%setup -q

%build
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
make release

%install
install -Dm0755 target/release/roam %{buildroot}%{_sbindir}/roam
install -Dm0644 roam.config.toml %{buildroot}%{_sysconfdir}/roam/config.toml
install -Dm0644 roam.policy.toml %{buildroot}%{_sysconfdir}/roam/policy.toml
install -Dm0440 roam.sudoers %{buildroot}%{_sysconfdir}/sudoers.d/roam

%pre
getent passwd roam >/dev/null 2>&1 || \
    useradd -r -m -s /sbin/nologin -c "Read-Only Access Mode" roam

%files
%license LICENSE
%doc README.md ARCHITECTURE.md
%attr(0755,root,root) %{_sbindir}/roam
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/roam/config.toml
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/roam/policy.toml
%config(noreplace) %attr(0440,root,root) %{_sysconfdir}/sudoers.d/roam

%changelog
* Sat Mar 28 2026 Paul Kilar <pkilar@gmail.com> - 2.0.0-1
- Rewrite roam and the privileged sidecar in Rust

* Sun Mar 16 2025 Paul Kilar <pkilar@gmail.com> - 1.0.0-1
- Initial package
