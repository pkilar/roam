# CLAUDE.md

This file provides guidance to Claude Code when working in this repository.

## Project Overview

`roam` is now a Rust workspace. It launches a read-only troubleshooting shell under the dedicated `roam` user while a root-owned per-session broker handles approved edits, exec profiles, service actions, and the optional `sudo_passthrough` break-glass path.

The current runtime model is:

1. `sudo /usr/sbin/roam shell`
2. Root launcher loads `/etc/roam/config.toml` and `/etc/roam/policy.toml`
3. Root broker process starts with a private session socket
4. Session child creates a private mount namespace, overmounts blacklisted paths, drops to `roam`, restores `CAP_DAC_READ_SEARCH`, applies Landlock, and execs the shell
5. In-session `roam edit`, `roam exec`, `roam service`, and `roam sudo-passthrough` commands talk to the broker over inherited FDs

No file capabilities are installed on the final binary anymore.

## Workspace Layout

- `crates/roam-cli`: user-facing binary and session commands
- `crates/roam-sandbox`: privilege drop, capabilities, Landlock, mount namespace setup
- `crates/roam-broker`: per-session root broker for approved edits, exec profiles, service actions, and sudo passthrough
- `crates/roam-core`: shared config, policy, protocol, session metadata, and errors

## Build and Test

```bash
make          # cargo build --workspace --release --bins
make check    # cargo check --workspace
make test     # cargo test --workspace
make fmt      # cargo fmt --all
make clippy   # cargo clippy --workspace --all-targets -- -D warnings
```

Install locally with:

```bash
sudo make install-user
sudo make install
```

## Packaging

- RPM: `roam.spec`, `make rpm`
- Debian: `debian/`, `make deb`
- Arch: `archpkg/PKGBUILD`, `make arch`

All package definitions should stay aligned with:

- installed binary path: `/usr/sbin/roam`
- session config: `/etc/roam/config.toml`
- broker policy: `/etc/roam/policy.toml`
- sudoers file: `/etc/sudoers.d/roam`

## Configuration

`/etc/roam/config.toml` supports:

- `user`
- `writable`
- `blacklist`
- `blacklist_glob`
- `allow_degraded`
- `shell`

`/etc/roam/policy.toml` contains allowlisted edit, exec, and service profiles plus the optional `sudo_passthrough` enable flag. Keep the profile-based paths strict.
The policy file is security-sensitive and must stay root-owned and not group/world-writable; the loader now enforces that.

## Important Design Constraints

- The read-only shell must stay read-only for normal session processes.
- Blacklist enforcement is real, not cosmetic: the session overmounts blocked paths before privilege drop.
- The broker must keep the profile-based paths structured. `sudo_passthrough` is the explicit break-glass exception.
- `roam edit` uses `sudoedit`-style temp copies, diff/validation, and atomic install.
- `roam exec` runs absolute program paths from named profiles and only appends extra args when the profile allows it.
- `roam service` is restricted to allowlisted profiles and `status` / `restart` / `reload`.
- `roam sudo-passthrough` must stay non-interactive and go through `/usr/bin/sudo -n` under the original invoking identity.
- Interactive `bash` and `zsh` sessions expose `alias sudo='roam sudo-passthrough'`, but broker-side policy still rejects it unless `[sudo_passthrough] enabled = true`. Treat it as a command shortcut, not a full host `sudo` CLI emulation.
- Broker child commands are bounded by a 30 second timeout so one hung validator or profile command cannot wedge the session forever.
- Any change to session config parsing should be mirrored in broker behavior if it affects privileged actions.

## Versioning

For the Rust rewrite, use `2.x` or higher so package-manager upgrades from the older `1.0.0` C release line work normally.
When bumping the release version, update these files together:

- `Cargo.toml`
- `roam.spec`
- `archpkg/PKGBUILD`
- `debian/changelog`
- `build-rpm.sh`
- `build-arch.sh`

## Manual Verification Priorities

When changing security-sensitive code, prefer these checks after build:

```bash
sudo roam shell /usr/bin/true
sudo roam shell cat /etc/hostname
sudo roam shell sh -lc 'touch /etc/should-fail'
sudo roam shell roam service status sshd
sudo roam shell roam exec journalctl -u sshd -n 20
sudo roam shell roam edit sshd_config
```

If a root-required smoke test cannot be run in the current environment, state that explicitly.
