# roam - Read-Only Access Mode

`roam` is a Linux troubleshooting utility for operators who already have root access but want a safer workflow. It starts a read-only shell under a dedicated non-root user, keeps full read visibility with `CAP_DAC_READ_SEARCH`, enforces write denial with Landlock, and exposes a narrow in-session broker for approved edits, exec profiles, service actions, and an optional `sudo` passthrough path.

Detailed internals are documented in [ARCHITECTURE.md](ARCHITECTURE.md).

## Why roam exists

Production troubleshooting is usually read-heavy: logs, configs, process state, and service status. The risk comes from accidental writes, not lack of privilege. `roam` reduces that risk without forcing operators to leave the shell when they need a carefully controlled edit, restart, or privileged command.

## What the current design does

- `sudo /usr/sbin/roam shell` starts a root launcher.
- The launcher spawns:
  - a read-only session as the `roam` user
  - a per-session privileged broker for approved actions
- The session:
  - can read protected files with `CAP_DAC_READ_SEARCH`
  - is locked down with Landlock and `PR_SET_NO_NEW_PRIVS`
  - can hide sensitive paths with blacklist overmounts
- The broker:
  - supports `roam edit <profile>` with `sudoedit`-style temp copies, diffs, validators, and atomic installs
  - supports `roam exec <profile> [args...]` for allowlisted command profiles
  - supports `roam service <status|restart|reload> <profile>` for allowlisted systemd units
  - can optionally support `roam sudo-passthrough -- <command> [args...]`; interactive `bash` and `zsh` sessions also install a local `sudo` alias for that path

No file capabilities are installed on the shipped binary. The root launcher configures the session process directly.

## Requirements

- Linux kernel 5.19+ recommended for Landlock ABI v3+
- `sudo`
- Rust toolchain for local builds: `cargo`, `rustc`
- Root access for installation and real session testing

## Quick Start

```bash
# Build
make

# Create the session user
sudo make install-user

# Install binary, session config, policy, and sudoers
sudo make install

# Start a read-only shell
sudo roam shell
```

Inside the session:

```bash
cat /etc/ssh/sshd_config
journalctl -u sshd --no-pager
roam edit sshd_config
roam exec journalctl -u sshd -n 50
roam service restart sshd
# Optional: works in interactive bash/zsh sessions when [sudo_passthrough] enabled = true
sudo id
```

## Configuration

### `/etc/roam/config.toml`

Session settings:

```toml
user = "roam"
writable = ["/dev", "/proc", "/sys", "/run", "/tmp"]
blacklist = ["/etc/shadow", "/dev/sda"]
blacklist_glob = ["/dev/sd[a-z]", "/etc/*.key"]
allow_degraded = false
shell = "/bin/bash"
```

- `blacklist` blocks exact paths or whole directory trees.
- `blacklist_glob` expands absolute glob patterns to concrete paths when the session starts.
- Blacklisted paths are hidden inside the session and are also rejected by the broker for edits.

### `/etc/roam/policy.toml`

Broker allowlist for edits, exec profiles, and service actions:

```toml
[edit.sshd_config]
path = "/etc/ssh/sshd_config"
validator = ["/usr/sbin/sshd", "-t", "-f", "{candidate}"]

[service.sshd]
unit = "sshd.service"
actions = ["status", "restart", "reload"]

[exec.journalctl]
program = "/usr/bin/journalctl"
args = ["--no-pager"]
allow_extra_args = true

[sudo_passthrough]
enabled = false
```

Edit, service, and exec actions all require named profiles. `sudo_passthrough` is optional, disabled by default, and acts as a break-glass path that re-enters `sudo` under the original operator identity. In interactive `bash` and `zsh` sessions, `roam` installs `alias sudo='roam sudo-passthrough'` for convenience, but the broker still fails closed unless `[sudo_passthrough] enabled = true`. Other shells should use the explicit `roam sudo-passthrough -- ...` command. The alias is only a shortcut for `sudo <command> ...`; it does not emulate host `sudo` option parsing.
The policy file must be owned by `root` and must not be group/world-writable; `roam` now refuses to load an unsafe policy file.

### `/etc/sudoers.d/roam`

```sudoers
Defaults:%wheel log_input, log_output
%wheel ALL=(root) NOPASSWD: /usr/sbin/roam shell, /usr/sbin/roam shell *
```

## Architecture

1. The root launcher loads `/etc/roam/config.toml` and `/etc/roam/policy.toml`.
2. It creates a per-session broker socket and lock FD.
3. It spawns the broker as a root-owned helper.
4. It creates a private mount namespace, overmounts blacklisted paths, drops to the `roam` user, restores `CAP_DAC_READ_SEARCH`, applies Landlock, and `exec`s the target shell or command.
5. In-session `roam edit`, `roam exec`, `roam service`, and `roam sudo-passthrough` commands talk to the broker over the inherited socket.

## Build and Package

Local development:

```bash
make
make check
make test
make fmt
make clippy
```

Packaging helpers:

```bash
make rpm
make deb
make arch
```

Package manifests live in:

- `roam.spec`
- `debian/`
- `archpkg/PKGBUILD`

## Verification

Verified in this repository:

- `make`
- `make check`
- `make test`
- `make clippy`
- `make install DESTDIR=/tmp/...`
- `make arch`
- `HOME=/tmp ./build-rpm.sh`
- `cargo check --workspace`
- `cargo test --workspace`

Recommended root smoke tests after installation:

```bash
sudo roam shell /usr/bin/true
sudo roam shell cat /etc/hostname
sudo roam shell sh -lc 'touch /etc/should-fail'   # should fail
sudo roam shell cat /etc/shadow                    # should fail if blacklisted
```

## Upgrade Notes

The Rust rewrite is versioned as `2.0.0` so package-manager upgrades from the older `1.0.0` C release line work normally. Upgrade the package in place with your usual RPM, Arch, or Debian tooling; no epoch override or downgrade flag should be needed.

## Troubleshooting

### `permission denied: use sudo to start a roam session`

Start the session with:

```bash
sudo roam shell
```

### `Landlock not supported by this kernel`

Use a kernel with Landlock support. Full read-only enforcement requires ABI v3+.
If you intentionally need degraded mode, set `allow_degraded = true` in `/etc/roam/config.toml`.

### Blacklist glob matched no paths

Blacklist globs are expanded when the session starts. Check the pattern against the current filesystem contents.

### `build-deb.sh` reports `Missing required command: dpkg-buildpackage`

Install Debian packaging tools such as `dpkg-dev` and `debhelper`, then rerun `make deb`.

### Validator failed during `roam edit`

The candidate file was edited, diffed, and then rejected by the profile validator. Fix the file and retry, or update the policy profile if the validator is wrong.

### Commands time out unexpectedly

Broker-run validators, exec profiles, service actions, and sudo passthrough commands now have a 30 second execution timeout. If a command legitimately needs longer, it must be redesigned or the timeout logic must be adjusted in code.

### `sudo passthrough is disabled in policy.toml`

Set `[sudo_passthrough] enabled = true` in `/etc/roam/policy.toml` if you want the break-glass path available inside the session.

## License

MIT
