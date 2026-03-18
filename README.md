# roam - Read-Only Access Mode

A Linux security utility that gives you a shell where you can **read any file on the system** but **cannot write to anything**. Designed for safe troubleshooting on production servers.

## The Problem

Your team has root access to production servers. 95% of the work is reading logs and config files. But a single misplaced `rm -rf /var/log` or accidental paste can destroy data. Your team wants a safety net.

## The Solution

`roam` drops you into a read-only shell with full visibility:

```bash
$ sudo -u roam roam
roam: Read-Only Access Mode active (user: roam, Landlock ABI v5)
  CAP_DAC_READ_SEARCH: can read all files
  Writable exceptions: /dev /proc /sys /run /tmp /home/roam
  Type 'exit' to return.

$ cat /etc/shadow          # works - can read any file
$ less /var/log/messages   # works - including interactive pagers
$ rm /var/log/messages     # blocked by Landlock
rm: cannot remove '/var/log/messages': Permission denied
$ exit
```

## How It Works

Six layers of protection work together:

| Layer | Mechanism                | Purpose                                                                                   |
| ----- | ------------------------ | ----------------------------------------------------------------------------------------- |
| 1     | **Landlock LSM**         | Kernel-enforced read-only filesystem. Blocks all writes except configured exceptions.     |
| 2     | **CAP_DAC_READ_SEARCH**  | Bypasses file read permissions so the non-root user can read everything.                  |
| 3     | **Bounding set cleared** | Only `CAP_DAC_READ_SEARCH` can ever be acquired. No other capability escalation possible. |
| 4     | **PR_SET_NO_NEW_PRIVS**  | Blocks setuid/setgid escalation. No `su`, no `sudo`, no escape.                           |
| 5     | **Non-root user**        | Standard POSIX isolation. Cannot signal other users' processes.                           |
| 6     | **Sudo session logging** | Full audit trail via `log_input`/`log_output`.                                            |

## Requirements

- Linux kernel 5.13+ (Landlock support) - RHEL 9+, Ubuntu 22.04+, Debian 12+
- `gcc` and Linux kernel headers for building
- `sudo` for invocation and audit logging
- No external library dependencies (uses raw syscalls)

## Quick Start

```bash
# Build
make

# Create the system user
sudo make install-user

# Install binary, config, and sudoers
sudo make install

# Use it
sudo -u roam roam
```

## Installation Details

`make install` does the following:

1. Installs the binary to `/usr/sbin/roam` (mode 0755)
2. Sets file capabilities: `cap_dac_read_search,cap_setpcap+eip`
3. Installs default config to `/etc/sysconfig/roam` (won't overwrite existing)
4. Installs sudoers drop-in to `/etc/sudoers.d/roam` (won't overwrite existing)

`make install-user` creates the `roam` system user:

```bash
useradd -r -m -s /sbin/nologin roam
```

### Verify the Setup

```bash
# Check file capabilities are set
getcap /usr/sbin/roam
# Expected: /usr/sbin/roam cap_dac_read_search,cap_setpcap=eip

# Check the user exists
id roam

# Check sudoers syntax
sudo visudo -c -f /etc/sudoers.d/roam
```

## Configuration

### /etc/sysconfig/roam

```bash
# System user (must exist)
ROAM_USER="roam"

# Writable path exceptions (space-separated)
# User's home dir is ALWAYS added automatically
ROAM_WRITABLE="/dev /proc /sys /run /tmp"

# Shell override (default: /bin/bash)
# ROAM_SHELL="/bin/bash"
```

**Security**: This file must be owned by root and not group/world-writable. `roam` validates this at startup and refuses to run if the file is tampered with.

### /etc/sudoers.d/roam

```
# Enable session I/O logging for audit
Defaults:%wheel log_input, log_output

# Allow wheel members to use roam without a password
%wheel ALL=(roam) NOPASSWD: /usr/sbin/roam
```

Adjust `%wheel` to match your environment (e.g., `%admins`, specific users).

### Why Are /dev, /proc, /sys, /run Writable?

These are virtual/pseudo filesystems. Since `roam` runs as a non-privileged user, **POSIX permissions already prevent writes** to these paths. Listing them as Landlock exceptions avoids edge cases with device files (`/dev/null`, `/dev/tty`, `/dev/pts/*`) and tools that interact with `/proc/self/*`, while adding zero security risk.

## Usage

### Interactive Shell

```bash
sudo -u roam roam
```

### Run a Single Command

```bash
sudo -u roam roam cat /etc/shadow
sudo -u roam roam grep ERROR /var/log/messages
sudo -u roam roam journalctl -u sshd --no-pager
```

### Shell Alias (Optional)

Add to your `~/.bashrc`:

```bash
alias roam='sudo -u roam /usr/sbin/roam'
```

Then just:

```bash
roam                           # interactive shell
roam less /var/log/messages    # one-off command
```

### Detecting roam Inside Scripts

The `ROAM` environment variable is set to `1` inside a roam session:

```bash
if [ "$ROAM" = "1" ]; then
    echo "Running in read-only mode"
fi
```

## Architecture

### How roam Runs

```
sudo -u roam /usr/sbin/roam
  |
  |-- Phase 1: Parse /etc/sysconfig/roam (validate root ownership)
  |-- Phase 2: Capability setup
  |     |-- Add CAP_DAC_READ_SEARCH to inheritable set
  |     |-- Raise as ambient capability
  |     |-- Clear bounding set (defense-in-depth)
  |     '-- Drop CAP_SETPCAP
  |-- Phase 3: Landlock setup
  |     |-- Detect ABI version (v1-v5)
  |     |-- Create read-only ruleset for /
  |     '-- Add writable exceptions from config
  |-- Phase 4: Lock down
  |     |-- PR_SET_NO_NEW_PRIVS
  |     '-- landlock_restrict_self
  '-- Phase 5: Launch bash (login shell)
        |
        '-- All child processes inherit:
              - CAP_DAC_READ_SEARCH (via ambient caps)
              - Landlock read-only restrictions
              - no_new_privs flag
```

### Capability Inheritance

The critical challenge is passing `CAP_DAC_READ_SEARCH` through to bash and all descendant processes. This is achieved via **ambient capabilities**:

1. The binary has file capabilities (`setcap cap_dac_read_search,cap_setpcap+eip`)
2. When sudo runs it as the `roam` user, the process gets `CAP_DAC_READ_SEARCH` in its effective/permitted sets
3. `roam` adds it to the inheritable set and raises it as ambient
4. After launching bash, the ambient cap becomes effective/permitted in bash
5. Every child process (`cat`, `less`, `grep`, ...) inherits it the same way

**Ordering constraint**: Ambient capabilities must be raised **before** `PR_SET_NO_NEW_PRIVS` is set, because some kernel versions block `PR_CAP_AMBIENT_RAISE` afterward.

### Landlock Access Masks

Landlock rejects directory-only access rights (e.g., `MAKE_DIR`, `REMOVE_DIR`) on non-directory file descriptors. `roam` uses `fstat()` on each writable exception path and selects the appropriate mask:

- **Directories**: Full read+write+create+delete access
- **Files**: Read+write+truncate only (file-compatible rights)

### What Cannot Be Done in a roam Session

- Write, create, rename, or delete files on persistent filesystems
- Escalate privileges (`su`, `sudo`, setuid binaries)
- Gain new capabilities beyond `CAP_DAC_READ_SEARCH`
- Signal processes owned by other users
- Load kernel modules, mount filesystems, or modify system state

### What CAN Be Done

- Read any file on any filesystem (local, NFS, Lustre, etc.)
- Use interactive tools: `less`, `vim` (read-only), `top`, `htop`, `journalctl`
- Run diagnostic commands: `ps`, `netstat`, `ss`, `ip`, `df`, `free`
- Write to `/tmp` (for tools that need temp files)
- Write to the roam user's home directory (shell history, etc.)

## Packaging Notes

### RPM

File capabilities are lost when a binary is replaced. In your `.spec` file:

```spec
%post
setcap cap_dac_read_search,cap_setpcap+eip /usr/sbin/roam

%caps(cap_dac_read_search,cap_setpcap=eip) /usr/sbin/roam
```

### SELinux

On RHEL with SELinux enforcing, verify the binary's SELinux context allows file capabilities. If needed:

```bash
semanage fcontext -a -t bin_t /usr/sbin/roam
restorecon -v /usr/sbin/roam
```

## Troubleshooting

### "CAP_DAC_READ_SEARCH not available"

File capabilities aren't set on the binary:
```bash
sudo setcap cap_dac_read_search,cap_setpcap+eip /usr/sbin/roam
```

### "must run as 'roam'"

You need to use sudo to switch users:
```bash
sudo -u roam /usr/sbin/roam
```

### "Landlock not supported by this kernel"

Your kernel is older than 5.13. Check with `uname -r`. Landlock may also be disabled via boot parameter or kernel config.

### "This account is currently not available" from less/vim

The `SHELL` environment variable is set to `/sbin/nologin`. This should be handled automatically by `roam`, but if you see it, set `ROAM_SHELL=/bin/bash` in `/etc/sysconfig/roam`.

### Permission denied writing to /dev/null

Ensure `/dev` is in the `ROAM_WRITABLE` list in `/etc/sysconfig/roam`.

### Config file validation failure

The config file must be owned by root (uid 0) and not group or world-writable:
```bash
sudo chown root:root /etc/sysconfig/roam
sudo chmod 644 /etc/sysconfig/roam
```

## License

MIT
