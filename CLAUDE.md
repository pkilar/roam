# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`roam` (Read-Only Access Mode) is a Linux security utility that creates a sandboxed shell with read-only filesystem access. It runs as a dedicated non-root user via `sudo -u roam`, uses `CAP_DAC_READ_SEARCH` (from file capabilities) to read all files, Landlock LSM for write protection, and sudo session logging for audit.

## Build

```bash
make              # builds roam
make install      # installs binary, config, sudoers (requires root)
make install-user # creates the 'roam' system user
```

No external dependencies beyond Linux kernel headers (`linux/landlock.h`, requires kernel 5.13+).

## Architecture

### roam.c (~370 lines)

Five-phase execution model, invoked via `sudo -u roam /usr/sbin/roam`:

1. **Configuration** — Parses `/etc/sysconfig/roam` (validates root ownership, no group/world-write). Settings: `ROAM_USER`, `ROAM_WRITABLE`, `ROAM_SHELL`. User's home dir is always added as writable.
2. **Capability setup** — Adds `CAP_DAC_READ_SEARCH` to inheritable set, raises it as ambient (so it survives exec), clears bounding set except `CAP_DAC_READ_SEARCH` (requires `CAP_SETPCAP` from file caps), drops `CAP_SETPCAP`. **Must happen before `PR_SET_NO_NEW_PRIVS`.**
3. **Landlock setup** — ABI detection (v1-v5), read-only ruleset on `/`, writable exceptions from config. Uses `fstat()` to select file-compatible vs directory access masks (Landlock rejects directory-only rights on file fds).
4. **Lock down** — `PR_SET_NO_NEW_PRIVS` + `landlock_restrict_self`.
5. **Exec shell** — Login shell via `argv[0]` prefix convention (`-bash`). All child processes inherit `CAP_DAC_READ_SEARCH` via ambient caps.

**File capabilities required on the binary:**
```bash
setcap cap_dac_read_search,cap_setpcap+eip /usr/sbin/roam
```

### Configuration: /etc/sysconfig/roam

```bash
ROAM_USER="roam"                        # dedicated non-root user
ROAM_WRITABLE="/dev /proc /sys /run /tmp" # writable path exceptions
# ROAM_SHELL="/bin/bash"                  # shell override
```

Virtual/pseudo filesystems (`/dev`, `/proc`, `/sys`, `/run`) are listed as writable exceptions because POSIX permissions already prevent the non-root `roam` user from writing to them. This avoids Landlock edge cases with device files while adding no security risk.

### Sudoers: /etc/sudoers.d/roam

```
Defaults:%wheel log_input, log_output
%wheel ALL=(roam) NOPASSWD: /usr/sbin/roam
```

## Key Design Details

- The `abi_mask[]` array maps ABI versions to bitmasks — each entry is `(highest_flag_for_version << 1) - 1`. This is the standard compatibility pattern from `landlock(7)`.
- `LANDLOCK_ACCESS_FS_TRAVERSE` is implicitly included in allowed access (not declared in `handled_access_fs`) — Landlock only restricts access types that are explicitly handled.
- The program never forks; it directly `exec`s into the target shell/command, so Landlock restrictions and ambient capabilities carry forward.
- **Capability ordering is critical**: ambient caps must be raised before `PR_SET_NO_NEW_PRIVS`, because some kernels block `PR_CAP_AMBIENT_RAISE` afterward. The bounding set must retain `CAP_DAC_READ_SEARCH` for ambient caps to survive exec.
- The config file undergoes security validation (root-owned, no group/world-write) to prevent a local user from injecting writable path exceptions.
