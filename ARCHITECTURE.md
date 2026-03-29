# Architecture

This document explains the Rust implementation of `roam`, including how the read-only shell and the privileged broker communicate.

## Overview

`roam` is a root-launched troubleshooting environment with two cooperating processes:

- A read-only session process that runs as the dedicated `roam` user.
- A per-session broker process that stays privileged and handles a small set of approved actions.

The code is split across these crates:

- `crates/roam-cli`: CLI entrypoints, broker spawning, in-session client commands
- `crates/roam-sandbox`: privilege drop, capability setup, Landlock, blacklist mounts, shell exec
- `crates/roam-broker`: privileged edit, exec, service, and sudo-passthrough broker
- `crates/roam-core`: shared config, policy, protocol, and session metadata

## Process Model

Starting `sudo roam shell` creates this process tree:

```text
root: roam shell
├── root: roam __broker
└── roam user: target shell or command
```

The root launcher in `crates/roam-cli/src/main.rs` loads:

- `/etc/roam/config.toml` into `SessionConfig`
- `/etc/roam/policy.toml` into `Policy`
- session metadata such as `SUDO_USER`, `SUDO_UID`, `SUDO_GID`, and the current tty

It then creates:

- a Unix `socketpair()` for shell-to-broker RPC
- a `memfd` lock used to serialize access to the shared broker socket

The broker side of the socket is passed to the broker process on fd `3`. The shell side is carried into the sandboxed session and exposed through environment variables.

## Session Startup Sequence

The session path in `crates/roam-sandbox/src/lib.rs` is intentionally ordered:

1. Load the configured `roam` user and build the writable-path allowlist.
2. Apply blacklist overmounts in a private mount namespace.
3. Drop to the `roam` uid and gid.
4. Restore `CAP_DAC_READ_SEARCH` so the session can read protected files.
5. Detect the Landlock ABI and reject degraded kernels unless explicitly allowed.
6. Build a Landlock ruleset with:
   - global read and execute access from `/`
   - read-write exceptions for configured writable paths
7. Close all non-essential file descriptors except:
   - the Landlock ruleset fd during setup
   - the broker socket fd
   - the broker lock fd
8. Set `PR_SET_NO_NEW_PRIVS` and apply `landlock_restrict_self`.
9. Export session environment:
   - `ROAM=1`
   - `ROAM_BROKER_FD=<n>`
   - `ROAM_BROKER_LOCK_FD=<n>`
   - `HOME`
   - `SHELL`
10. For interactive `bash` and `zsh` sessions, generate per-session startup files under `/tmp/roam-shell-<session-id>` that install `alias sudo='roam sudo-passthrough'`.
11. Clear `FD_CLOEXEC` on the broker and lock fds so the shell and its children inherit them.
12. `exec()` the requested command or login shell.

The session remains read-only for normal processes. Writable access is limited to configured exceptions such as `/tmp`, `/run`, and the session user home directory if it is considered safe.

## Blacklist Enforcement

Blacklist entries come from:

- `blacklist`
- `blacklist_glob`

Exact paths and glob matches are canonicalized up front. Enforcement has two layers:

- In the session, file-like paths are bind-mounted over an empty read-only `memfd`, and directory paths are overmounted with a tiny read-only `tmpfs`.
- In the broker, edit requests are rejected if the target path matches the blacklist.

This means a blacklisted file is both hidden from the shell and blocked from privileged edit flows.

## Broker Lifecycle

The broker entrypoint is `roam __broker`. The launcher passes metadata through environment variables:

- `ROAM_SESSION_ID`
- `ROAM_SESSION_USER`
- `ROAM_SESSION_UID`
- `ROAM_SESSION_GID`
- `ROAM_POLICY_PATH`
- optional `ROAM_INVOKING_USER`
- optional `ROAM_INVOKING_UID`
- optional `ROAM_INVOKING_GID`
- optional `ROAM_INVOKING_TTY`

On startup the broker:

- loads the session config to reuse blacklist rules
- loads `policy.toml`
- creates a per-session working directory under the system temp directory
- creates a per-session backup directory under `/var/lib/roam/backups/<session-id>`
- logs session start and later privileged actions to syslog with facility `authpriv`
- enforces a 30 second timeout for validator, exec, service, and sudo-passthrough child commands

The broker runs until the session closes its end of the Unix socket. EOF on the socket is treated as the session ending.

## Shell-to-Broker Communication

### Transport

The shell and broker talk over a private Unix stream socket created with `socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, ...)`.

This is not a global socket under `/run`. Each session gets its own private connection.

### Framing

Message framing lives in `crates/roam-core/src/protocol.rs`:

- Each message is JSON.
- Each JSON blob is prefixed with a 4-byte big-endian length.
- Maximum frame size is 1 MiB.

This keeps the protocol simple and avoids shell parsing or text scraping.

### Request and Response Types

Requests:

- `Ping`
- `BeginEdit { profile }`
- `Exec { profile, args }`
- `InspectEdit { ticket }`
- `CommitEdit { ticket }`
- `AbortEdit { ticket }`
- `ServiceAction { profile, action }`
- `SudoPassthrough { argv }`

Responses:

- `Pong`
- `EditStarted { ticket, target_path, candidate_path }`
- `EditInspection { changed, diff, validator }`
- `EditCommitted { backup_path }`
- `EditAborted`
- `ExecResult { status, stdout, stderr }`
- `ServiceResult { status, stdout, stderr }`
- `Error { message }`

### Client Access from the Shell

In-session `roam edit`, `roam exec`, `roam service`, and `roam sudo-passthrough` commands reconstruct a client connection from the inherited environment:

1. Verify `ROAM=1`.
2. Read `ROAM_BROKER_FD` and `ROAM_BROKER_LOCK_FD`.
3. Duplicate the broker fd with `F_DUPFD_CLOEXEC`.
4. Acquire an exclusive `flock()` on the lock fd.
5. Send one request and wait for one response.
6. Release the lock when the round trip completes.

The shared lock matters because every process in the shell inherits the same underlying broker socket. The lock prevents concurrent commands from interleaving JSON frames on that single connection.

### `sudo` Convenience in the Shell

When an interactive `bash` or `zsh` session starts, `roam-sandbox` writes temporary shell startup files under `/tmp/roam-shell-<session-id>` and installs:

```sh
alias sudo='roam sudo-passthrough'
```

So inside the `roam` shell, the operator can type:

```bash
sudo systemctl restart sshd.service
```

That expands to `roam sudo-passthrough ...`. The alias is only present in interactive `bash` and `zsh` sessions, and the broker still rejects the request unless `[sudo_passthrough] enabled = true` in `policy.toml`. Other shells must use the explicit `roam sudo-passthrough -- ...` command. This is a command shortcut, not a full reimplementation of host `sudo` option parsing.

## Edit Flow

`roam edit <profile>` uses `sudoedit`-style semantics:

1. The shell sends `BeginEdit`.
2. The broker resolves the named edit profile from `policy.toml`.
3. The broker rejects the request if the target is blacklisted.
4. The broker copies the target file into a per-session candidate file and `chown`s that candidate to the session uid and gid.
5. The broker returns `EditStarted` with a ticket and candidate path.
6. The shell launches `$VISUAL`, `$EDITOR`, or `/usr/bin/vi` against the candidate file.
7. After the editor exits, the shell sends `InspectEdit`.
8. The broker computes:
   - whether the file changed
   - a unified diff using `similar::TextDiff`
   - optional validator output after replacing `{candidate}` in the validator argv
9. The shell shows the diff and validator result.
10. If the operator confirms, the shell sends `CommitEdit`.
11. The broker re-runs the validator, writes a temp file next to the target, sets owner, group, and mode, fsyncs it, saves a backup, renames the temp file into place, then fsyncs the parent directory.
12. The broker returns the backup path.

If the editor exits non-zero, validation fails, or the operator declines installation, the shell sends `AbortEdit` and the broker deletes the candidate file.

## Exec Profile Flow

`roam exec <profile> [args...]` is the profile-based command runner:

1. The shell optionally confirms the request.
2. The shell sends `Exec { profile, args }`.
3. The broker resolves the named exec profile from `policy.toml`.
4. The broker appends extra CLI args only if `allow_extra_args = true`.
5. The broker runs the configured absolute program path with `env_clear()` and no shell.
6. If the profile names a user or group, the broker switches identity before `exec`.
7. The broker returns exit status, stdout, and stderr as `ExecResult`.

This is the preferred generic execution path because the executable and its base argv remain policy-defined.

## Service Flow

`roam service <status|restart|reload> <profile>` is simpler:

1. The shell optionally asks for confirmation for `restart` and `reload`.
2. The shell sends `ServiceAction { profile, action }`.
3. The broker checks that:
   - the service profile exists
   - the requested action is listed in that profile
4. The broker runs `/usr/bin/systemctl <action> <unit>` with `env_clear()` and no shell.
5. The broker returns exit status, stdout, and stderr.

## Sudo Passthrough Flow

`roam sudo-passthrough -- <command> [args...]` is the break-glass path:

1. The shell optionally confirms the request.
2. The shell sends `SudoPassthrough { argv }`.
3. The broker checks that `policy.toml` has `[sudo_passthrough] enabled = true`.
4. The broker reconstructs the original invoking identity from `SUDO_USER`, `SUDO_UID`, and `SUDO_GID`.
5. The broker resolves the invoking user supplemental groups.
6. The broker drops to that user identity and runs `/usr/bin/sudo -n -- <argv...>`.
7. The broker returns exit status, stdout, and stderr as `ExecResult`.

This path delegates authorization to the host `sudoers` policy. It is intentionally separate from exec profiles because it can be much broader.

## Policy Model

`/etc/roam/policy.toml` defines named allowlists and the optional passthrough flag.

Edit profiles contain:

- `path`
- optional `owner`
- optional `group`
- optional `mode`
- optional `validator` argv

Service profiles contain:

- `unit`
- allowed `actions`

Exec profiles contain:

- `program`
- fixed `args`
- `allow_extra_args`
- optional `user`
- optional `group`

The optional passthrough section contains:

- `enabled`

All edit paths and exec program paths must be absolute. Service units must be named explicitly. Free-form command lines are only accepted through the explicit `sudo_passthrough` break-glass path.

## Auditing and Failure Handling

Both session startup and broker actions are logged to syslog using `LOG_AUTHPRIV`.

Logged events include:

- session open
- broker start and exit
- committed edits
- exec profile runs
- service actions
- sudo passthrough runs

On exit, the broker also removes its per-session work directory and the per-session shell runtime directory under `/tmp/roam-shell-<session-id>`.

The broker converts internal failures into protocol `Error { message }` responses so the shell can show a clear operator-facing error without crashing the session.

## Security Boundaries

Important invariants in the current design:

- Only the broker retains privilege.
- The shell keeps read visibility through `CAP_DAC_READ_SEARCH`, not through uid `0`.
- `PR_SET_NO_NEW_PRIVS` prevents session processes from acquiring more privilege later.
- Landlock enforces filesystem write denial after setup.
- Blacklist rules are enforced in both the session and the broker.
- Edit, service, and exec profile actions are policy-based and structured, not shell-based.
- `sudo_passthrough` is the only open command path, and it re-enters host `sudo` policy under the original operator identity.
- The shared broker socket is private to one session, not globally discoverable.

If you change the protocol, fd inheritance, or blacklist semantics, update both this document and the corresponding code in `roam-cli`, `roam-sandbox`, and `roam-broker`.
