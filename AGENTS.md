# Repository Guidelines

## Project Structure & Module Organization

This repository is a Rust workspace. `crates/roam-cli` contains the user-facing `roam` binary and in-session subcommands. `crates/roam-sandbox` owns privilege drop, capabilities, Landlock, mount-namespace setup, and blacklist overmounts. `crates/roam-broker` implements the per-session root helper for allowlisted edits, exec profiles, service actions, and the optional `sudo_passthrough` path. `crates/roam-core` holds shared config, policy, protocol, and error types. Runtime defaults live in `roam.config.toml`, `roam.policy.toml`, and `roam.sudoers`. Packaging assets remain split by target: `roam.spec`, `debian/`, and `archpkg/PKGBUILD`.

## Build, Test, and Development Commands

Use `make` or `make release` to build the release binary and stage `./roam`. Use `make debug` for `target/debug/roam`, `make check` for `cargo check --workspace`, `make test` for `cargo test --workspace`, `make fmt` for `cargo fmt --all`, and `make clippy` for `cargo clippy --workspace --all-targets -- -D warnings`. Install locally with `sudo make install-user` and `sudo make install`. Package helpers are `make rpm`, `make deb`, and `make arch`.

## Coding Style & Naming Conventions

Follow standard Rust style and keep the workspace `cargo fmt` clean. Prefer small, explicit structs and enums for broker protocol and config parsing. Keep security-sensitive code straightforward: no shell interpolation, no broad “blacklist” logic in place of strict allowlists for broker actions, and treat `sudo_passthrough` as an explicit break-glass path rather than the default model. Use `snake_case` for Rust items and keep comments focused on capability, mount, or Landlock ordering where that logic is subtle.

## Testing Guidelines

Every change must pass `make check` and `make test`. Add focused `#[test]` coverage in the relevant crate when changing config parsing, blacklist matching, policy resolution, or protocol behavior. For sandbox or broker changes, also run root-required smoke tests when possible, for example `sudo roam shell /usr/bin/true` and a denied write under `/etc`.

## Commit & Pull Request Guidelines

Use short imperative commit subjects, matching the existing history. Keep each commit scoped to one behavioral change. PRs should summarize security impact, user-visible workflow changes, and the exact commands used for verification. When package metadata changes, mention which of `roam.spec`, `debian/`, and `archpkg/PKGBUILD` were updated.
