use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{Error, Result};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/roam/config.toml";
pub const DEFAULT_USER: &str = "roam";
pub const DEFAULT_WRITABLE: &str = "/dev /proc /sys /run /tmp";

#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub user: String,
    pub shell: Option<PathBuf>,
    pub writable: Vec<PathBuf>,
    pub blacklist: Vec<BlockedPath>,
    pub allow_degraded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlockedPath {
    pub path: PathBuf,
    pub kind: BlockedPathKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BlockedPathKind {
    Directory,
    FileLike,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct RawSessionConfig {
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    shell: Option<String>,
    #[serde(default)]
    writable: Option<PathList>,
    #[serde(default)]
    blacklist: Option<PathList>,
    #[serde(default)]
    blacklist_glob: Option<PathList>,
    #[serde(default)]
    allow_degraded: Option<Boolish>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum PathList {
    List(Vec<String>),
    String(String),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum Boolish {
    Bool(bool),
    Integer(i64),
    String(String),
}

impl SessionConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = load_raw_config(path.as_ref())?;
        Ok(finalize_raw_config(raw.unwrap_or_default()))
    }
}

impl PathList {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::List(values) => values,
            Self::String(value) => value
                .split_ascii_whitespace()
                .map(ToOwned::to_owned)
                .collect(),
        }
    }
}

impl Boolish {
    fn into_bool(self) -> bool {
        match self {
            Self::Bool(value) => value,
            Self::Integer(value) => value != 0,
            Self::String(value) => matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "yes" | "true" | "on"
            ),
        }
    }
}

fn load_raw_config(path: &Path) -> Result<Option<RawSessionConfig>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let metadata = fs::metadata(path)?;
    validate_config_file_metadata(path, metadata.uid(), metadata.mode())?;
    parse_toml_config(path, &contents).map(Some)
}

fn validate_config_file_metadata(path: &Path, uid: u32, mode: u32) -> Result<()> {
    if uid != 0 {
        return Err(Error::Config(format!(
            "{} must be owned by root",
            path.display()
        )));
    }
    if mode & 0o022 != 0 {
        return Err(Error::Config(format!(
            "{} must not be group/world-writable",
            path.display()
        )));
    }
    Ok(())
}

fn parse_toml_config(path: &Path, contents: &str) -> Result<RawSessionConfig> {
    toml::from_str(contents).map_err(|err| Error::Config(format!("{}: {err}", path.display())))
}

fn finalize_raw_config(raw: RawSessionConfig) -> SessionConfig {
    let mut blacklist = Vec::new();
    if let Some(paths) = raw.blacklist {
        blacklist.extend(parse_blocked_path_entries(paths.into_vec(), "blacklist"));
    }
    if let Some(patterns) = raw.blacklist_glob {
        blacklist.extend(parse_blocked_glob_entries(
            patterns.into_vec(),
            "blacklist glob",
        ));
    }

    let writable = raw.writable.map(PathList::into_vec).unwrap_or_else(|| {
        DEFAULT_WRITABLE
            .split_ascii_whitespace()
            .map(ToOwned::to_owned)
            .collect()
    });

    SessionConfig {
        user: raw.user.unwrap_or_else(|| DEFAULT_USER.to_string()),
        shell: raw
            .shell
            .as_deref()
            .and_then(|value| canonicalize_path(value, "shell")),
        writable: parse_path_entries(writable, "writable"),
        blacklist: dedupe_blocked_paths(blacklist),
        allow_degraded: raw.allow_degraded.map(Boolish::into_bool).unwrap_or(false),
    }
}

pub fn canonicalize_path(raw: &str, what: &str) -> Option<PathBuf> {
    let path = Path::new(raw);
    if !path.is_absolute() {
        eprintln!("roam: {what} path must be absolute: {raw}");
        return None;
    }
    match fs::canonicalize(path) {
        Ok(resolved) => Some(resolved),
        Err(err) => {
            eprintln!("roam: {what} path '{raw}': {err} (skipped)");
            None
        }
    }
}

pub fn is_safe_home_path(path: &Path) -> bool {
    if path == Path::new("/") {
        return false;
    }
    !matches!(
        path.to_str(),
        Some("/bin" | "/boot" | "/etc" | "/lib" | "/lib64" | "/opt" | "/sbin" | "/usr" | "/var")
    )
}

pub fn path_matches_blacklist(target: &Path, blacklist: &[BlockedPath]) -> bool {
    let normalized = normalize_existing_path(target);
    blacklist.iter().any(|blocked| match blocked.kind {
        BlockedPathKind::Directory => {
            normalized == blocked.path || normalized.starts_with(&blocked.path)
        }
        BlockedPathKind::FileLike => normalized == blocked.path,
    })
}

#[cfg(test)]
fn parse_blocked_glob_list(value: &str, what: &str) -> Vec<BlockedPath> {
    parse_blocked_glob_entries(
        value
            .split_ascii_whitespace()
            .map(ToOwned::to_owned)
            .collect(),
        what,
    )
}

fn parse_path_entries(entries: Vec<String>, what: &str) -> Vec<PathBuf> {
    entries
        .into_iter()
        .filter_map(|entry| canonicalize_path(&entry, what))
        .collect()
}

fn parse_blocked_path_entries(entries: Vec<String>, what: &str) -> Vec<BlockedPath> {
    entries
        .into_iter()
        .filter_map(|entry| canonicalize_blocked_path(&entry, what))
        .collect()
}

fn parse_blocked_glob_entries(entries: Vec<String>, what: &str) -> Vec<BlockedPath> {
    let mut blocked = Vec::new();

    for pattern in entries {
        if !Path::new(&pattern).is_absolute() {
            eprintln!("roam: {what} pattern must be absolute: {pattern}");
            continue;
        }

        match glob::glob(&pattern) {
            Ok(paths) => {
                let mut matched = false;
                for path in paths {
                    let Ok(path) = path else {
                        continue;
                    };
                    matched = true;
                    let Some(path_str) = path.to_str() else {
                        continue;
                    };
                    if let Some(blocked_path) = canonicalize_blocked_path(path_str, what) {
                        blocked.push(blocked_path);
                    }
                }
                if !matched {
                    eprintln!("roam: {what} pattern '{pattern}' matched no paths");
                }
            }
            Err(err) => {
                eprintln!("roam: {what} pattern '{pattern}': {err} (skipped)");
            }
        }
    }

    blocked
}

fn canonicalize_blocked_path(raw: &str, what: &str) -> Option<BlockedPath> {
    let path = canonicalize_path(raw, what)?;
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) => {
            eprintln!("roam: {what} path '{}': {err} (skipped)", path.display());
            return None;
        }
    };
    Some(BlockedPath {
        path,
        kind: if metadata.is_dir() {
            BlockedPathKind::Directory
        } else {
            BlockedPathKind::FileLike
        },
    })
}

fn normalize_existing_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn dedupe_blocked_paths(paths: Vec<BlockedPath>) -> Vec<BlockedPath> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();

    for path in paths {
        if seen.insert(path.clone()) {
            deduped.push(path);
        }
    }

    deduped
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::{env, fs};

    use super::{
        finalize_raw_config, parse_blocked_glob_list, parse_toml_config, path_matches_blacklist,
        BlockedPath, BlockedPathKind,
    };

    #[test]
    fn exact_file_blacklist_matches_only_that_path() {
        let blacklist = vec![BlockedPath {
            path: PathBuf::from("/etc/shadow"),
            kind: BlockedPathKind::FileLike,
        }];

        assert!(path_matches_blacklist(
            PathBuf::from("/etc/shadow").as_path(),
            &blacklist
        ));
        assert!(!path_matches_blacklist(
            PathBuf::from("/etc/shadow.backup").as_path(),
            &blacklist
        ));
    }

    #[test]
    fn directory_blacklist_matches_nested_paths() {
        let blacklist = vec![BlockedPath {
            path: PathBuf::from("/var/lib/secret"),
            kind: BlockedPathKind::Directory,
        }];

        assert!(path_matches_blacklist(
            PathBuf::from("/var/lib/secret").as_path(),
            &blacklist
        ));
        assert!(path_matches_blacklist(
            PathBuf::from("/var/lib/secret/nested/file.txt").as_path(),
            &blacklist
        ));
        assert!(!path_matches_blacklist(
            PathBuf::from("/var/lib/secretive/file.txt").as_path(),
            &blacklist
        ));
    }

    #[test]
    fn glob_blacklist_expands_multiple_files() {
        let mut dir = env::temp_dir();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        dir.push(format!("roam-blacklist-glob-{unique}"));
        fs::create_dir_all(&dir).expect("create temp dir");

        let a = dir.join("secret-a");
        let b = dir.join("secret-b");
        let keep = dir.join("public");
        fs::write(&a, "").expect("write file a");
        fs::write(&b, "").expect("write file b");
        fs::write(&keep, "").expect("write keep file");

        let pattern = format!("{}/secret-*", dir.display());
        let blocked = parse_blocked_glob_list(&pattern, "blacklist glob");

        assert!(path_matches_blacklist(&a, &blocked));
        assert!(path_matches_blacklist(&b, &blocked));
        assert!(!path_matches_blacklist(&keep, &blocked));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_new_toml_config_shape() {
        let path = PathBuf::from("/etc/roam/config.toml");
        let raw = parse_toml_config(
            &path,
            r#"
user = "roam"
writable = ["/dev", "/run", "/tmp"]
blacklist = ["/etc/shadow"]
blacklist_glob = ["/etc/*.key"]
allow_degraded = true
"#,
        )
        .expect("config should parse");
        let config = finalize_raw_config(raw);

        assert_eq!(config.user, "roam");
        assert!(config.allow_degraded);
        assert!(config.writable.iter().any(|path| path == Path::new("/tmp")));
    }

    #[test]
    fn missing_values_use_defaults() {
        let raw = parse_toml_config(Path::new("/etc/roam/config.toml"), "").expect("parse");
        let config = finalize_raw_config(raw);

        assert_eq!(config.user, "roam");
        assert!(!config.allow_degraded);
        assert!(config.writable.iter().any(|path| path == Path::new("/tmp")));
    }
}
