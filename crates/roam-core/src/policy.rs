use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

pub const DEFAULT_POLICY_PATH: &str = "/etc/roam/policy.toml";

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub edit: BTreeMap<String, EditProfile>,
    #[serde(default)]
    pub service: BTreeMap<String, ServiceProfile>,
    #[serde(default)]
    pub exec: BTreeMap<String, ExecProfile>,
    #[serde(default)]
    pub sudo_passthrough: SudoPassthroughPolicy,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EditProfile {
    pub path: PathBuf,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub mode: Option<u32>,
    #[serde(default)]
    pub validator: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServiceProfile {
    pub unit: String,
    #[serde(default)]
    pub actions: Vec<ServiceAction>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ExecProfile {
    pub program: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub allow_extra_args: bool,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct SudoPassthroughPolicy {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceAction {
    Status,
    Restart,
    Reload,
}

impl Policy {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let contents = match fs::read_to_string(path) {
            Ok(contents) => {
                let metadata = fs::metadata(path)?;
                validate_policy_file_metadata(path, metadata.uid(), metadata.mode())?;
                contents
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => return Err(err.into()),
        };

        let policy = parse_policy(path, &contents)?;
        Ok(policy)
    }
}

fn validate_policy_file_metadata(path: &Path, uid: u32, mode: u32) -> Result<()> {
    if uid != 0 {
        return Err(Error::Policy(format!(
            "{} must be owned by root",
            path.display()
        )));
    }
    if mode & 0o022 != 0 {
        return Err(Error::Policy(format!(
            "{} must not be group/world-writable",
            path.display()
        )));
    }
    Ok(())
}

fn parse_policy(path: &Path, contents: &str) -> Result<Policy> {
    let policy: Policy = toml::from_str(contents)
        .map_err(|err| Error::Policy(format!("{}: {err}", path.display())))?;

    for (name, profile) in &policy.edit {
        if !profile.path.is_absolute() {
            return Err(Error::Policy(format!(
                "edit profile '{name}' must use an absolute path"
            )));
        }
        if profile.validator.iter().any(|arg| arg.is_empty()) {
            return Err(Error::Policy(format!(
                "edit profile '{name}' contains an empty validator argument"
            )));
        }
    }

    for (name, profile) in &policy.service {
        if profile.unit.trim().is_empty() {
            return Err(Error::Policy(format!(
                "service profile '{name}' must define a unit"
            )));
        }
    }

    for (name, profile) in &policy.exec {
        if !profile.program.is_absolute() {
            return Err(Error::Policy(format!(
                "exec profile '{name}' must use an absolute program path"
            )));
        }
        if profile.args.iter().any(|arg| arg.is_empty()) {
            return Err(Error::Policy(format!(
                "exec profile '{name}' contains an empty argument"
            )));
        }
        if profile.user.as_deref() == Some("") {
            return Err(Error::Policy(format!(
                "exec profile '{name}' must not use an empty user"
            )));
        }
        if profile.group.as_deref() == Some("") {
            return Err(Error::Policy(format!(
                "exec profile '{name}' must not use an empty group"
            )));
        }
    }

    Ok(policy)
}

impl ServiceAction {
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceAction::Status => "status",
            ServiceAction::Restart => "restart",
            ServiceAction::Reload => "reload",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use std::path::Path;

    use super::{parse_policy, validate_policy_file_metadata};

    fn temp_policy_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        path.push(format!("roam-policy-{name}-{unique}.toml"));
        path
    }

    #[test]
    fn exec_profile_requires_absolute_program_path() {
        let path = temp_policy_path("relative-program");
        let err = parse_policy(
            &path,
            r#"
[exec.bad]
program = "journalctl"
"#,
        )
        .expect_err("policy should fail");
        assert!(err.to_string().contains("absolute program path"));
    }

    #[test]
    fn sudo_passthrough_flag_loads() {
        let path = temp_policy_path("sudo-passthrough");
        let policy = parse_policy(
            &path,
            r#"
[sudo_passthrough]
enabled = true
"#,
        )
        .expect("policy should load");
        assert!(policy.sudo_passthrough.enabled);
    }

    #[test]
    fn policy_file_must_not_be_world_writable() {
        let err = validate_policy_file_metadata(Path::new("/etc/roam/policy.toml"), 0, 0o666)
            .expect_err("policy should fail");
        assert!(err.to_string().contains("must not be group/world-writable"));
    }

    #[test]
    fn policy_file_must_be_owned_by_root() {
        let err = validate_policy_file_metadata(Path::new("/etc/roam/policy.toml"), 1000, 0o644)
            .expect_err("policy should fail");
        assert!(err.to_string().contains("must be owned by root"));
    }
}
