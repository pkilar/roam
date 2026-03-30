use std::env;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub session_id: Uuid,
    pub invoking_user: Option<String>,
    pub invoking_uid: Option<u32>,
    pub invoking_gid: Option<u32>,
    pub invoking_tty: Option<String>,
    pub session_user: String,
    pub session_uid: u32,
    pub session_gid: u32,
}

impl SessionMetadata {
    pub fn from_environment(session_user: String, session_uid: u32, session_gid: u32) -> Self {
        Self {
            session_id: Uuid::new_v4(),
            invoking_user: env::var("SUDO_USER").ok(),
            invoking_uid: env::var("SUDO_UID")
                .ok()
                .and_then(|value| value.parse().ok()),
            invoking_gid: env::var("SUDO_GID")
                .ok()
                .and_then(|value| value.parse().ok()),
            invoking_tty: current_tty(),
            session_user,
            session_uid,
            session_gid,
        }
    }

    pub fn runtime_root(&self) -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!("roam-shell-{}", self.session_id));
        path
    }
}

fn current_tty() -> Option<String> {
    fs::read_link("/proc/self/fd/0")
        .ok()
        .and_then(|path| path.to_str().map(ToOwned::to_owned))
}
