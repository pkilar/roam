use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("config error: {0}")]
    Config(String),

    #[error("policy error: {0}")]
    Policy(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("permission denied: {0}")]
    Permission(String),

    #[error("validation failed: {0}")]
    Validation(String),

    #[error("request rejected: {0}")]
    Rejected(String),

    #[error("edit conflict: {0}")]
    Conflict(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
}
