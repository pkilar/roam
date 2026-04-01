use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{Error, Result, ServiceAction};

const MAX_FRAME_SIZE: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BrokerRequest {
    Ping,
    BeginEdit {
        profile: String,
    },
    Exec {
        profile: String,
        args: Vec<String>,
    },
    InspectEdit {
        ticket: String,
    },
    CommitEdit {
        ticket: String,
    },
    AbortEdit {
        ticket: String,
    },
    ServiceAction {
        profile: String,
        action: ServiceAction,
    },
    SudoPassthrough {
        argv: Vec<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BrokerResponse {
    Pong,
    EditStarted(EditStarted),
    EditInspection(EditInspection),
    EditCommitted { backup_path: PathBuf },
    EditConflict {
        ticket: String,
        candidate_path: PathBuf,
        message: String,
    },
    EditAborted,
    ExecResult(CommandOutcome),
    ServiceResult(ServiceOutcome),
    Error { message: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EditStarted {
    pub ticket: String,
    pub target_path: PathBuf,
    pub candidate_path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EditInspection {
    pub changed: bool,
    pub diff: String,
    pub validator: Option<ValidatorOutcome>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorOutcome {
    pub ok: bool,
    pub command: Vec<String>,
    pub stdout: String,
    pub stderr: String,
    pub status: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandOutcome {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceOutcome {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn send_frame<T: Serialize>(stream: &mut UnixStream, message: &T) -> Result<()> {
    send_frame_io(stream, message)
}

pub fn recv_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    recv_frame_io(stream)
}

fn send_frame_io<W: Write, T: Serialize>(writer: &mut W, message: &T) -> Result<()> {
    let payload =
        serde_json::to_vec(message).map_err(|err| Error::Protocol(format!("encode: {err}")))?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(Error::Protocol(
            "message exceeds maximum frame size".to_string(),
        ));
    }
    let len = (payload.len() as u32).to_be_bytes();
    writer.write_all(&len)?;
    writer.write_all(&payload)?;
    Ok(())
}

fn recv_frame_io<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(Error::Protocol(
            "message exceeds maximum frame size".to_string(),
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(|err| Error::Protocol(format!("decode: {err}")))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::io::Write;

    use super::{recv_frame_io, send_frame_io, BrokerRequest, MAX_FRAME_SIZE};

    #[derive(serde::Serialize)]
    struct LargeMessage {
        payload: String,
    }

    #[test]
    fn round_trips_a_frame() {
        let mut buffer = Vec::new();
        send_frame_io(&mut buffer, &BrokerRequest::Ping).expect("send");
        let mut cursor = Cursor::new(buffer);
        let message: BrokerRequest = recv_frame_io(&mut cursor).expect("recv");
        assert!(matches!(message, BrokerRequest::Ping));
    }

    #[test]
    fn rejects_oversized_frame_before_send() {
        let mut buffer = Vec::new();
        let message = LargeMessage {
            payload: "x".repeat(MAX_FRAME_SIZE),
        };
        let err = send_frame_io(&mut buffer, &message).expect_err("should reject");
        assert!(err.to_string().contains("exceeds maximum frame size"));
    }

    #[test]
    fn truncated_payload_returns_io_error() {
        let mut sender = Vec::new();
        sender.write_all(&10u32.to_be_bytes()).expect("header");
        sender.write_all(b"abc").expect("partial payload");
        let mut cursor = Cursor::new(sender);
        let err = recv_frame_io::<_, BrokerRequest>(&mut cursor).expect_err("should fail");
        assert!(err.to_string().contains("io error"));
    }

    #[test]
    fn truncated_header_returns_io_error() {
        let mut cursor = Cursor::new(vec![0u8, 1u8]);
        let err = recv_frame_io::<_, BrokerRequest>(&mut cursor).expect_err("should fail");
        assert!(err.to_string().contains("io error"));
    }

    #[test]
    fn zero_length_frame_returns_decode_error() {
        let mut cursor = Cursor::new(0u32.to_be_bytes().to_vec());
        let err = recv_frame_io::<_, BrokerRequest>(&mut cursor).expect_err("should fail");
        assert!(err.to_string().contains("protocol error: decode:"));
    }

    #[test]
    fn invalid_json_returns_decode_error() {
        let mut sender = Vec::new();
        sender.write_all(&4u32.to_be_bytes()).expect("header");
        sender.write_all(b"nope").expect("payload");
        let mut cursor = Cursor::new(sender);
        let err = recv_frame_io::<_, BrokerRequest>(&mut cursor).expect_err("should fail");
        assert!(err.to_string().contains("protocol error: decode:"));
    }

    #[test]
    fn rejects_oversized_frame_during_receive() {
        let mut cursor = Cursor::new(((MAX_FRAME_SIZE + 1) as u32).to_be_bytes().to_vec());
        let err = recv_frame_io::<_, BrokerRequest>(&mut cursor).expect_err("should fail");
        assert!(err.to_string().contains("exceeds maximum frame size"));
    }
}
