use std::env;
use std::ffi::CString;
use std::io::{self, Write};
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use roam_broker::serve_fd;
use roam_core::protocol::{recv_frame, send_frame};
use roam_core::{
    lookup_user, BrokerRequest, BrokerResponse, Error, Result, ServiceAction, SessionConfig,
    SessionMetadata, DEFAULT_CONFIG_PATH, DEFAULT_POLICY_PATH,
};
use roam_sandbox::run_session;

const BROKER_FD: RawFd = 3;

fn main() {
    if let Err(err) = run() {
        eprintln!("roam: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("shell") => run_shell(args.collect()),
        Some("edit") => {
            let profile = args.next().ok_or_else(|| usage_error("missing edit profile"))?;
            if args.next().is_some() {
                return Err(usage_error("edit takes exactly one profile"));
            }
            run_edit(&profile)
        }
        Some("exec") => {
            let profile = args.next().ok_or_else(|| usage_error("missing exec profile"))?;
            run_exec(&profile, args.collect())
        }
        Some("service") => {
            let action = parse_service_action(args.next().as_deref())?;
            let profile = args.next().ok_or_else(|| usage_error("missing service profile"))?;
            if args.next().is_some() {
                return Err(usage_error("service takes exactly two arguments"));
            }
            run_service(action, &profile)
        }
        Some("sudo-passthrough") | Some("sudo_passthrough") => {
            run_sudo_passthrough(args.collect())
        }
        Some("__broker-launcher") => run_broker_launcher(),
        Some("__broker") => run_broker(),
        _ => Err(usage_error(
            "usage: roam shell [command...]\n       roam edit <profile>\n       roam exec <profile> [args...]\n       roam service <status|restart|reload> <profile>\n       roam sudo-passthrough -- <command> [args...]",
        )),
    }
}

fn run_shell(command: Vec<String>) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::Permission(
            "use sudo to start a roam session: sudo roam shell".to_string(),
        ));
    }

    let config = SessionConfig::load(DEFAULT_CONFIG_PATH)?;
    let session_user = lookup_user(&config.user)?;
    let metadata = SessionMetadata::from_environment(
        session_user.name.clone(),
        session_user.uid,
        session_user.gid,
    );

    let (client, server) = socket_pair()?;
    let lock_fd = create_lock_fd()?;

    spawn_broker(&metadata, server, Path::new(DEFAULT_POLICY_PATH))?;
    run_session(&config, &session_user, &metadata, client.into_raw_fd(), lock_fd, &command)
}

fn run_broker() -> Result<()> {
    let session_id =
        env::var("ROAM_SESSION_ID").map_err(|_| usage_error("missing ROAM_SESSION_ID"))?;
    let session_user =
        env::var("ROAM_SESSION_USER").map_err(|_| usage_error("missing ROAM_SESSION_USER"))?;
    let session_uid = env::var("ROAM_SESSION_UID")
        .map_err(|_| usage_error("missing ROAM_SESSION_UID"))?
        .parse()
        .map_err(|_| usage_error("invalid ROAM_SESSION_UID"))?;
    let session_gid = env::var("ROAM_SESSION_GID")
        .map_err(|_| usage_error("missing ROAM_SESSION_GID"))?
        .parse()
        .map_err(|_| usage_error("invalid ROAM_SESSION_GID"))?;
    let policy_path =
        env::var("ROAM_POLICY_PATH").unwrap_or_else(|_| DEFAULT_POLICY_PATH.to_string());

    let metadata = SessionMetadata {
        session_id: uuid::Uuid::parse_str(&session_id)
            .map_err(|_| usage_error("invalid ROAM_SESSION_ID"))?,
        invoking_user: env::var("ROAM_INVOKING_USER").ok(),
        invoking_uid: env::var("ROAM_INVOKING_UID")
            .ok()
            .and_then(|value| value.parse().ok()),
        invoking_gid: env::var("ROAM_INVOKING_GID")
            .ok()
            .and_then(|value| value.parse().ok()),
        invoking_tty: env::var("ROAM_INVOKING_TTY").ok(),
        session_user,
        session_uid,
        session_gid,
    };

    serve_fd(BROKER_FD, Path::new(&policy_path), metadata)
}

fn run_broker_launcher() -> Result<()> {
    let exe = env::current_exe()?;
    let mut command = Command::new(exe);
    command
        .arg("__broker")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let _child = command.spawn()?;
    Ok(())
}

fn run_edit(profile: &str) -> Result<()> {
    let mut session = SessionConnection::from_env()?;
    let started = match session.round_trip(BrokerRequest::BeginEdit {
        profile: profile.to_string(),
    })? {
        BrokerResponse::EditStarted(started) => started,
        BrokerResponse::Error { message } => return Err(Error::Rejected(message)),
        other => return Err(Error::Protocol(format!("unexpected response: {other:?}"))),
    };

    let editor = editor_command();
    let status = Command::new(&editor)
        .arg(&started.candidate_path)
        .status()?;
    if !status.success() {
        let _ = session.round_trip(BrokerRequest::AbortEdit {
            ticket: started.ticket.clone(),
        });
        return Err(Error::Rejected(format!(
            "editor exited with status {:?}",
            status.code()
        )));
    }

    let inspection = match session.round_trip(BrokerRequest::InspectEdit {
        ticket: started.ticket.clone(),
    })? {
        BrokerResponse::EditInspection(inspection) => inspection,
        BrokerResponse::Error { message } => return Err(Error::Rejected(message)),
        other => return Err(Error::Protocol(format!("unexpected response: {other:?}"))),
    };

    if !inspection.changed {
        println!("No changes detected.");
        let _ = session.round_trip(BrokerRequest::AbortEdit {
            ticket: started.ticket,
        });
        return Ok(());
    }

    if !inspection.diff.is_empty() {
        println!("{}", inspection.diff);
    }
    if let Some(validator) = inspection.validator {
        println!(
            "Validator: {} ({})",
            validator.command.join(" "),
            if validator.ok { "ok" } else { "failed" }
        );
        if !validator.stdout.is_empty() {
            print!("{}", validator.stdout);
        }
        if !validator.stderr.is_empty() {
            eprint!("{}", validator.stderr);
        }
        if !validator.ok {
            let _ = session.round_trip(BrokerRequest::AbortEdit {
                ticket: started.ticket,
            });
            return Err(Error::Validation(
                "validator failed; changes not installed".to_string(),
            ));
        }
    }

    if !confirm("Install these changes? [y/N]: ")? {
        let _ = session.round_trip(BrokerRequest::AbortEdit {
            ticket: started.ticket,
        });
        println!("Edit aborted.");
        return Ok(());
    }

    match session.round_trip(BrokerRequest::CommitEdit {
        ticket: started.ticket.clone(),
    })? {
        BrokerResponse::EditCommitted { backup_path } => {
            println!("Installed. Backup saved to {}", backup_path.display());
            Ok(())
        }
        BrokerResponse::EditConflict {
            candidate_path,
            message,
            ..
        } => {
            eprintln!("Conflict: {message}");
            eprintln!("Your draft is preserved at: {}", candidate_path.display());
            Err(Error::Rejected("edit aborted due to conflict".to_string()))
        }
        BrokerResponse::Error { message } => Err(Error::Rejected(message)),
        other => Err(Error::Protocol(format!("unexpected response: {other:?}"))),
    }
}

fn run_exec(profile: &str, args: Vec<String>) -> Result<()> {
    let prompt = if args.is_empty() {
        format!("Run exec profile '{profile}'? [y/N]: ")
    } else {
        format!(
            "Run exec profile '{}' with args '{}' ? [y/N]: ",
            profile,
            args.join(" ")
        )
    };
    if !confirm(&prompt)? {
        println!("Cancelled.");
        return Ok(());
    }

    let mut session = SessionConnection::from_env()?;
    match session.round_trip(BrokerRequest::Exec {
        profile: profile.to_string(),
        args,
    })? {
        BrokerResponse::ExecResult(result) => print_command_result(result),
        BrokerResponse::Error { message } => Err(Error::Rejected(message)),
        other => Err(Error::Protocol(format!("unexpected response: {other:?}"))),
    }
}

fn run_service(action: ServiceAction, profile: &str) -> Result<()> {
    if action != ServiceAction::Status {
        let prompt = format!(
            "Run '{}' for service profile '{}'? [y/N]: ",
            action.as_str(),
            profile
        );
        if !confirm(&prompt)? {
            println!("Cancelled.");
            return Ok(());
        }
    }

    let mut session = SessionConnection::from_env()?;
    match session.round_trip(BrokerRequest::ServiceAction {
        profile: profile.to_string(),
        action,
    })? {
        BrokerResponse::ServiceResult(result) => {
            if !result.stdout.is_empty() {
                print!("{}", result.stdout);
            }
            if !result.stderr.is_empty() {
                eprint!("{}", result.stderr);
            }
            if result.status != 0 {
                return Err(Error::Rejected(format!(
                    "service command exited with status {}",
                    result.status
                )));
            }
            Ok(())
        }
        BrokerResponse::Error { message } => Err(Error::Rejected(message)),
        other => Err(Error::Protocol(format!("unexpected response: {other:?}"))),
    }
}

fn run_sudo_passthrough(mut argv: Vec<String>) -> Result<()> {
    if argv.first().map(|value| value.as_str()) == Some("--") {
        argv.remove(0);
    }
    if argv.is_empty() {
        return Err(usage_error(
            "sudo-passthrough requires a command after '--'",
        ));
    }

    let prompt = format!("Run sudo passthrough '{}'? [y/N]: ", argv.join(" "));
    if !confirm(&prompt)? {
        println!("Cancelled.");
        return Ok(());
    }

    let mut session = SessionConnection::from_env()?;
    match session.round_trip(BrokerRequest::SudoPassthrough { argv })? {
        BrokerResponse::ExecResult(result) => print_command_result(result),
        BrokerResponse::Error { message } => Err(Error::Rejected(message)),
        other => Err(Error::Protocol(format!("unexpected response: {other:?}"))),
    }
}

struct SessionConnection {
    stream: UnixStream,
    lock_fd: RawFd,
}

impl SessionConnection {
    fn from_env() -> Result<Self> {
        if env::var("ROAM").ok().as_deref() != Some("1") {
            return Err(Error::Permission(
                "roam edit/service commands must be run from inside a roam shell".to_string(),
            ));
        }
        let broker_fd: RawFd = env::var("ROAM_BROKER_FD")
            .map_err(|_| usage_error("missing ROAM_BROKER_FD"))?
            .parse()
            .map_err(|_| usage_error("invalid ROAM_BROKER_FD"))?;
        let lock_fd: RawFd = env::var("ROAM_BROKER_LOCK_FD")
            .map_err(|_| usage_error("missing ROAM_BROKER_LOCK_FD"))?
            .parse()
            .map_err(|_| usage_error("invalid ROAM_BROKER_LOCK_FD"))?;

        check_fd(broker_fd, "ROAM_BROKER_FD")?;
        check_fd(lock_fd, "ROAM_BROKER_LOCK_FD")?;

        // SAFETY: the file descriptor is inherited from the parent shell process.
        let stream = unsafe { UnixStream::from_raw_fd(duplicate_fd(broker_fd)?) };
        Ok(Self { stream, lock_fd })
    }

    fn round_trip(&mut self, request: BrokerRequest) -> Result<BrokerResponse> {
        let _guard = SessionLock::acquire(self.lock_fd)?;
        send_frame(&mut self.stream, &request)?;
        recv_frame(&mut self.stream)
    }
}

struct SessionLock {
    fd: RawFd,
}

impl SessionLock {
    fn acquire(fd: RawFd) -> Result<Self> {
        // SAFETY: flock operates on the inherited per-session lock fd.
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if rc == -1 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self { fd })
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        // SAFETY: best-effort unlock on process-local inherited fd.
        unsafe {
            libc::flock(self.fd, libc::LOCK_UN);
        }
    }
}

fn spawn_broker(metadata: &SessionMetadata, server: UnixStream, policy_path: &Path) -> Result<()> {
    let exe = env::current_exe()?;
    let server_fd = server.into_raw_fd();
    let mut command = Command::new(exe);
    command
        .arg("__broker-launcher")
        .env("ROAM_SESSION_ID", metadata.session_id.to_string())
        .env("ROAM_POLICY_PATH", policy_path)
        .env("ROAM_SESSION_USER", &metadata.session_user)
        .env("ROAM_SESSION_UID", metadata.session_uid.to_string())
        .env("ROAM_SESSION_GID", metadata.session_gid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if let Some(value) = &metadata.invoking_user {
        command.env("ROAM_INVOKING_USER", value);
    }
    if let Some(value) = metadata.invoking_uid {
        command.env("ROAM_INVOKING_UID", value.to_string());
    }
    if let Some(value) = metadata.invoking_gid {
        command.env("ROAM_INVOKING_GID", value.to_string());
    }
    if let Some(value) = &metadata.invoking_tty {
        command.env("ROAM_INVOKING_TTY", value);
    }

    // SAFETY: pre_exec runs in the child just before exec; only async-signal-safe operations are used.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(server_fd, BROKER_FD) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            let flags = libc::fcntl(BROKER_FD, libc::F_GETFD);
            if flags == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(BROKER_FD, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut launcher = command.spawn()?;
    // SAFETY: server_fd is not needed in the parent after spawn.
    unsafe {
        libc::close(server_fd);
    }
    let status = launcher.wait()?;
    if !status.success() {
        return Err(Error::Rejected(format!(
            "broker launcher exited with status {:?}",
            status.code()
        )));
    }
    Ok(())
}

fn socket_pair() -> Result<(UnixStream, UnixStream)> {
    let mut fds = [0; 2];
    // SAFETY: fds points to two integers for socketpair to initialize.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: socketpair initialized both file descriptors on success.
    Ok(unsafe {
        (
            UnixStream::from_raw_fd(fds[0]),
            UnixStream::from_raw_fd(fds[1]),
        )
    })
}

fn create_lock_fd() -> Result<RawFd> {
    let name = CString::new("roam-broker-lock").expect("static");
    // SAFETY: name is NUL-terminated and valid for the duration of the call.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(fd)
}

fn check_fd(fd: RawFd, name: &str) -> Result<()> {
    // SAFETY: F_GETFD is a read-only query on the descriptor table.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
        return Err(Error::message(format!(
            "broker fd {fd} ({name}) is not valid — \
             the file descriptor was closed before reaching this command"
        )));
    }
    Ok(())
}

fn duplicate_fd(fd: RawFd) -> Result<RawFd> {
    // SAFETY: fcntl duplicates an existing fd into a new descriptor.
    let dup_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if dup_fd == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(dup_fd)
}

fn editor_command() -> String {
    env::var("VISUAL")
        .ok()
        .or_else(|| env::var("EDITOR").ok())
        .unwrap_or_else(|| "/usr/bin/vi".to_string())
}

fn confirm(prompt: &str) -> Result<bool> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES"))
}

fn parse_service_action(raw: Option<&str>) -> Result<ServiceAction> {
    match raw {
        Some("status") => Ok(ServiceAction::Status),
        Some("restart") => Ok(ServiceAction::Restart),
        Some("reload") => Ok(ServiceAction::Reload),
        Some(other) => Err(usage_error(format!("unsupported service action '{other}'"))),
        None => Err(usage_error("missing service action")),
    }
}

fn print_command_result(result: roam_core::CommandOutcome) -> Result<()> {
    if !result.stdout.is_empty() {
        print!("{}", result.stdout);
    }
    if !result.stderr.is_empty() {
        eprint!("{}", result.stderr);
    }
    if result.status != 0 {
        return Err(Error::Rejected(format!(
            "command exited with status {}",
            result.status
        )));
    }
    Ok(())
}

fn usage_error(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}
