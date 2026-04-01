use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use roam_core::protocol::{recv_frame, send_frame};
use roam_core::unix::{lookup_group, lookup_passwd};
use roam_core::{
    path_matches_blacklist, syslog_info, BlockedPath, BrokerRequest, BrokerResponse,
    CommandOutcome, EditInspection, EditProfile, EditStarted, Error, ExecProfile, Policy, Result,
    ServiceAction, ServiceOutcome, SessionConfig, SessionMetadata, ValidatorOutcome,
    DEFAULT_CONFIG_PATH, DEFAULT_POLICY_PATH,
};
use similar::TextDiff;

const SYSTEMCTL_PATH: &str = "/usr/bin/systemctl";
const SUDO_PATH: &str = "/usr/bin/sudo";
const BACKUP_ROOT: &str = "/var/lib/roam/backups";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONCURRENT_EDITS: usize = 16;

pub fn serve_fd(fd: RawFd, policy_path: &Path, metadata: SessionMetadata) -> Result<()> {
    let session_config = SessionConfig::load(DEFAULT_CONFIG_PATH)?;
    let policy = Policy::load(policy_path).or_else(|err| {
        if policy_path == Path::new(DEFAULT_POLICY_PATH) {
            Ok(Policy::default())
        } else {
            Err(err)
        }
    })?;

    let mut broker = Broker::new(fd, policy, session_config.blacklist, metadata)?;
    broker.serve()
}

struct Broker {
    stream: UnixStream,
    policy: Policy,
    blacklist: Vec<BlockedPath>,
    metadata: SessionMetadata,
    work_dir: PathBuf,
    edit_dir: PathBuf,
    edits: HashMap<String, EditTransaction>,
}

struct EditTransaction {
    profile_name: String,
    profile: EditProfile,
    candidate_path: PathBuf,
    original_content: Vec<u8>,
}

impl Broker {
    fn new(
        fd: RawFd,
        policy: Policy,
        blacklist: Vec<BlockedPath>,
        metadata: SessionMetadata,
    ) -> Result<Self> {
        // Broker internal work dir — root-owned, inaccessible to session user.
        // Protects temp stdout/stderr from privileged commands against cross-session reads.
        let mut work_dir = std::env::temp_dir();
        work_dir.push(format!("roam-broker-{}", metadata.session_id));
        fs::create_dir_all(&work_dir)?;
        fs::set_permissions(&work_dir, fs::Permissions::from_mode(0o700))?;

        // Edit candidate dir — session-user-owned 0o700 with opaque name.
        // Uses a separate random UUID (not the session_id) so the dir name
        // cannot be guessed even if the session_id leaks via syslog.
        // No recognizable prefix prevents glob enumeration by concurrent sessions.
        // Editors need a writable parent for swap files and rename-on-save.
        let edit_uuid = uuid::Uuid::new_v4();
        let mut edit_dir = std::env::temp_dir();
        edit_dir.push(format!(".{edit_uuid}"));
        fs::create_dir_all(&edit_dir)?;
        fs::set_permissions(&edit_dir, fs::Permissions::from_mode(0o700))?;
        chown_path(&edit_dir, metadata.session_uid, metadata.session_gid)?;

        let mut backup_root = PathBuf::from(BACKUP_ROOT);
        backup_root.push(metadata.session_id.to_string());
        fs::create_dir_all(&backup_root)?;
        fs::set_permissions(&backup_root, fs::Permissions::from_mode(0o700))?;

        syslog_info(&format!(
            "broker started: session_id={} invoking_user={} session_user={}",
            metadata.session_id,
            metadata.invoking_user.as_deref().unwrap_or("(unknown)"),
            metadata.session_user
        ));

        Ok(Self {
            // SAFETY: fd is passed by the parent process and owned by the broker process.
            stream: unsafe { UnixStream::from_raw_fd(fd) },
            policy,
            blacklist,
            metadata,
            work_dir,
            edit_dir,
            edits: HashMap::new(),
        })
    }

    fn serve(&mut self) -> Result<()> {
        loop {
            let request = match recv_frame::<BrokerRequest>(&mut self.stream) {
                Ok(request) => request,
                Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(err) => return Err(err),
            };

            let response = match self.handle_request(request) {
                Ok(response) => response,
                Err(err) => BrokerResponse::Error {
                    message: err.to_string(),
                },
            };
            send_frame(&mut self.stream, &response)?;
        }

        let _ = fs::remove_dir_all(&self.work_dir);
        let _ = fs::remove_dir_all(&self.edit_dir);
        let _ = fs::remove_dir_all(self.metadata.runtime_root());
        syslog_info(&format!(
            "broker exited: session_id={}",
            self.metadata.session_id
        ));
        Ok(())
    }

    fn handle_request(&mut self, request: BrokerRequest) -> Result<BrokerResponse> {
        match request {
            BrokerRequest::Ping => Ok(BrokerResponse::Pong),
            BrokerRequest::BeginEdit { profile } => self.begin_edit(&profile),
            BrokerRequest::Exec { profile, args } => self.exec_profile(&profile, args),
            BrokerRequest::InspectEdit { ticket } => self.inspect_edit(&ticket),
            BrokerRequest::CommitEdit { ticket } => self.commit_edit(&ticket),
            BrokerRequest::AbortEdit { ticket } => self.abort_edit(&ticket),
            BrokerRequest::ServiceAction { profile, action } => {
                self.service_action(&profile, action)
            }
            BrokerRequest::SudoPassthrough { argv } => self.sudo_passthrough(argv),
        }
    }

    fn begin_edit(&mut self, profile_name: &str) -> Result<BrokerResponse> {
        if self.edits.len() >= MAX_CONCURRENT_EDITS {
            return Err(Error::Rejected(format!(
                "too many concurrent edits (limit {})",
                MAX_CONCURRENT_EDITS
            )));
        }
        let profile = self
            .policy
            .edit
            .get(profile_name)
            .cloned()
            .ok_or_else(|| Error::Rejected(format!("unknown edit profile '{profile_name}'")))?;
        if path_matches_blacklist(&profile.path, &self.blacklist) {
            return Err(Error::Rejected(format!(
                "edit target '{}' is blacklisted",
                profile.path.display()
            )));
        }

        let ticket = uuid::Uuid::new_v4().to_string();
        let candidate_path = self
            .edit_dir
            .join(format!("{profile_name}.{ticket}.candidate"));

        let original_content = if profile.path.exists() {
            let content = fs::read(&profile.path)?;
            fs::write(&candidate_path, &content)?;
            content
        } else {
            File::create(&candidate_path)?;
            Vec::new()
        };
        fs::set_permissions(&candidate_path, fs::Permissions::from_mode(0o600))?;
        chown_path(
            &candidate_path,
            self.metadata.session_uid,
            self.metadata.session_gid,
        )?;

        let target_path = profile.path.clone();

        self.edits.insert(
            ticket.clone(),
            EditTransaction {
                profile_name: profile_name.to_string(),
                profile,
                candidate_path: candidate_path.clone(),
                original_content,
            },
        );

        Ok(BrokerResponse::EditStarted(EditStarted {
            ticket,
            target_path,
            candidate_path,
        }))
    }

    fn inspect_edit(&mut self, ticket: &str) -> Result<BrokerResponse> {
        let txn = self
            .edits
            .get(ticket)
            .ok_or_else(|| Error::Rejected(format!("unknown edit ticket '{ticket}'")))?;

        let current_bytes = match fs::read(&txn.profile.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(err) => return Err(err.into()),
        };
        let candidate_bytes = fs::read(&txn.candidate_path)?;
        let changed = current_bytes != candidate_bytes;
        let diff = if changed {
            let current = String::from_utf8_lossy(&current_bytes);
            let candidate = String::from_utf8_lossy(&candidate_bytes);
            TextDiff::from_lines(current.as_ref(), candidate.as_ref())
                .unified_diff()
                .context_radius(3)
                .header(
                    &txn.profile.path.display().to_string(),
                    &txn.candidate_path.display().to_string(),
                )
                .to_string()
        } else {
            String::new()
        };
        let validator = run_validator(&self.work_dir, &txn.profile, &txn.candidate_path)?;

        Ok(BrokerResponse::EditInspection(EditInspection {
            changed,
            diff,
            validator,
        }))
    }

    fn commit_edit(&mut self, ticket: &str) -> Result<BrokerResponse> {
        let txn = self
            .edits
            .remove(ticket)
            .ok_or_else(|| Error::Rejected(format!("unknown edit ticket '{ticket}'")))?;

        // Fail closed if the target was modified after the edit started.
        // On conflict, re-insert the transaction so the user can abort or
        // inspect their draft — the candidate file is intentionally preserved.
        let current_target = match fs::read(&txn.profile.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(err) => {
                self.edits.insert(ticket.to_string(), txn);
                return Err(err.into());
            }
        };
        if current_target != txn.original_content {
            let candidate_path = txn.candidate_path.clone();
            self.edits.insert(ticket.to_string(), txn);
            return Ok(BrokerResponse::EditConflict {
                ticket: ticket.to_string(),
                candidate_path,
                message: "target file was modified after edit started; your draft is preserved"
                    .to_string(),
            });
        }

        let changed = file_changed(&txn.profile.path, &txn.candidate_path)?;
        if !changed {
            let _ = fs::remove_file(&txn.candidate_path);
            return Err(Error::Rejected("candidate has no changes".to_string()));
        }

        if let Some(validator) = run_validator(&self.work_dir, &txn.profile, &txn.candidate_path)? {
            if !validator.ok {
                return Err(Error::Validation(format!(
                    "validator for profile '{}' failed",
                    txn.profile_name
                )));
            }
        }

        match install_candidate(&txn, &self.metadata) {
            Ok(backup_path) => {
                let _ = fs::remove_file(&txn.candidate_path);
                syslog_info(&format!(
                    "edit committed: session_id={} profile={} target={} backup={}",
                    self.metadata.session_id,
                    txn.profile_name,
                    txn.profile.path.display(),
                    backup_path.display()
                ));
                Ok(BrokerResponse::EditCommitted { backup_path })
            }
            Err(Error::Conflict(msg)) => {
                // Late conflict during install — re-insert for recovery,
                // same handling as the early conflict path.
                let candidate_path = txn.candidate_path.clone();
                self.edits.insert(ticket.to_string(), txn);
                Ok(BrokerResponse::EditConflict {
                    ticket: ticket.to_string(),
                    candidate_path,
                    message: msg,
                })
            }
            Err(err) => {
                // Other install error — re-insert so abort can clean up.
                self.edits.insert(ticket.to_string(), txn);
                Err(err)
            }
        }
    }

    fn abort_edit(&mut self, ticket: &str) -> Result<BrokerResponse> {
        if let Some(txn) = self.edits.remove(ticket) {
            let _ = fs::remove_file(&txn.candidate_path);
        }
        Ok(BrokerResponse::EditAborted)
    }

    fn service_action(
        &mut self,
        profile_name: &str,
        action: ServiceAction,
    ) -> Result<BrokerResponse> {
        let profile =
            self.policy.service.get(profile_name).ok_or_else(|| {
                Error::Rejected(format!("unknown service profile '{profile_name}'"))
            })?;
        if !profile.actions.contains(&action) {
            return Err(Error::Rejected(format!(
                "service profile '{profile_name}' does not allow {}",
                action.as_str()
            )));
        }

        let output = run_command(
            Path::new(SYSTEMCTL_PATH),
            &[action.as_str().to_string(), profile.unit.clone()],
            None,
            &self.work_dir,
        )?;

        syslog_info(&format!(
            "service action: session_id={} profile={} action={} unit={} status={}",
            self.metadata.session_id,
            profile_name,
            action.as_str(),
            profile.unit,
            output.status
        ));

        Ok(BrokerResponse::ServiceResult(ServiceOutcome {
            status: output.status,
            stdout: output.stdout,
            stderr: output.stderr,
        }))
    }

    fn exec_profile(
        &mut self,
        profile_name: &str,
        extra_args: Vec<String>,
    ) -> Result<BrokerResponse> {
        let profile = self
            .policy
            .exec
            .get(profile_name)
            .cloned()
            .ok_or_else(|| Error::Rejected(format!("unknown exec profile '{profile_name}'")))?;
        if !profile.allow_extra_args && !extra_args.is_empty() {
            return Err(Error::Rejected(format!(
                "exec profile '{profile_name}' does not allow extra arguments"
            )));
        }

        let mut argv = profile.args.clone();
        argv.extend(extra_args);
        let identity = identity_from_exec_profile(&profile)?;
        let outcome = run_command(&profile.program, &argv, identity, &self.work_dir)?;

        syslog_info(&format!(
            "exec profile: session_id={} profile={} program={} args={}",
            self.metadata.session_id,
            profile_name,
            profile.program.display(),
            argv.join(" ")
        ));

        Ok(BrokerResponse::ExecResult(outcome))
    }

    fn sudo_passthrough(&mut self, argv: Vec<String>) -> Result<BrokerResponse> {
        if !self.policy.sudo_passthrough.enabled {
            return Err(Error::Rejected(
                "sudo passthrough is disabled in policy.toml".to_string(),
            ));
        }
        if argv.is_empty() {
            return Err(Error::Rejected(
                "sudo passthrough requires a command".to_string(),
            ));
        }

        let identity = identity_from_invoking_user(&self.metadata)?;
        let sudo_argv = {
            let mut args = vec!["-n".to_string(), "--".to_string()];
            args.extend(argv.clone());
            args
        };
        let outcome = run_command(
            Path::new(SUDO_PATH),
            &sudo_argv,
            Some(identity),
            &self.work_dir,
        )?;

        syslog_info(&format!(
            "sudo passthrough: session_id={} invoking_user={} argv={}",
            self.metadata.session_id,
            self.metadata.invoking_user.as_deref().unwrap_or("(unknown)"),
            argv.join(" ")
        ));

        Ok(BrokerResponse::ExecResult(outcome))
    }
}

fn install_candidate(txn: &EditTransaction, metadata: &SessionMetadata) -> Result<PathBuf> {
    let parent = txn.profile.path.parent().ok_or_else(|| {
        Error::Rejected(format!(
            "{} has no parent directory",
            txn.profile.path.display()
        ))
    })?;

    let file_name = txn
        .profile
        .path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| Error::Rejected("target path must have a file name".to_string()))?;

    let temp_path = parent.join(format!(".{file_name}.roam.tmp.{}", metadata.session_id));
    let mut backup_dir = PathBuf::from(BACKUP_ROOT);
    backup_dir.push(metadata.session_id.to_string());
    fs::create_dir_all(&backup_dir)?;
    let backup_path = backup_dir.join(file_name);

    fs::copy(&txn.candidate_path, &temp_path)?;
    let (uid, gid, mode) = install_owner_group_mode(txn)?;
    chown_path(&temp_path, uid, gid)?;
    fs::set_permissions(&temp_path, fs::Permissions::from_mode(mode))?;
    fsync_file(&temp_path)?;

    // Final recheck immediately before rename to close the TOCTOU window
    // between the early check in commit_edit and the actual install
    // (a slow validator could widen this gap to seconds).
    let current_target = match fs::read(&txn.profile.path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(err) => {
            let _ = fs::remove_file(&temp_path);
            return Err(err.into());
        }
    };
    if current_target != txn.original_content {
        let _ = fs::remove_file(&temp_path);
        return Err(Error::Conflict(
            "target file was modified during commit; aborting to prevent data loss".to_string(),
        ));
    }

    if txn.profile.path.exists() {
        fs::copy(&txn.profile.path, &backup_path)?;
    } else {
        File::create(&backup_path)?;
    }

    fs::rename(&temp_path, &txn.profile.path)?;
    fsync_dir(parent)?;
    Ok(backup_path)
}

fn install_owner_group_mode(txn: &EditTransaction) -> Result<(u32, u32, u32)> {
    let metadata = fs::metadata(&txn.profile.path).ok();

    let uid = txn
        .profile
        .owner
        .as_deref()
        .map(|name| resolve_user(name).map(|(_, uid, _)| uid))
        .transpose()?
        .or_else(|| metadata.as_ref().map(|value| value.uid()))
        .unwrap_or(0);

    let gid = txn
        .profile
        .group
        .as_deref()
        .map(resolve_group)
        .transpose()?
        .or_else(|| metadata.as_ref().map(|value| value.gid()))
        .unwrap_or(0);

    let mode = txn
        .profile
        .mode
        .or_else(|| metadata.as_ref().map(|value| value.mode() & 0o7777))
        .unwrap_or(0o600);

    Ok((uid, gid, mode))
}

struct CommandIdentity {
    uid: u32,
    gid: u32,
    supplementary_groups: Vec<u32>,
}

struct TempOutputGuard {
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl TempOutputGuard {
    fn new(work_dir: &Path) -> Self {
        Self {
            stdout_path: work_dir.join(format!("command-{}.stdout", uuid::Uuid::new_v4())),
            stderr_path: work_dir.join(format!("command-{}.stderr", uuid::Uuid::new_v4())),
        }
    }
}

impl Drop for TempOutputGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.stdout_path);
        let _ = fs::remove_file(&self.stderr_path);
    }
}

fn identity_from_exec_profile(profile: &ExecProfile) -> Result<Option<CommandIdentity>> {
    let user = profile.user.as_deref().map(resolve_user).transpose()?;
    let group = profile.group.as_deref().map(resolve_group).transpose()?;

    match (user, group) {
        (None, None) => Ok(None),
        (Some((user_name, uid, primary_gid)), maybe_group) => {
            let gid = maybe_group.unwrap_or(primary_gid);
            let supplementary_groups = groups_for_user(&user_name, primary_gid)?;
            Ok(Some(CommandIdentity {
                uid,
                gid,
                supplementary_groups,
            }))
        }
        (None, Some(gid)) => Ok(Some(CommandIdentity {
            uid: 0,
            gid,
            supplementary_groups: Vec::new(),
        })),
    }
}

fn identity_from_invoking_user(metadata: &SessionMetadata) -> Result<CommandIdentity> {
    let user_name = metadata.invoking_user.clone().ok_or_else(|| {
        Error::Rejected("sudo passthrough requires SUDO_USER from the launcher".to_string())
    })?;
    let uid = metadata.invoking_uid.ok_or_else(|| {
        Error::Rejected("sudo passthrough requires SUDO_UID from the launcher".to_string())
    })?;
    let gid = metadata.invoking_gid.ok_or_else(|| {
        Error::Rejected("sudo passthrough requires SUDO_GID from the launcher".to_string())
    })?;
    let supplementary_groups = groups_for_user(&user_name, gid)?;

    Ok(CommandIdentity {
        uid,
        gid,
        supplementary_groups,
    })
}

fn run_command(
    program: &Path,
    args: &[String],
    identity: Option<CommandIdentity>,
    work_dir: &Path,
) -> Result<CommandOutcome> {
    let mut command = Command::new(program);
    let outputs = TempOutputGuard::new(work_dir);
    let stdout_file = File::create(&outputs.stdout_path)?;
    let stderr_file = File::create(&outputs.stderr_path)?;

    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .args(args);

    if let Some(identity) = identity {
        let groups: Vec<libc::gid_t> = identity
            .supplementary_groups
            .iter()
            .copied()
            .map(|gid| gid as libc::gid_t)
            .collect();
        let uid = identity.uid;
        let gid = identity.gid;
        // SAFETY: pre_exec performs direct libc syscalls with owned captured data.
        // setpgid creates a new process group so the broker can kill the entire tree on timeout.
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setgroups(groups.len(), groups.as_ptr()) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setresgid(gid, gid, gid) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setresuid(uid, uid, uid) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    } else {
        // SAFETY: setpgid is a direct libc syscall with no pointer arguments.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let mut child = command.spawn()?;
    let mut timed_out = false;
    let status = wait_for_child(&mut child, COMMAND_TIMEOUT, &mut timed_out)?;
    let stdout = read_command_output(&outputs.stdout_path)?;
    let mut stderr = read_command_output(&outputs.stderr_path)?;

    if timed_out {
        if !stderr.is_empty() && !stderr.ends_with('\n') {
            stderr.push('\n');
        }
        stderr.push_str(&format!(
            "roam: command timed out after {} seconds\n",
            COMMAND_TIMEOUT.as_secs()
        ));
    }
    Ok(CommandOutcome {
        status: if timed_out {
            124
        } else {
            status.code().unwrap_or(-1)
        },
        stdout,
        stderr,
    })
}

fn run_validator(
    work_dir: &Path,
    profile: &EditProfile,
    candidate_path: &Path,
) -> Result<Option<ValidatorOutcome>> {
    if profile.validator.is_empty() {
        return Ok(None);
    }

    let args: Vec<String> = profile
        .validator
        .iter()
        .map(|arg| arg.replace("{candidate}", &candidate_path.display().to_string()))
        .collect();
    let program = args
        .first()
        .cloned()
        .ok_or_else(|| Error::Policy("validator is empty".to_string()))?;
    let output = run_command(Path::new(&program), &args[1..], None, work_dir)?;

    Ok(Some(ValidatorOutcome {
        ok: output.status == 0,
        command: args,
        stdout: output.stdout,
        stderr: output.stderr,
        status: output.status,
    }))
}

fn wait_for_child(
    child: &mut std::process::Child,
    timeout: Duration,
    timed_out: &mut bool,
) -> Result<std::process::ExitStatus> {
    let start = Instant::now();
    let mut poll_interval = Duration::from_millis(10);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if start.elapsed() >= timeout {
            *timed_out = true;
            let pid = child.id() as libc::pid_t;
            // SAFETY: kill with a negative pid targets the process group;
            // positive pid targets the direct child as a fallback in case
            // the child moved itself to a different process group.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
                libc::kill(pid, libc::SIGKILL);
            }
            return Ok(child.wait()?);
        }
        thread::sleep(poll_interval);
        poll_interval = (poll_interval * 2).min(Duration::from_millis(200));
    }
}

fn read_command_output(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn file_changed(target_path: &Path, candidate_path: &Path) -> Result<bool> {
    let target = fs::read(target_path);
    let candidate = fs::read(candidate_path)?;
    match target {
        Ok(target) => Ok(target != candidate),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(!candidate.is_empty()),
        Err(err) => Err(err.into()),
    }
}

fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let c_path = CString::new(path.as_os_str().as_encoded_bytes().to_vec())
        .map_err(|_| Error::Rejected(format!("{} contains interior NUL", path.display())))?;
    // SAFETY: c_path is NUL-terminated and valid for the duration of the call.
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn resolve_user(name: &str) -> Result<(String, u32, u32)> {
    let c_name =
        CString::new(name).map_err(|_| Error::Policy(format!("invalid user name '{name}'")))?;
    let record = lookup_passwd(&c_name)
        .map_err(|err| Error::Policy(format!("failed to resolve user '{name}': {err}")))?
        .ok_or_else(|| Error::Policy(format!("unknown user '{name}'")))?;
    Ok((name.to_string(), record.uid, record.gid))
}

fn resolve_group(name: &str) -> Result<u32> {
    let c_name =
        CString::new(name).map_err(|_| Error::Policy(format!("invalid group name '{name}'")))?;
    let record = lookup_group(&c_name)
        .map_err(|err| Error::Policy(format!("failed to resolve group '{name}': {err}")))?
        .ok_or_else(|| Error::Policy(format!("unknown group '{name}'")))?;
    Ok(record.gid)
}

fn groups_for_user(name: &str, primary_gid: u32) -> Result<Vec<u32>> {
    let c_name =
        CString::new(name).map_err(|_| Error::Policy(format!("invalid user name '{name}'")))?;
    let mut ngroups: libc::c_int = 8;
    let mut groups = vec![0 as libc::gid_t; ngroups as usize];

    loop {
        // SAFETY: c_name is NUL-terminated and groups points to writable storage for ngroups entries.
        let rc = unsafe {
            libc::getgrouplist(
                c_name.as_ptr(),
                primary_gid as libc::gid_t,
                groups.as_mut_ptr(),
                &mut ngroups,
            )
        };
        if rc != -1 {
            groups.truncate(ngroups as usize);
            return Ok(groups);
        }
        if ngroups <= 0 {
            return Err(Error::Rejected(format!(
                "failed to resolve supplementary groups for '{name}'"
            )));
        }
        groups.resize(ngroups as usize, 0);
    }
}

fn fsync_file(path: &Path) -> Result<()> {
    let file = File::options().read(true).open(path)?;
    file.sync_all()?;
    Ok(())
}

fn fsync_dir(path: &Path) -> Result<()> {
    let dir = File::options().read(true).open(path)?;
    dir.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    use roam_core::BrokerRequest;

    use super::*;

    struct BrokerHarness {
        broker: Broker,
        root: PathBuf,
        _peer: UnixStream,
    }

    impl BrokerHarness {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("roam-broker-test-{}", uuid::Uuid::new_v4()));
            let work_dir = root.join("work");
            let edit_dir = root.join("edits");
            fs::create_dir_all(&work_dir).expect("create work dir");
            fs::create_dir_all(&edit_dir).expect("create edit dir");
            let (stream, peer) = UnixStream::pair().expect("socket pair");
            let uid = current_uid();
            let gid = current_gid();
            let broker = Broker {
                stream,
                policy: Policy {
                    edit: BTreeMap::new(),
                    service: BTreeMap::new(),
                    exec: BTreeMap::new(),
                    sudo_passthrough: Default::default(),
                },
                blacklist: Vec::new(),
                metadata: SessionMetadata {
                    session_id: uuid::Uuid::new_v4(),
                    invoking_user: Some("tester".to_string()),
                    invoking_uid: Some(uid),
                    invoking_gid: Some(gid),
                    invoking_tty: None,
                    session_user: "roam".to_string(),
                    session_uid: uid,
                    session_gid: gid,
                },
                work_dir,
                edit_dir,
                edits: HashMap::new(),
            };
            Self {
                broker,
                root,
                _peer: peer,
            }
        }

        fn add_edit_profile(&mut self, name: &str, path: PathBuf) {
            self.broker.policy.edit.insert(
                name.to_string(),
                EditProfile {
                    path,
                    owner: None,
                    group: None,
                    mode: None,
                    validator: Vec::new(),
                },
            );
        }
    }

    impl Drop for BrokerHarness {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn current_uid() -> u32 {
        // SAFETY: geteuid reads process credentials without requiring pointers.
        unsafe { libc::geteuid() as u32 }
    }

    fn current_gid() -> u32 {
        // SAFETY: getegid reads process credentials without requiring pointers.
        unsafe { libc::getegid() as u32 }
    }

    #[test]
    fn handle_request_ping_returns_pong() {
        let mut harness = BrokerHarness::new();
        let response = harness
            .broker
            .handle_request(BrokerRequest::Ping)
            .expect("request should succeed");
        assert!(matches!(response, BrokerResponse::Pong));
    }

    #[test]
    fn begin_edit_copies_target_and_abort_removes_candidate() {
        let mut harness = BrokerHarness::new();
        let target_path = harness.root.join("sshd_config");
        fs::write(&target_path, "Port 22\n").expect("write target");
        harness.add_edit_profile("sshd", target_path.clone());

        let response = harness
            .broker
            .handle_request(BrokerRequest::BeginEdit {
                profile: "sshd".to_string(),
            })
            .expect("begin edit should succeed");
        let BrokerResponse::EditStarted(started) = response else {
            panic!("unexpected response")
        };

        assert_eq!(
            fs::read_to_string(&started.candidate_path).expect("read candidate"),
            "Port 22\n"
        );
        assert!(started.candidate_path.exists());

        let response = harness
            .broker
            .handle_request(BrokerRequest::AbortEdit {
                ticket: started.ticket,
            })
            .expect("abort should succeed");
        assert!(matches!(response, BrokerResponse::EditAborted));
        assert!(!started.candidate_path.exists());
    }

    #[test]
    fn inspect_edit_reports_candidate_diff() {
        let mut harness = BrokerHarness::new();
        let target_path = harness.root.join("nginx.conf");
        fs::write(&target_path, "user nginx;\n").expect("write target");
        harness.add_edit_profile("nginx", target_path.clone());

        let response = harness
            .broker
            .handle_request(BrokerRequest::BeginEdit {
                profile: "nginx".to_string(),
            })
            .expect("begin edit should succeed");
        let BrokerResponse::EditStarted(started) = response else {
            panic!("unexpected response")
        };

        fs::write(&started.candidate_path, "user www-data;\n").expect("update candidate");

        let response = harness
            .broker
            .handle_request(BrokerRequest::InspectEdit {
                ticket: started.ticket,
            })
            .expect("inspect should succeed");
        let BrokerResponse::EditInspection(inspection) = response else {
            panic!("unexpected response")
        };

        assert!(inspection.changed);
        assert!(inspection.diff.contains("user nginx;"));
        assert!(inspection.diff.contains("user www-data;"));
        assert!(inspection.validator.is_none());
    }

    #[test]
    fn commit_edit_rejects_unchanged_candidate() {
        let mut harness = BrokerHarness::new();
        let target_path = harness.root.join("sshd_config");
        fs::write(&target_path, "Port 22\n").expect("write target");
        harness.add_edit_profile("sshd", target_path);

        let response = harness
            .broker
            .handle_request(BrokerRequest::BeginEdit {
                profile: "sshd".to_string(),
            })
            .expect("begin edit should succeed");
        let BrokerResponse::EditStarted(started) = response else {
            panic!("unexpected response")
        };

        let err = harness
            .broker
            .handle_request(BrokerRequest::CommitEdit {
                ticket: started.ticket,
            })
            .expect_err("commit should fail");

        assert!(err.to_string().contains("candidate has no changes"));
        assert!(!started.candidate_path.exists());
    }

    #[test]
    fn commit_edit_returns_conflict_and_preserves_candidate() {
        let mut harness = BrokerHarness::new();
        let target_path = harness.root.join("sshd_config");
        fs::write(&target_path, "Port 22\n").expect("write target");
        harness.add_edit_profile("sshd", target_path.clone());

        let response = harness
            .broker
            .handle_request(BrokerRequest::BeginEdit {
                profile: "sshd".to_string(),
            })
            .expect("begin edit should succeed");
        let BrokerResponse::EditStarted(started) = response else {
            panic!("unexpected response")
        };

        // Simulate the session user editing the candidate
        fs::write(&started.candidate_path, "Port 2222\n").expect("update candidate");

        // Simulate a concurrent admin modifying the target after the edit started
        fs::write(&target_path, "Port 443\n").expect("concurrent modification");

        let response = harness
            .broker
            .handle_request(BrokerRequest::CommitEdit {
                ticket: started.ticket.clone(),
            })
            .expect("request should succeed");

        let BrokerResponse::EditConflict {
            ticket,
            candidate_path,
            message,
        } = response
        else {
            panic!("expected EditConflict, got {response:?}")
        };

        assert!(message.contains("modified after edit started"));
        // User's draft must be preserved, not deleted
        assert!(candidate_path.exists());
        assert_eq!(
            fs::read_to_string(&candidate_path).expect("read candidate"),
            "Port 2222\n"
        );
        // Concurrent admin change must not be overwritten
        assert_eq!(
            fs::read_to_string(&target_path).expect("read target"),
            "Port 443\n"
        );
        // Transaction is re-inserted so abort can clean up
        let response = harness
            .broker
            .handle_request(BrokerRequest::AbortEdit { ticket })
            .expect("abort should succeed");
        assert!(matches!(response, BrokerResponse::EditAborted));
        assert!(!candidate_path.exists());
    }
}
