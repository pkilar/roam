use std::env;
use std::ffi::{CStr, CString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::RawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use roam_core::config::{canonicalize_path, is_safe_home_path};
use roam_core::{
    syslog_info, BlockedPath, BlockedPathKind, Error, Result, SessionConfig, SessionMetadata,
    SessionUser,
};

const CAP_DAC_READ_SEARCH: u32 = 2;
const CAP_SETPCAP: u32 = 8;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

const PR_SET_KEEPCAPS: libc::c_int = 8;
const PR_CAPBSET_DROP: libc::c_int = 24;
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

#[repr(C)]
struct UserCapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserCapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

pub fn run_session(
    config: &SessionConfig,
    user: &SessionUser,
    metadata: &SessionMetadata,
    broker_fd: RawFd,
    broker_lock_fd: RawFd,
    command: &[String],
) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::Permission(
            "roam shell must start as root so it can drop privileges safely".to_string(),
        ));
    }

    let writable = build_writable_paths(config, user);

    apply_blacklist(&config.blacklist)?;
    drop_privileges(user)?;
    configure_capabilities()?;

    let abi = detect_landlock_abi()?;
    guard_landlock_abi(abi, config.allow_degraded)?;

    let ruleset_fd = create_ruleset(abi)?;
    add_global_ro_rule(ruleset_fd)?;
    add_writable_rules(ruleset_fd, &writable)?;
    log_session_open(metadata, abi, &writable);

    sanitize_fds(&[ruleset_fd, broker_fd, broker_lock_fd])?;

    prctl(
        PR_SET_NO_NEW_PRIVS as _,
        1,
        0,
        0,
        0,
        "prctl(PR_SET_NO_NEW_PRIVS)",
    )?;
    ll_restrict_self(ruleset_fd, 0)?;
    close_fd(ruleset_fd);

    let shell = config
        .shell
        .clone()
        .unwrap_or_else(|| PathBuf::from("/bin/bash"));
    if let Some(home) = &user.home {
        env::set_var("HOME", home);
        env::set_var("ROAM_REAL_HOME", home);
    }
    env::set_var("SHELL", &shell);
    env::set_var("ROAM", "1");
    env::set_var("ROAM_BROKER_FD", broker_fd.to_string());
    env::set_var("ROAM_BROKER_LOCK_FD", broker_lock_fd.to_string());

    clear_cloexec(broker_fd)?;
    clear_cloexec(broker_lock_fd)?;

    eprintln!(
        "roam: Read-Only Access Mode active (user: {}, Landlock ABI v{})",
        user.name, abi
    );
    eprint!("  CAP_DAC_READ_SEARCH: can read all files\n  Writable exceptions:");
    for path in &writable {
        eprint!(" {}", path.display());
    }
    if !config.blacklist.is_empty() {
        eprint!("\n  Blacklisted paths:");
        for blocked in &config.blacklist {
            eprint!(" {}", blocked.path.display());
        }
    }
    eprintln!("\n  Type 'exit' to return.");

    exec_shell(&shell, command, metadata)
}

fn build_writable_paths(config: &SessionConfig, user: &SessionUser) -> Vec<PathBuf> {
    let mut writable = config.writable.clone();
    if let Some(home) = &user.home {
        if let Some(home) = canonicalize_path(&home.display().to_string(), "home") {
            if is_safe_home_path(&home) {
                writable.push(home);
            } else {
                eprintln!(
          "roam: SECURITY: home directory '{}' is too broad - skipping writable exception",
          home.display()
        );
            }
        }
    }
    writable
}

fn apply_blacklist(blacklist: &[BlockedPath]) -> Result<()> {
    if blacklist.is_empty() {
        return Ok(());
    }

    // SAFETY: unshare is called with a single clone flag bitmask.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    mount_path(
        None,
        Path::new("/"),
        None,
        (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
        None,
    )?;

    let placeholder_fd = create_blacklist_placeholder_fd()?;
    let placeholder_source = format!("/proc/self/fd/{placeholder_fd}");

    for blocked in blacklist
        .iter()
        .filter(|blocked| blocked.kind == BlockedPathKind::FileLike)
    {
        bind_mount_path(&placeholder_source, &blocked.path)?;
    }

    for blocked in blacklist
        .iter()
        .filter(|blocked| blocked.kind == BlockedPathKind::Directory)
    {
        mount_path(
            Some("tmpfs"),
            &blocked.path,
            Some("tmpfs"),
            (libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOSUID) as libc::c_ulong,
            Some("size=4k,mode=0555"),
        )?;
    }

    close_fd(placeholder_fd);
    Ok(())
}

fn drop_privileges(user: &SessionUser) -> Result<()> {
    prctl(PR_SET_KEEPCAPS as _, 1, 0, 0, 0, "prctl(PR_SET_KEEPCAPS)")?;

    let groups = [user.gid];
    // SAFETY: groups points to one gid_t entry for the duration of the call.
    let rc = unsafe { libc::setgroups(groups.len(), groups.as_ptr()) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error().into());
    }

    // SAFETY: valid scalar values passed directly to libc.
    if unsafe { libc::setresgid(user.gid, user.gid, user.gid) } == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::setresuid(user.uid, user.uid, user.uid) } == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn create_blacklist_placeholder_fd() -> Result<RawFd> {
    let name = CString::new("roam-blacklisted-file").expect("static name");
    // SAFETY: name is a valid NUL-terminated identifier.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: scalar arguments only.
    if unsafe { libc::fchmod(fd, 0o444) } == -1 {
        let err = std::io::Error::last_os_error();
        close_fd(fd);
        return Err(err.into());
    }
    Ok(fd)
}

fn configure_capabilities() -> Result<()> {
    let dac_bit = 1u32 << (CAP_DAC_READ_SEARCH % 32);
    let setpcap_bit = 1u32 << (CAP_SETPCAP % 32);

    cap_set_epi(
        dac_bit | setpcap_bit,
        0,
        dac_bit | setpcap_bit,
        0,
        dac_bit,
        0,
    )?;
    prctl(
        PR_CAP_AMBIENT as _,
        PR_CAP_AMBIENT_RAISE,
        CAP_DAC_READ_SEARCH as _,
        0,
        0,
        "prctl(PR_CAP_AMBIENT_RAISE)",
    )?;

    if cap_in_effective(CAP_SETPCAP)? {
        for cap in 0..64u32 {
            if cap == CAP_DAC_READ_SEARCH {
                continue;
            }
            // SAFETY: prctl is called with scalar arguments only.
            let rc = unsafe { libc::prctl(PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
            if rc == -1 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINVAL) {
                    break;
                }
            }
        }
    }

    cap_set_epi(dac_bit, 0, dac_bit, 0, dac_bit, 0)?;
    Ok(())
}

fn cap_in_effective(cap: u32) -> Result<bool> {
    let mut header = UserCapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [UserCapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: header/data point to properly sized capability structures.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut UserCapHeader,
            data.as_mut_ptr(),
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((data[(cap / 32) as usize].effective & (1 << (cap % 32))) != 0)
}

fn cap_set_epi(eff0: u32, eff1: u32, prm0: u32, prm1: u32, inh0: u32, inh1: u32) -> Result<()> {
    let mut header = UserCapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [
        UserCapData {
            effective: eff0,
            permitted: prm0,
            inheritable: inh0,
        },
        UserCapData {
            effective: eff1,
            permitted: prm1,
            inheritable: inh1,
        },
    ];
    // SAFETY: header/data point to properly sized capability structures.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut UserCapHeader,
            data.as_mut_ptr(),
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn detect_landlock_abi() -> Result<i32> {
    // SAFETY: null attribute pointer and zero size are the documented ABI query.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi == -1 {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => {
                return Err(Error::Rejected(
                    "Landlock not supported by this kernel (need 5.13+)".to_string(),
                ))
            }
            _ => return Err(err.into()),
        }
    }
    Ok((abi as i32).min(5))
}

fn guard_landlock_abi(abi: i32, allow_degraded: bool) -> Result<()> {
    if abi >= 3 {
        return Ok(());
    }
    let missing = if abi < 2 {
        "REFER (rename) and TRUNCATE"
    } else {
        "TRUNCATE"
    };
    eprintln!(
        "roam: WARNING: Landlock ABI v{} does not mediate {} operations.",
        abi, missing
    );
    if !allow_degraded {
        return Err(Error::Rejected(
            "refusing to start on Landlock ABI < 3; set allow_degraded = true in /etc/roam/config.toml to override"
                .to_string(),
        ));
    }
    Ok(())
}

fn create_ruleset(abi: i32) -> Result<RawFd> {
    let abi_mask = [
        (LANDLOCK_ACCESS_FS_MAKE_SYM << 1) - 1,
        (LANDLOCK_ACCESS_FS_REFER << 1) - 1,
        (LANDLOCK_ACCESS_FS_TRUNCATE << 1) - 1,
        (LANDLOCK_ACCESS_FS_TRUNCATE << 1) - 1,
        (LANDLOCK_ACCESS_FS_IOCTL_DEV << 1) - 1,
    ];

    let handled_access_fs = (LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM
        | LANDLOCK_ACCESS_FS_REFER
        | LANDLOCK_ACCESS_FS_TRUNCATE
        | LANDLOCK_ACCESS_FS_IOCTL_DEV)
        & abi_mask[(abi - 1) as usize];

    let attr = LandlockRulesetAttr { handled_access_fs };
    // SAFETY: attr points to a valid ruleset struct for the duration of the call.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0,
        )
    };
    if fd == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(fd as RawFd)
}

fn add_global_ro_rule(ruleset_fd: RawFd) -> Result<()> {
    let fd = open_path(Path::new("/"))?;
    let rule = LandlockPathBeneathAttr {
        allowed_access: LANDLOCK_ACCESS_FS_EXECUTE
            | LANDLOCK_ACCESS_FS_READ_FILE
            | LANDLOCK_ACCESS_FS_READ_DIR,
        parent_fd: fd,
    };
    ll_add_rule(ruleset_fd, &rule)?;
    close_fd(fd);
    Ok(())
}

fn add_writable_rules(ruleset_fd: RawFd, writable: &[PathBuf]) -> Result<()> {
    let file_compat = LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_TRUNCATE
        | LANDLOCK_ACCESS_FS_IOCTL_DEV;
    let rw_dir_access = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM
        | LANDLOCK_ACCESS_FS_REFER
        | LANDLOCK_ACCESS_FS_TRUNCATE
        | LANDLOCK_ACCESS_FS_IOCTL_DEV;

    for path in writable {
        let fd = match open_path(path) {
            Ok(fd) => fd,
            Err(err) => {
                eprintln!(
                    "roam: note: writable path '{}': {} (skipped)",
                    path.display(),
                    err
                );
                continue;
            }
        };
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(err) => {
                eprintln!("roam: note: stat '{}': {} (skipped)", path.display(), err);
                close_fd(fd);
                continue;
            }
        };
        let rule = LandlockPathBeneathAttr {
            allowed_access: if metadata.is_dir() {
                rw_dir_access
            } else {
                file_compat
            },
            parent_fd: fd,
        };
        if let Err(err) = ll_add_rule(ruleset_fd, &rule) {
            eprintln!(
                "roam: note: landlock rule '{}': {} (skipped)",
                path.display(),
                err
            );
        }
        close_fd(fd);
    }
    Ok(())
}

fn sanitize_fds(exceptions: &[RawFd]) -> Result<()> {
    let path = CString::new("/proc/self/fd").expect("static path");
    // SAFETY: path is a valid NUL-terminated string for the duration of the call.
    let dir = unsafe { libc::opendir(path.as_ptr()) };
    if dir.is_null() {
        for fd in 3..1024 {
            if exceptions.contains(&fd) {
                continue;
            }
            close_fd(fd);
        }
        return Ok(());
    }

    // SAFETY: dir is a valid DIR* returned by opendir.
    let dir_fd = unsafe { libc::dirfd(dir) };
    loop {
        // SAFETY: readdir consumes dir until it returns null at EOF or error.
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break;
        }

        // SAFETY: entry points to a valid dirent for this iteration.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let Ok(name) = name.to_str() else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let Ok(fd) = name.parse::<RawFd>() else {
            continue;
        };
        if fd <= 2 || fd == dir_fd || exceptions.contains(&fd) {
            continue;
        }
        close_fd(fd);
    }

    // SAFETY: dir is still valid because we skipped dir_fd during iteration.
    if unsafe { libc::closedir(dir) } == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn exec_shell(shell: &Path, command: &[String], metadata: &SessionMetadata) -> Result<()> {
    if !command.is_empty() {
        let mut cmd = Command::new(&command[0]);
        cmd.args(&command[1..]);
        let err = cmd.exec();
        return Err(err.into());
    }

    let shell_name = shell
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| Error::Rejected("shell path must have a file name".to_string()))?;

    let login_name = format!("-{shell_name}");
    let err = match shell_name {
        "bash" => exec_bash_shell(shell, &login_name, metadata),
        "zsh" => exec_zsh_shell(shell, &login_name, metadata),
        _ => Command::new(shell).arg0(login_name).exec(),
    };
    Err(err.into())
}

fn exec_bash_shell(shell: &Path, login_name: &str, metadata: &SessionMetadata) -> std::io::Error {
    let runtime_root = metadata.runtime_root();
    if let Err(err) = fs::create_dir_all(&runtime_root) {
        return err;
    }
    if let Err(err) = fs::set_permissions(&runtime_root, fs::Permissions::from_mode(0o700)) {
        return err;
    }

    let init_path = runtime_root.join("bashrc");
    if let Err(err) = write_shell_init(&init_path, bash_sudo_alias_init()) {
        return err;
    }

    Command::new(shell)
        .arg("--noprofile")
        .arg("--rcfile")
        .arg(&init_path)
        .arg("-i")
        .arg0(login_name)
        .exec()
}

fn exec_zsh_shell(shell: &Path, login_name: &str, metadata: &SessionMetadata) -> std::io::Error {
    let zdotdir = metadata.runtime_root().join("zsh");
    if let Err(err) = fs::create_dir_all(&zdotdir) {
        return err;
    }
    if let Err(err) = fs::set_permissions(&zdotdir, fs::Permissions::from_mode(0o700)) {
        return err;
    }

    for (name, contents) in zsh_sudo_alias_init_files() {
        let path = zdotdir.join(name);
        if let Err(err) = write_shell_init(&path, &contents) {
            return err;
        }
    }

    env::set_var("ZDOTDIR", &zdotdir);
    Command::new(shell).arg0(login_name).exec()
}

fn write_shell_init(path: &Path, contents: &str) -> std::io::Result<()> {
    fs::write(path, contents)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn bash_sudo_alias_init() -> &'static str {
    r#"# Generated by roam.
for profile in "$ROAM_REAL_HOME/.bash_profile" "$ROAM_REAL_HOME/.bash_login" "$ROAM_REAL_HOME/.profile"; do
  if [ -f "$profile" ]; then
    . "$profile"
    break
  fi
done
if [ -f "$ROAM_REAL_HOME/.bashrc" ]; then
  . "$ROAM_REAL_HOME/.bashrc"
fi
alias sudo='roam sudo-passthrough'
"#
}

fn zsh_sudo_alias_init_files() -> [(&'static str, String); 5] {
    [
        (".zshenv", zsh_source_file(".zshenv", false)),
        (".zprofile", zsh_source_file(".zprofile", false)),
        (".zshrc", zsh_source_file(".zshrc", true)),
        (".zlogin", zsh_source_file(".zlogin", false)),
        (".zlogout", zsh_source_file(".zlogout", false)),
    ]
}

fn zsh_source_file(name: &str, add_alias: bool) -> String {
    let mut contents = if name == ".zshenv" {
        format!(
            "# Generated by roam.\nroam_zdotdir=\"$ZDOTDIR\"\nif [ -f \"$ROAM_REAL_HOME/{name}\" ]; then\n  . \"$ROAM_REAL_HOME/{name}\"\nfi\nZDOTDIR=\"$roam_zdotdir\"\nexport ZDOTDIR\nunset roam_zdotdir\n"
        )
    } else {
        format!(
            "# Generated by roam.\nif [ -f \"$ROAM_REAL_HOME/{name}\" ]; then\n  . \"$ROAM_REAL_HOME/{name}\"\nfi\n"
        )
    };
    if add_alias {
        contents.push_str("alias sudo='roam sudo-passthrough'\n");
    }
    contents
}

fn log_session_open(metadata: &SessionMetadata, abi: i32, writable: &[PathBuf]) {
    let joined = writable
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    syslog_info(&format!(
        "session opened: session_id={} invoking_user={} roam_user={} landlock_abi=v{} writable={}",
        metadata.session_id,
        metadata.invoking_user.as_deref().unwrap_or("(unknown)"),
        metadata.session_user,
        abi,
        joined
    ));
}

fn open_path(path: &Path) -> Result<RawFd> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::Rejected(format!("{} contains interior NUL", path.display())))?;
    // SAFETY: c_path is NUL-terminated and valid for the duration of the call.
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(fd)
}

fn bind_mount_path(source: &str, target: &Path) -> Result<()> {
    mount_path(
        Some(source),
        target,
        None,
        libc::MS_BIND as libc::c_ulong,
        None,
    )
}

fn mount_path(
    source: Option<&str>,
    target: &Path,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<()> {
    let source_c = match source {
        Some(source) => Some(
            CString::new(source)
                .map_err(|_| Error::Rejected(format!("invalid mount source '{source}'")))?,
        ),
        None => None,
    };
    let target_c = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| Error::Rejected(format!("{} contains interior NUL", target.display())))?;
    let fstype_c = match fstype {
        Some(fstype) => Some(
            CString::new(fstype)
                .map_err(|_| Error::Rejected(format!("invalid filesystem type '{fstype}'")))?,
        ),
        None => None,
    };
    let data_c = match data {
        Some(data) => Some(
            CString::new(data)
                .map_err(|_| Error::Rejected(format!("invalid mount data '{data}'")))?,
        ),
        None => None,
    };

    // SAFETY: all pointers are either null or valid NUL-terminated strings.
    let rc = unsafe {
        libc::mount(
            source_c
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            target_c.as_ptr(),
            fstype_c
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            flags,
            data_c
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr().cast()),
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn ll_add_rule(ruleset_fd: RawFd, rule: &LandlockPathBeneathAttr) -> Result<()> {
    // SAFETY: rule points to a valid path-beneath struct for the duration of the call.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            rule as *const LandlockPathBeneathAttr,
            0,
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn ll_restrict_self(ruleset_fd: RawFd, flags: u32) -> Result<()> {
    // SAFETY: scalar arguments only.
    let rc = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, flags) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn clear_cloexec(fd: RawFd) -> Result<()> {
    // SAFETY: scalar arguments only.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: scalar arguments only.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn prctl(
    option: libc::c_int,
    arg2: libc::c_ulong,
    arg3: libc::c_ulong,
    arg4: libc::c_ulong,
    arg5: libc::c_ulong,
    label: &str,
) -> Result<()> {
    // SAFETY: scalar arguments only.
    let rc = unsafe { libc::prctl(option, arg2, arg3, arg4, arg5) };
    if rc == -1 {
        return Err(Error::Message(format!(
            "{label}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn close_fd(fd: RawFd) {
    // SAFETY: closing an fd is safe; errors are ignored on cleanup paths.
    unsafe {
        libc::close(fd);
    }
}

#[cfg(test)]
mod tests {
    use super::{bash_sudo_alias_init, zsh_source_file};

    #[test]
    fn bash_init_installs_sudo_alias() {
        let init = bash_sudo_alias_init();
        assert!(init.contains("alias sudo='roam sudo-passthrough'"));
        assert!(init.contains("$ROAM_REAL_HOME/.bash_profile"));
    }

    #[test]
    fn zsh_rc_installs_sudo_alias() {
        let init = zsh_source_file(".zshrc", true);
        assert!(init.contains(". \"$ROAM_REAL_HOME/.zshrc\""));
        assert!(init.contains("alias sudo='roam sudo-passthrough'"));
    }

    #[test]
    fn zsh_non_rc_files_do_not_install_alias() {
        let init = zsh_source_file(".zprofile", false);
        assert!(init.contains(". \"$ROAM_REAL_HOME/.zprofile\""));
        assert!(!init.contains("alias sudo='roam sudo-passthrough'"));
    }

    #[test]
    fn zshenv_restores_temp_zdotdir_after_sourcing_user_file() {
        let init = zsh_source_file(".zshenv", false);
        assert!(init.contains("roam_zdotdir=\"$ZDOTDIR\""));
        assert!(init.contains("ZDOTDIR=\"$roam_zdotdir\""));
    }
}
