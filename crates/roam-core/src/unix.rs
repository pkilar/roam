use std::ffi::{CStr, CString};
use std::path::PathBuf;

use crate::{Error, Result};

#[derive(Clone, Debug)]
pub struct SessionUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: Option<PathBuf>,
}

pub struct PasswdRecord {
    pub uid: u32,
    pub gid: u32,
    pub home: String,
}

pub struct GroupRecord {
    pub gid: u32,
}

pub fn lookup_user(name: &str) -> Result<SessionUser> {
    let c_name =
        CString::new(name).map_err(|_| Error::Config(format!("invalid user name '{name}'")))?;
    let passwd = lookup_passwd(&c_name)
        .map_err(|err| Error::Config(format!("failed to resolve user '{name}': {err}")))?
        .ok_or_else(|| Error::Config(format!("user '{name}' not found")))?;
    let home = if passwd.home.is_empty() {
        None
    } else {
        Some(PathBuf::from(passwd.home))
    };
    Ok(SessionUser {
        name: name.to_string(),
        uid: passwd.uid,
        gid: passwd.gid,
        home,
    })
}

pub fn lookup_passwd(name: &CStr) -> Result<Option<PasswdRecord>> {
    let mut buf_len = initial_r_buffer_size(libc::_SC_GETPW_R_SIZE_MAX);
    loop {
        let mut passwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut buffer = vec![0u8; buf_len];
        let mut result = std::ptr::null_mut();

        // SAFETY: passwd points to valid storage, buffer is writable, and name is a valid C string.
        let rc = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                passwd.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if rc == 0 {
            if result.is_null() {
                return Ok(None);
            }
            // SAFETY: result is non-null and points to the passwd struct filled by getpwnam_r.
            let passwd = unsafe { passwd.assume_init() };
            let home = if passwd.pw_dir.is_null() {
                String::new()
            } else {
                // SAFETY: pw_dir points into buffer for the lifetime of this scope; we copy it out.
                unsafe { CStr::from_ptr(passwd.pw_dir) }
                    .to_string_lossy()
                    .into_owned()
            };
            return Ok(Some(PasswdRecord {
                uid: passwd.pw_uid,
                gid: passwd.pw_gid,
                home,
            }));
        }
        if rc == libc::ERANGE {
            buf_len *= 2;
            continue;
        }
        return Err(std::io::Error::from_raw_os_error(rc).into());
    }
}

pub fn lookup_group(name: &CStr) -> Result<Option<GroupRecord>> {
    let mut buf_len = initial_r_buffer_size(libc::_SC_GETGR_R_SIZE_MAX);
    loop {
        let mut group = std::mem::MaybeUninit::<libc::group>::uninit();
        let mut buffer = vec![0u8; buf_len];
        let mut result = std::ptr::null_mut();

        // SAFETY: group points to valid storage, buffer is writable, and name is a valid C string.
        let rc = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                group.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if rc == 0 {
            if result.is_null() {
                return Ok(None);
            }
            // SAFETY: result is non-null and points to initialized group storage.
            let group = unsafe { group.assume_init() };
            return Ok(Some(GroupRecord { gid: group.gr_gid }));
        }
        if rc == libc::ERANGE {
            buf_len *= 2;
            continue;
        }
        return Err(std::io::Error::from_raw_os_error(rc).into());
    }
}

pub fn syslog_info(message: &str) {
    let ident = CString::new("roam").expect("static string");
    let Ok(message) = CString::new(message) else {
        return;
    };
    // SAFETY: static and stack CStrings remain valid for the duration of the calls.
    unsafe {
        libc::openlog(ident.as_ptr(), libc::LOG_PID, libc::LOG_AUTHPRIV);
        libc::syslog(libc::LOG_INFO, c"%s".as_ptr(), message.as_ptr());
        libc::closelog();
    }
}

fn initial_r_buffer_size(sysconf_name: libc::c_int) -> usize {
    // SAFETY: sysconf only reads the provided name constant.
    let size = unsafe { libc::sysconf(sysconf_name) };
    if size <= 0 {
        16 * 1024
    } else {
        size as usize
    }
}
