//! `AF_VSOCK` (Linux guest VM, CID_ANY:7001) and `AF_UNIX` listener/connector primitives.

use std::{
    fs,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::net::{UnixListener, UnixStream},
    },
    path::Path,
};

pub struct VsockStream(OwnedFd);

impl Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe { libc::read(self.0.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
    }
}

impl Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = unsafe { libc::write(self.0.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
        if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub struct VsockListener(OwnedFd);

#[cfg(target_os = "linux")]
impl VsockListener {
    pub fn bind(cid: u32, port: u32) -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = cid;
        addr.svm_port = port;
        let rc = unsafe {
            libc::bind(
                owned.as_raw_fd(),
                (&addr as *const libc::sockaddr_vm).cast(),
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::listen(owned.as_raw_fd(), 16) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(owned))
    }

    pub fn accept(&self) -> io::Result<VsockStream> {
        let fd = unsafe {
            libc::accept4(
                self.0.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(VsockStream(unsafe { OwnedFd::from_raw_fd(fd) }))
    }
}

pub fn bind_unix(path: &Path) -> io::Result<UnixListener> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    let l = UnixListener::bind(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(l)
}

pub fn connect_unix(path: &Path) -> io::Result<UnixStream> {
    UnixStream::connect(path)
}
