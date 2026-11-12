//! AF_VSOCK helpers (not provided by std) and small socket utilities.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub const VMADDR_CID_ANY: u32 = u32::MAX;
pub const VMADDR_CID_HOST: u32 = 2;

const SO_VM_SOCKETS_BUFFER_SIZE: libc::c_int = 0;
const SO_VM_SOCKETS_BUFFER_MAX_SIZE: libc::c_int = 2;

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r) }
}

fn vsock_addr(cid: u32, port: u32) -> libc::sockaddr_vm {
    let mut a: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    a.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    a.svm_cid = cid;
    a.svm_port = port;
    a
}

fn vsock_socket() -> io::Result<OwnedFd> {
    let fd = cvt(unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn vsock_connect(cid: u32, port: u32, buf: Option<u64>) -> io::Result<OwnedFd> {
    let fd = vsock_socket()?;
    if let Some(b) = buf {
        set_vsock_buffer(fd.as_raw_fd(), b)?;
    }
    let a = vsock_addr(cid, port);
    cvt(unsafe {
        libc::connect(fd.as_raw_fd(), (&a as *const libc::sockaddr_vm).cast(), size_of::<libc::sockaddr_vm>() as u32)
    })?;
    Ok(fd)
}

pub fn vsock_listen(port: u32) -> io::Result<OwnedFd> {
    let fd = vsock_socket()?;
    let a = vsock_addr(VMADDR_CID_ANY, port);
    cvt(unsafe {
        libc::bind(fd.as_raw_fd(), (&a as *const libc::sockaddr_vm).cast(), size_of::<libc::sockaddr_vm>() as u32)
    })?;
    cvt(unsafe { libc::listen(fd.as_raw_fd(), 1024) })?;
    Ok(fd)
}

/// Raise the vsock credit window. Larger windows keep the virtqueue busy on
/// high bandwidth-delay paths.
pub fn set_vsock_buffer(fd: RawFd, size: u64) -> io::Result<()> {
    for opt in [SO_VM_SOCKETS_BUFFER_MAX_SIZE, SO_VM_SOCKETS_BUFFER_SIZE] {
        cvt(unsafe {
            libc::setsockopt(fd, libc::AF_VSOCK, opt, (&size as *const u64).cast(), size_of::<u64>() as u32)
        })?;
    }
    Ok(())
}

pub fn accept(listener: RawFd) -> io::Result<OwnedFd> {
    loop {
        let fd = unsafe { libc::accept4(listener, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
        if fd >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINTR) {
            return Err(e);
        }
    }
}
