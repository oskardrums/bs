use libc::{
    c_void, close, fcntl, socket, EAGAIN, EWOULDBLOCK, FD_CLOEXEC, F_GETFD, F_GETFL, F_SETFD,
    F_SETFL, MSG_DONTWAIT, O_NONBLOCK,
};

use bs_filter as filter;

#[cfg(target_os = "linux")]
use libc::{SOCK_CLOEXEC, SOCK_NONBLOCK};

use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

use bs_system::{cvt, Result, SetSocketOption, SocketOptionError};

pub const PROTO_NULL: i32 = 0_i32;
pub const IPPROTO_L2TP: i32 = 115_i32;
pub const DRAIN_BUFFER_SIZE: usize = 4096;

pub trait SocketDesc {
    fn new(fd: RawFd) -> Self;
    fn os(&self) -> i32;
    fn domain() -> i32;
    fn type_() -> i32;
    fn protocol() -> i32;
}

#[derive(Debug)]
pub struct Socket<S: SocketDesc> {
    inner: S,
}

use std::iter::FromIterator;
impl<S: SocketDesc> Socket<S> {
    pub(crate) fn os(&self) -> i32 {
        self.inner.os()
    }

    #[cfg(target_os = "linux")]
    pub fn new() -> Result<Self> {
        Self::with_flags(SOCK_CLOEXEC)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new() -> Result<Self> {
        Self::with_flags(0)
    }

    #[cfg(target_os = "linux")]
    pub fn plain() -> Result<Self> {
        Self::with_flags(0)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn plain() -> Result<Self> {
        Self::new()
    }

    #[cfg(target_os = "linux")]
    pub fn nonblocking() -> Result<Self> {
        Self::with_flags(SOCK_CLOEXEC | SOCK_NONBLOCK)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn nonblocking() -> Result<Self> {
        Self::new().and_then(|s| s.set_nonblocking().map_ok(|| s))
    }

    #[cfg(target_os = "linux")]
    pub fn plain_nonblocking() -> Result<Self> {
        Self::with_flags(SOCK_NONBLOCK)
    }

    fn with_flags(flags: i32) -> Result<Self> {
        match unsafe { cvt(socket(S::domain(), S::type_() | flags, S::protocol())) } {
            Ok(fd) => Ok(Self {
                inner: S::new(fd as i32),
            }),
            Err(e) => Err(e.into()),
        }
    }

    pub fn flags(&self) -> Result<i32> {
        unsafe { Ok(cvt(fcntl(self.os(), F_GETFL))?) }
    }

    pub fn fd_flags(&self) -> Result<i32> {
        unsafe { Ok(cvt(fcntl(self.os(), F_GETFD))?) }
    }

    fn attach_filter<K: filter::backend::Backend>(
        &mut self,
        filter: filter::Filter<K>,
    ) -> Result<()> {
        let mut prog: filter::Program<K> = filter.into();
        if let Some(opt) = prog.build() {
            return opt.set(self.os());
        } else {
            // TODO - imlpement
            unreachable!()
        }
    }
    // TODO - feature filter
    pub fn set_filter<K: filter::backend::Backend>(
        &mut self,
        filter: filter::Filter<K>,
    ) -> Result<()> {
        let drop_filter = filter::Filter::<K>::from_iter(K::contradiction());
        self.attach_filter(drop_filter)?;
        self.drain().unwrap();
        self.attach_filter(filter)
    }

    // TODO - make recv more fun
    // TODO - recv_from
    // TODO - send, send_from
    pub fn recv(&self, buf: &mut [u8], flags: i32) -> Result<usize> {
        unsafe {
            let n =
                cvt({ libc::recv(self.os(), buf.as_mut_ptr() as *mut c_void, buf.len(), flags) })?;
            Ok(n as usize)
        }
    }

    // TODO - set blocking(bool)
    pub fn set_nonblocking(&mut self) -> Result<()> {
        self.set_flags(self.flags()? | O_NONBLOCK)
    }

    pub fn set_blocking(&mut self) -> Result<()> {
        self.set_flags(self.flags()? & !O_NONBLOCK)
    }

    #[cfg(target_os = "linux")]
    fn drain(&mut self) -> Result<()> {
        let mut buf = [0; DRAIN_BUFFER_SIZE];
        loop {
            match self.recv(&mut buf, MSG_DONTWAIT) {
                Err(SocketOptionError(EWOULDBLOCK)) => {
                    return Ok(());
                }
                // rustc claims this branch is unreachable
                // because it assumes EWOULDBLOCK == EAGAIN == 11
                // but that's not always the case
                #[allow(unreachable_patterns)]
                Err(SocketOptionError(EAGAIN)) => {
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(_) => {
                    continue;
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn drain(&mut self) -> Result<()> {
        let mut buf = [0; DRAIN_BUFFER_SIZE];
        let original_flags = self.flags()?;
        let revert = false;
        if !(original_flags & O_NONBLOCK) {
            let revert = true;
        }
        self.set_flags(original_flags | O_NONBLOCK);
        let res = loop {
            match self.recv(&mut buf, 0) {
                Err(SocketOptionError(EWOULDBLOCK)) => {
                    return Ok(());
                }
                #[allow(unreachable_patterns)]
                Err(SocketOptionError(EAGAIN)) => {
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(_) => {
                    continue;
                }
            }
        };
        if revert {
            self.set_flags(original_flags);
        }
        res
    }

    pub fn set_cloexec(&mut self) -> Result<()> {
        self.set_fd_flags(FD_CLOEXEC)
    }

    // TODO - flags to bitflags
    fn set_flags(&mut self, flags: i32) -> Result<()> {
        unsafe {
            cvt(fcntl(self.os(), F_SETFL, flags))
                .map_err(|e| SocketOptionError::from(e))
                .and(Ok(()))
        }
    }

    // TODO - flags to bitflags
    fn set_fd_flags(&mut self, flags: i32) -> Result<()> {
        unsafe {
            cvt(fcntl(self.os(), F_SETFD, flags))
                .map_err(|e| SocketOptionError::from(e))
                .and(Ok(()))
        }
    }
}

use libc::EINTR;
impl<S: SocketDesc> Drop for Socket<S> {
    fn drop(&mut self) {
        loop {
            match unsafe { cvt(close(self.inner.os())) } {
                Ok(_) => return,
                Err(SocketOptionError(EINTR)) => continue,
                _ => unreachable!(),
            }
        }
    }
}

impl<S: SocketDesc> AsRawFd for Socket<S> {
    fn as_raw_fd(&self) -> RawFd {
        self.os()
    }
}

impl<S: SocketDesc> IntoRawFd for Socket<S> {
    fn into_raw_fd(self) -> RawFd {
        self.os()
    }
}

impl<S: SocketDesc> FromRawFd for Socket<S> {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self { inner: S::new(fd) }
    }
}
