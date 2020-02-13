use libc::c_void;
use libc::{close, fcntl, socket};
use libc::{
    EAGAIN, EINTR, EWOULDBLOCK, FD_CLOEXEC, F_GETFD, F_GETFL, F_SETFD, F_SETFL, MSG_DONTWAIT,
    O_NONBLOCK,
};

#[cfg(feature = "bs-filter")]
use bs_filter::{backend, backend::Backend, Filter};

#[cfg(target_os = "linux")]
use libc::{SOCK_CLOEXEC, SOCK_NONBLOCK};

use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::iter::FromIterator;

use bs_system::{cvt, Result, SetSocketOption, SystemError};

pub(crate) const PROTO_NULL: i32 = 0_i32;
// TODO - use this pub(crate) const IPPROTO_L2TP: i32 = 115_i32;
pub(crate) const DRAIN_BUFFER_SIZE: usize = 4096;

#[doc(hidden)]
pub trait SocketKind {
    fn new(fd: RawFd) -> Self;
    fn os(&self) -> i32;
    fn domain() -> i32;
    fn type_() -> i32;
    fn protocol() -> i32;
}

/// a generic `socket(7)` type
#[derive(Debug)]
pub struct Socket<S: SocketKind> {
    inner: S,
}

impl<S: SocketKind> Socket<S> {
    /// Creates a new `Socket` with the `O_CLOEXEC` flag set
    ///
    /// this is the recommended way to create blocking `Socket`s
    #[cfg(target_os = "linux")]
    pub fn new() -> Result<Self> {
        Self::with_flags(SOCK_CLOEXEC)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new() -> Result<Self> {
        Self::with_flags(0)
    }

    /// Creates a new `Socket` without setting any creation flags
    #[cfg(target_os = "linux")]
    pub fn plain() -> Result<Self> {
        Self::with_flags(0)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn plain() -> Result<Self> {
        Self::new()
    }

    /// Creates a new nonblocking `Socket` with the `O_CLOEXEC` and the `O_NONBLOCK` flags set
    ///
    /// this is the recommended way to create nonblocking `Socket`s
    #[cfg(target_os = "linux")]
    #[cfg(target_os = "linux")]
    pub fn nonblocking() -> Result<Self> {
        Self::with_flags(SOCK_CLOEXEC | SOCK_NONBLOCK)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn nonblocking() -> Result<Self> {
        Self::new().and_then(|s| s.set_nonblocking().map_ok(|| s))
    }

    /// Creates a new nonblocking `Socket` without setting the `O_CLOEXEC` flag
    #[cfg(target_os = "linux")]
    pub fn plain_nonblocking() -> Result<Self> {
        Self::with_flags(SOCK_NONBLOCK)
    }

    fn with_flags(flags: i32) -> Result<Self> {
        match unsafe { cvt(socket(S::domain(), S::type_() | flags, S::protocol())) } {
            Ok(fd) => Ok(Self { inner: S::new(fd) }),
            Err(e) => Err(e.into()),
        }
    }
}

impl<S: SocketKind> Drop for Socket<S> {
    fn drop(&mut self) {
        loop {
            match unsafe { cvt(close(self.inner.os())) } {
                Ok(_) => return,
                Err(SystemError(EINTR)) => continue,
                _ => unreachable!(),
            }
        }
    }
}

mod private {
    use super::*;

    pub trait PrivateBasicSocket: Sized {
        fn os(&self) -> RawFd;

        fn set_option(&mut self, option: impl SetSocketOption) -> Result<&mut Self> {
            option.set(self.os()).map(|_| self)
        }

        // TODO - flags to bitflags
        fn set_flags(&mut self, flags: i32) -> Result<()> {
            unsafe {
                cvt(fcntl(self.os(), F_SETFL, flags))
                    .map_err(|e| SystemError::from(e))
                    .and(Ok(()))
            }
        }

        // TODO - flags to bitflags
        fn set_fd_flags(&mut self, flags: i32) -> Result<()> {
            unsafe {
                cvt(fcntl(self.os(), F_SETFD, flags))
                    .map_err(|e| SystemError::from(e))
                    .and(Ok(()))
            }
        }
    }
}

impl<S: SocketKind> private::PrivateBasicSocket for Socket<S> {
    fn os(&self) -> i32 {
        self.inner.os()
    }
}

/// The most basic socket operations, implemented for all socket kinds
pub trait BasicSocket: private::PrivateBasicSocket {
    /// `fcntl(..., F_GETFL, ...)`
    fn flags(&self) -> Result<i32> {
        unsafe { Ok(cvt(fcntl(self.os(), F_GETFL))?) }
    }

    /// `fcntl(..., F_GETFD, ...)`
    fn fd_flags(&self) -> Result<i32> {
        unsafe { Ok(cvt(fcntl(self.os(), F_GETFD))?) }
    }

    // TODO - make recv more fun and document
    // TODO - recv_from
    // TODO - send, send_from
    /// recieve a packet on the socket
    fn recv(&self, buf: &mut [u8], flags: i32) -> Result<usize> {
        unsafe {
            let n =
                cvt({ libc::recv(self.os(), buf.as_mut_ptr() as *mut c_void, buf.len(), flags) })?;
            Ok(n as usize)
        }
    }

    // TODO - set blocking(bool)
    /// set the socket to nonblocking mode
    fn set_nonblocking(&mut self) -> Result<()> {
        self.set_flags(self.flags()? | O_NONBLOCK)
    }

    /// set the socket to blocking mode
    fn set_blocking(&mut self) -> Result<()> {
        self.set_flags(self.flags()? & !O_NONBLOCK)
    }

    /// flush the socket's recieve queue
    #[cfg(target_os = "linux")]
    fn drain(&mut self) -> Result<&mut Self> {
        let mut buf = [0; DRAIN_BUFFER_SIZE];
        loop {
            match self.recv(&mut buf, MSG_DONTWAIT) {
                Err(SystemError(EWOULDBLOCK)) => {
                    return Ok(self);
                }
                // rustc claims this branch is unreachable
                // because it assumes EWOULDBLOCK == EAGAIN == 11
                // but that's not always the case
                #[allow(unreachable_patterns)]
                Err(SystemError(EAGAIN)) => {
                    return Ok(self);
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
    fn drain(&mut self) -> Result<&mut Self> {
        let mut buf = [0; DRAIN_BUFFER_SIZE];
        let original_flags = self.flags()?;
        let revert = false;
        if !(original_flags & O_NONBLOCK) {
            let revert = true;
        }
        self.set_flags(original_flags | O_NONBLOCK);
        let res = loop {
            match self.recv(&mut buf, 0) {
                Err(SystemError(EWOULDBLOCK)) => {
                    return Ok(self);
                }
                #[allow(unreachable_patterns)]
                Err(SystemError(EAGAIN)) => {
                    return Ok(self);
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

    /// set's the socket `FD_CLOEXEC` flag
    fn set_cloexec(&mut self) -> Result<()> {
        self.set_fd_flags(FD_CLOEXEC)
    }
}

impl<S: SocketKind> BasicSocket for Socket<S> {}

impl<S: SocketKind> AsRawFd for Socket<S> {
    fn as_raw_fd(&self) -> RawFd {
        private::PrivateBasicSocket::os(self)
    }
}

impl<S: SocketKind> IntoRawFd for Socket<S> {
    fn into_raw_fd(self) -> RawFd {
        private::PrivateBasicSocket::os(&self)
    }
}

impl<S: SocketKind> FromRawFd for Socket<S> {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self { inner: S::new(fd) }
    }
}

/// Extends [`BasicSocket`](trait.BasicSocket.html) with a method to set a packet filter on the
/// socket
#[cfg(feature = "bs-filter")]
pub trait SetFilter: BasicSocket {
    /// set a `Filter` to choose which packets this `Socket` will accept
    fn set_filter(&mut self, filter: impl SetSocketOption) -> Result<&mut Self> {
        let f = Filter::<backend::Classic>::from_iter(backend::Classic::contradiction());
        let drop_filter = f.build()?;
        self.set_option(drop_filter)?.drain()?.set_option(filter)
    }
}

#[cfg(target_os = "linux")]
impl<S: SocketKind> SetFilter for Socket<S> {}

