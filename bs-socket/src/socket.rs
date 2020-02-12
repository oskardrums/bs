use libc::{
    c_void, close, fcntl, socket, EAGAIN, EWOULDBLOCK, FD_CLOEXEC, F_GETFD, F_GETFL, F_SETFD,
    F_SETFL, O_NONBLOCK,
};
#[cfg(target_os = "linux")]
use libc::MSG_DONTWAIT;

#[cfg(target_os = "linux")]
use bs_filter as filter;
#[cfg(target_os = "linux")]
use bs_filter::backend::Backend;

#[cfg(target_os = "linux")]
use libc::{SOCK_CLOEXEC, SOCK_NONBLOCK};

use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

use bs_system::{cvt, Result, SetSocketOption, SystemError};

pub(crate) const PROTO_NULL: i32 = 0_i32;
// TODO - use this pub(crate) const IPPROTO_L2TP: i32 = 115_i32;
pub(crate) const DRAIN_BUFFER_SIZE: usize = 4096;

#[doc(hidden)]
pub trait SocketDesc {
    fn new(fd: RawFd) -> Self;
    fn os(&self) -> i32;
    fn domain() -> i32;
    fn type_() -> i32;
    fn protocol() -> i32;
}

/// a generic `socket(7)` type
#[derive(Debug)]
pub struct Socket<S: SocketDesc> {
    inner: S,
}
#[cfg(target_os = "linux")]
use std::iter::FromIterator;
impl<S: SocketDesc> Socket<S> {
    pub(crate) fn os(&self) -> i32 {
        self.inner.os()
    }

    /// Creates a new `Socket` with the `O_CLOEXEC` flag set
    ///
    /// this is the recommended way to create blocking `Socket`s
    #[cfg(target_os = "linux")]
    pub fn new() -> Result<Self> {
        Self::with_flags(SOCK_CLOEXEC)
    }

    /// Creates a new `Socket`
    ///
    /// this is the recommended way to create blocking `Socket`s
    #[cfg(not(target_os = "linux"))]
    pub fn new() -> Result<Self> {
        Self::with_flags(0)
    }

    /// Creates a new `Socket` without setting any creation flags
    #[cfg(target_os = "linux")]
    pub fn plain() -> Result<Self> {
        Self::with_flags(0)
    }

    /// Creates a new `Socket` without setting any creation flags
    #[cfg(not(target_os = "linux"))]
    pub fn plain() -> Result<Self> {
        Self::new()
    }

    /// Creates a new nonblocking `Socket` with the `O_CLOEXEC` and the `O_NONBLOCK` flags set
    ///
    /// this is the recommended way to create nonblocking `Socket`s
    #[cfg(target_os = "linux")]
    pub fn nonblocking() -> Result<Self> {
        Self::with_flags(SOCK_CLOEXEC | SOCK_NONBLOCK)
    }

    /// Creates a new nonblocking `Socket` with `O_NONBLOCK` flag set
    #[cfg(not(target_os = "linux"))]
    pub fn nonblocking() -> Result<Self> {
        Self::new().and_then(|mut s| s.set_nonblocking().map(|_| s))
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

    /// `fcntl(..., F_GETFL, ...)`
    pub fn flags(&self) -> Result<i32> {
        unsafe { Ok(cvt(fcntl(self.os(), F_GETFL))?) }
    }

    /// `fcntl(..., F_GETFD, ...)`
    pub fn fd_flags(&self) -> Result<i32> {
        unsafe { Ok(cvt(fcntl(self.os(), F_GETFD))?) }
    }

    #[allow(dead_code)]
    fn set_option(&mut self, option: impl SetSocketOption) -> Result<&mut Self> {
        option.set(self.os()).map(|_| self)
    }

    /// set a `Filter` to choose which packets this `Socket` will accept
    #[cfg(target_os = "linux")]
    #[cfg(feature = "bs-filter")]
    pub fn set_filter(&mut self, filter: impl SetSocketOption) -> Result<&mut Self> {
        let f = filter::Filter::<filter::backend::Classic>::from_iter(
            filter::backend::Classic::contradiction(),
        );
        let drop_filter = f.build()?;
        self.set_option(drop_filter)?.drain()?.set_option(filter)
    }

    // TODO - make recv more fun and document
    // TODO - recv_from
    // TODO - send, send_from
    /// recieve a packet on the socket
    pub fn recv(&self, buf: &mut [u8], flags: i32) -> Result<usize> {
        unsafe {
            let n =
                cvt({ libc::recv(self.os(), buf.as_mut_ptr() as *mut c_void, buf.len(), flags) })?;
            Ok(n as usize)
        }
    }

    // TODO - set blocking(bool)
    /// set the socket to nonblocking mode
    pub fn set_nonblocking(&mut self) -> Result<()> {
        self.set_flags(self.flags()? | O_NONBLOCK)
    }

    /// set the socket to blocking mode
    pub fn set_blocking(&mut self) -> Result<()> {
        self.set_flags(self.flags()? & !O_NONBLOCK)
    }

    fn _drain(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        let extra_flag = MSG_DONTWAIT;
        #[cfg(not(target_os = "linux"))]
        let extra_flag = 0;
        let mut buf = [0; DRAIN_BUFFER_SIZE];
        loop {
            match self.recv(&mut buf, extra_flag) {
                Err(SystemError(EWOULDBLOCK)) => {
                    return Ok(());
                },
                #[allow(unreachable_patterns)]
                Err(SystemError(EAGAIN)) => {
                    return Ok(());
                },
                Err(e) => {
                    return Err(e);
                },
                Ok(_) => {
                    continue;
                }
            }
        }
    }

    /// Drains a socket (discards all data) until there's no data left.
    #[cfg(target_os = "linux")]
    pub fn drain(&mut self) -> Result<&mut Self> {
        let res = self._drain();
        match res {
            Ok(_) => Ok(self),
            Err(err) => Err(err)
        }
    }

    /// Drains a socket (discards all data) until there's no data left.
    #[cfg(not(target_os = "linux"))]
    pub fn drain(&mut self) -> Result<&mut Self> {

        let original_flags = self.flags()?;
        let mut revert = false;
        if (original_flags & O_NONBLOCK) == 0 {
            revert = true;
        }
        self.set_flags(original_flags | O_NONBLOCK)?;

        let res = self._drain();

        if revert {
            self.set_flags(original_flags)?;
        }
        res.map(|_| self)
    }

    /// XXX
    pub fn set_cloexec(&mut self) -> Result<()> {
        self.set_fd_flags(FD_CLOEXEC)
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

use libc::EINTR;
impl<S: SocketDesc> Drop for Socket<S> {
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
