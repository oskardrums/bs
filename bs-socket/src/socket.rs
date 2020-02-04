use cvt::cvt;
use libc::{
    c_void, close, fcntl, setsockopt, socket, socklen_t, FD_CLOEXEC, F_GETFD, F_GETFL, F_SETFD,
    F_SETFL, MSG_DONTWAIT, O_NONBLOCK,
};

use bs_filter as filter;

#[cfg(target_os = "linux")]
use libc::{SOCK_CLOEXEC, SOCK_NONBLOCK};

use std::io::ErrorKind::{Interrupted, WouldBlock};
use std::io::Result;
use std::mem::size_of_val;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

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
            Err(e) => Err(e),
        }
    }

    pub fn flags(&self) -> Result<i32> {
        unsafe { cvt(fcntl(self.os(), F_GETFL)) }
    }

    pub fn fd_flags(&self) -> Result<i32> {
        unsafe { cvt(fcntl(self.os(), F_GETFD)) }
    }

    fn attach_filter<K: filter::Backend>(&mut self, filter: filter::Filter<K>) -> Result<()> {
        let prog: filter::Program<K> = filter.into();
        let opt = prog.build();
        match unsafe {
            cvt(setsockopt(
                self.os(),
                K::option_level(),
                K::option_name(),
                &opt as *const _ as *const c_void,
                size_of_val(&opt) as socklen_t,
            ))
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
    // TODO - feature filter
    pub fn set_filter<K: filter::Backend>(&mut self, filter: filter::Filter<K>) -> Result<()> {
        self.attach_filter(filter::Filter::from_iter(K::contradiction()))?;
        self.drain()?;
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
                Err(e) => {
                    if e.kind() == WouldBlock {
                        return Ok(());
                    } else {
                        return Err(e);
                    }
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
                Err(e) => {
                    if e.kind() == WouldBlock {
                        Ok(())
                    } else {
                        Err(e)
                    }
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
        match unsafe { cvt(fcntl(self.os(), F_SETFL, flags)) } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    // TODO - flags to bitflags
    fn set_fd_flags(&mut self, flags: i32) -> Result<()> {
        match unsafe { cvt(fcntl(self.os(), F_SETFD, flags)) } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl<S: SocketDesc> Drop for Socket<S> {
    fn drop(&mut self) {
        loop {
            match unsafe { cvt(close(self.inner.os())) } {
                Ok(_) => return,
                Err(e) => {
                    if e.kind() == Interrupted {
                        continue;
                    } else {
                        unreachable!();
                    }
                }
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
