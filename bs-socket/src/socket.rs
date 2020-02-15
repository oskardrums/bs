use bs_system::{cvt, Result, SystemError};
use cfg_if::cfg_if;
use libc::c_void;
use libc::{close, fcntl, socket};
use libc::{
    EAGAIN, EINTR, EWOULDBLOCK, FD_CLOEXEC, F_GETFD, F_GETFL, F_SETFD, F_SETFL, O_NONBLOCK,
};
use std::iter::FromIterator;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

cfg_if! {
    if #[cfg(target_os = "linux")] {
        pub(crate) use libc::MSG_DONTWAIT;
        pub(crate) use libc::SOCK_CLOEXEC;
        pub(crate) use libc::SOCK_NONBLOCK;
    }
}

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
    cfg_if! {
        if #[cfg(target_os = "linux")] {

            /// Creates a new `Socket`
            ///
            /// sets the O_CLOEXEC creation flag if available for the target
            pub fn new() -> Result<Self> {
                Self::with_flags(SOCK_CLOEXEC)
            }

            /// Creates a new `Socket` without setting any creation flags
            pub fn plain() -> Result<Self> {
                Self::with_flags(0)
            }

            /// Creates a new nonblocking `Socket` with the `O_CLOEXEC` and the `O_NONBLOCK` flags set
            ///
            /// this is the recommended way to create nonblocking `Socket`s
            pub fn nonblocking() -> Result<Self> {
                Self::with_flags(SOCK_CLOEXEC | SOCK_NONBLOCK)
            }

           /// Creates a new nonblocking `Socket` without setting the `O_CLOEXEC` flag
            pub fn plain_nonblocking() -> Result<Self> {
                Self::with_flags(SOCK_NONBLOCK)
            }
        } else {

            /// Creates a new `Socket`
            ///
            /// sets the O_CLOEXEC creation flag if available for the target
            pub fn new() -> Result<Self> {
                Self::with_flags(0)
            }

            /// Creates a new nonblocking `Socket` with `O_NONBLOCK` flag set
            ///
            /// this is the recommended way to create nonblocking `Socket`s
            pub fn nonblocking() -> Result<Self> {
                // TODO - also set the O_CLOEXEC flag
                Self::new().and_then(|mut s| s.set_nonblocking().map(|_| s))
            }
        }
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
    use bs_system::SetSocketOption;

    pub trait PrivateBasicSocket: Sized {
        fn os(&self) -> RawFd;

        fn set_option(&mut self, option: impl SetSocketOption) -> Result<&mut Self> {
            option.set(self.os()).map(|_| self)
        }

        // TODO - flags to bitflags
        fn set_flags(&mut self, flags: i32) -> Result<&mut Self> {
            unsafe {
                cvt(fcntl(self.os(), F_SETFL, flags))
                    .map_err(|e| SystemError::from(e))
                    .and(Ok(self))
            }
        }

        // TODO - flags to bitflags
        fn set_fd_flags(&mut self, flags: i32) -> Result<&mut Self> {
            unsafe {
                cvt(fcntl(self.os(), F_SETFD, flags))
                    .map_err(|e| SystemError::from(e))
                    .map(|_| self)
            }
        }

        // TODO - make recv more fun and document
        // TODO - recv_from
        // TODO - send, send_from
        fn recv(&self, buf: &mut [u8], flags: i32) -> Result<usize> {
            unsafe {
                let n = cvt({
                    libc::recv(self.os(), buf.as_mut_ptr() as *mut c_void, buf.len(), flags)
                })?;
                Ok(n as usize)
            }
        }

        fn recv_until_empty(&mut self, flags: i32) -> Result<&mut Self> {
            let mut buf = [0; DRAIN_BUFFER_SIZE];
            loop {
                match self.recv(&mut buf, flags) {
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

    /// set the socket to nonblocking mode
    fn set_nonblocking(&mut self) -> Result<&mut Self> {
        self.set_flags(self.flags()? | O_NONBLOCK)
    }

    /// set the socket to blocking mode
    fn set_blocking(&mut self) -> Result<&mut Self> {
        self.set_flags(self.flags()? & !O_NONBLOCK)
    }

    /// Receives a packet on the socket
    fn receive(&self, buf: &mut [u8], flags: i32) -> Result<usize> {
        self.recv(buf, flags)
    }

    /// Flushes the socket's receive queue
    fn drain(&mut self) -> Result<&mut Self> {
        if cfg!(target_os = "linux") {
            self.recv_until_empty(MSG_DONTWAIT)
        } else {
            let original_flags = self.flags()?;
            let is_blocking = original_flags & O_NONBLOCK == 0;
            if is_blocking {
                self.set_flags(original_flags | O_NONBLOCK)?
                    .recv_until_empty(0)?
                    .set_flags(original_flags)
            } else {
                Ok(self)
            }
        }
    }

    /// set's the socket `FD_CLOEXEC` flag
    fn set_cloexec(&mut self) -> Result<&mut Self> {
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

cfg_if! {
    if #[cfg(feature = "bs-filter")] {
        use bs_filter::{backend, backend::Backend, AttachFilter, Filter};
        use std::convert::TryFrom;
        /// Extends [`BasicSocket`](trait.BasicSocket.html) with a method to set a packet filter on the
        /// socket
        pub trait SetFilter<K: Backend, A: AttachFilter + TryFrom<Vec<K::Instruction>, Error=SystemError>>: BasicSocket {
            /// Sets a new socket filter in the socket, or replaces the existing filter if already set
            // TODO - should this method really be public?
            fn attach_filter(&mut self, filter: A) -> Result<&mut Self> {
                filter.attach(self.os()).map(|_| self)
            }

            /// Flushes the socket's incoming stream and sets a new filter
            fn set_filter(&mut self, filter: A) -> std::result::Result<&mut Self, A::Error> {
                let f = Filter::<backend::Classic>::from_iter(backend::Classic::contradiction());
                let drop_filter = f.build().unwrap();
                self.attach_filter(drop_filter)?
                    .drain()?
                    .attach_filter(filter)
            }
        }

        impl<K: Backend, A: AttachFilter + TryFrom<Vec<K::Instruction>, Error=SystemError>, S: SocketKind> SetFilter<K, A> for Socket<S> {}
    }
}
