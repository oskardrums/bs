//! Socket options related interface and functionality
//!
//! Used by `bs-socket` to set `SocketOption`s for `Socket`s
//! including BPF filters created with `bs-filter`
//!
//! # Example
//! ```ignore
//! use bs::socket::{Socket, UdpSocket};
//! use bs::filter::{Filter, backend::Classic};
//!
//! fn attach_classic_filter(sock: Socket<UdpSocket>, filter: Filter<Classic>) -> Result<()> {
//!    let prog: Program<Classic> = filter.into();
//!    let mut opt = prog.build()?;
//!    opt.set(self.os())
//! }
//! ```
//!
//! # More information
//! For more infromation about socket options, see
//! * `getsockopt(2)`/`setsockopt(2)`
//! * `socket(7)`
//! * `ip(7)`
//! * `tcp(7)`
//! * `udp(7)`
//! * ...

#![deny(
    bad_style,
    const_err,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    missing_copy_implementations
)]

#[doc(hidden)]
pub mod consts;

/// Shamelessly copied from `nix`'s `errno` module
pub(crate) mod errno {
    use libc::c_int;

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    unsafe fn errno_location() -> *mut c_int {
        extern "C" {
            fn __error() -> *mut c_int;
        }
        __error()
    }

    #[cfg(target_os = "bitrig")]
    fn errno_location() -> *mut c_int {
        extern "C" {
            fn __errno() -> *mut c_int;
        }
        unsafe { __errno() }
    }

    #[cfg(target_os = "dragonfly")]
    unsafe fn errno_location() -> *mut c_int {
        extern "C" {
            fn __dfly_error() -> *mut c_int;
        }
        __dfly_error()
    }

    #[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
    unsafe fn errno_location() -> *mut c_int {
        extern "C" {
            fn __errno() -> *mut c_int;
        }
        __errno()
    }

    #[cfg(target_os = "linux")]
    unsafe fn errno_location() -> *mut c_int {
        extern "C" {
            fn __errno_location() -> *mut c_int;
        }
        __errno_location()
    }

    #[cfg(target_os = "android")]
    unsafe fn errno_location() -> *mut c_int {
        extern "C" {
            fn __errno() -> *mut c_int;
        }
        __errno()
    }

    /// Sets the platform-specific errno to no-error
    #[allow(dead_code)]
    unsafe fn clear() -> () {
        *errno_location() = 0;
    }

    /// Returns the platform-specific value of errno
    pub fn errno() -> i32 {
        unsafe { *errno_location() }
    }
}

// TODO - PR to cvt/std::io::Result
#[doc(hidden)]
pub trait IsMinusOne {
    fn is_minus_one(&self) -> bool;
}

macro_rules! impl_is_minus_one {
    ($($t:ident)*) => ($(impl IsMinusOne for $t {
        fn is_minus_one(&self) -> bool {
            *self == -1
        }
    })*)
}

impl_is_minus_one! { i8 i16 i32 i64 isize }

/// like `cvt::cvt`, but uses the more expresive `SystemError`
/// instead of `std::io::Error`
pub fn cvt<T: IsMinusOne>(t: T) -> Result<T> {
    if t.is_minus_one() {
        Err(SystemError(errno()))
    } else {
        Ok(t)
    }
}

use errno::errno;
use libc::c_void;
use libc::socklen_t;
use libc::EBADF;
use libc::SOL_SOCKET;
//use libc::{getsockopt, setsockopt};
use libc::setsockopt;
use log::debug;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::os::unix::io::RawFd;

/// `bs-system`'s custom `Error` type, returned by `SocketOption::set`/`get`.
///
/// much like `std::io::Error`, this is mostly just a wrapper for `errno`,
/// but unlike `std::io::Error`, it can
/// [actually](https://internals.rust-lang.org/t/insufficient-std-io-error/3597) represent every relevant `errno` value
#[derive(Debug, PartialEq, Copy, Clone)]
pub struct SystemError(pub i32);

impl error::Error for SystemError {}

impl fmt::Display for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            EBADF => write!(f, "Bad file descriptor"),
            _ => unreachable!(), // TODO - think this through
        }
    }
}

impl From<std::io::Error> for SystemError {
    fn from(error: std::io::Error) -> Self {
        SystemError(error.kind() as i32)
    }
}

/// `bs-sockopt`'s custom `Result` type, returned by `SocketOption::set`/`get`, etc.
/// uses `SystemError` as its `Err` variant
pub type Result<T> = std::result::Result<T, SystemError>;

/// `setsockopt`'s `level` arguments
#[repr(i32)]
#[derive(Debug, Copy, Clone)]
pub enum Level {
    /// `SOL_SOCKET`
    Socket = SOL_SOCKET,
}

/// `setsockopt`'s `optname` arguments
#[repr(i32)]
#[derive(Debug, Copy, Clone)]
pub enum Name {
    /// `SO_ATTACH_FILTER`
    AttachFilter = 26,

    /// `SO_ATTACH_BPF`
    AttachBpf = 50,
}

/// A viable `optval` argument for `set/getsockopt(2)`
pub trait SocketOption: Sized + Debug {
    /// Returns a `Level` to be passed to `set/getsockopt(2)`
    fn level() -> Level;

    /// Returns a `Name` to be passed to `set/getsockopt(2)`
    fn name() -> Name;

    /// binary size, used as the `optlen` argument for `set/getsockopt(2)`
    fn optlen(&self) -> socklen_t;
}

/// Extension trait for a settable `SocketOption`
pub trait SetSocketOption: SocketOption {
    /// Calls `setsockopt(2)` to apply `self` to a given `socket`
    /// # Errors
    /// Will rethrow any errors produced by the underlying `setsockopt` call
    fn set(&self, socket: RawFd) -> Result<i32> {
        debug!("setting option {:?} on socket {:?}", self, socket);

        let ptr: *const Self = self;

        unsafe {
            cvt(setsockopt(
                socket,
                Self::level() as i32,
                Self::name() as i32,
                ptr as *const c_void,
                self.optlen(),
            ))
        }
    }
}


/* TODO - rethink this
/// Extension trait for a gettable `SocketOption`
pub trait GetSocketOption: SocketOption + From<Vec<u8>> {
    /// Calls `getsockopt(2)` to retrieve a `SocktOption` of the given socket.
    /// From<Vec<u8>> is required due to safe implementation considerations.
    /// # Errors
    /// Will rethrow any errors produced by the underlying `getsockopt` call
    // TODO - test GetSocketOption
    //
    fn get(socket: RawFd) -> Result<Self> {
        let mut optlen = size_of::<Self>();
        let optlen_ptr: *mut usize = &mut optlen;
        let mut new = Vec::<u8>::with_capacity(optlen);

        unsafe {
            cvt(getsockopt(
                socket,
                Self::level() as i32,
                Self::name() as i32,
                new.as_mut_ptr() as *mut c_void,
                optlen_ptr as *mut u32,
            ));
        };
        Ok(new)
    }
}
*/
#[cfg(test)]
mod tests {
    /*
    use super::*;
    #[test]
    fn set_sock_fprog_expect_ebadf() {
        let expected = Err(SystemError(EBADF));
        let prog = SocketFilterProgram::from_vector(Vec::new());
        assert_eq!(prog.set(-1), expected);
        assert_eq!(prog.set(-321), expected);
        assert_eq!(prog.set(-3214), expected);
        assert_eq!(prog.set(-55555), expected);
        assert_eq!(prog.set(55555), expected);
        assert_eq!(prog.set(3214), expected);
    }
    */
}
