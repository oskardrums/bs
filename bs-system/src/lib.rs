//! XXX

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
mod cvt;

pub use cvt::cvt;
use libc::EBADF;
use libc::SOL_SOCKET;
use libc::{c_void, socklen_t};
use libc::{getsockopt, setsockopt};
use log::debug;
use std::convert::TryFrom;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::mem::size_of;
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
    fn set(&self, socket: RawFd) -> Result<()> {
        debug!("setting option {:?} on socket {:?}", self, socket);

        let ptr: *const Self = self;

        let _ = unsafe {
            cvt(setsockopt(
                socket,
                Self::level() as i32,
                Self::name() as i32,
                ptr as *const c_void,
                self.optlen(),
            ))?
        };
        Ok(())
    }
}

/// Extension trait for a gettable `SocketOption`
pub trait GetSocketOption: SocketOption + TryFrom<Vec<u8>>
where
    Self::Error: Into<SystemError>,
{
    /// Calls `getsockopt(2)` to retrieve a `SocktOption` of the given socket.
    /// From<Vec<u8>> is required because it is currently demanded for the safety of the
    /// implementation, this restriction may be lifted in a future revision.
    /// # Errors
    /// Will rethrow any errors produced by the underlying `getsockopt` call
    // TODO - test GetSocketOption
    //
    fn get(socket: RawFd) -> Result<Self> {
        let mut optlen = size_of::<Self>();
        let optlen_ptr: *mut usize = &mut optlen;
        let mut placeholder = Vec::<u8>::with_capacity(optlen);

        (unsafe {
            cvt(getsockopt(
                socket,
                Self::level() as i32,
                Self::name() as i32,
                placeholder.as_mut_ptr() as *mut c_void,
                optlen_ptr as *mut u32,
            ))
        })
        .and(Self::try_from(placeholder).map_err(|e| e.into()))
    }
}

#[cfg(test)]
mod tests {
    // TODO - test bs-system
}
