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
use std::hash::Hash;
use std::mem::size_of;
use std::mem::size_of_val;
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

/// `sock_filter`
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct SocketFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl SocketFilter {
    /// Creates a new `SocketFilter` with the given parameters
    pub const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }

    /// Helper function, creates a new `SocketFilter` with given `code`
    /// other parameters (`jt`, `jf`, `k`) are set to 0
    pub const fn from_code(code: u16) -> Self {
        Self {
            code,
            jt: 0,
            jf: 0,
            k: 0,
        }
    }
}

/// `sock_filter`
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct BpfInstruction {
    code: u8,
    // Rust bitflags are no fun
    regs: u8,
    off: i16,
    imm: i32,
}

#[doc(hidden)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum BpfRegister {
    Ret = 0,
    Context = 1,
    Arg1 = 2,
    Arg2 = 3,
    Arg3 = 4,
    Arg4 = 5,
    SocketBuffer = 6,
    Gen1 = 7,
    Gen2 = 8,
    Gen3 = 9,
    FramePointer = 10,
}

impl BpfRegister {
    #[doc(hidden)]
    #[allow(non_upper_case_globals)]
    pub const None: Self = Self::Ret;
}

impl BpfInstruction {
    /// Creates a new `BpfInstruction` with the given parameters
    pub const fn new(
        code: u8,
        dst_reg: BpfRegister,
        src_reg: BpfRegister,
        off: i16,
        imm: i32,
    ) -> Self {
        Self {
            code,
            regs: ((dst_reg as u8) << 4) | src_reg as u8,
            off,
            imm,
        }
    }

    /// Helper function, creates a new `BpfInstruction` with given `code`
    /// other parameters (registers, `off`, `imm`) are set to 0
    pub const fn from_code(code: u8) -> Self {
        Self {
            code,
            regs: 0,
            off: 0,
            imm: 0,
        }
    }
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

/// `sock_fprog`
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SocketFilterBpfAttribute {
    program_type: u32,
    instructions_count: u32,
    instructions: Box<[BpfInstruction]>,
    license: CString,
    log_level: u32,
    log_size: u32,
    log_buffer: Vec<u8>,
    kernel_version: u32,
}

const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;

use std::ffi::CString;
//use std::ptr::null_mut;
use std::mem::forget;
use syscall::syscall;

impl SocketFilterBpfAttribute {
    /// Creates a new `SocketFilterBpfAttribute` from the given `BpfInstruction` vector
    pub fn from_vector(v: Vec<BpfInstruction>) -> Self {
        let program_type = BPF_PROG_TYPE_SOCKET_FILTER;
        let instructions_count = v.len() as u32;
        let instructions = v.into_boxed_slice();
        let license = CString::new("GPL").unwrap();
//        let log_level = if cfg!(debug_assertions) { 1 } else { 0 };
//        let log_size: u32 = if cfg!(debug_assertions) { 4096 } else { 0 };
        let log_level = 1;
        let log_size = 4096;
        let log_buffer = Vec::with_capacity(log_size as usize);
        let kernel_version = 0;
        Self {
            program_type,
            instructions_count,
            instructions,
            license,
            log_level,
            log_size,
            log_buffer,
            kernel_version,
        }
    }

    /// XXX
    pub fn load(mut self) -> Result<SocketFilterFd> {
        #[repr(C)]
        struct Attr {
            program_type: u32,
            instructions_count: u32,
            instructions: *const c_void,
            license: *const c_void,
            log_level: u32,
            log_size: u32,
            log_buffer: *mut c_void,
            kernel_version: u32,
            prog_flags: u32,
        }
        let log_ptr = 
            self.log_buffer.as_mut_ptr();
        /*
        let log_ptr = if cfg!(debug_assertions) {
            self.log_buffer.as_mut_ptr()
        } else {
            null_mut()
        };
        */

        let mut attr = Attr {
            program_type: self.program_type,
            instructions_count: self.instructions_count,
            instructions: self.instructions.as_ptr() as *const c_void,
            license: self.license.as_ptr() as *const c_void,
            log_level: self.log_level,
            log_size: self.log_size,
            log_buffer: log_ptr as *mut c_void,
            kernel_version: self.kernel_version,
            prog_flags: 0,
        };

        let ptr: *mut Attr = &mut attr;
        let fd = unsafe {
            syscall!(BPF, 5, ptr, size_of_val(&attr)) as i32 
        };

        unsafe {
            forget(self.log_buffer);
            let log = Vec::from_raw_parts(log_ptr, self.log_size as usize, self.log_size as usize);
            debug!("BPF_PROG_LOAD log: {:}", String::from_utf8(log).unwrap());
        }

        if fd > 0 {
            Ok(SocketFilterFd { fd })
        } else {
            Err(SystemError(-fd))
        }
    }
}

/// `sock_fprog`
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SocketFilterProgram {
    len: u16,
    filter: Box<[SocketFilter]>,
}

impl SocketFilterProgram {
    /// Creates a new `SocketFilterProgram` from the given `SocketFilter` vector
    pub fn from_vector(v: Vec<SocketFilter>) -> Self {
        let len = v.len() as u16;
        let filter = v.into_boxed_slice();
        Self { len, filter }
    }
}

impl SocketOption for SocketFilterProgram {
    fn level() -> Level {
        Level::Socket
    }
    fn name() -> Name {
        Name::AttachFilter
    }
    fn optlen(&self) -> socklen_t {
        // XXX - here be dragons
        #[repr(C)]
        struct S {
            len: u16,
            filter: *mut SocketFilter,
        }
        size_of::<S>() as socklen_t
    }
}

impl SetSocketOption for SocketFilterProgram {}

/// File descriptor referring to a loaded and verified (e)BPF socket filter
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SocketFilterFd {
    fd: RawFd,
}

impl SocketOption for SocketFilterFd {
    fn level() -> Level {
        Level::Socket
    }
    fn name() -> Name {
        Name::AttachBpf
    }
    fn optlen(&self) -> socklen_t {
        size_of_val(self) as socklen_t
    }
}

impl SetSocketOption for SocketFilterFd {}

#[cfg(test)]
mod tests {
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
}
