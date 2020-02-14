use crate::{Result, SystemError};

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

use errno::errno;

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
