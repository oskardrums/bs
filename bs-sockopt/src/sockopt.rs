use cvt::cvt;
use libc::c_void;
use libc::setsockopt;
use libc::socklen_t;
use std::mem::size_of_val;
use std::os::unix::io::RawFd;

use crate::Result;

/// `setsockopt`'s `level` arguments
#[repr(i32)]
pub enum Level {
    Socket,
}

/// `setsockopt`'s `optname` arguments
#[repr(i32)]
pub enum Name {
    AttachFilter,
}

/// packed `bpf_insn`/`sock_filter`
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Instruction {
    inner: [u8; 8],
}

/// `sock_fprog`
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SocketFilterProgram {
    len: u16,
    filter: *mut Instruction,
}

pub trait SocketOption {
    fn level() -> Level;
    fn name() -> Name;

    /// # Panics
    /// Will panic if either `Self::level()` or `Self::name` fails to convert to `i32`
    fn set(&self, socket: RawFd) -> Result<()> {
        match unsafe {
            cvt(setsockopt(
                socket,
                Self::level(),
                Self::name(),
                &self as *const _ as *const c_void,
                size_of_val(&self) as socklen_t,
            ))
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl SocketOption for SocketFilterProgram {
    fn level() -> Level {
        Level::Socket
    }
    fn name() -> Name {
        Name::AttachFilter
    }
}
