use crate::ebpf::operation::exit;
use crate::ebpf::operation::Operation;
use bpf_sys::*;
use cvt::cvt;
use libc::close;
use libc::{c_void, setsockopt, SOL_SOCKET, SO_ATTACH_BPF};
use std::ffi::CString;
use std::io::ErrorKind::Interrupted;
use std::io::Result;
use std::iter::FromIterator;
use std::mem::size_of;
use std::os::unix::io::RawFd;
use std::ptr::null_mut;

struct ProgramFd {
    pub fd: RawFd,
}

impl Drop for ProgramFd {
    fn drop(&mut self) {
        loop {
            match unsafe { cvt(close(self.fd)) } {
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

#[repr(C)]
#[derive(Debug)]
pub struct Program {
    filter: Vec<Operation>,
}

impl Program {
    pub fn new(ops: Vec<Operation>) -> Self {
        Self { filter: ops }
    }

    pub fn as_mut_ptr(&mut self) -> *mut Operation {
        self.filter.as_mut_ptr()
    }

    pub fn attach(mut self, socket: RawFd) -> Result<()> {
        unsafe {
            let ptr = self.as_mut_ptr();
            let fd = ProgramFd {
                fd: cvt(bcc_prog_load(
                    bpf_prog_type_BPF_PROG_TYPE_SOCKET_FILTER,
                    CString::new("").unwrap().as_ptr(),
                    ptr as *const _,
                    (self.filter.len() * size_of::<Operation>()) as _,
                    CString::new("GPL").unwrap().as_ptr(),
                    //(4 << 16) + (19 << 8) + (0),
                    0,
                    0,
                    null_mut(),
                    0,
                ))?,
            };
            match cvt(setsockopt(
                socket,
                SOL_SOCKET,
                SO_ATTACH_BPF,
                &fd as *const _ as *const c_void,
                size_of::<RawFd>() as _,
            )) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        }
    }
}

impl FromIterator<Operation> for Program {
    fn from_iter<I: IntoIterator<Item = Operation>>(iter: I) -> Self {
        Self::new(Vec::from_iter(iter))
    }
}
