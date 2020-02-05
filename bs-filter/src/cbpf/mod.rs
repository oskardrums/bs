use libc::{SOL_SOCKET, SO_ATTACH_FILTER};
pub const OPTION_LEVEL: i32 = SOL_SOCKET;
pub const OPTION_NAME: i32 = SO_ATTACH_FILTER;

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub enum Comparison {
    Unknown = 0x00,
    Equal = 0x10,
    GreaterThan = 0x20,
    GreaterEqual = 0x30,
    AndMask = 0x40,
}

impl From<u8> for Comparison {
    fn from(value: u8) -> Self {
        // TODO - rethink this part - maybe mask th input
        match value {
            0x10 => Self::Equal,
            0x20 => Self::GreaterThan,
            0x30 => Self::GreaterEqual,
            0x40 => Self::AndMask,
            _ => Self::Unknown,
        }
    }
}

pub type Value = u32;

use crate::backend::Classic as Kind;
use crate::Instruction;
use crate::Result;
use bpf_sys::*;
use std::marker::PhantomData;

// BPF_A is missing from bpf_sys
const BPF_A: u32 = 0x10;

const DROP: Instruction<Kind> = Instruction {
    bytes: [(BPF_RET | BPF_K) as _, 0, 0, 0, 0, 0, 0, 0],
    phantom: PhantomData,
};

const RETURN_A: Instruction<Kind> = Instruction {
    bytes: [(BPF_RET | BPF_A) as _, 0, 0, 0, 0, 0, 0, 0],
    phantom: PhantomData,
};

const LOAD_LENGTH: Instruction<Kind> = Instruction {
    bytes: [(BPF_LD | BPF_LEN | BPF_W) as _, 0, 0, 0, 0, 0, 0, 0],
    phantom: PhantomData,
};

pub fn initialization_sequence() -> Vec<Instruction<Kind>> {
    Default::default()
}
pub fn return_sequence() -> (Vec<Instruction<Kind>>, usize, usize) {
    (vec![RETURN_A, LOAD_LENGTH, DROP], 1, 2)
}
pub fn teotology() -> Vec<Instruction<Kind>> {
    vec![RETURN_A, LOAD_LENGTH]
}
pub fn contradiction() -> Vec<Instruction<Kind>> {
    vec![DROP]
}

#[repr(C)]
#[derive(Debug)]
pub struct SocketOption {
    value: Vec<[u8;8]>,
}
#[repr(C)]
struct SockOpt {
    len: u16,
    val: *mut [u8; 8],
}

use std::os::unix::io::RawFd;
use std::mem::size_of_val;
use cvt::cvt;
use libc::setsockopt;
use libc::socklen_t;
use libc::c_void;
use crate::ApplyFilter;
impl ApplyFilter for SocketOption {
    fn apply(&mut self, fd: RawFd) -> Result<()> {
        let opt = SockOpt {
            len: self.value.len() as u16,
            val: self.value.as_mut_ptr(),
        };
        match unsafe {
            cvt(setsockopt(
                fd,
                OPTION_LEVEL,
                OPTION_NAME,
                &opt as * const _ as * const c_void,
                size_of_val(&opt) as socklen_t,
            ))
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }



    }
}

pub fn into_socket_option(instructions: Vec<Instruction<Kind>>) -> Result<SocketOption> {
    let mut val = Vec::new();
    for i in instructions {
        val.push(i.bytes)
    }
    Ok(SocketOption {
        value: val,
    })
}

use std::mem::transmute;
mod operation;
pub fn jump(
    comparison: Comparison,
    operand: Value,
    jt: usize,
    jf: usize,
) -> Vec<Instruction<Kind>> {
    // TODO - implement
    unsafe {
        vec![transmute::<operation::Operation, Instruction<Kind>>(
            operation::jump(comparison as _, operand, jt, jf),
        )]
    }
}

pub fn load_u8_at(offset: u32) -> Vec<Instruction<Kind>> {
    let op = operation::Operation::new((BPF_ABS | BPF_LD | BPF_B) as _, 0, 0, offset);
    vec![unsafe { transmute::<operation::Operation, Instruction<Kind>>(op) }]
}

pub fn load_u16_at(offset: u32) -> Vec<Instruction<Kind>> {
    let op = operation::Operation::new((BPF_ABS | BPF_LD | BPF_H) as _, 0, 0, offset);
    vec![unsafe { transmute::<operation::Operation, Instruction<Kind>>(op) }]
}

pub fn load_u32_at(offset: u32) -> Vec<Instruction<Kind>> {
    let op = operation::Operation::new((BPF_ABS | BPF_LD | BPF_W) as _, 0, 0, offset);
    vec![unsafe { transmute::<operation::Operation, Instruction<Kind>>(op) }]
}
