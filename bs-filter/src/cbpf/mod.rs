use libc::{SOL_SOCKET, SO_ATTACH_FILTER};
const OPTION_LEVEL: i32 = SOL_SOCKET;
const OPTION_NAME: i32 = SO_ATTACH_FILTER;

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub enum Comparison {
    Always = 0x00,
    Equal = 0x10,
    GreaterThan = 0x20,
    GreaterEqual = 0x30,
    AndMask = 0x40,
    Unknown,
}

impl From<u8> for Comparison {
    fn from(value: u8) -> Self {
        // TODO - rethink this part - maybe mask the input
        // also change to tryfrom and return err when nothing fits
        match value {
            0x00 => Self::Always,
            0x10 => Self::Equal,
            0x20 => Self::GreaterThan,
            0x30 => Self::GreaterEqual,
            0x40 => Self::AndMask,
            _ => Self::Unknown,
        }
    }
}

pub type Value = u32;

use crate::Result;
use bpf_sys::*;

/*
#[repr(C)]
#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd, Default)]
pub struct Instruction {
    bytes: [u8; 8],
}
*/
mod operation;
pub use operation::Instruction;
// BPF_A is missing from bpf_sys
const BPF_A: u32 = 0x10;

const DROP: Instruction = Instruction {
    code: (BPF_RET | BPF_K) as _,
    jt: 0,
    jf: 0, 
    k: 0,
};

const RETURN_A: Instruction = Instruction {
    code: (BPF_RET | BPF_A) as _,
    jt: 0,
    jf: 0, 
    k: 0,
};

const LOAD_LENGTH: Instruction = Instruction {
    code: (BPF_LD | BPF_LEN | BPF_W) as _,
    jt: 0,
    jf: 0, 
    k: 0,
};

pub fn initialization_sequence() -> Vec<Instruction> {
    Default::default()
}
pub fn return_sequence() -> (Vec<Instruction>, usize, usize) {
    // TODO - undo magic
    (vec![RETURN_A, LOAD_LENGTH, DROP], 1, 2)
}
pub fn teotology() -> Vec<Instruction> {
    vec![RETURN_A, LOAD_LENGTH]
}
pub fn contradiction() -> Vec<Instruction> {
    vec![DROP]
}

#[repr(C)]
#[derive(Debug)]
pub struct SocketOption {
    value: Vec<[u8; 8]>,
}
#[repr(C)]
struct SockOpt {
    len: u16,
    val: *mut u8,
}

use crate::ApplyFilter;
use std::os::unix::io::RawFd;
impl ApplyFilter for SocketOption {
    fn apply(&mut self, fd: RawFd) -> Result<()> {
        let opt = SockOpt {
            len: self.value.len() as u16,
            val: self.value.as_mut_ptr() as _,
        };
        match unsafe {
            cvt(setsockopt(
                fd,
                OPTION_LEVEL,
                OPTION_NAME,
                &opt as *const _ as *const c_void,
                size_of_val(&opt) as socklen_t,
            ))
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

pub fn into_socket_option(instructions: Vec<Instruction>) -> Result<SocketOption> {
    let mut val = Vec::new();
    for i in instructions {
        val.push(i.bytes)
    }
    Ok(SocketOption { value: val })
}


pub fn jump(comparison: Comparison, operand: u32, jt: usize, jf: usize) -> Instruction {
    Instruction {
        code: (BPF_JMP as u8 | comparison | BPF_K as u8) as _,
        jt: jt as _,
        jf: jf as _,
        k: operand as _,
    }
}
pub fn load_u8_at(offset: u32) -> Vec<Instruction> {
 vec![operation::Instruction::new((BPF_ABS | BPF_LD | BPF_B) as _, 0, 0, offset)]
}

pub fn load_u16_at(offset: u32) -> Vec<Instruction> {
    let op = operation::Operation::new((BPF_ABS | BPF_LD | BPF_H) as _, 0, 0, offset);
    vec![unsafe { transmute::<operation::Operation, Instruction>(op) }]
}

pub fn load_u32_at(offset: u32) -> Vec<Instruction> {
    let op = operation::Operation::new((BPF_ABS | BPF_LD | BPF_W) as _, 0, 0, offset);
    vec![unsafe { transmute::<operation::Operation, Instruction>(op) }]
}
