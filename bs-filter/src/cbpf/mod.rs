use libc::{SOL_SOCKET, SO_ATTACH_FILTER};
pub const OPTION_LEVEL: i32 = SOL_SOCKET;
pub const OPTION_NAME: i32 = SO_ATTACH_FILTER;

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub enum Comparison {
    Equal = 0x10,
    GreaterThan = 0x20,
    GreaterEqual = 0x30,
    AndMask = 0x40,
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
    bytes: [(BPF_RET | BPF_K) as _; 8],
    phantom: PhantomData,
};

const RETURN_A: Instruction<Kind> = Instruction {
    bytes: [(BPF_RET | BPF_A) as _; 8],
    phantom: PhantomData,
};

const LOAD_LENGTH: Instruction<Kind> = Instruction {
    bytes: [(BPF_LD | BPF_LEN | BPF_W) as _; 8],
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

pub struct SocketOption {
    value: Vec<Instruction<Kind>>,
}

pub fn into_socket_option(instructions: Vec<Instruction<Kind>>) -> Result<SocketOption> {
    Ok(SocketOption {
        value: instructions,
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
    vec![transmute::<operation::Operation, Instruction<Kind>>(op)]
}

pub fn load_u16_at(offset: u32) -> Vec<Instruction<Kind>> {
    let op = operation::Operation::new((BPF_ABS | BPF_LD | BPF_H) as _, 0, 0, offset);
    vec![transmute::<operation::Operation, Instruction<Kind>>(op)]
}

pub fn load_u32_at(offset: u32) -> Vec<Instruction<Kind>> {
    let op = operation::Operation::new((BPF_ABS | BPF_LD | BPF_W) as _, 0, 0, offset);
    vec![transmute::<operation::Operation, Instruction<Kind>>(op)]
}
