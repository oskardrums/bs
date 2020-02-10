use libc::{SOL_SOCKET, EOVERFLOW};
use bs_sockopt::{Result, SocketOptionError};
pub const OPTION_LEVEL: i32 = SOL_SOCKET;
pub const OPTION_NAME: i32 = 26; // SO_ATTACH_FILTER;

#[repr(u8)]
#[derive(Copy, Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
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


pub use bs_sockopt::SocketFilter as Instruction;
use crate::consts::*;

const DROP: Instruction = Instruction::new((BPF_RET | BPF_K) as _, 0, 0, 0);
const RETURN_A: Instruction = Instruction::new((BPF_RET | BPF_A) as _, 0, 0, 0);
const LOAD_LENGTH: Instruction = Instruction::new((BPF_LD | BPF_LEN | BPF_W) as _, 0, 0, 0);

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

pub use bs_sockopt::SocketFilterProgram as SocketOption;

pub fn into_socket_option(instructions: Vec<Instruction>) -> Result<SocketOption> {
    let len = instructions.len();
    if len > u16::max_value() as usize {
        return Err(SocketOptionError(EOVERFLOW));
    }
    Ok(SocketOption::from_vector(instructions))
}

pub fn jump(comparison: Comparison, operand: u32, jt: usize, jf: usize) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_JMP as u8 | comparison as u8 | BPF_K as u8) as _,
        jt as _,
        jf as _,
        operand,
    )]
}
pub fn load_u8_at(offset: u32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_ABS | BPF_LD | BPF_B) as _,
        0,
        0,
        offset,
    )]
}

pub fn load_u16_at(offset: u32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_ABS | BPF_LD | BPF_H) as _,
        0,
        0,
        offset,
    )]
}

pub fn load_u32_at(offset: u32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_ABS | BPF_LD | BPF_W) as _,
        0,
        0,
        offset,
    )]
}
