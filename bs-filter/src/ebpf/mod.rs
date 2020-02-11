use libc::{SOL_SOCKET, EOVERFLOW};
use bs_system::{Result, SystemError};
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
    NotEqual = 0x50,
    SignedGreaterThan = 0x60,
    SignedGreaterEqual = 0x70,
    LesserThan = 0xa0,
    LesserEqual = 0xb0,
    SignedLesserThan = 0xc0,
    SignedLesserEqual = 0xd0,
    Unknown,
}

pub type Value = i32;

pub use bs_system::BpfInstruction as Instruction;
use bs_system::BpfRegister as Register;
use crate::consts::*;

const EXIT: Instruction= Instruction::from_code(BPF_JMP | BPF_EXIT);
const RETURN_A: Instruction = Instruction::new((BPF_RET | BPF_A) as _, 0, 0, 0);
const LOAD_LENGTH: Instruction = Instruction::new((BPF_LD | BPF_LEN | BPF_W) as _, 0, 0, 0);

pub fn initialization_sequence() -> Vec<Instruction> {
    Default::default()
}
pub fn return_sequence() -> (Vec<Instruction>, usize, usize) {
    // TODO - undo magic
    (vec![DROP, RETURN_A, LOAD_LENGTH], 0, 2)
}
pub fn teotology() -> Vec<Instruction> {
    vec![RETURN_A, LOAD_LENGTH]
}
pub fn contradiction() -> Vec<Instruction> {
    vec![DROP]
}

pub use bs_system::SocketFilterFd as SocketOption;

pub fn into_socket_option(instructions: Vec<Instruction>) -> Result<SocketOption> {
    let len = instructions.len();
    if len > u16::max_value() as usize {
        return Err(SystemError(EOVERFLOW));
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
pub fn load_u8_at(offset: i32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_ABS | BPF_LD | BPF_B) as _,
        Register::None,
        Register::None,
        0,
        offset,
    )]
}
pub fn load_u16_at(offset: i32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_ABS | BPF_LD | BPF_H) as _,
        Register::None,
        Register::None,
        0,
        offset,
    )]
}

pub fn load_u32_at(offset: i32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_ABS | BPF_LD | BPF_W) as _,
        Register::None,
        Register::None,
        0,
        offset,
    )]
}
