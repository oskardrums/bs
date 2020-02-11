use bs_system::{Result, SystemError};
use libc::{EOVERFLOW, SOL_SOCKET};
#[macro_use]
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive as FromVal;

pub const OPTION_LEVEL: i32 = SOL_SOCKET;
pub const OPTION_NAME: i32 = 50; // SO_ATTACH_BPF;

#[repr(u8)]
#[derive(Copy, Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd, FromPrimitive, ToPrimitive)]
pub enum Comparison {
    // TODO - 32 bit comparisons
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

impl From<u8> for Comparison {
    fn from(u: u8) -> Self {
        FromVal::from_u8(u).unwrap()
    }
}

#[derive(Copy, Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub(crate) enum Opernad {
    DstAndSrc(Register, Register),
    RegAndImm(Register, i32),
}

impl From<u32> for Opernad {
    fn from(u: u32) -> Self {
        Opernad::RegAndImm(Register::Ret, u as i32)
    }
}

pub type Value = Opernad;

use crate::consts::*;
pub use bs_system::BpfInstruction as Instruction;
use bs_system::BpfRegister as Register;

const OFFSET_SK_BUFF_LEN: i16 = 0;

const EXIT: Instruction = Instruction::from_code((BPF_JMP | BPF_EXIT) as u8);

const fn load_packet_length(dst: Register) -> Instruction {
    Instruction::new(
        (BPF_LDX | BPF_W | BPF_MEM) as u8,
        dst,
        Register::SocketBuffer,
        OFFSET_SK_BUFF_LEN,
        0,
    )
}

const fn copy_imm(dst: Register, imm: i32) -> Instruction {
    Instruction::new(
        (BPF_ALU64 | BPF_MOV | BPF_W) as u8,
        dst,
        Register::None,
        0,
        imm,
    )
}

const fn copy(dst: Register, src: Register) -> Instruction {
    Instruction::new((BPF_ALU64 | BPF_MOV | BPF_X) as u8, dst, src, 0, 0)
}

pub const fn initialization_sequence() -> Vec<Instruction> {
    vec![
        copy_imm(Register::Ret, 0),
        copy(Register::Context, Register::SocketBuffer),
    ]
}

pub fn return_sequence() -> (Vec<Instruction>, usize, usize) {
    let res = vec![
        EXIT,
        copy_imm(Register::Ret, 0),
        jump_always(1),
        load_packet_length(Register::Ret),
    ];
    (res, 0, 2)
}

pub fn teotology() -> Vec<Instruction> {
    vec![EXIT, load_packet_length(Register::Ret)]
}
pub fn contradiction() -> Vec<Instruction> {
    vec![copy_imm(Register::Ret, 0)]
}

pub use bs_system::SocketFilterFd as SocketOption;

pub fn into_socket_option(instructions: Vec<Instruction>) -> Result<SocketOption> {
    let len = instructions.len();
    if len > u16::max_value() as usize {
        return Err(SystemError(EOVERFLOW));
    }
    Ok(SocketOption::from_vector(instructions))
}

const fn jump_always(offset: i16) -> Instruction {
    Instruction::new(
        (BPF_JMP as u8) | (BPF_JA as u8),
        Register::None,
        Register::None,
        offset,
        0,
    )
}

const fn jump_imm(comp: Comparison, reg: Register, imm: i32, offset: i16) -> Instruction {
    Instruction::new(
        (BPF_JMP as u8) | comp as u8 | (BPF_K as u8),
        reg,
        Register::None,
        offset,
        imm,
    )
}

const fn jump_reg(comp: Comparison, dst: Register, src: Register, offset: i16) -> Instruction {
    Instruction::new(
        (BPF_JMP as u8) | comp as u8 | (BPF_X as u8),
        dst,
        src,
        offset,
        0,
    )
}

pub fn jump(comparison: Comparison, operand: Opernad, jt: usize, jf: usize) -> Vec<Instruction> {
    let distance_to_true_label: i16 = jt as i16 + 1;
    match operand {
        Opernad::RegAndImm(reg, imm) => vec![
            jump_always(jf as i16),
            jump_imm(comparison, reg, imm, distance_to_true_label),
        ],
        Opernad::DstAndSrc(dst, src) => vec![
            jump_always(jf as i16),
            jump_reg(comparison, dst, src, distance_to_true_label),
        ],
    }
}

pub const fn load_u8_at(offset: i32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_ABS | BPF_LD | BPF_B) as _,
        Register::None,
        Register::None,
        0,
        offset,
    )]
}

pub const fn load_u16_at(offset: i32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_ABS | BPF_LD | BPF_H) as _,
        Register::None,
        Register::None,
        0,
        offset,
    )]
}

pub const fn load_u32_at(offset: i32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_ABS | BPF_LD | BPF_W) as _,
        Register::None,
        Register::None,
        0,
        offset,
    )]
}
