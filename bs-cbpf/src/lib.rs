use bs_system::{consts::*, Level, Name, Result, SetSocketOption, SocketOption, SystemError};
use libc::socklen_t;
use libc::{EOVERFLOW, SOL_SOCKET};
use std::hash::Hash;
use std::mem::size_of;
pub const OPTION_LEVEL: i32 = SOL_SOCKET;
pub const OPTION_NAME: i32 = 26; // SO_ATTACH_FILTER;

/// `sock_filter`
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct SocketFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

pub type Instruction = SocketFilter;

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

// TODO - use FromPrimitive instead
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

const DROP: Instruction = Instruction::new((BPF_RET | BPF_K) as _, 0, 0, 0);
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

pub fn into_socket_option(instructions: Vec<Instruction>) -> Result<SocketFilterProgram> {
    let len = instructions.len();
    if len > u16::max_value() as usize {
        return Err(SystemError(EOVERFLOW));
    }
    Ok(SocketFilterProgram::from_vector(instructions))
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
