//! Classic BPF implementation
//!
//! Provides basic BPF building blocks used by [`bs-filter`] when used with the [`Classic`] backend.
//!
//! [`bs-filter`]: ../bs-filter/index.html
//! [`Classic`]: ../bs-filter/backend/struct.Classic.html

#![deny(
    bad_style,
    const_err,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    missing_copy_implementations
)]

use bs_system::{consts::*, Level, Name, SetSocketOption, SocketOption};
use libc::socklen_t;
use std::hash::Hash;
use std::mem::size_of;

/// `sock_filter`
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct SocketFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// `sock_filter` alias
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
        // here be lions
        #[repr(C)]
        struct S {
            len: u16,
            filter: *mut SocketFilter,
        }
        size_of::<S>() as socklen_t
    }
}

impl SetSocketOption for SocketFilterProgram {}

/// Different kinds of comparisons to perform upon `BPF_JMP` instructions
#[repr(u8)]
#[derive(Copy, Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub enum Comparison {
    /// always true
    Always = 0x00,
    /// true if operands equal
    Equal = 0x10,
    /// true if the first operand is greater then the second
    GreaterThan = 0x20,
    /// true if the first operand is greater or equal to the second
    GreaterEqual = 0x30,
    /// true if the first operand bitmasked with second operand is greater then 0
    AndMask = 0x40,
    #[doc(hidden)]
    Unknown,
}

// TODO - use FromPrimitive instead
impl From<u8> for Comparison {
    fn from(value: u8) -> Self {
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

/// type of `k` operand
pub type Value = u32;

const DROP: Instruction = Instruction::new((BPF_RET | BPF_K) as _, 0, 0, 0);
const RETURN_A: Instruction = Instruction::new((BPF_RET | BPF_A) as _, 0, 0, 0);
const LOAD_LENGTH: Instruction = Instruction::new((BPF_LD | BPF_LEN | BPF_W) as _, 0, 0, 0);

/// Generates a sequence of instructions that implement the exit logic of a programs.
///
/// BPF programs return value is interpreted as an unsigned length to which the packet will be
/// truncated, where 0 means "drop the packet".
/// Unlike libpcap, `bs-cbpf` doesn't truncate the packet to an arbitrary size, but instead
/// fetches the inspected packet total length and returns that value when packets are determined as
/// valid by the program's logic.
/// So `bs-cbpf`'s exit sequence has 2 entry points corresponding to the 2 possible outcomes
/// of the program - let the packet PASS, or DROP the packet.
///
/// # Return Value
/// Return value is a tuple containing a `Vec<Instruction>` representing the exit sequence, an
/// offset in the sequence pointing to the PASS entry point, and an offset in the sequence pointing
/// to the DROP entry point.
pub fn return_sequence() -> (Vec<Instruction>, usize, usize) {
    (vec![DROP, RETURN_A, LOAD_LENGTH], 0, 2)
}

/// Generates a sequence of instructions that passes the entire packet.
pub fn teotology() -> Vec<Instruction> {
    vec![RETURN_A, LOAD_LENGTH]
}

/// Generates a sequence of instructions that drops the packet.
pub fn contradiction() -> Vec<Instruction> {
    vec![DROP]
}

/// Generates a sequence of instructions that implements a conditional jump.
pub fn jump(comparison: Comparison, operand: u32, jt: usize, jf: usize) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_JMP as u8 | comparison as u8 | BPF_K as u8) as _,
        jt as _,
        jf as _,
        operand,
    )]
}

/// Generates a sequence of instructions that loads one octet from a given offset in the packet.
pub fn load_u8_at(offset: u32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_ABS | BPF_LD | BPF_B) as _,
        0,
        0,
        offset,
    )]
}

/// Generates a sequence of instructions that loads two octets from a given offset in the packet.
pub fn load_u16_at(offset: u32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_ABS | BPF_LD | BPF_H) as _,
        0,
        0,
        offset,
    )]
}

/// Generates a sequence of instructions that loads four octets from a given offset in the packet.
pub fn load_u32_at(offset: u32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_ABS | BPF_LD | BPF_W) as _,
        0,
        0,
        offset,
    )]
}
