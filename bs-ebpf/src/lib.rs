//! Extended BPF implementation
//!
//! Provides basic BPF building blocks used by [`bs-filter`] when used with the [`Extended`] backend.
//!
//! [`bs-filter`]: ../bs-filter/index.html
//! [`Extended`]: ../bs-filter/backend/struct.Extended.html

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

use bs_system::{consts::*, Level, Name, Result, SetSocketOption, SocketOption, SystemError};
use libc::socklen_t;
use log::debug;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive as FromVal;
use std::mem::size_of_val;
use std::os::unix::io::RawFd;

/// `bpf_insn`
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct Instruction {
    code: u8,
    // Rust bitflags are no fun
    regs: u8,
    off: i16,
    imm: i32,
}

/// An eBPF virtual machine register, identified by its index.
#[allow(dead_code)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Register {
    /// R0: The return register, interpreted as the program's return value at exit.
    ///
    /// Must be set by the program before exiting.
    Ret = 0,

    /// The context register, set by the kernel to a pointer to the program's sole argument, repreenting the the program's
    /// context.
    ///
    /// Initiated by the kernel on startup.
    ///
    /// R1: For socket filters this is a pointer `struct sk_buff`.
    Context = 1,

    /// R2-5: arguments for kernel helper functions.
    Arg1 = 2,
    #[allow(missing_docs)]
    Arg2 = 3,
    #[allow(missing_docs)]
    Arg3 = 4,
    #[allow(missing_docs)]
    Arg4 = 5,

    /// R6: Used by socket filter programs for direct packet access.
    ///
    /// Must be set to a `struct sk_buff *`
    SocketBuffer = 6,

    /// General use registers that are never altered by kernel helper functions.
    Gen1 = 7,
    #[allow(missing_docs)]
    Gen2 = 8,
    #[allow(missing_docs)]
    Gen3 = 9,

    /// Contains a read-only pointer to the program's stack frame.
    ///
    /// Initiated by the kernel on startup.
    FramePointer = 10,
}

impl Register {
    #[allow(non_upper_case_globals)]
    const None: Self = Self::Ret;
}

impl Instruction {
    /// Creates a new `Instruction` with the given parameters
    pub const fn new(code: u8, dst_reg: Register, src_reg: Register, off: i16, imm: i32) -> Self {
        Self {
            code,
            regs: ((dst_reg as u8) << 4) | src_reg as u8,
            off,
            imm,
        }
    }

    /// Helper function, creates a new `Instruction` with given `code`
    /// other parameters (registers, `off`, `imm`) are set to 0
    const fn from_code(code: u8) -> Self {
        Self {
            code,
            regs: 0,
            off: 0,
            imm: 0,
        }
    }
}

/// File descriptor referring to a loaded and verified (e)BPF socket filter
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SocketFilterFd {
    fd: RawFd,
}

impl SocketOption for SocketFilterFd {
    fn level() -> Level {
        Level::Socket
    }
    fn name() -> Name {
        Name::AttachBpf
    }
    fn optlen(&self) -> socklen_t {
        size_of_val(self) as socklen_t
    }
}

impl SetSocketOption for SocketFilterFd {}

/// Mirrors `bpf_attr`'s `BPF_PROG_LOAD` variant
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SocketFilterBpfAttribute {
    program_type: u32,
    instructions_count: u32,
    instructions: Box<[Instruction]>,
    license: CString,
    log_level: u32,
    log_size: u32,
    log_buffer: Vec<u8>,
    kernel_version: u32,
    program_flags: u32,
}

const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;

use std::ffi::CString;
use std::mem::forget;
use std::ptr::null_mut;
use syscall::syscall;

impl SocketFilterBpfAttribute {
    /// Creates a new `SocketFilterBpfAttribute` from the given `Instruction` vector
    pub fn new(v: Vec<Instruction>) -> Self {
        let program_type = BPF_PROG_TYPE_SOCKET_FILTER;
        let instructions_count = v.len() as u32;
        let instructions = v.into_boxed_slice();
        let license = CString::new("GPL").unwrap();
        let log_level = if cfg!(debug_assertions) { 1 } else { 0 };
        let log_size: u32 = if cfg!(debug_assertions) { 4096 } else { 0 };
        let log_buffer = Vec::with_capacity(log_size as usize);
        let kernel_version = 0;
        let program_flags = 0;
        Self {
            program_type,
            instructions_count,
            instructions,
            license,
            log_level,
            log_size,
            log_buffer,
            kernel_version,
            program_flags,
        }
    }

    /// Calls the `bpf(2)` syscall to verify and load an eBPF program into the kernel, producings a [`SocketFilterFd`](struct.SocketFilterFd.html) applicable to a [`Socket`](../bs_socket/socket/struct.Socket.html)
    pub fn load(mut self) -> Result<SocketFilterFd> {
        // here be dragons

        #[repr(C)]
        struct Attr {
            program_type: u32,
            instructions_count: u32,
            instructions: u64,
            license: u64,
            log_level: u32,
            log_size: u32,
            log_buffer: u64,
            kernel_version: u32,
            prog_flags: u32,
        }
        let log_ptr = if cfg!(debug_assertions) {
            self.log_buffer.as_mut_ptr()
        } else {
            null_mut()
        };

        let mut attr = Attr {
            program_type: self.program_type,
            instructions_count: self.instructions_count,
            instructions: self.instructions.as_ptr() as u64,
            license: self.license.as_ptr() as u64,
            log_level: self.log_level,
            log_size: self.log_size,
            log_buffer: log_ptr as u64,
            kernel_version: self.kernel_version,
            prog_flags: self.program_flags,
        };

        let ptr: *mut Attr = &mut attr;

        let fd = unsafe { syscall!(BPF, 5, ptr, size_of_val(&attr)) as i32 };

        if cfg!(debug_assertions) {
            unsafe {
                forget(self.log_buffer);
                let log =
                    Vec::from_raw_parts(log_ptr, self.log_size as usize, self.log_size as usize);
                debug!("BPF_PROG_LOAD log: {:}", String::from_utf8(log).unwrap());
            }
        }

        if fd > 0 {
            Ok(SocketFilterFd { fd })
        } else {
            Err(SystemError(-fd))
        }
    }
}

/// Different kinds of comparisons to perform upon `BPF_JMP` instructions
#[repr(u8)]
#[derive(Copy, Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd, FromPrimitive, ToPrimitive)]
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
    /// true if the operands differ
    NotEqual = 0x50,
    /// true if the first operand is greater then the second (operands are treated as signed 64-bit
    /// integers)
    SignedGreaterThan = 0x60,
    /// true if the first operand is greater or equal to the second (operands are treated as signed 64-bit
    /// integers)
    SignedGreaterEqual = 0x70,
    /// true if the first operand is lesser then the second
    LesserThan = 0xa0,
    /// true if the first operand is lesser or equal to the second
    LesserEqual = 0xb0,
    /// true if the first operand is lesser then the second (operands are treated as signed 64-bit
    /// integers)
    SignedLesserThan = 0xc0,
    /// true if the first operand is lesser or equal to the second (operands are treated as signed 64-bit
    SignedLesserEqual = 0xd0,
    // TODO - 32 bit comparisons
    #[doc(hidden)]
    Unknown,
}

impl From<u8> for Comparison {
    fn from(u: u8) -> Self {
        FromVal::from_u8(u).unwrap()
    }
}

/// A couple of operands to be compared by [`jump`]
///
/// [`jump`]: function.jump.html
#[derive(Copy, Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub enum Operand {
    /// Compare a `Register` to an immediate value
    RegAndImm(Register, i32),

    // XXX - remove the allow deriviate when no longer needed
    /// Compare two `Register`s
    #[allow(dead_code)]
    DstAndSrc(Register, Register),
}

impl From<u32> for Operand {
    fn from(u: u32) -> Self {
        Operand::RegAndImm(Register::Ret, u as i32)
    }
}

const OFFSET_SK_BUFF_LEN: i16 = 0;

const EXIT: Instruction = Instruction::from_code((BPF_JMP | BPF_EXIT) as u8);

const fn load_packet_length(dst: Register) -> Instruction {
    Instruction::new(
        (BPF_LDX | BPF_W | BPF_MEM) as u8,
        Register::SocketBuffer,
        dst,
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

/// Generates a sequence of instructions that sets R6 to a pointer to the processed packet, necessary for any eBPF direct packet access
pub fn initialization_sequence() -> Vec<Instruction> {
    vec![copy(Register::Context, Register::SocketBuffer)]
}

/// Generates a sequence of instructions that implement the exit logic of a programs.
pub fn return_sequence() -> (Vec<Instruction>, usize, usize) {
    let res = vec![
        EXIT,
        copy_imm(Register::Ret, 0),
        jump_always(1),
        load_packet_length(Register::Ret),
    ];
    (res, 0, 2)
}

/// Generates a sequence of instructions that passes the entire packet.
pub fn teotology() -> Vec<Instruction> {
    vec![EXIT, load_packet_length(Register::Ret)]
}

/// Generates a sequence of instructions that drops the packet.
pub fn contradiction() -> Vec<Instruction> {
    vec![copy_imm(Register::Ret, 0)]
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

/// Generates a sequence of instructions that implements a conditional jump.
pub fn jump(comparison: Comparison, operand: Operand, jt: usize, jf: usize) -> Vec<Instruction> {
    let distance_to_true_label: i16 = jt as i16 + 1;
    match operand {
        Operand::DstAndSrc(dst, src) => vec![
            jump_always(jf as i16),
            jump_reg(comparison, dst, src, distance_to_true_label),
        ],
        Operand::RegAndImm(reg, imm) => vec![
            jump_always(jf as i16),
            jump_imm(comparison, reg, imm, distance_to_true_label),
        ],
    }
}

/// Generates a sequence of instructions that loads one octet from a given offset in the packet.
pub fn load_u8_at(offset: i32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_ABS | BPF_LD | BPF_B) as _,
        Register::None,
        Register::None,
        0,
        offset,
    )]
}

/// Generates a sequence of instructions that loads two octets from a given offset in the packet.
pub fn load_u16_at(offset: i32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_ABS | BPF_LD | BPF_H) as _,
        Register::None,
        Register::None,
        0,
        offset,
    )]
}

/// Generates a sequence of instructions that loads four octets from a given offset in the packet.
pub fn load_u32_at(offset: i32) -> Vec<Instruction> {
    vec![Instruction::new(
        (BPF_ABS | BPF_LD | BPF_W) as _,
        Register::None,
        Register::None,
        0,
        offset,
    )]
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
