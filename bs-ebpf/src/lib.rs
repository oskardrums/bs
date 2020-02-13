use bs_system::{consts::*, Level, Name, Result, SetSocketOption, SocketOption, SystemError};
use libc::socklen_t;
use libc::{EOVERFLOW, SOL_SOCKET};
use log::debug;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive as FromVal;
use std::mem::size_of_val;
use std::os::unix::io::RawFd;
pub const OPTION_LEVEL: i32 = SOL_SOCKET;
pub const OPTION_NAME: i32 = 50; // SO_ATTACH_BPF;

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

#[doc(hidden)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Register {
    Ret = 0,
    Context = 1,
    Arg1 = 2,
    Arg2 = 3,
    Arg3 = 4,
    Arg4 = 5,
    SocketBuffer = 6,
    Gen1 = 7,
    Gen2 = 8,
    Gen3 = 9,
    FramePointer = 10,
}

impl Register {
    #[doc(hidden)]
    #[allow(non_upper_case_globals)]
    pub const None: Self = Self::Ret;
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
    pub const fn from_code(code: u8) -> Self {
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
pub enum Operand {
    RegAndImm(Register, i32),

    // XXX - remove the allow deriviate when no longer needed
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

/// # logic
/// * set R6 a pointer to the processed packet, necessary for eBPF direct packet access
pub fn initialization_sequence() -> Vec<Instruction> {
    vec![copy(Register::Context, Register::SocketBuffer)]
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

pub fn into_socket_option(instructions: Vec<Instruction>) -> Result<SocketFilterFd> {
    let len = instructions.len();
    if len > u16::max_value() as usize {
        return Err(SystemError(EOVERFLOW));
    }
    Ok(SocketFilterBpfAttribute::new(instructions).load()?)
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

/// jump sequence
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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
