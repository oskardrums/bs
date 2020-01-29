use modular_bitfield::prelude::*;
pub type Code = u8;
pub type OpCode = B8;
pub type JumpOffset = u16;
pub type Offset = B16;
pub type Arg = u64;
pub type Arg32 = u32;
pub type ImmArg = B64;

#[derive(BitfieldSpecifier, Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub enum Register {
    Ret = 0,
    Arg1 = 1,
    Arg2 = 2,
    Arg3 = 3,
    Arg4 = 4,
    Arg5 = 5,
    Gen1 = 6,
    Gen2 = 7,
    Gen3 = 8,
    Gen4 = 9,
    Frame = 10,
    // BitfieldSpecifier demands that the number
    // of variants will be a power of 2
    // so we need to define phantom variants to get
    // to 16 (that is, 2^4) variants
    #[doc(hidden)]
    __NO1 = 11,
    #[doc(hidden)]
    __NO2 = 12,
    #[doc(hidden)]
    __NO3 = 13,
    #[doc(hidden)]
    __NO4 = 14,
    #[doc(hidden)]
    __NO5 = 15,
}

#[bitfield]
#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub struct Operation {
    code: OpCode,
    #[bits = 4]
    dst: Register,
    #[bits = 4]
    src: Register,
    offset: Offset,
    imm: ImmArg,
}

use bpf_sys::*;

// modular_bitfield blocks struct initialization, so
// we have to create a `new` Operation and mutate it.
// unfortunately mutation in isn't supported in `const fn`
// so this will have to be non-`const` for now
pub fn exit() -> Operation {
    let mut op = Operation::new();
    op.set_code((BPF_JMP | BPF_EXIT) as _);
    op
}
