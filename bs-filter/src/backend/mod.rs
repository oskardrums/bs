//! The `backend` module holds phantom structs that
//! represent the relevant backend of BPF operation
//! (Classic / Extended). This module will be replaced
//! with an enum when const generics land in stable rust.
use std::fmt::Debug;
use std::hash::Hash;
use bs_system::SetSocketOption;
use bs_system::Result;
mod classic;
#[cfg(feature = "bs-ebpf")]
mod extended;

pub use classic::Classic;
#[cfg(feature = "bs-ebpf")]
pub use extended::Extended;

#[doc(hidden)]
pub trait FilterBackend {
    type SocketOption: SetSocketOption;
}

#[doc(hidden)]
pub trait Backend: Sized + Clone + Ord + Debug + Hash + FilterBackend {
    type Comparison: Clone + Ord + Debug + Hash + From<u8>;
    type Value: Clone + Ord + Debug + Hash + From<u32>;
    type Instruction: Clone + Ord + Debug + Hash + Sized;

    fn option_level() -> i32;
    fn option_name() -> i32;
    fn initialization_sequence() -> Vec<Self::Instruction>;
    fn return_sequence() -> (Vec<Self::Instruction>, usize, usize);
    fn teotology() -> Vec<Self::Instruction>;
    fn contradiction() -> Vec<Self::Instruction>;
    fn into_socket_option(instructions: Vec<Self::Instruction>) -> Result<Self::SocketOption>;
    fn jump(
        comparison: Self::Comparison,
        operand: Self::Value,
        jt: usize,
        jf: usize,
    ) -> Vec<Self::Instruction>;
    fn load_u8_at(offset: u32) -> Vec<Self::Instruction>;
    fn load_u16_at(offset: u32) -> Vec<Self::Instruction>;
    fn load_u32_at(offset: u32) -> Vec<Self::Instruction>;
}
