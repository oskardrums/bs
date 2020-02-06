/// The `backend` module holds phantom structs that
/// represent the relevant backend of BPF operation
/// (Classic / Extended). This module will be replaced
/// with an enum when const generics land in stable rust.
use crate::ApplyFilter;
use crate::Instruction;
use crate::Result;
use std::fmt::Debug;
use std::hash::Hash;
pub(crate) mod classic;
//pub(crate) mod extended;

pub trait FilterBackend {
    type SocketOption: Debug + ApplyFilter;
}

pub trait Backend: Sized + Clone + Ord + Debug + Hash + FilterBackend {
    type Comparison: Clone + Ord + Debug + Hash + From<u8>;
    type Value: Clone + Ord + Debug + Hash + From<u32>;

    fn option_level() -> i32;
    fn option_name() -> i32;
    fn initialization_sequence() -> Vec<Instruction<Self>>;
    fn return_sequence() -> (Vec<Instruction<Self>>, usize, usize);
    fn teotology() -> Vec<Instruction<Self>>;
    fn contradiction() -> Vec<Instruction<Self>>;
    fn into_socket_option(instructions: Vec<Instruction<Self>>) -> Result<Self::SocketOption>;
    fn jump(
        comparison: Self::Comparison,
        operand: Self::Value,
        jt: usize,
        jf: usize,
    ) -> Vec<Instruction<Self>>;
    fn load_u8_at(offset: u32) -> Vec<Instruction<Self>>;
    fn load_u16_at(offset: u32) -> Vec<Instruction<Self>>;
    fn load_u32_at(offset: u32) -> Vec<Instruction<Self>>;
}
