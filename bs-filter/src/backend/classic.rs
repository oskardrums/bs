use crate::cbpf;
use crate::backend::{Backend, FilterBackend};
use crate::{Instruction, Result};

/// Phantom struct to represent Classic BPF related
/// functionalities.
#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub struct Classic {}

pub(crate) type Kind = Classic;

impl FilterBackend for Classic {
    type SocketOption = cbpf::SocketOption;
}

impl Backend for Classic {
    type Comparison = cbpf::Comparison;
    type Value = cbpf::Value;

    fn option_level() -> i32 {
        cbpf::OPTION_LEVEL
    }
    fn option_name() -> i32 {
        cbpf::OPTION_NAME
    }
    fn initialization_sequence() -> Vec<Instruction<Self>> {
        cbpf::initialization_sequence()
    }
    fn return_sequence() -> (Vec<Instruction<Self>>, usize, usize) {
        cbpf::return_sequence()
    }
    fn teotology() -> Vec<Instruction<Self>> {
        cbpf::teotology()
    }
    fn contradiction() -> Vec<Instruction<Self>> {
        cbpf::contradiction()
    }
    fn into_socket_option(instructions: Vec<Instruction<Self>>) -> Result<Self::SocketOption> {
        cbpf::into_socket_option(instructions)
    }
    fn jump(
        comparison: Self::Comparison,
        operand: Self::Value,
        jt: usize,
        jf: usize,
    ) -> Vec<Instruction<Self>> {
        cbpf::jump(comparison, operand, jt, jf)
    }
    fn load_u8_at(offset: u32) -> Vec<Instruction<Self>> {
        cbpf::load_u8_at(offset)
    }
    fn load_u16_at(offset: u32) -> Vec<Instruction<Self>> {
        cbpf::load_u16_at(offset)
    }
    fn load_u32_at(offset: u32) -> Vec<Instruction<Self>> {
        cbpf::load_u32_at(offset)
    }
}
