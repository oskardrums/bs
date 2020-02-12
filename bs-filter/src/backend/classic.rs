use crate::backend::{Backend, FilterBackend};
use bs_cbpf as cbpf;
use bs_system::Result;

/// Phantom struct to represent Classic BPF related
/// functionalities.
#[derive(Copy, Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub struct Classic {}

impl FilterBackend for Classic {
    type SocketOption = cbpf::SocketFilterProgram;
}

impl Backend for Classic {
    type Comparison = cbpf::Comparison;
    type Value = cbpf::Value;
    type Instruction = cbpf::Instruction;

    fn option_level() -> i32 {
        cbpf::OPTION_LEVEL
    }
    fn option_name() -> i32 {
        cbpf::OPTION_NAME
    }
    fn initialization_sequence() -> Vec<Self::Instruction> {
        cbpf::initialization_sequence()
    }
    fn return_sequence() -> (Vec<Self::Instruction>, usize, usize) {
        cbpf::return_sequence()
    }
    fn teotology() -> Vec<Self::Instruction> {
        cbpf::teotology()
    }
    fn contradiction() -> Vec<Self::Instruction> {
        cbpf::contradiction()
    }
    fn into_socket_option(instructions: Vec<Self::Instruction>) -> Result<Self::SocketOption> {
        cbpf::into_socket_option(instructions)
    }
    fn jump(
        comparison: Self::Comparison,
        operand: Self::Value,
        jt: usize,
        jf: usize,
    ) -> Vec<Self::Instruction> {
        cbpf::jump(comparison, operand, jt, jf)
    }
    fn load_u8_at(offset: u32) -> Vec<Self::Instruction> {
        cbpf::load_u8_at(offset)
    }
    fn load_u16_at(offset: u32) -> Vec<Self::Instruction> {
        cbpf::load_u16_at(offset)
    }
    fn load_u32_at(offset: u32) -> Vec<Self::Instruction> {
        cbpf::load_u32_at(offset)
    }
}
