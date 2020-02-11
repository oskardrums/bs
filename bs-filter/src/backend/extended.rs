use crate::ebpf;
use crate::backend::{Backend, FilterBackend};
use bs_system::Result;

/// Phantom struct to represent Extended BPF related
/// functionalities.
#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub struct Extended {}

impl FilterBackend for Extended {
    type SocketOption = ebpf::SocketOption;
}

impl Backend for Extended {
    type Comparison = ebpf::Comparison;
    type Value = ebpf::Value;
    type Instruction = ebpf::Instruction;

    fn option_level() -> i32 {
        ebpf::OPTION_LEVEL
    }
    fn option_name() -> i32 {
        ebpf::OPTION_NAME
    }
    fn initialization_sequence() -> Vec<Instruction<Self>> {
        ebpf::initialization_sequence()
    }
    fn return_sequence() -> (Vec<Instruction<Self>>, usize, usize) {
        ebpf::return_sequence()
    }
    fn teotology() -> Vec<Instruction<Self>> {
        ebpf::teotology()
    }
    fn contradiction() -> Vec<Instruction<Self>> {
        ebpf::contradiction()
    }
    fn into_socket_option(instructions: Vec<Instruction<Self>>) -> Result<Self::SocketOption> {
        ebpf::into_socket_option(instructions)
    }
    fn jump(
        comparison: Self::Comparison,
        operand: Self::Value,
        jt: usize,
        jf: usize,
    ) -> Vec<Instruction<Self>> {
        ebpf::jump(comparison, operand, jt, jf)
    }
    fn load_u8_at(offset: u32) -> Vec<Instruction<Self>> {
        ebpf::load_u8_at(offset)
    }
    fn load_u16_at(offset: u32) -> Vec<Instruction<Self>> {
        ebpf::load_u16_at(offset)
    }
    fn load_u32_at(offset: u32) -> Vec<Instruction<Self>> {
        ebpf::load_u32_at(offset)
    }
}
