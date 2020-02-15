use crate::backend::Backend;
use bs_ebpf as ebpf;

/// Phantom struct to represent Extended BPF related
/// functionalities.
#[derive(Copy, Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub struct Extended {}

impl Backend for Extended {
    type Comparison = ebpf::Comparison;
    type Value = ebpf::Operand;
    type Instruction = ebpf::Instruction;

    fn initialization_sequence() -> Vec<Self::Instruction> {
        ebpf::initialization_sequence()
    }
    fn return_sequence() -> (Vec<Self::Instruction>, usize, usize) {
        ebpf::return_sequence()
    }
    fn teotology() -> Vec<Self::Instruction> {
        ebpf::teotology()
    }
    fn contradiction() -> Vec<Self::Instruction> {
        ebpf::contradiction()
    }

    /*
    fn build_attachable(instructions: Vec<Self::Instruction>) -> Result<Self::Output> {
        let len = instructions.len();
        if len > u16::max_value() as usize {
            return Err(SystemError(EOVERFLOW));
        }
        Ok(ebpf::SocketFilterBpfAttribute::new(instructions).load()?)
    }
    */

    fn jump(
        comparison: Self::Comparison,
        operand: Self::Value,
        jt: usize,
        jf: usize,
    ) -> Vec<Self::Instruction> {
        ebpf::jump(comparison, operand, jt, jf)
    }

    fn load_u8_at(offset: u32) -> Vec<Self::Instruction> {
        ebpf::load_u8_at(offset as i32)
    }

    fn load_u16_at(offset: u32) -> Vec<Self::Instruction> {
        ebpf::load_u16_at(offset as i32)
    }

    fn load_u32_at(offset: u32) -> Vec<Self::Instruction> {
        ebpf::load_u32_at(offset as i32)
    }
}
