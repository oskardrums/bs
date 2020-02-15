use crate::backend::Backend;
use bs_cbpf as cbpf;

/// Phantom struct to represent Classic BPF related
/// functionalities.
#[derive(Copy, Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub struct Classic {}

impl Backend for Classic {
    type Comparison = cbpf::Comparison;
    type Value = cbpf::Value;
    type Instruction = cbpf::Instruction;

    fn initialization_sequence() -> Vec<Self::Instruction> {
        Default::default()
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

    /*
use bs_system::{Result, SystemError};
use libc::EOVERFLOW;
    fn build_attachable(instructions: Vec<Self::Instruction>) -> Result<Self::Output> {
        let len = instructions.len();
        if len > u16::max_value() as usize {
            return Err(SystemError(EOVERFLOW));
        }
        Ok(Self::Output::from_vector(instructions))
    }
    */

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
