use crate::condition_builder::ConditionBuilder;
use crate::ebpf::computation::Computation;
use crate::ebpf::jump_strategy::JumpStrategy;
use crate::ebpf::operation::{JumpOffset, Operation, Register};
use bpf_sys::*;

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub struct Condition {
    computation: Computation,
    jump: JumpStrategy,
}

impl Condition {
    pub const fn new(computation: Computation, jump: JumpStrategy) -> Self {
        Self { computation, jump }
    }

    pub fn computation(self) -> Computation {
        self.computation
    }

    pub fn build(self, jump_offset: u16) -> Vec<Operation> {
        let mut res = self.jump.build(jump_offset);
        res.extend(self.computation.build());
        res
    }
}

impl ConditionBuilder for Condition {
    type Offset = JumpOffset;
    type Condition = Self;

    fn exit() -> Self::Condition {
        Condition::new(Computation::new(Vec::new()), JumpStrategy::Imm32(BPF_JEQ as _, Register::Ret, 0))
    }

    fn offset_equals_u8(offset: Self::Offset, value: u8) -> Self::Condition {
        let mut op_load = Operation::new();
        op_load.set_code((BPF_LD | BPF_ABS | BPF_B) as u8);
        op_load.set_dst(Register::Ret);
        op_load.set_imm((offset as u32).to_be());
        Condition::new(
            Computation::new(vec![op_load]),
            JumpStrategy::Imm32(BPF_JEQ as _, Register::Ret, (value as u32).to_be()),
        )
    }

    fn offset_equals_u16(offset: Self::Offset, value: u16) -> Self::Condition {
        let mut op_load = Operation::new();
        op_load.set_code((BPF_LD | BPF_ABS | BPF_H) as _);
        op_load.set_dst(Register::Ret);
        op_load.set_imm((offset as u32).to_be());
        Condition::new(
            Computation::new(vec![op_load]),
            JumpStrategy::Imm32(BPF_JEQ as _, Register::Ret, (value as u32).to_be()),
        )
    }

    fn offset_equals_u32(offset: Self::Offset, value: u32) -> Self::Condition {
        let mut op_load = Operation::new();
        op_load.set_code((BPF_LD | BPF_ABS | BPF_W) as _);
        op_load.set_dst(Register::Ret);
        op_load.set_imm((offset as u32).to_be());
        Condition::new(
            Computation::new(vec![op_load]),
            JumpStrategy::Imm32(BPF_JEQ as _, Register::Ret, value.to_be()),
        )
    }

    fn offset_equals_u64(offset: Self::Offset, value: u64) -> Self::Condition {
        let mut op_load = Operation::new();
        op_load.set_code((BPF_LD | BPF_ABS | BPF_DW) as _);
        op_load.set_dst(Register::Ret);
        op_load.set_imm((offset as u32).to_be());
        Condition::new(
            Computation::new(vec![op_load]),
            JumpStrategy::Imm(BPF_JEQ as _, Register::Ret, (value as u32).to_be()),
        )
    }
}
