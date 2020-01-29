use crate::ebpf::computation::Computation;
use crate::ebpf::jump_strategy::JumpStrategy;
use crate::ebpf::operation::Operation;

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub struct Condition {
    computation: Computation,
    jump: JumpStrategy,
}

impl Condition {
    pub const fn new(computation: Computation, jump: JumpStrategy) -> Self {
        Self {
            computation,
            jump,
        }
    }

    pub fn computation(self) -> Computation {
        self.computation
    }

    pub fn build(self, jump_offset: usize) -> Vec<Operation> {
        let mut res = self.jump.build(jump_offset as _);
        res.extend(self.computation.build());
        res
    }
}
