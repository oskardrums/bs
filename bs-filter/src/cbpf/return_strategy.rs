use crate::cbpf::computation::Computation;
use crate::cbpf::operation::{return_imm, ImmArg, Operation, DROP, RETURN_A};

pub enum ReturnStrategy {
    Truncate(ImmArg),
    Calculate(Computation),
}

impl ReturnStrategy {
    pub fn build(self) -> Vec<Operation> {
        match self {
            Self::Truncate(k) => vec![DROP, return_imm(k)],
            Self::Calculate(computation) => {
                let mut res = vec![DROP, RETURN_A];
                res.extend(computation.build());
                res
            }
        }
    }
}
