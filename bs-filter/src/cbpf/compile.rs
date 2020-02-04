use std::iter::FromIterator;
use crate::cbpf::return_strategy::ReturnStrategy;
use crate::cbpf::Filter;
use crate::cbpf::condition::Condition;
use crate::cbpf::operation::{Operation, DROP, return_imm};

pub trait Compile
where
    Self: Sized,
{
    fn compile(self) -> Filter;
}

use crate::predicate::Predicate;
use crate::predicate::{And, Const, Not, Or, Terminal};

fn walk(predicate: Predicate<Condition>, jt: usize, jf: usize) -> Vec<Operation> {
    match predicate.into_inner() {
        Terminal(condition) => condition.build(jt, jf),
        Not(e) => walk(Predicate::from(*e), jf, jt),
        And(a, b) => {
            let mut res = walk(Predicate::from(*b), jt, jf);
            res.extend(walk(Predicate::from(*a), 0, jf + res.len()));
            res
        }
        Or(a, b) => {
            let mut res = walk(Predicate::from(*b), jt, jf);
            res.extend(walk(Predicate::from(*a), jt + res.len(), 0));
            res
        }
        Const(boolean) => {
            if boolean {
                vec![return_imm(std::u32::MAX)]
            } else {
                vec![DROP]
            }
        }
    }
}

impl Compile for Predicate<Condition> {
    fn compile_with_return_strategy(mut self, return_strategy: ReturnStrategy) -> Filter {
        self = Predicate::from(self.into_inner().simplify_via_laws());
        let mut instructions = return_strategy.build();

        instructions.extend(walk(self, 0, instructions.len() - 1));

        instructions.reverse();

        println!("instructions: {:?}", instructions);
        Filter::from_iter(instructions)
    }
}
