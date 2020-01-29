use std::iter::FromIterator;
use crate::ebpf::Filter;
use crate::ebpf::condition::Condition;
use crate::ebpf::operation::{Operation, exit};

pub trait Compile
where
    Self: Sized,
{
    fn compile(self) -> Filter;
}

use crate::predicate::Predicate;
use crate::predicate::{And, Const, Not, Or, Terminal};

fn walk(predicate: Predicate<Condition>, offset: u16) -> Vec<Operation> {
    match predicate.into_inner() {
        Terminal(condition) => condition.build(offset),
        Not(e) => walk(Predicate::from(*e), offset),
        And(a, b) => {
            let mut res = walk(Predicate::from(*b), offset);
            res.extend(walk(Predicate::from(*a), offset + res.len() as u16));
            res
        }
        Or(a, b) => {
            let mut res = walk(Predicate::from(*b), offset);
            res.extend(walk(Predicate::from(*a), offset + res.len() as u16));
            res
        }
        Const(boolean) => {
            // TODO - implement
            unreachable!()
            /*
            if boolean {
                vec![return_imm(std::u32::MAX)]
            } else {
                vec![DROP]
            }
            */
        }
    }
}

impl Compile for Predicate<Condition> {
    fn compile(mut self) -> Filter {
        self = Predicate::from(self.into_inner().simplify_via_laws());
        let mut instructions = vec![exit()];

        instructions.extend(walk(self, instructions.len() as u16 - 1));

        instructions.reverse();

        println!("instructions: {:?}", instructions);
        Filter::from_iter(instructions)
    }
}
