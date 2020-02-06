use crate::backend::Backend;
use crate::filter::Filter;
use crate::predicate::Predicate;
use crate::predicate::{And, Const, Expr, Not, Or, Terminal};
use crate::Condition;

pub trait Compile<K: Backend>
where
    Self: Sized,
{
    fn compile(self) -> Filter<K>;

    fn into_expr(self) -> Expr<Condition<K>>;

    fn walk(self, jt: usize, jf: usize) -> Vec<K::Instruction> {
        match self.into_expr() {
            Terminal(condition) => condition.build(jt, jf),
            Not(e) => Predicate::from(*e).walk(jf, jt),
            And(a, b) => {
                let mut res = Predicate::from(*b).walk(jt, jf);
                res.extend(Predicate::from(*a).walk(0, jf + res.len()));
                res
            }
            Or(a, b) => {
                let mut res = Predicate::from(*b).walk(jt, jf);
                res.extend(Predicate::from(*a).walk(jt + res.len(), 0));
                res
            }
            Const(boolean) => {
                if boolean {
                    K::teotology()
                } else {
                    K::contradiction()
                }
            }
        }
    }
}
