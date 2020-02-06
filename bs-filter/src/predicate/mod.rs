pub use boolean_expression::Expr;
pub use boolean_expression::Expr::*;
use std::fmt::Debug;
use std::hash::Hash;
use std::ops::{BitAnd, BitOr};

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub struct Predicate<T>
where
    T: Clone + Debug + Ord + Hash,
{
    expr: Expr<T>,
}

impl<T> Predicate<T>
where
    T: Clone + Debug + Ord + Hash,
{
    pub fn into_inner(self) -> Expr<T> {
        self.expr
    }
}

impl<T> BitAnd for Predicate<T>
where
    T: Clone + Debug + Ord + Hash,
{
    type Output = Predicate<T>;

    fn bitand(self, rhs: Predicate<T>) -> Self::Output {
        Predicate {
            expr: And(Box::new(self.into_inner()), Box::new(rhs.into_inner())),
        }
    }
}

impl<T> BitOr for Predicate<T>
where
    T: Clone + Debug + Ord + Hash,
{
    type Output = Predicate<T>;

    fn bitor(self, rhs: Predicate<T>) -> Self::Output {
        Predicate {
            expr: Or(Box::new(self.into_inner()), Box::new(rhs.into_inner())),
        }
    }
}

impl<T> From<Expr<T>> for Predicate<T>
where
    T: Clone + Debug + Ord + Hash,
{
    fn from(expr: Expr<T>) -> Self {
        Self { expr }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn simple_and() {
        assert_eq!(
            Predicate::<bool>::from(Const(true)) & Predicate::from(Const(false)),
            Predicate::<bool>::from(And(Box::new(Const(true)), Box::new(Const(false))))
        );
    }

    #[test]
    fn simple_or() {
        assert_eq!(
            Predicate::<bool>::from(Const(true)) | Predicate::from(Const(false)),
            Predicate::<bool>::from(Or(Box::new(Const(true)), Box::new(Const(false))))
        );
    }
}

use std::cmp::Ord;
use crate::backend;
use crate::Condition;
use crate::compile::Compile;
use crate::filter::Filter;
use std::iter::FromIterator;

impl<K: backend::Backend> Compile<K> for Predicate<Condition<K>> {
    fn compile(mut self) -> Filter<K> {
        self = Predicate::from(self.into_inner().simplify_via_laws());
        let (mut instructions, jt, jf) = K::return_sequence();

        instructions.extend(self.walk(jt, jf));

        instructions.extend(K::initialization_sequence());

        instructions.reverse();
        println!("{:?}", instructions);

        Filter::from_iter(instructions)
    }

    fn into_expr(self) -> Expr<Condition<K>> {
        self.into_inner()
    }
}

