
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

mod tests {
    use super::*;
    use crate::filter::cbpf::Condition;

    #[test]
    fn simple_and() {
        assert_eq!(
            Predicate::<Condition>::from(Const(true)) & Predicate::from(Const(false)),
            Predicate::<Condition>::from(And(Box::new(Const(true)), Box::new(Const(false))))
        );
    }

    #[test]
    fn simple_or() {
        assert_eq!(
            Predicate::<Condition>::from(Const(true)) | Predicate::from(Const(false)),
            Predicate::<Condition>::from(Or(Box::new(Const(true)), Box::new(Const(false))))
        );
    }
}
