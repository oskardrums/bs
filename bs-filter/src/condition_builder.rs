use std::fmt::Debug;
use std::cmp::Ord;
use std::hash::Hash;

pub trait ConditionBuilder {
    type Offset: From<u16>;
    type Condition: Clone + Debug + Ord + Hash;

    fn offset_equals_u8(offset: Self::Offset, value: u8) -> Self::Condition;
    fn offset_equals_u16(offset: Self::Offset, value: u16) -> Self::Condition;
    fn offset_equals_u32(offset: Self::Offset, value: u32) -> Self::Condition;
    fn offset_equals_u64(offset: Self::Offset, value: u64) -> Self::Condition;
}
