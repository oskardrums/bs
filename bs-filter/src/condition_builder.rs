pub trait ConditionBuilder {
    type Offset;
    type Value;
    type Condition;
    fn offset_equals(offset: Self::Offset, value: Self::Value) -> Self::Condition;
}
