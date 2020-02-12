use crate::backend::Backend;
use crate::predicate::{Expr::*, Predicate};
use crate::Condition;
use bs_system::consts::BPF_JEQ;

/// true iff the octet at offset `offset` equals `value`
pub fn offset_equals_u8<K: Backend>(offset: u32, value: u8) -> Predicate<K> {
    Predicate::from_inner(Terminal(Condition::new(
        K::load_u8_at(offset),
        K::Comparison::from(BPF_JEQ as u8),
        K::Value::from(value as u32),
    )))
}

/// true iff the octet at offset `offset + shift` equals `value`
// TODO - should `shift` be i32?
pub fn shift_offset_equals_u8<K: Backend>(offset: u32, value: u8, shift: u32) -> Predicate<K> {
    Predicate::from_inner(Terminal(Condition::new(
        K::load_u8_at(offset + shift),
        K::Comparison::from(BPF_JEQ as u8),
        K::Value::from(value as u32),
    )))
}

/// true iff the u16 at offset `offset` equals `value`
pub fn offset_equals_u16<K: Backend>(offset: u32, value: u16) -> Predicate<K> {
    Predicate::from_inner(Terminal(Condition::new(
        K::load_u16_at(offset),
        K::Comparison::from(BPF_JEQ as u8),
        K::Value::from(value as u32),
    )))
}

/// true iff the u16 at offset `offset + shift` equals `value`
pub fn shift_offset_equals_u16<K: Backend>(offset: u32, value: u16, shift: u32) -> Predicate<K> {
    Predicate::from_inner(Terminal(Condition::new(
        K::load_u16_at(offset + shift),
        K::Comparison::from(BPF_JEQ as u8),
        K::Value::from(value as u32),
    )))
}

/// true iff the u32 at offset `offset` equals `value`
pub fn offset_equals_u32<K: Backend>(offset: u32, value: u32) -> Predicate<K> {
    Predicate::from_inner(Terminal(Condition::new(
        K::load_u32_at(offset),
        K::Comparison::from(BPF_JEQ as u8),
        K::Value::from(value),
    )))
}

/// true iff the u32 at offset `offset + shift` equals `value`
pub fn shift_offset_equals_u32<K: Backend>(offset: u32, value: u32, shift: u32) -> Predicate<K> {
    Predicate::from_inner(Terminal(Condition::new(
        K::load_u32_at(offset + shift),
        K::Comparison::from(BPF_JEQ as u8),
        K::Value::from(value),
    )))
}

/// Ethernet layer filtering idioms
pub mod ethernet;

/// IP layer filtering idioms
pub mod ip;
