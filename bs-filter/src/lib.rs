#[cfg(test)]
mod tests;

pub(crate) mod predicate;
pub(crate) mod util;
pub(crate) mod condition_builder;
pub mod ready_made;
pub mod cbpf;
pub mod ebpf;

pub enum Filter {
    Classic(cbpf::Filter),
    Extended(i32),
}

