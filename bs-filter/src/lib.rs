#[cfg(test)]
mod tests;

pub(crate) mod predicate;
pub mod cbpf;
pub mod ebpf;

pub enum Filter {
    Classic(cbpf::Filter),
    Extended(i32),
}
