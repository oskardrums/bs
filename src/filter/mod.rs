pub mod cbpf;
pub mod ebpf;
mod predicate;

pub enum Filter {
    Classic(cbpf::Prog),
    Extended(i32),
}
