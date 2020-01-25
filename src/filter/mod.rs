pub mod cbpf;
mod predicate;

pub enum Filter {
    Classic(cbpf::Prog),
    Extended(i32),
}
