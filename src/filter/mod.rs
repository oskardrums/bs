pub mod cbpf;

pub enum Filter {
    Classic(cbpf::Prog),
    Extended(i32),
}
