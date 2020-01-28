use crate::cbpf::operation::Operation;
use std::iter::FromIterator;
use std::mem::forget;

#[repr(C)]
#[derive(Debug)]
pub struct Program {
    len: u16,
    filter: *mut Operation,
}

impl Program {
    pub fn new(ops: Vec<Operation>) -> Self {
        let mut ops = ops.into_boxed_slice();
        let len = ops.len();
        let ptr = ops.as_mut_ptr();

        forget(ops);

        Self {
            len: len as _,
            filter: ptr,
        }
    }

    pub fn len(&self) -> u16 {
        self.len
    }
}

impl Drop for Program {
    fn drop(&mut self) {
        unsafe {
            let len = self.len as usize;
            let ptr = self.filter;
            Vec::from_raw_parts(ptr, len, len);
        }
    }
}


impl FromIterator<Operation> for Program {
    fn from_iter<I: IntoIterator<Item=Operation>>(iter: I) -> Self {
        Self::new(Vec::from_iter(iter))
    }
}
