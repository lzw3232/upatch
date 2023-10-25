use memmap2::Mmap;

use super::super::{Endian, HeaderRead, OperateRead, ReadInteger};

#[derive(Debug)]
pub struct Header<'a> {
    mmap: &'a Mmap,
    endian: Endian,
}

impl<'a> Header<'a> {
    pub fn from(mmap: &'a Mmap, endian: Endian) -> Self {
        Self { mmap, endian }
    }
}

impl HeaderRead for Header<'_> {}

impl OperateRead for Header<'_> {
    fn get<T: ReadInteger<T>>(&self, start: usize) -> T {
        self.endian
            .read_integer::<T>(&self.mmap[start..(start + std::mem::size_of::<T>())])
    }
}
