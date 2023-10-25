use memmap2::MmapMut;

use super::super::{Endian, HeaderRead, HeaderWrite, OperateRead, OperateWrite, ReadInteger};

#[derive(Debug)]
pub struct Header {
    mmap: MmapMut,
    endian: Endian,
}

impl Header {
    pub fn from(mmap: MmapMut, endian: Endian) -> Self {
        Self { mmap, endian }
    }
}

impl HeaderRead for Header {}

impl HeaderWrite for Header {}

impl OperateRead for Header {
    fn get<T: ReadInteger<T>>(&self, start: usize) -> T {
        self.endian
            .read_integer::<T>(&self.mmap[start..(start + std::mem::size_of::<T>())])
    }
}

impl OperateWrite for Header {
    fn set<T: ReadInteger<T>>(&mut self, start: usize, data: T) {
        let vec = self.endian.write_integer::<T>(data);
        for (i, _) in vec.iter().enumerate() {
            self.mmap[start + i] = vec[i];
        }
    }
}
