use std::ffi::OsStr;
use std::os::unix::prelude::OsStrExt;

use memmap2::Mmap;

use super::super::{Endian, OperateRead, ReadInteger, SymbolRead};

#[derive(Debug)]
pub struct SymbolHeader<'a> {
    mmap: &'a Mmap,
    endian: Endian,
    strtab: usize,
    offset: usize,
}

impl<'a> SymbolHeader<'a> {
    pub fn from(mmap: &'a Mmap, endian: Endian, strtab: usize, offset: usize) -> Self {
        Self {
            mmap,
            endian,
            strtab,
            offset,
        }
    }

    pub fn get_st_name(&mut self) -> &'a OsStr {
        let name_offset = self.get_st_name_offset() as usize;
        self.read_to_os_string(name_offset)
    }
}

impl SymbolRead for SymbolHeader<'_> {}

impl<'a> SymbolHeader<'a> {
    fn read_to_os_string(&self, offset: usize) -> &'a OsStr {
        let mut end = offset;
        loop {
            let data = &self.mmap[self.strtab + end];
            if data.eq(&0) {
                break;
            }
            end += 1;
        }
        OsStr::from_bytes(&self.mmap[self.strtab + offset..self.strtab + end])
    }
}

impl OperateRead for SymbolHeader<'_> {
    fn get<T: ReadInteger<T>>(&self, start: usize) -> T {
        self.endian.read_integer::<T>(
            &self.mmap[self.offset + start..(self.offset + start + std::mem::size_of::<T>())],
        )
    }
}

#[derive(Debug)]
pub struct SymbolHeaderTable<'a> {
    mmap: &'a Mmap,
    endian: Endian,
    strtab: usize,
    offset: usize,
    size: usize,
    num: usize,
    count: usize,
}

impl<'a> SymbolHeaderTable<'a> {
    pub fn from(
        mmap: &'a Mmap,
        endian: Endian,
        strtab: usize,
        offset: usize,
        size: usize,
        num: usize,
    ) -> Self {
        Self {
            mmap,
            endian,
            strtab,
            offset,
            size,
            num,
            count: 0,
        }
    }

    pub fn reset(&mut self, n: usize) {
        match n < self.num {
            true => self.count = n,
            false => self.count = 0,
        }
    }
}

impl<'a> Iterator for SymbolHeaderTable<'a> {
    type Item = SymbolHeader<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.count < self.num {
            true => {
                let offset = self.count * self.size + self.offset;
                self.count += 1;
                Some(SymbolHeader::from(
                    self.mmap,
                    self.endian,
                    self.strtab,
                    offset,
                ))
            }
            false => {
                self.count = 0;
                None
            }
        }
    }
}
