use std::os::unix::prelude::OsStrExt;
use std::{ffi::OsStr, fs::File};

use memmap2::{Mmap, MmapMut, MmapOptions};

use super::super::{Endian, OperateRead, OperateWrite, ReadInteger, SymbolRead, SymbolWrite};

#[derive(Debug)]
pub struct SymbolHeader<'a> {
    mmap: MmapMut,
    endian: Endian,
    strtab: &'a Mmap,
    name: &'a OsStr,
}

impl<'a> SymbolHeader<'a> {
    pub fn from(mmap: MmapMut, endian: Endian, strtab: &'a Mmap) -> Self {
        Self {
            mmap,
            endian,
            strtab,
            name: OsStr::new(""),
        }
    }

    pub fn get_st_name(&mut self) -> &OsStr {
        match self.name.is_empty() {
            false => <&std::ffi::OsStr>::clone(&self.name),
            true => {
                let name_offset = self.get_st_name_offset() as usize;
                self.name = self.read_to_os_string(name_offset);
                self.name
            }
        }
    }
}

impl SymbolRead for SymbolHeader<'_> {}

impl SymbolWrite for SymbolHeader<'_> {}

impl<'a> SymbolHeader<'a> {
    fn read_to_os_string(&self, offset: usize) -> &'a OsStr {
        let mut end = offset;
        loop {
            let data = self.strtab[end];
            if data.eq(&0) {
                break;
            }
            end += 1;
        }
        OsStr::from_bytes(&self.strtab[offset..end])
    }
}

impl OperateRead for SymbolHeader<'_> {
    fn get<T: ReadInteger<T>>(&self, start: usize) -> T {
        self.endian
            .read_integer::<T>(&self.mmap[start..(start + std::mem::size_of::<T>())])
    }
}

impl OperateWrite for SymbolHeader<'_> {
    fn set<T: ReadInteger<T>>(&mut self, start: usize, data: T) {
        let vec = self.endian.write_integer::<T>(data);
        for (i, _) in vec.iter().enumerate() {
            self.mmap[start + i] = vec[i];
        }
    }
}

#[derive(Debug)]
pub struct SymbolHeaderTable<'a> {
    file: &'a File,
    endian: Endian,
    strtab: &'a Mmap,
    size: usize,
    start: usize,
    end: usize,
    count: usize,
}

impl<'a> SymbolHeaderTable<'a> {
    pub fn from(
        file: &'a File,
        endian: Endian,
        strtab: &'a Mmap,
        start: usize,
        size: usize,
        end: usize,
    ) -> Self {
        Self {
            file,
            endian,
            strtab,
            size,
            start,
            end,
            count: 0,
        }
    }
}

impl<'a> Iterator for SymbolHeaderTable<'a> {
    type Item = SymbolHeader<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let offset = self.count * self.size + self.start;
        match offset < self.end {
            true => {
                self.count += 1;
                let mmap = unsafe {
                    MmapOptions::new()
                        .offset(offset as u64)
                        .len(self.size)
                        .map_mut(self.file)
                        .unwrap()
                };
                Some(SymbolHeader::from(mmap, self.endian, self.strtab))
            }
            false => {
                self.count = 0;
                None
            }
        }
    }
}
