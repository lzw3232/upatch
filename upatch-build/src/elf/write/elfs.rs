use std::fs::{File, OpenOptions};
use std::path::Path;

use memmap2::{Mmap, MmapOptions};

use super::super::*;
use super::header::*;
use super::section::*;
use super::symbol::*;

#[derive(Debug)]
pub struct Elf {
    file: File,
    _class: u8,
    endian: Endian,
    strtab: Option<Mmap>,
}

impl Elf {
    pub fn parse<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(&path)?;
        match check_elf(&file) {
            Ok(true) => (),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    format!("{:?} is not elf format", path.as_ref()),
                ))
            }
        };
        let (_class, endian) = check_header(&file)?;

        Ok(Self {
            file,
            _class,
            endian,
            strtab: None,
        })
    }

    pub fn header(&mut self) -> std::io::Result<Header> {
        let mmap = unsafe { MmapOptions::new().offset(0).len(64).map_mut(&self.file)? };
        Ok(Header::from(mmap, self.endian))
    }

    pub fn sections(&mut self) -> std::io::Result<Vec<SectionHeader>> {
        let mut res = Vec::new();
        let header = self.header()?;
        let offset = header.get_e_shoff() as usize;
        let num = header.get_e_shnum() as usize;
        let shentsize = header.get_e_shentsize() as usize;

        for i in 0..num {
            let start = (offset + (i * shentsize)) as u64;
            let mmap = unsafe {
                MmapOptions::new()
                    .offset(start)
                    .len(shentsize)
                    .map_mut(&self.file)?
            };
            res.push(SectionHeader::from(mmap, self.endian));
        }

        Ok(res)
    }

    pub fn symbols(&mut self) -> std::io::Result<SymbolHeaderTable> {
        let sections = &self.sections()?;
        for section in sections {
            if section.get_sh_type().eq(&SHT_SYMTAB) {
                let offset = section.get_sh_offset() as usize;
                let size_sum = section.get_sh_size() as usize;
                let size = std::mem::size_of::<SymbolHeader64>();
                let strtab_offset = sections[section.get_sh_link() as usize].get_sh_offset();
                let strtab_size = sections[section.get_sh_link() as usize].get_sh_size() as usize;

                self.strtab = Some(unsafe {
                    MmapOptions::new()
                        .offset(strtab_offset)
                        .len(strtab_size)
                        .map(&self.file)?
                });

                return Ok(SymbolHeaderTable::from(
                    &self.file,
                    self.endian,
                    self.strtab.as_ref().unwrap(),
                    offset,
                    size,
                    offset + size_sum,
                ));
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "elf symbols is error".to_string(),
        ))
    }
}
