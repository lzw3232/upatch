use std::fs::OpenOptions;
use std::path::Path;

use memmap2::{Mmap, MmapOptions};

use super::super::*;
use super::header::*;
use super::section::*;
use super::symbol::*;

#[derive(Debug)]
pub struct Elf {
    mmap: Mmap,
    _class: u8,
    endian: Endian,
}

impl Elf {
    pub fn parse<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).open(&path)?;
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
        let mmap = unsafe { MmapOptions::new().map(&file)? };

        Ok(Self {
            mmap,
            _class,
            endian,
        })
    }

    pub fn header(&mut self) -> std::io::Result<Header> {
        Ok(Header::from(&self.mmap, self.endian))
    }

    pub fn sections(&mut self) -> std::io::Result<SectionHeaderTable> {
        let header = self.header()?;
        let offset = header.get_e_shoff() as usize;
        let num = header.get_e_shnum() as usize;
        let shentsize = header.get_e_shentsize() as usize;
        Ok(SectionHeaderTable::from(
            &self.mmap,
            self.endian,
            offset,
            shentsize,
            num,
        ))
    }

    pub fn symbols(&mut self) -> std::io::Result<SymbolHeaderTable> {
        let sections = self.sections()?;
        for section in sections {
            if section.get_sh_type().eq(&SHT_SYMTAB) {
                let offset = section.get_sh_offset() as usize;
                let size_sum = section.get_sh_size() as usize;
                let size = std::mem::size_of::<SymbolHeader64>();
                let num = size_sum / size;
                let strtab_offset = sections
                    .get(section.get_sh_link() as usize)?
                    .get_sh_offset() as usize;

                return Ok(SymbolHeaderTable::from(
                    &self.mmap,
                    self.endian,
                    strtab_offset,
                    offset,
                    size,
                    num,
                ));
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "elf symbols is error".to_string(),
        ))
    }
}
