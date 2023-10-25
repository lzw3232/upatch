use memoffset::offset_of;

use super::{OperateRead, OperateWrite};

pub const SHN_UNDEF: u16 = 0;
pub const SHN_LIVEPATCH: u16 = 0xff20;

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;

pub const SYM_OTHER: u8 = 0x40;

pub const STT_SECTION: u8 = 0x3;
pub const STT_FILE: u8 = 0x4;
pub const STT_IFUNC: u8 = 0xa;

pub trait SymbolRead: OperateRead {
    fn get_st_name_offset(&self) -> u32 {
        self.get::<u32>(offset_of!(SymbolHeader64, st_name))
    }

    fn get_st_info(&self) -> u8 {
        self.get(offset_of!(SymbolHeader64, st_info))
    }

    fn get_st_other(&self) -> u8 {
        self.get(offset_of!(SymbolHeader64, st_other))
    }

    fn get_st_shndx(&self) -> u16 {
        self.get(offset_of!(SymbolHeader64, st_shndx))
    }

    fn get_st_value(&self) -> u64 {
        self.get(offset_of!(SymbolHeader64, st_value))
    }

    fn get_st_size(&self) -> u64 {
        self.get(offset_of!(SymbolHeader64, st_size))
    }
}

pub trait SymbolWrite: OperateWrite {
    fn set_st_info(&mut self, st_info: u8) {
        self.set(offset_of!(SymbolHeader64, st_info), st_info)
    }

    fn set_st_other(&mut self, st_other: u8) {
        self.set(offset_of!(SymbolHeader64, st_other), st_other)
    }

    fn set_st_shndx(&mut self, st_shndx: u16) {
        self.set(offset_of!(SymbolHeader64, st_shndx), st_shndx)
    }

    fn set_st_value(&mut self, st_value: u64) {
        self.set(offset_of!(SymbolHeader64, st_value), st_value)
    }

    fn set_st_size(&mut self, st_size: u64) {
        self.set(offset_of!(SymbolHeader64, st_size), st_size)
    }
}

#[repr(C)]
pub struct SymbolHeader64 {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

pub fn elf_st_type(st_info: u8) -> u8 {
    st_info & 0xf
}

pub fn elf_st_bind(st_info: u8) -> u8 {
    st_info >> 4
}
