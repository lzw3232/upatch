use std::fs::File;

use memmap2::MmapOptions;

use super::{Endian, Endianness};

const ELFCLASS64: u8 = 2;

pub fn check_elf(file: &File) -> std::io::Result<bool> {
    match file.metadata() {
        Ok(metadata) => match metadata.len() > 64 {
            true => (),
            false => return Ok(false),
        },
        Err(_) => return Ok(false),
    };
    let mmap = unsafe { MmapOptions::new().offset(0).len(4).map(file)? };
    Ok(mmap[0..4].eq(&[0x7f, 0x45, 0x4c, 0x46]))
}

pub fn check_header(file: &File) -> std::io::Result<(u8, Endian)> {
    let mmap = unsafe { MmapOptions::new().offset(4).len(2).map(file)? };
    //Now we only support 64 bit
    let class = match mmap.get(0..1) {
        Some(&[ELFCLASS64]) => ELFCLASS64,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "elf format is not class64".to_string(),
            ))
        }
    };

    let endian = match mmap.get(1..2) {
        Some([1]) => Endian::new(Endianness::Little),
        Some([2]) => Endian::new(Endianness::Big),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "elf endian is error".to_string(),
            ))
        }
    };

    Ok((class, endian))
}
