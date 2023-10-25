use std::path::Path;

use crate::log::*;

use crate::elf::*;

pub fn resolve_upatch<P: AsRef<Path>, Q: AsRef<Path>>(
    debug_info: P,
    patch: Q,
) -> std::io::Result<()> {
    let mut patch_elf = write::Elf::parse(patch)?;
    let mut debug_info_elf = read::Elf::parse(debug_info)?;
    let debug_info_e_ident = debug_info_elf.header()?.get_e_ident();
    patch_elf.header()?.set_e_ident(debug_info_e_ident);
    let ei_osabi = elf_ei_osabi(debug_info_e_ident);

    let debug_info_symbols = &mut debug_info_elf.symbols()?;

    for mut symbol in &mut patch_elf.symbols()? {
        /* No need to handle section symbol */
        let sym_info = symbol.get_st_info();
        if elf_st_type(sym_info) == STT_SECTION {
            continue;
        }

        let sym_other = symbol.get_st_other();
        if sym_other & SYM_OTHER != 0 {
            // TODO: we can delete these symbol's section here.
            symbol.set_st_other(sym_other & !SYM_OTHER);
            match symbol.get_st_value() {
                0 => symbol.set_st_shndx(SHN_UNDEF),
                _ => symbol.set_st_shndx(SHN_LIVEPATCH),
            };
        } else if symbol.get_st_shndx() == SHN_UNDEF {
            if elf_st_bind(sym_info) == STB_LOCAL {
                /* only partly resolved undefined symbol could have st_value */
                if symbol.get_st_value() != 0 {
                    symbol.set_st_shndx(SHN_LIVEPATCH);
                }
            } else {
                __partly_resolve_patch(&mut symbol, debug_info_symbols, ei_osabi)?;
            }
        }
    }
    Ok(())
}

fn __partly_resolve_patch(
    symbol: &mut write::SymbolHeader,
    debug_info_symbols: &mut read::SymbolHeaderTable,
    ei_osabi: u8,
) -> std::io::Result<()> {
    debug_info_symbols.reset(0);
    for mut debug_info_symbol in debug_info_symbols {
        /* No need to handle section symbol */
        let sym_info = debug_info_symbol.get_st_info();
        if elf_st_type(sym_info) == STT_SECTION {
            continue;
        }

        let debug_info_name = debug_info_symbol.get_st_name();

        if elf_st_bind(sym_info).ne(&elf_st_bind(symbol.get_st_info()))
            || debug_info_name.ne(symbol.get_st_name())
        {
            continue;
        }

        /* leave it to be handled in running time */
        if debug_info_symbol.get_st_shndx() == SHN_UNDEF {
            continue;
        }

        // symbol type is STT_IFUNC, need search st_value in .plt table in upatch.
        let is_ifunc = (ei_osabi.eq(&ELFOSABI_GNU) || ei_osabi.eq(&ELFOSABI_FREEBSD))
            && elf_st_type(sym_info).eq(&STT_IFUNC);
        symbol.set_st_shndx(match is_ifunc {
            true => SHN_UNDEF,
            false => SHN_LIVEPATCH,
        });
        symbol.set_st_info(sym_info);
        symbol.set_st_other(debug_info_symbol.get_st_other());
        symbol.set_st_value(debug_info_symbol.get_st_value());
        symbol.set_st_size(debug_info_symbol.get_st_size());
        trace!(
            "found unresolved symbol {:?} at 0x{:x}",
            debug_info_symbol.get_st_name(),
            symbol.get_st_value()
        );
        break;
    }

    Ok(())
}

/*
 * In order to avoid external access to internal symbols, the dynamic library changes some GLOBAL symbols to the LOCAL symbols,
 * then we can't match these symbols, we change these symbols to GLOBAL here.
 */
pub fn resolve_dynamic<P: AsRef<Path>>(debug_info: P) -> std::io::Result<()> {
    let mut debug_info_elf = write::Elf::parse(debug_info)?;
    let debug_info_header = debug_info_elf.header()?;

    if debug_info_header.get_e_type().ne(&ET_DYN) {
        return Ok(());
    }

    let mut debug_info_symbols = debug_info_elf.symbols()?;

    for mut symbol in &mut debug_info_symbols {
        if elf_st_type(symbol.get_st_info()).ne(&STT_FILE) {
            continue;
        }

        let symbol_name = symbol.get_st_name();
        if symbol_name.eq("") {
            _resolve_dynamic(&mut debug_info_symbols)?;
            break;
        }
    }
    Ok(())
}

fn _resolve_dynamic(debug_info_symbols: &mut write::SymbolHeaderTable) -> std::io::Result<()> {
    for mut symbol in debug_info_symbols {
        if elf_st_type(symbol.get_st_info()).eq(&STT_FILE) {
            break;
        }

        let info = symbol.get_st_info();
        if elf_st_bind(info).ne(&STB_GLOBAL) {
            let symbol_name = symbol.get_st_name();
            debug!(
                "resolve_dynamic: set {:?}'s bind {} to 1",
                symbol_name,
                elf_st_bind(info)
            );

            let info = elf_st_type(symbol.get_st_info()) | (STB_GLOBAL << 4);
            symbol.set_st_info(info);
        }
    }
    Ok(())
}
