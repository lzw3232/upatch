use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::path::PathBuf;

use crate::tool::OsStrExt;

use crate::elf::read;

const OBJECT_PREFIX: &str = ".upatch_";
const OBJECT_EXTENSION: &str = "o";

pub struct LinkMessages {
    link_message: HashMap<PathBuf, HashSet<PathBuf>>,
}

impl LinkMessages {
    /*
     * In order to find out the object files which compose the binary,
     * we add symbol which's name is ".upatch_xxx" in object, and xxx is the object's name
     */
    fn parse<P: AsRef<Path>, Q: AsRef<Path>>(
        path: P,
        fliter: Q,
    ) -> std::io::Result<HashSet<PathBuf>> {
        let mut result: HashSet<PathBuf> = HashSet::new();
        let mut elf = read::Elf::parse(path)?;

        for mut symbol in elf.symbols()? {
            let symbol_name = symbol.get_st_name();
            let mut object_path = match symbol_name.strip_prefix(OBJECT_PREFIX) {
                Some(name) => fliter.as_ref().join(name),
                None => continue,
            };
            object_path.set_extension(OBJECT_EXTENSION);
            if object_path.exists() {
                result.insert(object_path);
            }
        }
        Ok(result)
    }
}

impl LinkMessages {
    pub fn new() -> Self {
        Self {
            link_message: HashMap::new(),
        }
    }

    pub fn from<P: AsRef<Path>, Q: AsRef<Path>>(
        pathes: &Vec<P>,
        fliter: Q,
    ) -> std::io::Result<Self> {
        let mut link_message: HashMap<PathBuf, HashSet<PathBuf>> = HashMap::new();
        for path in pathes {
            link_message.insert(path.as_ref().to_path_buf(), Self::parse(path, &fliter)?);
        }
        Ok(Self { link_message })
    }

    pub fn get_objects<P: AsRef<Path>>(&self, binary: P) -> Option<&HashSet<PathBuf>> {
        match self.link_message.get(binary.as_ref()) {
            Some(objects) => match objects.is_empty() {
                true => None,
                false => Some(objects),
            },
            None => None,
        }
    }
}

impl std::fmt::Debug for LinkMessages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self.link_message))
    }
}

impl Default for LinkMessages {
    fn default() -> Self {
        Self::new()
    }
}
