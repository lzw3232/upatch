use std::cmp;
use std::collections::HashSet;
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use log::*;
use which::which;

use crate::ffi::*;
use crate::cmd::*;
use crate::dwarf::Dwarf;
use crate::tool::search_tool;

use super::Error;
use super::Result;

const COMPILER_HIJACKER: &str = "compiler-hijacker";
const ASSEMBLER_HIJACKER: &str = "as-hijacker";

#[derive(Clone)]
pub struct Compiler {
    compiler: Vec<PathBuf>,
    assembler: Vec<PathBuf>,
    linker: Vec<PathBuf>,
    compiler_hijacker: PathBuf,
    assembler_hijacker: PathBuf,
    hijacker_dir: PathBuf,
}

impl Compiler {
    pub fn new() -> Self {
        Self {
            compiler: Vec::new(),
            assembler: Vec::new(),
            linker: Vec::new(),
            compiler_hijacker: PathBuf::new(),
            assembler_hijacker: PathBuf::new(),
            hijacker_dir: PathBuf::new(),
        }
    }

    pub fn which(&self, name: &OsStr) -> Result<PathBuf> {
        match which(name) {
            Ok(result) => Ok(result),
            Err(e) => Err(Error::Compiler(format!("get {:?} failed: {}", name, e))),
        }
    }

    pub fn read_from_compiler<P: AsRef<Path>>(&self, compiler: P, name: &str) -> Result<OsString> {
        let args_list = ExternCommandArgs::new().arg(name);
        let output = ExternCommand::new(compiler.as_ref()).execv(args_list)?;
        if !output.exit_status().success() {
            return Err(Error::Compiler(format!(
                "get {} from compiler {:?} failed",
                name, &self.compiler
            )));
        }
        Ok(output.stdout().to_os_string())
    }

    pub fn analyze<I, P, Q>(&mut self, compiler_file: I, hijacker_dir: Q) -> Result<()>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
        Q: AsRef<Path>,
    {
        self.compiler_hijacker = search_tool(COMPILER_HIJACKER)?;
        self.assembler_hijacker = search_tool(ASSEMBLER_HIJACKER)?;
        self.hijacker_dir = hijacker_dir.as_ref().to_path_buf();
        for compiler in compiler_file {
            let compiler = compiler.as_ref().to_path_buf();
            let assembler =
                self.which(&self.read_from_compiler(&compiler, "-print-prog-name=as")?)?;
            let linker = self.which(&self.read_from_compiler(&compiler, "-print-prog-name=ld")?)?;

            if !self.compiler.contains(&compiler) {
                self.compiler.push(compiler);
            }

            if !self.assembler.contains(&assembler) {
                self.assembler.push(assembler);
            }

            if !self.linker.contains(&linker) {
                self.linker.push(linker);
            }
        }

        info!("Using compiler at: {:?}", &self.compiler);
        trace!("Using assembler at: {:?}", &self.assembler);
        trace!("Using linker at: {:?}", &self.linker);
        if self.assembler.is_empty() {
            return Err(Error::Compiler(
                "can't find assembler in compiler".to_string(),
            ));
        }
        if self.linker.is_empty() {
            return Err(Error::Compiler("can't find linker in compiler".to_string()));
        }
        Ok(())
    }

    pub fn hack(&self) -> Result<()> {
        unsafe {
            let ret = upatch_hijacker_init();
            if ret != 0 {
                return Err(Error::Mod(format!("upatch hijacker init failed - {}", ret)));
            }
            self.hijacker_register(self.compiler.len() + self.assembler.len())
        }
    }

    pub fn unhack(&self) -> Result<()> {
        unsafe {
            let ret = upatch_hijacker_init();
            if ret != 0 {
                return Err(Error::Mod(format!("upatch hijacker init failed - {}", ret)));
            }
            self.hijacker_unregister(self.compiler.len() + self.assembler.len())
        }
    }

    pub fn check_version<P, I, Q>(&self, cache_dir: P, debug_infoes: I) -> Result<()>
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = Q>,
        Q: AsRef<Path>,
    {
        let cache_dir = cache_dir.as_ref();
        let test_path = Path::new(&cache_dir).join("test.c");
        let mut test_file = File::create(&test_path)?;
        test_file.write_all(b"int main() {return 0;}")?;
        let test_obj = Path::new(&cache_dir).join("test.o");
        let dwarf = Dwarf::new();
        let mut system_compiler_version = HashSet::new();

        for compiler in &self.compiler {
            let args_list = ExternCommandArgs::new()
                .args(["-gdwarf", "-ffunction-sections", "-fdata-sections", "-c"])
                .arg(&test_path)
                .arg("-o")
                .arg(&test_obj);
            let output = ExternCommand::new(compiler).execv(args_list)?;
            if !output.exit_status().success() {
                return Err(Error::Compiler(format!(
                    "compiler build test error {}: {}",
                    output.exit_code(),
                    output.stderr().to_string_lossy()
                )));
            };

            /* Dwraf DW_AT_producer
             * GNU standard version
             */
            for element in dwarf.file_in_obj(test_obj.clone())? {
                let compiler_version = element.get_compiler_version();
                let compiler_version_arr = compiler_version.split(' ').collect::<Vec<_>>();
                if compiler_version_arr.len() < 3 {
                    return Err(Error::Compiler(format!(
                        "read system compiler version failed: {}",
                        element.get_compiler_version()
                    )));
                }
                system_compiler_version.insert(compiler_version_arr[2].to_string());
            }
        }
        debug!("system compiler version: {:?}", &system_compiler_version);

        for debug_info in debug_infoes {
            for element in dwarf.file_in_obj(debug_info.as_ref())? {
                let compiler_version = element.get_compiler_version();
                let compiler_version_arr = compiler_version.split(' ').collect::<Vec<_>>();
                if compiler_version_arr.len() < 3 {
                    return Err(Error::Compiler(format!(
                        "read {:?} compiler version failed: {}",
                        debug_info.as_ref(),
                        &element.get_compiler_version()
                    )));
                }
                if !system_compiler_version.contains(compiler_version_arr[2]) {
                    return Err(Error::Compiler(format!("compiler version is different \n{:?}'s compiler version: {} \nsystem compiler version: {:?}", debug_info.as_ref(), &compiler_version_arr[2], &system_compiler_version)));
                }
            }
        }
        Ok(())
    }

    pub fn linker<P, Q>(&self, link_list: &Vec<P>, output_file: Q) -> Result<()>
    where
        P: AsRef<OsStr>,
        Q: AsRef<Path>,
    {
        let args_list = ExternCommandArgs::new()
            .args(["-r", "-o"])
            .arg(output_file.as_ref())
            .args(link_list);
        let output = ExternCommand::new(&self.linker[0]).execv(args_list)?;
        if !output.exit_status().success() {
            return Err(Error::Compiler(format!(
                "link object file error {}: {}",
                output.exit_code(),
                output.stderr().to_string_lossy()
            )));
        };
        Ok(())
    }
}

impl Compiler {
    fn hijacker_register(&self, num: usize) -> Result<()> {
        for i in 0..cmp::min(num, self.compiler.len()) {
            let compiler_hijacker = self.hijacker_dir.join(i.to_string());
            std::fs::hard_link(&self.compiler_hijacker, &compiler_hijacker)?;

            trace!("hack {:?} -> {:?}", self.compiler[i], compiler_hijacker);
            let compiler_cstr = CString::new(self.compiler[i].as_os_str().as_bytes()).unwrap();
            let compiler_hijacker_cstr =
                CString::new(compiler_hijacker.as_os_str().as_bytes()).unwrap();
            let ret = unsafe {
                upatch_hijacker_register(compiler_cstr.as_ptr(), compiler_hijacker_cstr.as_ptr())
            };
            if ret != 0 {
                trace!("hack {:?} error {}, try to rollback", self.compiler[i], ret);
                self.hijacker_unregister(i)?;
                return Err(Error::Mod(format!(
                    "hack {:?} error {}",
                    self.compiler[i], ret
                )));
            }
        }
        for i in self.compiler.len()..num {
            let assembler_hijacker = self.hijacker_dir.join(i.to_string());
            std::fs::hard_link(&self.assembler_hijacker, &assembler_hijacker)?;

            let i = i - self.compiler.len();
            trace!("hack {:?} -> {:?}", self.assembler[i], assembler_hijacker);
            let assembler_cstr = CString::new(self.assembler[i].as_os_str().as_bytes()).unwrap();
            let assembler_hijacker_cstr =
                CString::new(assembler_hijacker.as_os_str().as_bytes()).unwrap();
            let ret = unsafe {
                upatch_hijacker_register(assembler_cstr.as_ptr(), assembler_hijacker_cstr.as_ptr())
            };
            if ret != 0 {
                trace!(
                    "hack {:?} error {}, try to rollback",
                    self.assembler[i],
                    ret
                );
                self.hijacker_unregister(i)?;
                return Err(Error::Mod(format!(
                    "hack {:?} error {}",
                    self.assembler[i], ret
                )));
            }
        }
        Ok(())
    }

    fn hijacker_unregister(&self, num: usize) -> Result<()> {
        for i in (self.compiler.len()..num).rev() {
            let assembler_hijacker = self.hijacker_dir.join(i.to_string());

            let i = i - self.compiler.len();
            trace!("unhack {:?} -> {:?}", self.assembler[i], assembler_hijacker);
            let assembler_cstr = CString::new(self.assembler[i].as_os_str().as_bytes()).unwrap();
            let assembler_hijacker_cstr =
                CString::new(assembler_hijacker.as_os_str().as_bytes()).unwrap();
            let ret = unsafe {
                upatch_hijacker_unregister(
                    assembler_cstr.as_ptr(),
                    assembler_hijacker_cstr.as_ptr(),
                )
            };
            if ret != 0 {
                trace!("unhack {:?} error {}", self.assembler[i], ret);
                return Err(Error::Mod(format!(
                    "unhack {:?} error {}",
                    self.assembler[i], ret
                )));
            }
        }

        for i in (0..cmp::min(num, self.compiler.len())).rev() {
            let compiler_hijacker = self.hijacker_dir.join(i.to_string());

            trace!("unhack {:?} -> {:?}", self.compiler[i], compiler_hijacker);
            let compiler_cstr = CString::new(self.compiler[i].as_os_str().as_bytes()).unwrap();
            let compiler_hijacker_cstr =
                CString::new(compiler_hijacker.as_os_str().as_bytes()).unwrap();
            let ret = unsafe {
                upatch_hijacker_unregister(compiler_cstr.as_ptr(), compiler_hijacker_cstr.as_ptr())
            };
            if ret != 0 {
                trace!("unhack {:?} error {}", self.compiler[i], ret);
                return Err(Error::Mod(format!(
                    "unhack {:?} error {}",
                    self.compiler[i], ret
                )));
            }
        }
        Ok(())
    }
}

pub struct CompilerHackGuard {
    compiler: Compiler,
}

impl CompilerHackGuard {
    pub fn new(compiler: Compiler) -> Result<Self> {
        compiler.hack()?;
        Ok(CompilerHackGuard { compiler })
    }
}
impl Drop for CompilerHackGuard {
    fn drop(&mut self) {
        if let Err(e) = self.compiler.unhack() {
            trace!("{}", e);
        }
    }
}

impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}