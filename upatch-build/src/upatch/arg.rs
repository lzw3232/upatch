use std::ffi::OsString;
use std::path::PathBuf;

use clap::Parser;
use which::which;

use crate::tool::*;

const GCC_NAME: &str = "gcc";

#[derive(Parser, Debug)]
#[clap(bin_name = "upatch-build", version, term_width = 200)]
pub struct Arguments {
    /// Specify work directory
    /// will add upatch in work_dir [default: ~/.upatch]
    #[clap(short, long, verbatim_doc_comment)]
    pub work_dir: Option<PathBuf>,

    /// Specify source directory
    /// will modify the debug_source
    #[clap(short = 's', long, verbatim_doc_comment)]
    pub debug_source: PathBuf,

    /// Specify build source command
    #[clap(short, long)]
    pub build_source_cmd: String,

    /// Specify build patched command [default: <BUILD_SOURCE_COMMAND>]
    #[clap(long, default_value_t = String::new(), hide_default_value = true)]
    pub build_patch_cmd: String,

    /// Specify debug info list
    #[clap(short = 'i', long = "debug-info", required = true)]
    pub debug_infoes: Vec<PathBuf>,

    /// Specify elf's relative path relate to elf-dir or absolute path list.
    /// one-to-one correspondence with debug-info
    #[clap(short, long = "elf-path", required = true, verbatim_doc_comment)]
    pub elf_pathes: Vec<PathBuf>,

    /// Specify the directory of searching elf [default: <DEBUG_SOURCE>]
    #[clap(long, required = false)]
    pub elf_dir: Option<PathBuf>,

    /// Specify compiler [default: gcc]
    #[clap(short, long)]
    pub compiler: Option<Vec<PathBuf>>,

    /// Specify output directory [default: <WORK_DIR>]
    #[clap(short, long)]
    pub output_dir: Option<PathBuf>,

    /// Specify output name
    #[clap(short, long, default_value = "", hide_default_value = true)]
    pub name: OsString,

    /// Skip compiler version check (not recommended)
    #[clap(long)]
    pub skip_compiler_check: bool,

    /// Provide more detailed info
    #[clap(short, long)]
    pub verbose: bool,

    /// Patch file(s)
    #[clap(required = true)]
    pub patches: Vec<PathBuf>,
}

impl Arguments {
    pub fn new() -> Self {
        Arguments::parse()
    }
}

impl Arguments {
    pub fn check(&mut self) -> std::io::Result<()> {
        self.work_dir = Some(match &self.work_dir {
            Some(work_dir) => {
                if !work_dir.is_dir() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("work_dir {} should be a directory", work_dir.display()),
                    ));
                }
                real_arg(work_dir)?.join("upatch")
            }
            #[allow(deprecated)]
            None => match std::env::home_dir() {
                Some(work_dir) => work_dir.join(".upatch"),
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "home_dir don't support BSD system".to_string(),
                    ))
                }
            },
        });

        let mut default_compiler = vec![PathBuf::from(GCC_NAME)];
        let compiler_paths = self
            .compiler
            .as_deref_mut()
            .unwrap_or(&mut default_compiler);
        self.compiler = Some({
            for compiler_path in &mut compiler_paths.iter_mut() {
                *compiler_path = match compiler_path.is_file() {
                    true => compiler_path.to_path_buf(),
                    false => which(&compiler_path).map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            format!("can't find {:?} in system: {}", compiler_path, e),
                        )
                    })?,
                };
            }
            compiler_paths.to_vec()
        });

        if !self.debug_source.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "debug_source {} should be a directory",
                    self.debug_source.display()
                ),
            ));
        }
        self.debug_source = real_arg(&self.debug_source)?;

        for debug_info in &mut self.debug_infoes {
            if !debug_info.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("debug_info {} should be a file", debug_info.display()),
                ));
            }
            *debug_info = real_arg(&debug_info)?;
        }

        for patch in &mut self.patches {
            if !patch.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("patch {} should be a file", patch.display()),
                ));
            }
            *patch = real_arg(&patch)?;
        }

        if self.build_patch_cmd.is_empty() {
            self.build_patch_cmd = self.build_source_cmd.clone();
        }

        if !self.name.is_empty() {
            self.name.push("-");
        }

        self.elf_dir = match &self.elf_dir {
            Some(elf_dir) => Some({
                if !elf_dir.is_dir() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("elf_dir {} should be a directory", elf_dir.display()),
                    ));
                }
                real_arg(elf_dir)?
            }),
            None => Some(self.debug_source.clone()),
        };

        match self.elf_pathes.len().eq(&self.debug_infoes.len()) {
            true => {
                for elf_path in &mut self.elf_pathes {
                    *elf_path = self.elf_dir.as_ref().unwrap().join(&elf_path);
                }
            }
            false => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "{}'s elf-path don't match {}'s debug-info",
                        self.elf_pathes.len(),
                        self.debug_infoes.len()
                    ),
                ))
            }
        }

        if let Some(output_dir) = &self.output_dir {
            if !output_dir.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("output_dir {} should be a directory", output_dir.display()),
                ));
            }
        }

        Ok(())
    }
}

impl Default for Arguments {
    fn default() -> Self {
        Self::new()
    }
}
