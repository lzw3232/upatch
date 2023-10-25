use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use log::{log, Level};

use crate::cmd::*;

use super::Error;
use super::Result;

const COMPILER_CMD_ENV: &str = "UPATCH_HIJACKER";
const BUILD_SHELL: &str = "build.sh";

pub struct Project {
    project_dir: PathBuf,
}

impl Project {
    pub fn new<P: AsRef<Path>>(project_dir: P) -> Self {
        Self {
            project_dir: project_dir.as_ref().to_path_buf(),
        }
    }

    pub fn build<P: AsRef<Path>>(&self, assembler_output: P, build_command: String) -> Result<()> {
        let assembler_output = assembler_output.as_ref();
        let command_shell_path = assembler_output.join(BUILD_SHELL);
        let mut command_shell = File::create(&command_shell_path)?;
        command_shell.write_all(b"#!/bin/bash\n")?;
        command_shell.write_all(build_command.as_ref())?;
        let args_list = ExternCommandArgs::new().arg(command_shell_path);
        let envs_list = ExternCommandEnvs::new().env(COMPILER_CMD_ENV, assembler_output);
        let output =
            ExternCommand::new("sh").execve_dir(args_list, envs_list, &self.project_dir)?;
        if !output.exit_status().success() {
            return Err(Error::Project(format!(
                "build project error {}: {}",
                output.exit_code(),
                output.stderr().to_string_lossy()
            )));
        };
        Ok(())
    }

    pub fn patch_all<P: AsRef<Path>>(&self, patches: &Vec<P>, level: Level) -> Result<()> {
        for patch in patches {
            log!(level, "Patching file: {:?}", patch.as_ref());
            let file = match File::open(patch) {
                Ok(file) => file,
                Err(e) => {
                    return Err(Error::Project(format!(
                        "open {:?} error: {}",
                        patch.as_ref(),
                        e
                    )))
                }
            };
            let args_list = ExternCommandArgs::new().args(["-N", "-p1"]);
            if let Err(e) = self.patch(file, args_list, level) {
                return Err(Error::Project(format!(
                    "patch file {:?} {}",
                    patch.as_ref(),
                    e
                )));
            }
        }
        Ok(())
    }

    pub fn unpatch_all<P: AsRef<Path>>(&self, patches: &[P], level: Level) -> Result<()> {
        for patch in patches.iter().rev() {
            log!(level, "Patching file: {:?}", patch.as_ref());
            let file = match File::open(patch) {
                Ok(file) => file,
                Err(e) => {
                    return Err(Error::Project(format!(
                        "open {:?} error: {}",
                        patch.as_ref(),
                        e
                    )))
                }
            };
            let args_list = ExternCommandArgs::new().args(["-N", "-p1", "-R"]);
            if let Err(e) = self.patch(file, args_list, level) {
                return Err(Error::Project(format!(
                    "unpatch file {:?} {}",
                    patch.as_ref(),
                    e
                )));
            }
        }
        Ok(())
    }
}

impl Project {
    fn patch(&self, file: File, args_list: ExternCommandArgs, level: Level) -> Result<()> {
        let output = ExternCommand::new("patch").execve_dir_stdio_level(
            args_list,
            &self.project_dir,
            file,
            level,
        )?;
        if !output.exit_status().success() {
            return Err(Error::Project(format!(
                "error {}: {}",
                output.exit_code(),
                output.stderr().to_string_lossy()
            )));
        };
        Ok(())
    }
}
