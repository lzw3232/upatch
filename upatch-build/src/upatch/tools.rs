use std::path::{Path, PathBuf};

use crate::cmd::*;
use crate::tool::*;

use super::Error;
use super::Result;

const SUPPORT_DIFF: &str = "upatch-diff";
pub struct Tool {
    diff: PathBuf,
}

impl Tool {
    pub fn new() -> Self {
        Self {
            diff: PathBuf::new(),
        }
    }

    pub fn check(&mut self) -> std::io::Result<()> {
        self.diff = search_tool(SUPPORT_DIFF)?;
        Ok(())
    }

    pub fn upatch_diff<P, Q, O, D, L>(
        &self,
        source: P,
        patch: Q,
        output: O,
        debug_info: D,
        log_file: L,
        verbose: bool,
    ) -> Result<()>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
        O: AsRef<Path>,
        D: AsRef<Path>,
        L: AsRef<Path>,
    {
        let mut args_list = ExternCommandArgs::new()
            .arg("-s")
            .arg(source.as_ref())
            .arg("-p")
            .arg(patch.as_ref())
            .arg("-o")
            .arg(output.as_ref())
            .arg("-r")
            .arg(debug_info.as_ref());
        if verbose {
            args_list = args_list.arg("-d");
        }
        let output = ExternCommand::new(&self.diff).execv(args_list)?;
        if !output.exit_status().success() {
            return Err(Error::Diff(format!(
                "{}: please look {:?} for detail.",
                output.exit_code(),
                log_file.as_ref()
            )));
        };
        Ok(())
    }
}

impl Default for Tool {
    fn default() -> Self {
        Self::new()
    }
}
