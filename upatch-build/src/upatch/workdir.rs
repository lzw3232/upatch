use std::fs::{self, File};
use std::path::{Path, PathBuf};

use super::Result;
use crate::tool::*;

pub struct WorkDir {
    cache_dir: PathBuf,
    source_dir: PathBuf,
    patch_dir: PathBuf,
    debuginfo_dir: PathBuf,
    hijacker_dir: PathBuf,
    output_dir: PathBuf,
    log_file: PathBuf,
}

impl WorkDir {
    pub fn new() -> Self {
        Self {
            cache_dir: PathBuf::new(),
            source_dir: PathBuf::new(),
            patch_dir: PathBuf::new(),
            debuginfo_dir: PathBuf::new(),
            hijacker_dir: PathBuf::new(),
            output_dir: PathBuf::new(),
            log_file: PathBuf::new(),
        }
    }

    pub fn create_dir<P: AsRef<Path>>(&mut self, work_dir: P) -> Result<()> {
        self.cache_dir = work_dir.as_ref().to_path_buf();
        self.source_dir = self.cache_dir.join("source");
        self.patch_dir = self.cache_dir.join("patch");
        self.debuginfo_dir = self.cache_dir.join("debug_info");
        self.hijacker_dir = self.cache_dir.join("hijacker");
        self.output_dir = self.cache_dir.join("output");
        self.log_file = self.cache_dir.join("build.log");

        if let Ok(()) = self::check_dir(&self.cache_dir) {
            fs::remove_dir_all(&self.cache_dir)?;
        }

        fs::create_dir_all(&self.cache_dir)?;
        fs::create_dir(&self.source_dir)?;
        fs::create_dir(&self.patch_dir)?;
        fs::create_dir(&self.debuginfo_dir)?;
        fs::create_dir(&self.hijacker_dir)?;
        fs::create_dir(&self.output_dir)?;
        File::create(&self.log_file)?;
        Ok(())
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    pub fn source_dir(&self) -> &Path {
        &self.source_dir
    }

    pub fn patch_dir(&self) -> &Path {
        &self.patch_dir
    }

    pub fn debuginfo_dir(&self) -> &Path {
        &self.debuginfo_dir
    }

    pub fn hijacker_dir(&self) -> &Path {
        &self.hijacker_dir
    }

    pub fn output_dir(&self) -> &Path {
        &self.output_dir
    }

    pub fn log_file(&self) -> &Path {
        &self.log_file
    }
}

impl Default for WorkDir {
    fn default() -> Self {
        Self::new()
    }
}
