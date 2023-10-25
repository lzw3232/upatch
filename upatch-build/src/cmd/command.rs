use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::{BufReader, Read};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread::JoinHandle;

use log::*;

use super::RawLines;

#[derive(Clone)]
pub struct ExternCommandArgs {
    args: Vec<OsString>,
}

impl ExternCommandArgs {
    pub fn new() -> Self {
        Self { args: Vec::new() }
    }

    pub fn arg<S>(mut self, arg: S) -> Self
    where
        S: AsRef<OsStr>,
    {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for arg in args {
            self.args.push(arg.as_ref().to_os_string())
        }

        self
    }
}

impl IntoIterator for ExternCommandArgs {
    type Item = OsString;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.args.into_iter()
    }
}

impl Default for ExternCommandArgs {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ExternCommandEnvs {
    envs: HashMap<OsString, OsString>,
}

impl ExternCommandEnvs {
    pub fn new() -> Self {
        Self {
            envs: HashMap::new(),
        }
    }

    pub fn env<K, V>(mut self, k: K, v: V) -> Self
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.envs
            .insert(k.as_ref().to_os_string(), v.as_ref().to_os_string());
        self
    }
}

impl Default for ExternCommandEnvs {
    fn default() -> Self {
        Self::new()
    }
}

impl IntoIterator for ExternCommandEnvs {
    type Item = (OsString, OsString);

    type IntoIter = std::collections::hash_map::IntoIter<OsString, OsString>;

    fn into_iter(self) -> Self::IntoIter {
        self.envs.into_iter()
    }
}

#[derive(Debug)]
pub struct ExternCommandExitStatus {
    exit_status: ExitStatus,
    stdout: OsString,
    stderr: OsString,
}

impl ExternCommandExitStatus {
    pub fn exit_code(&self) -> String {
        match self.exit_status.code() {
            Some(code) => code.to_string(),
            None => String::from("None"),
        }
    }

    pub fn exit_status(&self) -> ExitStatus {
        self.exit_status
    }

    pub fn stdout(&self) -> &OsStr {
        &self.stdout
    }

    pub fn stderr(&self) -> &OsStr {
        &self.stderr
    }
}

#[derive(Debug, Clone)]
pub struct ExternCommand<'a> {
    path: &'a OsStr,
}

impl ExternCommand<'_> {
    #[inline(always)]
    pub fn execute_command(
        &self,
        command: &mut Command,
        filter: Level,
    ) -> std::io::Result<ExternCommandExitStatus> {
        let mut child_process = match command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child_process) => child_process,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("can't find command: {:?}", self.path),
                    ));
                }
                return Err(e);
            }
        };

        trace!("Executing '{}' ({:?}):", &self, command);
        let stdout_thread = Self::create_stdio_thread(
            child_process.stdout.take().expect("Pipe stdout failed"),
            filter,
        );
        let stderr_thread = Self::create_stdio_thread(
            child_process.stderr.take().expect("Pipe stderr failed"),
            Level::Trace,
        );

        let exit_status = child_process.wait()?;
        let last_stdout = stdout_thread.join().expect("join stdout thread failed")?;
        let last_stderr = stderr_thread.join().expect("join stdout thread failed")?;
        match exit_status.code() {
            Some(code) => trace!("Process ({}) exited, exit_code={}\n", &self, code),
            None => trace!("Process ({}) exited, exit_code = None\n", &self),
        }

        Ok(ExternCommandExitStatus {
            exit_status,
            stdout: last_stdout,
            stderr: last_stderr,
        })
    }

    #[inline(always)]
    fn create_stdio_thread<R>(stdio: R, filter: Level) -> JoinHandle<std::io::Result<OsString>>
    where
        R: Read + Send + Sync + 'static,
    {
        std::thread::spawn(move || -> std::io::Result<OsString> {
            let mut last_line = OsString::new();
            for read_line in RawLines::from(BufReader::new(stdio)) {
                last_line = read_line?;
                log!(filter, "{}", last_line.to_string_lossy());
            }
            Ok(last_line)
        })
    }
}

impl<'a> ExternCommand<'a> {
    pub fn new<S: AsRef<OsStr> + ?Sized>(path: &'a S) -> Self {
        Self {
            path: path.as_ref(),
        }
    }

    pub fn execv(&self, args: ExternCommandArgs) -> std::io::Result<ExternCommandExitStatus> {
        let mut command = Command::new(self.path);
        command.args(args.into_iter());

        self.execute_command(&mut command, Level::Debug)
    }

    pub fn execve_dir_stdio_level<P, T>(
        &self,
        args: ExternCommandArgs,
        current_dir: P,
        stdio: T,
        level: Level,
    ) -> std::io::Result<ExternCommandExitStatus>
    where
        P: AsRef<Path>,
        T: Into<Stdio>,
    {
        let mut command = Command::new(self.path);
        command.args(args.into_iter());
        command.current_dir(current_dir);
        command.stdin(stdio);

        self.execute_command(&mut command, level)
    }

    pub fn execve_dir<P: AsRef<Path>>(
        &self,
        args: ExternCommandArgs,
        envs: ExternCommandEnvs,
        current_dir: P,
    ) -> std::io::Result<ExternCommandExitStatus> {
        let mut command = Command::new(self.path);
        command.args(args.into_iter());
        command.envs(envs.into_iter());
        command.current_dir(current_dir);

        self.execute_command(&mut command, Level::Debug)
    }
}

impl std::fmt::Display for ExternCommand<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self.path))
    }
}
