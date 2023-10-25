use std::fs::File;
use std::io::{LineWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use super::{Level, LevelFilter, Metadata, Record};

static LOGGER_INIT_FLAG: AtomicBool = AtomicBool::new(false);

pub struct Logger {
    print_level: LevelFilter,
    file_level: LevelFilter,
    file_writer: Option<Mutex<LineWriter<File>>>,
}

impl Logger {
    pub fn init_logger(logger: Self) {
        let max_log_level = logger.max_log_level();
        let static_logger = Box::leak(Box::new(logger));

        log::set_logger(static_logger)
            .map(|_| log::set_max_level(max_log_level))
            .expect("Set logger failed");
        LOGGER_INIT_FLAG.store(true, Ordering::Relaxed);
    }

    pub fn is_inited() -> bool {
        LOGGER_INIT_FLAG.load(Ordering::Relaxed)
    }

    pub fn new() -> Self {
        Self {
            print_level: LevelFilter::Off,
            file_level: LevelFilter::Off,
            file_writer: None,
        }
    }

    pub fn set_print_level(&mut self, log_level: LevelFilter) {
        self.print_level = log_level;
    }

    pub fn set_log_file<P: AsRef<Path>>(
        &mut self,
        log_level: LevelFilter,
        file_path: P,
    ) -> std::io::Result<()> {
        let log_writter = LineWriter::new(
            File::options()
                .create(true)
                .append(true)
                .read(false)
                .write(true)
                .open(file_path)?,
        );
        self.file_level = log_level;
        self.file_writer = Some(Mutex::new(log_writter));

        Ok(())
    }

    fn max_log_level(&self) -> LevelFilter {
        std::cmp::max(self.print_level, self.file_level)
    }

    fn create_log_content(&self, record: &Record) -> String {
        match record.metadata().level() {
            Level::Error | Level::Warn => {
                format!("{}: {}", record.level(), record.args())
            }
            _ => {
                format!("{}", record.args())
            }
        }
    }

    fn enabled_screen(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.print_level || metadata.level() == LevelFilter::Error
    }

    fn enabled_file(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.file_level || metadata.level() == LevelFilter::Error
    }

    fn write_screen(&self, level: Level, log_str: &str) {
        match level {
            Level::Error | Level::Warn => {
                eprintln!("{}", log_str);
            }
            _ => {
                println!("{}", log_str);
            }
        };
    }

    fn write_file(&self, log_str: &str) {
        if let Some(writer_lock) = &self.file_writer {
            let mut writer = writer_lock.lock().expect("Lock posioned");
            writeln!(writer, "{}", log_str).expect("Write log to file failed");
        }
    }

    fn flush_writer(&self) {
        if let Some(writer_lock) = &self.file_writer {
            let mut writer = writer_lock.lock().expect("Lock posioned");
            writer.flush().expect("Flush log writer failed");
        }
    }
}

impl Default for Logger {
    fn default() -> Self {
        Self::new()
    }
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.enabled_screen(metadata) || self.enabled_file(metadata)
    }

    fn log(&self, record: &Record) {
        let metadata = record.metadata();
        if !self.enabled(metadata) {
            return;
        }

        let log_level = metadata.level();
        let log_str = self.create_log_content(record);

        if self.enabled_screen(metadata) {
            self.write_screen(log_level, &log_str);
        }

        if self.enabled_file(metadata) {
            self.write_file(&log_str);
        }
    }

    fn flush(&self) {
        self.flush_writer();
    }
}
