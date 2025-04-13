use crate::config::{ Config as NodeConfig, ConfigProvider };
use anyhow::{ Context, Result };
use std::fs;
use std::fs::OpenOptions;
use std::io::{ BufRead, BufReader, Write };
use std::path::Path;
use tracing::info;
use tracing_log::LogTracer;
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::layer::SubscriberExt;

static mut LOGGING_INITIALIZED: bool = false;

pub struct MobileLogInitializer;

impl MobileLogInitializer {
    pub fn init() {
        if (unsafe { LOGGING_INITIALIZED }) == false {
            Self::configure().expect("Initialize logger");
            info!("Logging initialized");
            unsafe {
                LOGGING_INITIALIZED = true;
            }
        }
    }

    fn configure() -> Result<()> {
        let log_path = NodeConfig::get_gridlock_directory().join("rust_logs.log");
        truncate_log_file(log_path.clone(), 1024 * 1024)?;

        let log_file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(log_path)?
            .with_max_level(tracing::Level::INFO);
        let logfile_sub = fmt::Layer::new().with_writer(log_file).with_ansi(false);

        let collector = tracing_subscriber::registry().with(logfile_sub);
        LogTracer::init().context("Set logger")?;
        tracing::subscriber::set_global_default(collector).context("Set tracing subscriber")
    }
}

pub struct GridlockLogInitializer;

impl GridlockLogInitializer {
    pub fn init() {
        if (unsafe { LOGGING_INITIALIZED }) == false {
            Self::configure().expect("Initialize logger");
            info!("Logging initialized");
            unsafe {
                LOGGING_INITIALIZED = true;
            }
        }
    }

    fn configure() -> Result<()> {
        let log_path = NodeConfig::get_gridlock_directory().join("logs.log");
        truncate_log_file(log_path.clone(), 1024 * 1024)?;

        let output = std::io::stdout.with_max_level(tracing::Level::INFO);
        let stdout_sub = fmt::Layer::new().with_writer(output).with_ansi(true);

        let log_file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(log_path)?
            .with_max_level(tracing::Level::INFO);
        let logfile_sub = fmt::Layer::new().with_writer(log_file).with_ansi(false);

        let collector = tracing_subscriber::registry().with(stdout_sub).with(logfile_sub);
        LogTracer::init().context("Sset logger")?;
        tracing::subscriber::set_global_default(collector).context("Set tracing subscriber")
    }
}

/// Truncate file from beginning if its size is more then max_length.
/// Leaves max_lenght / 2 of its initial size.
/// Returns bool meaning weather file was truncated.
fn truncate_log_file<P: AsRef<Path>>(path: P, max_length: u64) -> Result<bool> {
    let log_path = path.as_ref();
    let file = OpenOptions::new()
        .read(true)
        .create(true)
        .write(true)
        .open(log_path)
        .expect("Open log file");
    let file_name = log_path
        .file_name()
        .context("Get log file name from path")?
        .to_str()
        .context("Get log file name from OsStr")?;
    let current_file_len = file.metadata().context("Get log file metadata")?.len();

    if current_file_len > max_length {
        let tmp_log_path = log_path
            .parent()
            .expect("Parent directory of log file")
            .join(format!("{}.tmp", file_name));
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(tmp_log_path.clone())
            .context("Open/create tmp file to truncate log")?;

        let mut to_remove_len = current_file_len - max_length / 2;
        let lines = BufReader::new(&file)
            .lines()
            .flatten()
            .skip_while(|line| {
                let line_len = (line.len() as u64) + 1; // +1 for newline character
                to_remove_len = to_remove_len.saturating_sub(line_len);
                to_remove_len > 0
            });

        for line in lines {
            writeln!(tmp_file, "{}", line).context("Write line to temp log file")?;
        }

        fs::remove_file(log_path).context("Remove old log file")?;
        fs::rename(tmp_log_path, log_path).context("Rename new log file")?;
        return Ok(true);
    }
    Ok(false)
}
