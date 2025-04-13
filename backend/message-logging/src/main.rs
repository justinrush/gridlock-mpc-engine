use anyhow::{ anyhow, Context, Result };
use chrono::{ DateTime, Datelike, Utc };

use log::{ error, info, LevelFilter };
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{ Appender, Root };
use log4rs::Config;
use nats::Message;
use std::sync::atomic::{ AtomicBool, Ordering };
use std::sync::Arc;
use std::time::Duration;
use std::{ fmt, fs, fs::{ File, OpenOptions }, io::Write, path::PathBuf };

use s3::{ bucket::Bucket, creds::Credentials };

const LOG_DIRECTORY: &str = "/var/log/gridlock";
const NATS_ROLE: &str = "node";
const NATS_PASS: &str = "68da8b26e61039cff90bb9ca5bc78a239b049bb9c4e5cc79147364f3653f8f";
const NATS_ADDRESS: &str = "nats://stagingnats.gridlock.network:4222";

fn main() -> Result<()> {
    init_logger()?;
    run_nats_logging()?;
    Ok(())
}

fn subscribe_to_all_messages(address: &str) -> Result<(nats::Connection, nats::Subscription)> {
    let conn = nats::Options::with_user_pass(NATS_ROLE, NATS_PASS).connect(address)?;
    let sub = conn.subscribe(">")?;
    info!("Successfully subscribed to \">\" on \"{}\"", address);
    Ok((conn, sub))
}

fn run_nats_logging() -> Result<()> {
    let mut storage = LogStorage::new()?;
    storage.try_upload_old_logs();

    let (_nc, sub_nats) = subscribe_to_all_messages(NATS_ADDRESS).map_err(|err| {
        anyhow!("Failed to connect to NATS server at {}: {}", NATS_ADDRESS, err)
    })?;

    let has_terminate = Arc::new(AtomicBool::new(false));
    signal_hook::flag
        ::register(signal_hook::SIGTERM, Arc::clone(&has_terminate))
        .expect("SIGTERM Signal hook registered");

    while !has_terminate.load(Ordering::Relaxed) {
        if let Ok(message) = sub_nats.next_timeout(Duration::from_millis(500)) {
            storage.process_nats_msg(message)?;
        }
    }
    Ok(())
}

fn init_logger() -> Result<()> {
    let stdout = ConsoleAppender::builder().build();
    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LevelFilter::Info))?;
    log4rs::init_config(config)?;
    Ok(())
}

struct LogStorage {
    bucket: Option<Bucket>,
    start_date: DateTime<Utc>,
    log_path: PathBuf,
    log_file: File,
}

impl LogStorage {
    fn new() -> Result<Self> {
        let bucket = match setup_bucket() {
            Ok(bucket) => Some(bucket),
            Err(err) => {
                error!("Failed to setup blob storage bucket - {err}");
                None
            }
        };
        let start_date = Utc::now();
        let mut log_path = format_log_file_path(&start_date);
        let mut log_file = open_existing_file_or_create(&log_path)?;
        Ok(LogStorage {
            bucket,
            start_date,
            log_path,
            log_file,
        })
    }

    pub fn try_upload_old_logs(&self) {
        let bucket = match &self.bucket {
            None => {
                error!("Unable upload logs. Blob storage is not set");
                return;
            }
            Some(bucket) => bucket,
        };

        let dir = match fs::read_dir(LOG_DIRECTORY) {
            Ok(value) => value,
            Err(err) => {
                error!("Failed to open directory \"{}\": {}", LOG_DIRECTORY, err);
                return;
            }
        };

        for (path, name) in dir
            .filter_map(|e| e.ok())
            .filter(|e| &e.path() != &self.log_path)
            .filter(dir_entry_is_regular_file)
            .filter_map(|e| {
                // Only process files which names are valid UTF-8 and start with "nats-"
                if let Some(name) = e.file_name().to_str() {
                    if name.starts_with("nats-") {
                        return Some((e.path(), String::from(name)));
                    }
                }
                None
            }) {
            match bucket.put_object_stream_blocking(path.clone(), name.clone()) {
                Ok(_) => {
                    info!("Successfully uploaded log file \"{}\"", name);

                    // Rename the file after upload so we don't upload it again
                    let mut new_path = path.clone();
                    new_path.set_file_name(format!("backup-{}", name));
                    let _ = fs::rename(path, &new_path);
                }
                Err(err) => {
                    error!("Failed to upload log file \"{}\" to S3: {}", name, err);
                }
            }
        }
    }

    pub fn process_nats_msg(&mut self, message: Message) -> Result<()> {
        let now: DateTime<Utc> = Utc::now();

        // If month has changed, close current log file, open new file and trigger upload
        if self.start_date.month() != now.month() {
            let _ = self.log_file.flush();

            self.start_date = now;
            self.log_path = format_log_file_path(&self.start_date);
            self.log_file = open_existing_file_or_create(&self.log_path)?;

            self.try_upload_old_logs();
        }

        let message_log = MessageLog { message, time: now };
        let _ = self.log_file.write(message_log.to_string().as_ref())?;
        Ok(())
    }
}

struct MessageLog {
    message: nats::Message,
    time: DateTime<Utc>,
}

impl fmt::Display for MessageLog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message_body = match std::str::from_utf8(&self.message.data) {
            Ok(str) => str.to_string(),
            Err(_) => format!("(binary, {} bytes)", self.message.data.len()),
        };

        let message_headers = match &self.message.headers {
            Some(headers) =>
                headers
                    .iter()
                    .map(|(key, value)| format!("  - {} = {:?}\n", key, value))
                    .fold(String::from(""), |acc, el| acc + &el),
            None => String::new(),
        };
        write!(
            f,
            "[{}] {}\n{}  > {}\n",
            // Print the datetime in ISO8601 format (YYYY-MM-DD\THH:MM:SS)
            self.time.format("%Y-%m-%dT%H:%M:%S"),
            self.message.subject,
            message_headers,
            message_body
        )
    }
}

fn setup_bucket() -> Result<Bucket> {
    let bucket_name = "gridlocklogs";
    let region = "eu-west-2".parse().unwrap();
    let credentials = Credentials::from_env()?;
    Bucket::new(bucket_name, region, credentials).map_err(anyhow::Error::msg)
}

fn format_log_file_path(date: &DateTime<Utc>) -> PathBuf {
    PathBuf::from(format!("{}/nats-{}", LOG_DIRECTORY, date.format("%Y-%m")))
}

fn open_existing_file_or_create(path: &PathBuf) -> Result<File> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("Could not retrieve enclosing directory of provided path"))?;
    fs::create_dir_all(parent).map_err(|err| anyhow!("Could not create directory, errror: {err}"))?;

    let file = OpenOptions::new().append(true).create(true).read(true).open(path)?;

    Ok(file)
}

fn dir_entry_is_regular_file(entry: &fs::DirEntry) -> bool {
    match entry.file_type() {
        Ok(ft) => ft.is_file(),
        Err(err) => {
            error!(
                "Unable to determine filetype of \"{}\": {}",
                entry.path().to_string_lossy(),
                err
            );
            false
        }
    }
}
