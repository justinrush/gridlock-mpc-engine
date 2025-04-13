use crate::config::ConfigProvider;
use std::sync::Once;

use std::path::PathBuf;

pub struct ConfigGridlock {}

// const STORAGE_DIR: &str = "./node";
// const api_key: &str = std::env::var("STORAGE_DIR").unwrap().as_str();

static mut STORAGE_DIR: Option<&str> = None;
static INIT: Once = Once::new();

fn get_storage_dir() -> &'static str {
    unsafe {
        INIT.call_once(|| {
            // Retrieve the environment variable
            let value = std::env::var("STORAGE_DIR").unwrap_or_else(|_| "./node2".to_string());
            // Leak the String to get a &'static str
            STORAGE_DIR = Some(Box::leak(value.into_boxed_str()));
        });
        STORAGE_DIR.unwrap()
    }
}

impl ConfigProvider for ConfigGridlock {
    fn create_data_dirs() -> std::io::Result<()> {
        std::fs::create_dir_all(get_storage_dir())
    }

    fn get_nats_address() -> String {
        let env_override = std::env::var("NATS_ADDRESS");
        if env_override.is_ok() {
            let env_override = env_override.unwrap();
            if !env_override.is_empty() {
                return env_override;
            }
        }

        String::from("nats://stagingnats.gridlock.network:4222")
    }

    fn get_key_storage_path(key_id: &str, index: usize) -> PathBuf {
        let path_append = if index > 0 {
            format!("--{}", &index.to_string())
        } else {
            String::from("")
        };
        PathBuf::from(format!("{}/keys--{}{}.json", get_storage_dir(), key_id, path_append))
    }

    fn get_key_info_storage_path(key_id: &str) -> PathBuf {
        PathBuf::from(format!("{}/info--{}.json", get_storage_dir(), key_id))
    }

    fn get_gridlock_directory() -> PathBuf {
        PathBuf::from(format!("{}", get_storage_dir()))
    }
}
