use crate::config::ConfigProvider;

use std::path::PathBuf;

type IoResult = std::io::Result<()>;

static mut STORAGE_PATH: Option<PathBuf> = None;

pub unsafe fn set_storage_path(path: &str) {
    STORAGE_PATH = Some(PathBuf::from(path));
}

pub fn set_nats_address(address: &str) -> IoResult {
    let mut path = unsafe { STORAGE_PATH.clone().unwrap() };
    path.push("nats_address");

    if !address.is_empty() {
        std::fs::write(path, address)
    } else {
        std::fs::remove_file(path)
    }
}

pub struct ConfigMobile {}

impl ConfigProvider for ConfigMobile {
    fn create_data_dirs() -> IoResult {
        let path = unsafe { STORAGE_PATH.clone().unwrap() };
        std::fs::create_dir_all(path)
    }

    fn get_nats_address() -> String {
        let mut path = unsafe { STORAGE_PATH.clone().unwrap() };
        path.push("nats_address");

        match std::fs::read(path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(_) => String::from("nats://app.gridlock.network:4222"),
        }
    }

    fn get_key_storage_path(key_id: &str, index: usize) -> PathBuf {
        let mut path = unsafe { STORAGE_PATH.clone().unwrap() };
        let path_append = if index > 0 {
            format!("--{}", &index.to_string())
        } else {
            String::from("")
        };
        path.push(format!("keys--{}{}.json", key_id, path_append));
        path
    }

    fn get_key_info_storage_path(key_id: &str) -> PathBuf {
        let mut path = unsafe { STORAGE_PATH.clone().unwrap() };
        path.push(format!("info--{}.json", key_id));
        path
    }

    fn get_gridlock_directory() -> PathBuf {
        let path = unsafe { STORAGE_PATH.clone().unwrap() };
        path
    }
}
