use cfg_if::cfg_if;
use std::path::PathBuf;

pub trait ConfigProvider {
    fn create_data_dirs() -> std::io::Result<()>;
    fn get_nats_address() -> String;
    fn get_key_storage_path(key_id: &str, index: usize) -> PathBuf;
    fn get_key_info_storage_path(key_id: &str) -> PathBuf;
    fn get_gridlock_directory() -> PathBuf;
}

cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "ios"))] {
        mod mobile;
        pub type Config = crate::config::mobile::ConfigMobile;
        pub type LogInitiator = crate::logging::MobileLogInitializer;
        pub use crate::config::mobile::set_storage_path as mobile_set_storage_path;
        pub use crate::config::mobile::set_nats_address as mobile_set_nats_address;
    } else {
        mod gridlock;
        pub type Config = crate::config::gridlock::ConfigGridlock;
        pub type LogInitiator = crate::logging::GridlockLogInitializer;
    }
}
