use crate::common::config::Config;
use anyhow::Context;
use nats::asynk::Connection;
use std::path::Path;
use std::{ env, fs };
/// Retrieve name of current function
#[macro_export]
macro_rules! function {
    () => {
        {
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        type_name_of(f)
            .rsplit("::")
            .find(|&part| part != "f" && part != "{{closure}}")
            .expect("Short function name")
        }
    };
}

pub async fn get_nats_connection(config: &Config) -> anyhow::Result<Connection> {
    nats::asynk::Options
        ::with_user_pass("admin", "2711b50ccffcd2d0db7319f7fca22f8cc5b0a238110ee59b7b763fa0f46d53")
        .connect(&config.address).await
        .context("Failed connect to NATs")
}

pub enum FileKind {
    Key,
    Info,
}

pub fn delete_file(kind: FileKind, node_index: usize, key_id: &str) -> anyhow::Result<()> {
    let file_prefix = match kind {
        FileKind::Key => "keys",
        FileKind::Info => "info",
    };
    let key_file_path = format!("nodes/{0}/{1}--{2}.json", node_index, file_prefix, key_id);
    match env::var("DATA_DIR") {
        Ok(data_dir) => {
            fs::remove_file(Path::new(&data_dir).join(key_file_path))?;
        }
        Err(_) =>
            fs::remove_file(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("data").join(key_file_path)
            )?,
    }
    Ok(())
}

pub fn is_file_exist(kind: FileKind, node_index: usize, key_id: &str) -> bool {
    let file_prefix = match kind {
        FileKind::Key => "keys",
        FileKind::Info => "info",
    };
    let key_file_path = format!("nodes/{0}/{1}--{2}.json", node_index, file_prefix, key_id);
    match env::var("DATA_DIR") {
        Ok(data_dir) => Path::new(&data_dir).join(key_file_path).exists(),
        Err(_) => Path::new(env!("CARGO_MANIFEST_DIR")).join("data").join(key_file_path).exists(),
    }
}
