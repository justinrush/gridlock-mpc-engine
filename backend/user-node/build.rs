use std::{ process::Command, str::from_utf8 as str_from_utf8 };

fn command_to_env_var(cmd: &str, args: &[&str], varname: &str) {
    let result = &Command::new(cmd).args(args).output().unwrap();

    let stdout = str_from_utf8(&result.stdout).unwrap();

    println!("cargo:rustc-env={}={}", varname, stdout);
}

fn main() {
    command_to_env_var("git", &["rev-parse", "HEAD"], "GRIDLOCK_NODE_COMMIT_HASH");
    command_to_env_var(
        "git",
        &["show", "--no-patch", "--format=%cd", "--date=format:%Y-%m-%dT%H:%M:%S%z", "HEAD"],
        "GRIDLOCK_NODE_COMMIT_DATE"
    );
}
