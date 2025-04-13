use anyhow::Result;
use jni::{ objects::{ JClass, JObject, JString, JValue }, JNIEnv };
use node::command::{ handle_json_message, MsgContext };
use node::config::*;
use node::node::NodeIdentity;
use std::error::Error;
use std::fmt::Debug;
use tracing::{ error, info };

// The following code is copy-pasted from the ndk-glue crate.
// See the init() function in the following link:
// https://github.com/rust-windowing/android-ndk-rs/blob/master/ndk-glue/src/lib.rs
//
// License: Apache 2.0
unsafe fn redirect_stdout_stderr() {
    use std::ffi::{ CStr, CString };
    use std::fs::File;
    use std::io::{ BufRead, BufReader };
    use std::os::raw;
    use std::os::unix::prelude::*;
    use std::thread;

    let mut logpipe: [RawFd; 2] = Default::default();
    libc::pipe(logpipe.as_mut_ptr());
    libc::dup2(logpipe[1], libc::STDOUT_FILENO);
    libc::dup2(logpipe[1], libc::STDERR_FILENO);
    thread::spawn(move || {
        let tag = CStr::from_bytes_with_nul(b"GuardianNode\0").unwrap();
        let file = File::from_raw_fd(logpipe[0]);
        let mut reader = BufReader::new(file);
        let mut buffer = String::new();
        let priority = ndk_sys::android_LogPriority_ANDROID_LOG_INFO as raw::c_int;
        loop {
            buffer.clear();
            if let Ok(len) = reader.read_line(&mut buffer) {
                if len == 0 {
                    break;
                } else if let Ok(msg) = CString::new(buffer.clone()) {
                    ndk_sys::__android_log_write(priority, tag.as_ptr(), msg.as_ptr());
                }
            }
        }
    });
}

fn create_java_result<'e>(env: &JNIEnv<'e>, is_ok: bool, value: &str) -> JObject<'e> {
    // We want to construct a Java object from JNI. To do that, we need to do three things:
    // 1. Get the class handle. This is the simpler part, as we call env.find_class().
    //    The class name is just the full name of the class, as it appears in Java,
    //    with one caveat - using the slash ("/") instead of the dot (".") as separator.
    // 2. Get the constructor signature. Since Java allows for method overloading,
    //    a class can have several constructors, so we need to tell JNI which one to call.
    //    To achieve this, we can use the javap tool, like this:
    //      $ javac client/android/app/src/main/java/network/gridlock/App/Result.java
    //      $ javap -s client/android/app/src/main/java/network/gridlock/App/Result.class
    //    The first step compiles the class, the second one extracts the symbols.
    //    From the listing, we need to manually extract the constructor's signature.
    // 3. Create the array holding the arguments to the constructor.
    //    Our Result class takes two arguments:
    //    a) A boolean, specifying whether it's a success (true) or error (false)
    //    b) The success value / error message, which in both cases is a string.
    let class = env.find_class("network/gridlock/App/Result").unwrap();
    let args: [JValue<'e>; 2] = [
        JValue::Bool(u8::from(is_ok)),
        JValue::Object(JObject::from(env.new_string(value).unwrap())),
    ];
    env.new_object(class, "(ZLjava/lang/String;)V", &args).unwrap()
}

fn rust_result_to_java_result<'e, T>(env: &JNIEnv<'e>, result: Result<T>) -> JObject<'e>
    where T: Debug
{
    let (ok, value) = match result {
        Ok(value) => (true, format!("{:#?}", value)),
        Err(e) => (false, format!("{:#?}", e)),
    };

    create_java_result(env, ok, &value)
}

fn rust_error_to_java_result<'e, E>(env: &JNIEnv<'e>, err: E) -> JObject<'e> where E: Error {
    create_java_result(env, false, &format!("{}", err))
}

#[no_mangle]
pub extern "system" fn Java_network_gridlock_App_RustGuardian_start<'a>(
    env: JNIEnv<'a>,
    _class: JClass
) -> JObject<'a> {
    rust_result_to_java_result(
        &env,
        node::start().map(|_| "")
    )
}

#[no_mangle]
pub extern "system" fn Java_network_gridlock_App_RustGuardian_getNodeId<'a>(
    env: JNIEnv<'a>,
    _class: JClass
) -> JObject<'a> {
    let result = NodeIdentity::load().map(|n| n.node_id);
    rust_result_to_java_result(&env, result)
}

fn set_nats_address(env: &JNIEnv, address: JString) -> Result<&'static str> {
    let rust_string = String::from(env.get_string(address)?);
    mobile_set_nats_address(&rust_string)?;
    Ok("")
}

#[no_mangle]
pub extern "system" fn Java_network_gridlock_App_RustGuardian_getBuildInfo<'a>(
    env: JNIEnv<'a>,
    _class: JClass
) -> JObject<'a> {
    LogInitiator::init();
    let result = Ok(
        format!("{}\t{}", crate::build_info::COMMIT_HASH, crate::build_info::COMMIT_DATE)
    );
    rust_result_to_java_result(&env, result)
}

#[no_mangle]
pub extern "system" fn Java_network_gridlock_App_RustGuardian_getPublicKey<'a>(
    env: JNIEnv<'a>,
    _class: JClass
) -> JObject<'a> {
    LogInitiator::init();
    let result = NodeIdentity::load().map(|n| n.public_key);
    rust_result_to_java_result(&env, result)
}

#[no_mangle]
pub extern "system" fn Java_network_gridlock_App_RustGuardian_setNatsAddress<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    address: JString
) -> JObject<'a> {
    LogInitiator::init();
    let result = set_nats_address(&env, address);
    rust_result_to_java_result(&env, result)
}

#[no_mangle]
pub extern "system" fn Java_network_gridlock_App_RustGuardian_getNatsAddress<'a>(
    env: JNIEnv<'a>,
    _class: JClass
) -> JObject<'a> {
    LogInitiator::init();
    let result = Ok(Config::get_nats_address());
    rust_result_to_java_result(&env, result)
}

/// initializes the guardian environment before the node is started
/// Android need to be able get the node id store it in firebase, then wait for a notification before starting the node
#[no_mangle]
pub extern "system" fn Java_network_gridlock_App_RustGuardian_init<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    files_dir: JString
) -> JObject<'a> {
    unsafe {
        redirect_stdout_stderr();
        info!("stdout/stderr redirected, setting up filesDir");
        mobile_set_storage_path(&String::from(env.get_string(files_dir).unwrap()));
    }
    LogInitiator::init();

    // Ensure that the application data directory exists.
    if let Err(e) = Config::create_data_dirs() {
        return rust_error_to_java_result(&env, e);
    }

    let result = Ok("");
    rust_result_to_java_result(&env, result)
}

fn connect(env: &JNIEnv, action: JString) -> Result<&'static str> {
    let rust_string = String::from(env.get_string(action)?);
    info!("Connect called (android) with action string {:?}", rust_string);
    match crate::connect_and_listen(&rust_string) {
        Ok(_) => {
            info!("Connect and listen completed successfully");
            Ok("")
        }
        Err(err) => {
            error!("Connect and listen failed with error {:?}", err);
            Err(err)
        }
    }
}

// connect and listen to nats
#[no_mangle]
pub extern "system" fn Java_network_gridlock_App_RustGuardian_connect<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    action: JString
) -> JObject<'a> {
    LogInitiator::init();
    rust_result_to_java_result(&env, connect(&env, action))
}

#[no_mangle]
pub extern "system" fn Java_network_gridlock_App_RustGuardian_message<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    message: JString
) -> JObject<'a> {
    LogInitiator::init();
    let result = process_message(&env, message);
    rust_result_to_java_result(&env, result)
}

fn process_message(env: &JNIEnv, message: JString) -> Result<String> {
    let request = String::from(env.get_string(message)?);
    let result = handle_json_message(&request, MsgContext::FFI)?;
    Ok(result.to_string())
}
