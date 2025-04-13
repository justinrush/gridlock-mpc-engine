use node::command::{ handle_json_message, MsgContext };
use node::config::*;

use anyhow::Result;
use libc::{ c_char, c_int, c_void, size_t };
use node::node::NodeIdentity;
use std::{ error::Error, ffi::CStr, fmt::Debug };
use tracing::{ error, info };

fn fill_buffer(value: &str, buffer: *mut c_char, bufsize: size_t) {
    // Check if there's enough space in the buffer to fit the whole response.
    // If there's not, truncate the response.
    //
    // TODO: Instead of truncating the response, switch to returning an error.
    // To be correct, when returning a "buffer to small" response, the code
    // still needs to check whether that error message will fit into the buffer.
    // If it does not, then just give up and truncate the error message.
    let copy_size = match value.len() < bufsize {
        true => value.len(),
        false => (bufsize - 1) as usize,
    };

    unsafe {
        libc::memcpy(buffer as *mut c_void, value.as_ptr() as *const c_void, copy_size as size_t);

        // Rust's strings are not nul-terminated, so we need to manually add one.
        let slice = std::slice::from_raw_parts_mut(buffer, bufsize);
        slice[copy_size] = 0;
    }
}

fn rust_error_to_c_buffer<E>(error: E, buffer: *mut c_char, bufsize: size_t) -> c_int where E: Error {
    fill_buffer(&error.to_string(), buffer, bufsize);
    return 1;
}

fn rust_result_to_c_buffer<T>(result: Result<T>, buffer: *mut c_char, bufsize: size_t) -> c_int
    where T: Debug
{
    let (ok, value) = match result {
        Ok(value) => (0, format!("{:?}", value)),
        Err(e) => (1, format!("{}", e)),
    };

    fill_buffer(&value, buffer, bufsize);
    return ok;
}

#[no_mangle]
pub extern "system" fn RustGuardian_getNodeId(buffer: *mut c_char, bufsize: size_t) -> c_int {
    LogInitiator::init();
    let result = NodeIdentity::load().map(|n| n.node_id);
    rust_result_to_c_buffer(result, buffer, bufsize)
}

fn set_nats_address(deeplink_id: *const c_char) -> Result<&'static str> {
    let deeplink_id = rust_string_from_c(deeplink_id)?;
    mobile_set_nats_address(deeplink_id)?;
    Ok("")
}

#[no_mangle]
pub extern "system" fn RustGuardian_getBuildInfo(buffer: *mut c_char, bufsize: size_t) -> c_int {
    LogInitiator::init();
    let result = Ok(
        format!("{}\t{}", crate::build_info::COMMIT_HASH, crate::build_info::COMMIT_DATE)
    );
    rust_result_to_c_buffer(result, buffer, bufsize)
}

#[no_mangle]
pub extern "system" fn RustGuardian_setNatsAddress(
    buffer: *mut c_char,
    bufsize: size_t,
    address: *const c_char
) -> c_int {
    LogInitiator::init();
    let result = set_nats_address(address);
    rust_result_to_c_buffer(result, buffer, bufsize)
}

#[no_mangle]
pub extern "system" fn RustGuardian_getNatsAddress(buffer: *mut c_char, bufsize: size_t) -> c_int {
    LogInitiator::init();
    let result = Ok(Config::get_nats_address());
    rust_result_to_c_buffer(result, buffer, bufsize)
}

#[no_mangle]
pub extern "system" fn RustGuardian_getPublicKey(buffer: *mut c_char, bufsize: size_t) -> c_int {
    LogInitiator::init();
    let result = NodeIdentity::load().map(|n| n.public_key);
    rust_result_to_c_buffer(result, buffer, bufsize)
}

#[no_mangle]
pub extern "system" fn RustGuardian_init(
    buffer: *mut c_char,
    bufsize: size_t,
    storage_path: *const c_char
) -> c_int {
    unsafe {
        match CStr::from_ptr(storage_path).to_str() {
            Ok(str) => mobile_set_storage_path(str),
            Err(e) => {
                return rust_error_to_c_buffer(e, buffer, bufsize);
            }
        };
    }
    LogInitiator::init();

    // Ensure that the application data directory exists.
    if let Err(e) = Config::create_data_dirs() {
        return rust_error_to_c_buffer(e, buffer, bufsize);
    }
    rust_result_to_c_buffer(Ok(""), buffer, bufsize);
    return 0;
}

#[no_mangle]
pub extern "system" fn RustGuardian_start(buffer: *mut c_char, bufsize: size_t) -> c_int {
    rust_result_to_c_buffer(
        node::start().map(|_| ""),
        buffer,
        bufsize
    )
}

fn connect(action: *const c_char) -> Result<&'static str> {
    let action = rust_string_from_c(action)?;
    info!("Connect called (ios) with action string {:?}", &action);
    match crate::connect_and_listen(&action) {
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

#[no_mangle]
pub extern "system" fn RustGuardian_connect(
    buffer: *mut c_char,
    bufsize: size_t,
    address: *const c_char
) -> c_int {
    LogInitiator::init();
    let result = connect(address);
    rust_result_to_c_buffer(result, buffer, bufsize)
}

fn rust_string_from_c<'a>(p: *const c_char) -> Result<&'a str> {
    let cstr = unsafe { CStr::from_ptr(p) };
    let s = cstr.to_str()?;
    Ok(s)
}

#[no_mangle]
pub extern "system" fn RustGuardian_message(
    message_bytes: *const c_char,
    response_bytes: *mut c_char,
    response_length: size_t
) -> c_int {
    LogInitiator::init();
    let cstr = unsafe { CStr::from_ptr(message_bytes) };
    let request = match cstr.to_str() {
        Ok(s) => s,
        Err(err) => {
            error!("Could not convert ffi message to string: {}", err);
            return 1;
        }
    };
    let mut ret_code = 0;
    let response = handle_json_message(&request, MsgContext::FFI).unwrap_or_else(|err| {
        ret_code = 1;
        err.to_string()
    });

    fill_buffer(&response, response_bytes, response_length);
    ret_code
}
