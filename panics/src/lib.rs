use core::any::Any;

use anyhow::Error;
use logging::error_with_peers;

pub fn log(payload: Box<dyn Any + Send + 'static>) {
    let thread = std::thread::current();
    // Use the same default as the standard library and various third-party crates.
    let name = thread.name().unwrap_or("<unnamed>");
    let error = payload_into_error(payload);
    error_with_peers!("thread {name} panicked: {error}");
}

#[must_use]
pub fn payload_into_error(payload: Box<dyn Any + Send + 'static>) -> Error {
    let payload = match payload.downcast::<String>() {
        Ok(string) => return Error::msg(*string),
        Err(other) => other,
    };

    if let Ok(string) = payload.downcast::<&str>() {
        return Error::msg(*string);
    }

    Error::msg("panic with payload of unknown type")
}
