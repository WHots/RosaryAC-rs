//! debug_utils.rs

// This module contains utilities functions to help debug self.





use std::time::{Instant, Duration};



/// Logs debug information including the error code, file, and line number.
#[macro_export]
macro_rules! debug_log {
    ($error_code:expr) => {
        #[cfg(debug_assertions)]
        {
            println!("Error {}: at {}:{}", $error_code, file!(), line!());
        }
    };
}
