//! debug_utils.rs

/// Logs debug information including the error code, file, and line number to a log file.
/// The log file is created if it doesn't exist, or appended to if it does exist.
#[macro_export]
macro_rules! debug_log {
    ($error_code:expr) => {
        #[cfg(debug_assertions)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;

            let log_file = OpenOptions::new().create(true).append(true).open("log.txt");

            match log_file {
                Ok(mut file) => {
                    let log_entry = format!("Error {}: at {}:{}\n",$error_code, file!(), line!());

                    if let Err(e) = file.write_all(log_entry.as_bytes()) {
                        eprintln!("Failed to write to log file: {}", e);
                    }
                },
                Err(e) => {
                    eprintln!("Failed to open log file: {}", e);
                }
            }
        }
    };
}