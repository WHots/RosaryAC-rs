/// Logs debug information including the error code, file, line number, and system date/time to a log file.
/// The log file is created if it doesn't exist, or appended to if it does exist.
#[macro_export]
macro_rules! debug_log {
    ($error_code:expr) => {
        #[cfg(debug_assertions)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::time::{SystemTime, UNIX_EPOCH};

            let log_file = OpenOptions::new().create(true).append(true).open("log.txt");

            match log_file {
                Ok(mut file) => {

                    let system_time = SystemTime::now();
                    let datetime = match system_time.duration_since(UNIX_EPOCH) {
                        Ok(duration) => {
                            let secs = duration.as_secs();
                            let nanos = duration.subsec_nanos();
                            format!("{}.{}", secs, nanos)
                        }
                        Err(_) => "SystemTimeError".to_string(),
                    };

                    let log_entry = format!(
                        "[{}] Error {}: at {}:{}\n",
                        datetime,
                        $error_code,
                        file!(),
                        line!()
                    );

                    if let Err(e) = file.write_all(log_entry.as_bytes())

                    {
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
