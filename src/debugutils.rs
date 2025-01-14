//! src/debugutils.rs

// Logs debug information including the error code, file, line number, and system date/time to a log file.
// The log file is created if it doesn't exist, or appended to if it does exist.





#[macro_export]
macro_rules! debug_log {
   ($error_code:expr) => {
       #[cfg(debug_assertions)]
       {
           use std::fs::OpenOptions;
           use std::io::Write;
           use std::time::SystemTime;

           let log_file = OpenOptions::new().create(true).append(true).open("log.txt");

           match log_file {

               Ok(mut file) => {
                   let time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
                   
                   let secs = time.as_secs();
                   let millis = time.subsec_millis();

                   let year = 1970 + (secs / 31557600); // Seconds per year
                   let remaining_secs = secs % 31557600;
                   let month = remaining_secs / 2629800; // Seconds per month (approx)
                   let day = (remaining_secs % 2629800) / 86400; // Seconds per day
                   let hour = (remaining_secs % 86400) / 3600;
                   let min = (remaining_secs % 3600) / 60;
                   let sec = remaining_secs % 60;

                   let log_entry = format!(
                       "[{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}] Error {}: at {}:{}\n",
                       year, month+1, day+1, hour, min, sec, millis,
                       $error_code,
                       file!(),
                       line!()
                   );

                   if let Err(e) = file.write_all(log_entry.as_bytes()) {
                       eprintln!("Failed to write to log file: {}", e);
                   }
               },
               Err(e) => eprintln!("Failed to open log file: {}", e)
           }
       }
   };
}