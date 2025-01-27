//! src/debugutils.rs

// Logs debug information including the error code, file, line number, and system date/time to a log file.
// The log file is created if it doesn't exist, or appended to if it does exist.





#[macro_export]
macro_rules! debug_log
{
   ($error:expr) => {
       #[cfg(debug_assertions)]
       {
           use std::fs::OpenOptions;
           use std::io::Write;
           use std::time::SystemTime;
           use windows_sys::Win32::Foundation::GetLastError;

           if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("debug.log") {
               let time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
               let secs = time.as_secs();
               let millis = time.subsec_millis();

               let year = 1970 + (secs / 31557600);
               let remaining_secs = secs % 31557600;
               let month = remaining_secs / 2629800;
               let day = (remaining_secs % 2629800) / 86400;
               let hour = (remaining_secs % 86400) / 3600;
               let min = (remaining_secs % 3600) / 60;
               let sec = remaining_secs % 60;

               let win_error = unsafe { GetLastError() };
               let log_entry = format!(
                   "[{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}] {} : GetLastError Code = {} : Near {}:{}\n",
                   year, month+1, day+1, hour, min, sec, millis,
                   $error,
                   win_error,
                   file!(),
                   line!()
               );
               let _ = file.write_all(log_entry.as_bytes());
           }
       }
   };
}