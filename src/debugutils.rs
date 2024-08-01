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


/// A struct to hold performance debugging information
pub struct PerformanceDebug
{
    start_time: Instant,
    checkpoints: Vec<(String, Duration)>,
}

impl PerformanceDebug
{
    /// Creates a new PerformanceDebug instance.
    ///
    /// # Returns
    ///
    /// Returns a new PerformanceDebug struct with the current time as the start time.
    pub fn new() -> Self
    {
        PerformanceDebug {
            start_time: Instant::now(),
            checkpoints: Vec::new(),
        }
    }


    /// Adds a new checkpoint with the given name and the elapsed time since the start.
    ///
    /// # Arguments
    ///
    /// * `name` - A string slice that holds the name of the checkpoint.
    pub fn checkpoint(&mut self, name: &str)
    {
        let elapsed = self.start_time.elapsed();
        self.checkpoints.push((name.to_string(), elapsed));
    }


    /// Prints a summary of all checkpoints and their durations.
    ///
    /// # Usage
    ///
    /// This method is only active in debug builds.
    pub fn print_summary(&self)
    {
        #[cfg(debug_assertions)]
        {
            println!("Performance Summary:");
            for (i, (name, duration)) in self.checkpoints.iter().enumerate() {
                if i == 0 {
                    println!("  {} - {:?}", name, duration);
                } else {
                    let prev_duration = self.checkpoints[i-1].1;
                    let diff = duration.saturating_sub(prev_duration);
                    println!("  {} - {:?} (+ {:?})", name, duration, diff);
                }
            }
        }
    }
}


/// Prints the size of a given vector or slice.
///
/// # Usage
///
/// This macro is only active in debug builds.
#[macro_export]
macro_rules! debug_size {
    ($container:expr) => {
        #[cfg(debug_assertions)]
        {
            println!("Size of {} at {}:{}: {} bytes, {} elements",
                stringify!($container),
                file!(),
                line!(),
                std::mem::size_of_val($container),
                $container.len()
            );
        }
    };
}
