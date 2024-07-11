// src/mathutils.rs

// This module contains utility functions based around math operations.












/// A macro to calculate a specific percentage of a numeric value.
///
/// # Arguments
///
/// * `$value` - The numeric value.
/// * `$percentage` - The percentage to calculate.
///
/// # Returns
///
/// The result of calculating the specified percentage of the input value.
macro_rules! percentage_of {
    ($value:expr, $percentage:expr) => {
        ($value as f64 * ($percentage as f64 / 100.0)) as $value
    };
}