pub mod json;
pub mod plain;
pub mod table;

use crate::cli::OutputFormat;

/// Format and print a value according to the chosen output format.
#[allow(dead_code)]
pub fn print_output<T: serde::Serialize + tabled::Tabled + std::fmt::Display>(
    format: &OutputFormat,
    value: &T,
) {
    match format {
        OutputFormat::Json => json::print(value),
        OutputFormat::Table => table::print(value),
        OutputFormat::Plain => plain::print(value),
    }
}

/// Format and print a list of values according to the chosen output format.
pub fn print_list<T: serde::Serialize + tabled::Tabled + std::fmt::Display>(
    format: &OutputFormat,
    values: &[T],
) {
    match format {
        OutputFormat::Json => json::print_list(values),
        OutputFormat::Table => table::print_list(values),
        OutputFormat::Plain => plain::print_list(values),
    }
}
