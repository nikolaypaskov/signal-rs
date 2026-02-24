use std::fmt::Display;

/// Print a single value as plain text using its Display implementation.
#[allow(dead_code)]
pub fn print<T: Display>(value: &T) {
    println!("{value}");
}

/// Print a list of values as plain text, one per line.
pub fn print_list<T: Display>(values: &[T]) {
    if values.is_empty() {
        println!("(no results)");
        return;
    }
    for value in values {
        println!("{value}");
    }
}
