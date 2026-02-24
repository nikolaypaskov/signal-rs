use serde::Serialize;

/// Print a single value as pretty-printed JSON.
#[allow(dead_code)]
pub fn print<T: Serialize>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("Error serializing to JSON: {e}"),
    }
}

/// Print a list of values as a pretty-printed JSON array.
pub fn print_list<T: Serialize>(values: &[T]) {
    match serde_json::to_string_pretty(values) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("Error serializing to JSON: {e}"),
    }
}
