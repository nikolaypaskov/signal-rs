use tabled::{Table, Tabled};

/// Print a single value as a table.
#[allow(dead_code)]
pub fn print<T: Tabled>(value: &T) {
    let table = Table::new(std::iter::once(value)).to_string();
    println!("{table}");
}

/// Print a list of values as a table.
pub fn print_list<T: Tabled>(values: &[T]) {
    if values.is_empty() {
        println!("(no results)");
        return;
    }
    let table = Table::new(values).to_string();
    println!("{table}");
}
