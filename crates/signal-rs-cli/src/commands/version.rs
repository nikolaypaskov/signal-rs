use color_eyre::Result;

pub async fn execute() -> Result<()> {
    use owo_colors::OwoColorize;

    let name = "signal-rs".bold();
    let version = env!("CARGO_PKG_VERSION").green();
    println!("{name} {version}");
    println!("A modern Signal messenger CLI client");
    println!();
    println!("Built with Rust for performance and reliability.");
    Ok(())
}
