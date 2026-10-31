pub mod audit;
pub mod cli;
pub mod error;
pub mod model;
pub mod password;
pub mod proxy;
pub mod retry;
pub mod store;
pub mod util;
pub mod vkey;

use clap::Parser;

fn bootstrap() {
    // Exit silently per Unix convention when the downstream closes the pipe, rather than panicking.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into());
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&filter).unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
}

pub fn entry() {
    bootstrap();
    let cli = cli::Cli::parse();
    if let Err(e) = cli::run(cli) {
        eprintln!("keysink: {e}");
        std::process::exit(1);
    }
}
