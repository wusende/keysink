pub mod audit;
pub mod cli;
pub mod error;
#[cfg(test)]
pub(crate) mod fuzz;
pub mod hardening;
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
        .with_timer(crate::util::LocalTimer)
        .with_target(false)
        // Dedicated writer thread with a bounded queue: the hot warn paths
        // (upstream timeout, retry, shed) run on tokio workers, and a slow log
        // consumer must not be able to block a worker inside a write syscall.
        .with_writer(crate::util::non_blocking_stdout())
        .init();
    install_panic_hook();
}

/// Reports panics through tracing before the default handler prints them.
///
/// A panic inside a task (a request handler, a connection, the store watcher)
/// is caught by the task harness and only surfaces as a `JoinError` on the
/// handle — for a connection that used to mean one silently dropped socket and
/// no log line at all. The default hook still runs, so the message, location
/// and backtrace reach stderr exactly as before.
fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(panic = %info, "panic");
        default(info);
    }));
}

pub fn entry() {
    bootstrap();
    let cli = cli::Cli::parse();
    let result = cli::run(cli);
    // Drain what the non-blocking log writer still has queued: the subscriber
    // leaks its sender for the process lifetime, so the writer thread never
    // runs to completion on its own, and the tail lines — shutdown, cleanup,
    // the error printed below — would otherwise race process teardown.
    util::flush_logs(std::time::Duration::from_secs(2));
    if let Err(e) = result {
        eprintln!("keysink: {e}");
        std::process::exit(1);
    }
}
