//! Development harnesses for live `WalletConnect` protocol exploration.

mod api_snapshot;
mod cli;
mod lab;
mod probe;
mod relay;
mod relay_socket;
mod scenario;
mod util;

fn main() -> anyhow::Result<()> {
    cli::run()
}
