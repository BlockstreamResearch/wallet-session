//! Development harnesses for live `WalletConnect` protocol exploration.

mod cli;
mod probe;
mod relay;
mod relay_socket;
mod scenario;
mod util;

fn main() -> anyhow::Result<()> {
    cli::run()
}
