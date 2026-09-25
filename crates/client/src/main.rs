use clap::{Parser, Subcommand};
use skyblock_proto::keys::PrivateKey;

/// skyblock game accelerator client.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a user key pair (paste into the client config; give the
    /// public key to each node's `adduser`).
    Keygen,
}

fn main() {
    match Cli::parse().command {
        Command::Keygen => {
            let sk = PrivateKey::generate();
            println!("private_key = \"{}\"", sk.to_base64());
            println!("# public_key = \"{}\"", sk.public_key());
        }
    }
}
