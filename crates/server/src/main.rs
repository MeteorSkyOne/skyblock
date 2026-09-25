// The relay node (SPEC §7) lands in M1; this crate only reserves its place
// in the workspace for now.
fn main() {
    eprintln!(
        "skyblock-server {}: not implemented yet (M1)",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(1);
}
