//! Running system tools (`ip`, `nft`, `sysctl`) with useful error messages.

use std::io::{self, Write};
use std::process::{Command, Stdio};

/// Runs `program args...`, failing with its stderr on a non-zero exit.
pub fn run(program: &str, args: &[&str]) -> io::Result<()> {
    output(program, args).map(drop)
}

/// Runs `program args...` and returns its stdout.
pub fn output(program: &str, args: &[&str]) -> io::Result<String> {
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| io::Error::new(e.kind(), format!("{program}: {e}")))?;
    check(program, args, out.status.success(), &out.stderr)?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Runs `program args...` feeding `input` on stdin.
pub fn run_with_stdin(program: &str, args: &[&str], input: &str) -> io::Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("{program}: {e}")))?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input.as_bytes())?;
    let out = child.wait_with_output()?;
    check(program, args, out.status.success(), &out.stderr)
}

fn check(program: &str, args: &[&str], ok: bool, stderr: &[u8]) -> io::Result<()> {
    if ok {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "`{program} {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(stderr).trim()
    )))
}
