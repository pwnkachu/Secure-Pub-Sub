#![forbid(unsafe_code)]

use clap::{Parser, ValueEnum};
use ed25519_dalek::SigningKey;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use x25519_dalek::StaticSecret;

#[derive(Parser)]
#[command(about = "Generate independent SecurePubSub key files")]
struct Args {
    #[arg(long)]
    output: PathBuf,
    #[arg(long, value_enum)]
    kind: Kind,
    /// File prefix. Defaults to `ca` or `agent` according to `--kind`.
    #[arg(long)]
    prefix: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Kind {
    Ca,
    Agent,
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    writeln!(file, "{}", hex::encode(bytes))?;
    file.sync_all()?;
    Ok(())
}

fn write_public(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(path)?;
    writeln!(file, "{}", hex::encode(bytes))?;
    file.sync_all()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    fs::create_dir_all(&args.output)?;
    let mut ed_seed = [0; 32];
    let mut x_secret = [0; 32];
    getrandom::fill(&mut ed_seed).map_err(|_| "operating-system randomness unavailable")?;
    getrandom::fill(&mut x_secret).map_err(|_| "operating-system randomness unavailable")?;
    let default_prefix = match args.kind {
        Kind::Ca => "ca",
        Kind::Agent => "agent",
    };
    let prefix = args.prefix.as_deref().unwrap_or(default_prefix);
    if prefix.is_empty()
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("prefix must contain only ASCII letters, digits, '-' or '_'".into());
    }
    write_private(
        &args.output.join(format!("{prefix}-ed25519.secret")),
        &ed_seed,
    )?;
    write_private(
        &args.output.join(format!("{prefix}-x25519.secret")),
        &x_secret,
    )?;
    write_public(
        &args.output.join(format!("{prefix}-ed25519.public")),
        &SigningKey::from_bytes(&ed_seed).verifying_key().to_bytes(),
    )?;
    write_public(
        &args.output.join(format!("{prefix}-x25519.public")),
        &x25519_dalek::PublicKey::from(&StaticSecret::from(x_secret)).to_bytes(),
    )?;
    println!(
        "keygen complete prefix={prefix} output={}",
        args.output.display()
    );
    Ok(())
}
