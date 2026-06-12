//! `fxapp` — operator CLI for `flexnetos_github_app` (ADR-0008 §1). P0 exposes the
//! webhook signature primitives (smoke aids) and a `doctor` wiring report.

use app_core::mint::{
    Access, EnvctlMinter, InstallationTokenRequest, Permission, SecretctlInvoker, TokenMinter,
};
use app_core::webhook;
use clap::{Parser, Subcommand};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "fxapp", version, about = "flexnetos_github_app operator CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Compute the `sha256=` signature for a body under a secret (webhook smoke aid).
    Sign {
        #[arg(long)]
        secret: String,
        #[arg(long)]
        body: String,
    },
    /// Verify a `sha256=` signature header against a body+secret.
    Verify {
        #[arg(long)]
        secret: String,
        #[arg(long)]
        body: String,
        #[arg(long)]
        signature: String,
    },
    /// Mint a scoped installation token via envctl (EnvctlMinter → `secretctl mint-github`).
    /// Prints only the expiry — the token is redacted by design (never logged).
    MintToken {
        #[arg(long)]
        installation_id: u64,
        /// Repository IDs to scope to (comma-separated). Empty ⇒ installation default.
        #[arg(long, value_delimiter = ',')]
        repository_ids: Vec<u64>,
        /// Permissions as `name:access` (comma-separated), e.g. `checks:write,contents:read`.
        #[arg(long, value_delimiter = ',')]
        permissions: Vec<String>,
        /// Requested TTL in seconds (GitHub fixes installation tokens at ~1h regardless).
        #[arg(long, default_value_t = 3600)]
        ttl_secs: u64,
    },
    /// Report wiring status of each seam.
    Doctor,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Sign { secret, body } => {
            println!("{}", webhook::sign(secret.as_bytes(), body.as_bytes()));
        }
        Cmd::Verify {
            secret,
            body,
            signature,
        } => match webhook::verify_signature(secret.as_bytes(), body.as_bytes(), &signature) {
            Ok(()) => println!("ok"),
            Err(e) => {
                eprintln!("invalid: {e}");
                std::process::exit(1);
            }
        },
        Cmd::MintToken {
            installation_id,
            repository_ids,
            permissions,
            ttl_secs,
        } => {
            let perms = permissions
                .iter()
                .map(|s| parse_permission(s))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let req = InstallationTokenRequest {
                installation_id,
                repository_ids,
                permissions: perms,
                ttl: Duration::from_secs(ttl_secs),
            };
            let minter = EnvctlMinter::new(SecretctlInvoker::default());
            match minter.mint(&req) {
                Ok(tok) => println!(
                    "minted: expires_at_unix={} (token redacted; envctl held the key)",
                    tok.expires_at_unix
                ),
                Err(e) => {
                    eprintln!("mint failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Doctor => {
            println!("fxapp P1");
            println!("  webhook signature verify : OK");
            println!("  envctl token mint        : WIRED (EnvctlMinter → secretctl mint-github; live needs secretd)");
            println!("  webhook routing/dispatch : UNWIRED (P2)");
            println!("  merge-gate (check-runs)  : UNWIRED (P3)");
        }
    }
    Ok(())
}

/// Parse a `name:access` permission (access defaults to `read`).
fn parse_permission(s: &str) -> anyhow::Result<Permission> {
    let (name, access) = s.split_once(':').unwrap_or((s, "read"));
    let access = match access.trim() {
        "read" => Access::Read,
        "write" => Access::Write,
        other => anyhow::bail!("unknown access '{other}' in '{s}' (use read|write)"),
    };
    Ok(Permission {
        name: name.trim().to_string(),
        access,
    })
}
