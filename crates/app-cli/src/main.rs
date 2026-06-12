//! `fxapp` — operator CLI for `flexnetos_github_app` (ADR-0008 §1). P0 exposes the
//! webhook signature primitives (smoke aids) and a `doctor` wiring report.

use app_core::webhook;
use clap::{Parser, Subcommand};

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
        Cmd::Doctor => {
            println!("fxapp P0");
            println!("  webhook signature verify : OK");
            println!("  envctl token mint        : UNWIRED (P1 — secretd UDS)");
            println!("  webhook routing/dispatch : UNWIRED (P2)");
            println!("  merge-gate (check-runs)  : UNWIRED (P3)");
        }
    }
    Ok(())
}
