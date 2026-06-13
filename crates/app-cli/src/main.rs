//! `fxapp` — operator CLI for `flexnetos_github_app` (ADR-0008 §1). P0 exposes the
//! webhook signature primitives (smoke aids) and a `doctor` wiring report.

use app_core::manifest::{
    build_manifest, install_url, org_create_url, parse_conversion, ManifestConfig,
};
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
    /// Create (+ optionally install) the trusted-writer GitHub App via the Manifest flow, then
    /// seal its private key + webhook secret into envctl's vault. The reproducible, near-zero-touch
    /// replacement for the manual NEEDS-HUMAN-D step. `--dry-run` prints the manifest + URLs only.
    Register {
        /// GitHub org to own the App.
        #[arg(long, default_value = "FlexNetOS")]
        org: String,
        /// App name (must be globally unique on GitHub).
        #[arg(long, default_value = "flexnetos-trusted-writer")]
        name: String,
        /// Public webhook URL (from the cloudflared tunnel), e.g. https://app.example.com/webhook.
        #[arg(long)]
        webhook_url: String,
        /// App homepage URL.
        #[arg(
            long,
            default_value = "https://github.com/FlexNetOS/flexnetos_github_app"
        )]
        homepage: String,
        /// Post-creation redirect target; the approver reads the `?code=` off it (no server needed).
        #[arg(long, default_value = "http://localhost:8765/callback")]
        redirect_url: String,
        /// Make the App public (installable beyond the org). Default: private.
        #[arg(long)]
        public: bool,
        /// Drive the single GitHub click headlessly via the playwright approver (true 0-click).
        /// Without it, the approver opens a window for one manual click.
        #[arg(long)]
        auto_approve: bool,
        /// Browser user-data-dir with a logged-in GitHub session (org owner) for the approver.
        #[arg(long)]
        browser_profile: Option<String>,
        /// Path to the node/playwright approver script.
        #[arg(long, default_value = "scripts/bootstrap/auto-approve.mjs")]
        approver: String,
        /// Print the manifest + create URL + next steps; do not touch the browser or vault.
        #[arg(long)]
        dry_run: bool,
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
        Cmd::Register {
            org,
            name,
            webhook_url,
            homepage,
            redirect_url,
            public,
            auto_approve,
            browser_profile,
            approver,
            dry_run,
        } => register(RegisterArgs {
            org,
            name,
            webhook_url,
            homepage,
            redirect_url,
            public,
            auto_approve,
            browser_profile,
            approver,
            dry_run,
        })?,
        Cmd::Doctor => {
            println!("fxapp");
            println!("  webhook signature verify : OK");
            println!("  envctl token mint        : WIRED (EnvctlMinter → secretctl mint-github; live needs secretd)");
            println!(
                "  webhook routing/dispatch : WIRED (router → signed JobSpec → runner UDS; P2)"
            );
            println!("  app bootstrap (register) : WIRED (manifest flow → envctl seal; needs node+playwright+gh)");
            println!("  merge-gate (check-runs)  : UNWIRED (P3)");
        }
    }
    Ok(())
}

struct RegisterArgs {
    org: String,
    name: String,
    webhook_url: String,
    homepage: String,
    redirect_url: String,
    public: bool,
    auto_approve: bool,
    browser_profile: Option<String>,
    approver: String,
    dry_run: bool,
}

/// Orchestrate the GitHub App Manifest flow end to end (ADR-0008 §B):
/// deterministic manifest → browser submit+click (playwright) → one-time `code` →
/// `gh api …/conversions` → seal `{pem, webhook_secret, id}` into envctl's vault.
/// The pure parts (manifest, URLs, conversion parsing) live in `app_core::manifest` and are tested
/// there; this function is the I/O shell.
fn register(a: RegisterArgs) -> anyhow::Result<()> {
    let mut cfg =
        ManifestConfig::trusted_writer(&a.name, &a.homepage, &a.webhook_url, &a.redirect_url);
    cfg.public = a.public;
    let manifest = build_manifest(&cfg);
    let manifest_str = serde_json::to_string(&manifest)?;
    let state = gen_state();
    let create_url = org_create_url(&a.org, &state);

    if a.dry_run {
        println!("# fxapp register (dry-run) — nothing was created\n");
        println!("org         : {}", a.org);
        println!("create URL  : {create_url}");
        println!("redirect    : {}", a.redirect_url);
        println!("webhook     : {}", a.webhook_url);
        println!("\nmanifest:\n{}", serde_json::to_string_pretty(&manifest)?);
        println!(
            "\nlive run: drop --dry-run. With --auto-approve + --browser-profile <dir> (a GitHub\n\
             session logged in as an org owner) the approver clicks 'Create GitHub App', captures\n\
             the redirect code, converts it, installs the App, and envctl seals the private key +\n\
             webhook secret. Without --auto-approve it opens a window for one manual click."
        );
        return Ok(());
    }

    let profile = a.browser_profile.clone().unwrap_or_default();
    // 1) Browser: submit the manifest, click "Create GitHub App", capture the redirect `code`.
    eprintln!("→ creating the App via the manifest flow (org={}) …", a.org);
    let created = drive_browser(
        &a.approver,
        &[
            ("FXAPP_MODE", "create"),
            ("FXAPP_CREATE_URL", &create_url),
            ("FXAPP_MANIFEST", &manifest_str),
            ("FXAPP_STATE", &state),
            ("FXAPP_REDIRECT", &a.redirect_url),
            ("FXAPP_AUTO_APPROVE", if a.auto_approve { "1" } else { "0" }),
            ("FXAPP_BROWSER_PROFILE", &profile),
        ],
    )?;
    let code = created["code"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("approver returned no `code`"))?;
    let got_state = created["state"].as_str().unwrap_or_default();
    if got_state != state {
        anyhow::bail!("CSRF state mismatch (expected {state}, got {got_state}); aborting");
    }

    // 2) Convert the one-time code into credentials (gh is already authenticated).
    eprintln!("→ converting manifest code → credentials …");
    let conv_json = run_capture(
        "gh",
        &[
            "api",
            "--method",
            "POST",
            &format!("/app-manifests/{code}/conversions"),
        ],
        None,
    )?;
    let conv = parse_conversion(&conv_json).map_err(|e| anyhow::anyhow!(e))?;

    // 3) Seal into envctl's vault. The private key is broker-only (never revealable); the webhook
    //    secret is injectable (the server HMACs incoming deliveries with it).
    eprintln!("→ sealing credentials into envctl …");
    seal_secret("github-app-private-key", conv.pem.as_bytes(), true)?;
    seal_secret(
        "github-app-webhook-secret",
        conv.webhook_secret.as_bytes(),
        false,
    )?;
    seal_secret("github-app-id", conv.id.to_string().as_bytes(), false)?;

    // 4) Install (0-click) when auto-approving.
    if a.auto_approve {
        if let Some(iurl) = install_url(&conv) {
            eprintln!("→ installing the App …");
            let inst = drive_browser(
                &a.approver,
                &[
                    ("FXAPP_MODE", "install"),
                    ("FXAPP_INSTALL_URL", &iurl),
                    ("FXAPP_AUTO_APPROVE", "1"),
                    ("FXAPP_BROWSER_PROFILE", &profile),
                ],
            )?;
            if let Some(id) = inst.get("installation_id").and_then(|v| v.as_u64()) {
                seal_secret(
                    "github-app-installation-id",
                    id.to_string().as_bytes(),
                    false,
                )?;
                eprintln!("  installation_id={id}");
            }
        }
    }

    println!("✓ GitHub App created + sealed into envctl");
    println!("  app_id   = {}", conv.id);
    if let Some(s) = &conv.slug {
        println!("  slug     = {s}");
    }
    if let Some(u) = &conv.html_url {
        println!("  html_url = {u}");
    }
    if let Some(iurl) = install_url(&conv) {
        println!("  install  = {iurl}");
    }
    println!("  vault    = github-app-private-key (broker-only), github-app-webhook-secret, github-app-id");
    Ok(())
}

/// An opaque CSRF token echoed through the GitHub redirect. Not cryptographic — just a
/// round-trip nonce, so process id + wall-clock nanos is sufficient (no extra deps).
fn gen_state() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("fxapp-{}-{nanos:x}", std::process::id())
}

/// Run the node/playwright approver with `envs`; return the last JSON line it prints on stdout.
/// stderr is inherited so the operator sees browser progress live.
fn drive_browser(approver: &str, envs: &[(&str, &str)]) -> anyhow::Result<serde_json::Value> {
    use std::process::{Command, Stdio};
    let mut cmd = Command::new("node");
    cmd.arg(approver)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().map_err(|e| {
        anyhow::anyhow!("could not run `node {approver}`: {e} — install node and run `npm i` in scripts/bootstrap")
    })?;
    if !out.status.success() {
        anyhow::bail!("approver exited {}", out.status);
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| anyhow::anyhow!("approver produced no JSON result on stdout"))?;
    serde_json::from_str(line.trim()).map_err(|e| anyhow::anyhow!("approver JSON parse: {e}"))
}

/// Pipe `value` into `secretctl secret add <name> --provider github --value-stdin --overwrite`,
/// adding `--broker-only` when the value must never be revealable (the App private key).
fn seal_secret(name: &str, value: &[u8], broker_only: bool) -> anyhow::Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut args = vec![
        "secret",
        "add",
        name,
        "--provider",
        "github",
        "--value-stdin",
        "--overwrite",
    ];
    if broker_only {
        args.push("--broker-only");
    }
    let mut child = Command::new("secretctl")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            anyhow::anyhow!("could not run `secretctl`: {e} (is envctl installed + unlocked?)")
        })?;
    child.stdin.take().expect("piped stdin").write_all(value)?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        anyhow::bail!(
            "secretctl secret add {name} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    eprintln!(
        "  sealed → {name}{}",
        if broker_only { " (broker-only)" } else { "" }
    );
    Ok(())
}

/// Run `program args…`, optionally piping `stdin_bytes`, and capture stdout. Fails with stderr on
/// a non-zero exit.
fn run_capture(program: &str, args: &[&str], stdin_bytes: Option<&[u8]>) -> anyhow::Result<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(program);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.stdin(if stdin_bytes.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("could not run `{program}`: {e}"))?;
    if let Some(bytes) = stdin_bytes {
        child.stdin.take().expect("piped stdin").write_all(bytes)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        anyhow::bail!(
            "{program} exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
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
