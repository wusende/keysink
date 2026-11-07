use crate::audit::Audit;
use crate::error::{Error, Result};
use crate::model::{Auth, Route, Terminator, validate_name};
use crate::proxy::{self, AppState, Snapshot};
use crate::retry::RetryPolicy;
use crate::store::{self, Paths};
use crate::util;
use crate::vkey;
use arc_swap::ArcSwap;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Long help for `--home`, matching what `default_vault_home()` actually resolves to on
/// the current platform (the static doc-comment text was Linux-only and misled macOS/Windows
/// users checking where their vault lives).
const VAULT_HOME_LONG_HELP: &str = if cfg!(target_os = "windows") {
    "vault directory (default: $KEYSINK_VAULT_HOME or %LOCALAPPDATA%\\keysink)"
} else if cfg!(target_os = "macos") {
    "vault directory (default: $KEYSINK_VAULT_HOME or ~/.local/share/keysink)"
} else {
    "vault directory (default: $KEYSINK_VAULT_HOME or ~/.local/share/keysink; system installs: /var/lib/keysink)"
};

#[derive(Parser, Debug)]
#[command(
    name = "keysink",
    version,
    about = "Local credential gateway: agents see only vkeys; upstream keys go in, never out (cannot be read/exported)",
    long_about = None
)]
pub struct Cli {
    /// vault directory
    #[arg(
        long,
        global = true,
        env = "KEYSINK_VAULT_HOME",
        value_name = "DIR",
        long_help = VAULT_HOME_LONG_HELP
    )]
    pub home: Option<PathBuf>,

    #[command(subcommand)]
    pub cmd: Cmd,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Initialize the vault (vault.key + vault.age); sets the master password first
    Init {
        /// If one already exists, rename it to a backup before rebuilding
        #[arg(long)]
        force: bool,
        /// Read the master password from stdin (non-interactive environments)
        #[arg(long)]
        password_stdin: bool,
    },
    /// Create a route and generate a virtual key (= route add)
    Add(RouteAddArgs),
    /// Manage routes (vkey → upstream)
    Route {
        #[command(subcommand)]
        cmd: RouteCmd,
    },
    /// Start the gateway
    Serve(ServeArgs),
    /// Show a vault summary
    Status,
    /// Self-check the vault
    Doctor,
    /// Rotate the vault master key (the vault is first encrypted under both the new and old keys)
    Rekey {
        #[arg(long)]
        yes: bool,
    },
    /// Export a passphrase-encrypted backup (contains no key values; requires the master password)
    Export(ExportArgs),
    /// Remove everything keysink wrote: the vault (keys and routes — gone for
    /// good), and on system installs also the systemd unit, sudoers and the
    /// installed binary. Standalone installs keep the binary itself; its path
    /// is printed instead.
    Uninstall {
        /// Skip the confirmation prompt (non-interactive environments)
        #[arg(long)]
        yes: bool,
    },
    /// One-shot system deployment (Linux + systemd, run as root via sudo):
    /// creates the keysink service user, installs this binary to
    /// /usr/local/bin/keysink, writes the systemd unit and the sudoers rule
    /// for the invoking admin, initializes the vault interactively and
    /// enables the service. Idempotent — re-running upgrades the binary and
    /// unit in place and restarts the service.
    Deploy,
}

pub fn run(cli: Cli) -> Result<()> {
    let home = cli.home.unwrap_or_else(default_vault_home);
    let paths = Paths::vault(home);

    match cli.cmd {
        Cmd::Init {
            force,
            password_stdin,
        } => cmd_init(&paths, force, password_stdin),
        Cmd::Add(args) => cmd_route(&paths, RouteCmd::Add(args)),
        Cmd::Route { cmd } => cmd_route(&paths, cmd),
        Cmd::Serve(args) => cmd_serve(paths, args),
        Cmd::Status => cmd_status(&paths),
        Cmd::Doctor => cmd_doctor(&paths),
        Cmd::Rekey { yes } => cmd_rekey(&paths, yes),
        Cmd::Export(args) => cmd_export(&paths, args),
        Cmd::Uninstall { yes } => cmd_uninstall(&paths, yes),
        Cmd::Deploy => cmd_deploy(),
    }
}

/// vault directory precedence: --home > $KEYSINK_VAULT_HOME > system vault
/// (Unix only) > the current user's standalone directory (Unix:
/// ~/.local/share/keysink; Windows: %LOCALAPPDATA%\keysink).
///
/// Under a system deployment (deploy.sh + systemd), root / the keysink service user can read
/// /var/lib/keysink and thus hit the system vault; regular users cannot, so they fall straight
/// to their own standalone directory — no system user or sudo needed to run.
fn default_vault_home() -> PathBuf {
    if let Some(home) = std::env::var_os("KEYSINK_VAULT_HOME") {
        return PathBuf::from(home);
    }
    if let Some(system) = system_vault_home() {
        return system;
    }
    standalone_home_from(
        std::env::var_os("XDG_DATA_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

/// System vault: probing whether the key file opens is enough to use it
/// (if the current user can't open it, fall back to standalone automatically).
#[cfg(unix)]
fn system_vault_home() -> Option<PathBuf> {
    let system = PathBuf::from("/var/lib/keysink");
    std::fs::File::open(system.join("vault.key"))
        .is_ok()
        .then_some(system)
}

/// Windows has no system-vault convention; always use the user directory.
#[cfg(not(unix))]
fn system_vault_home() -> Option<PathBuf> {
    None
}

/// Default standalone directory: $XDG_DATA_HOME/keysink (when set to an
/// absolute path), otherwise the platform's data-directory convention.
fn standalone_home_from(
    xdg_data_home: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> PathBuf {
    let base = match xdg_data_home.filter(|p| std::path::Path::new(p).is_absolute()) {
        Some(p) => PathBuf::from(p),
        None => data_home_fallback(home),
    };
    base.join("keysink")
}

#[cfg(unix)]
fn data_home_fallback(home: Option<&std::ffi::OsStr>) -> PathBuf {
    PathBuf::from(home.unwrap_or_default()).join(".local/share")
}

#[cfg(not(unix))]
fn data_home_fallback(_home: Option<&std::ffi::OsStr>) -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_default()
}

fn cmd_init(paths: &Paths, force: bool, password_stdin: bool) -> Result<()> {
    if store::external_identity_configured() {
        return Err(Error::msg(
            "KEYSINK_MASTER_KEY / KEYSINK_MASTER_KEY_FILE is set: init creates vault.key and \
             encrypts the store to it, so the external identity could not decrypt the vault. \
             Initialize without the variable, then point the gateway at the generated vault.key \
             (or copy it to the credential path).",
        ));
    }
    let password = crate::password::read_new_password(password_stdin)?;
    store::init(paths, force, &password)?;
    println!("vault initialized: {}", paths.home.display());
    println!("  {}  0600", paths.master_key().display());
    println!("  {}  0600", paths.store().display());
    if force {
        // --force renames the old key/store pairs (both the live and the .bak
        // pair) to .old.<millis> instead of deleting them; each pair still
        // decrypts each other, so a rebuild done to flush a compromise is not
        // complete until they are removed. The prefix list comes from Paths so
        // it can never drift from the renames in store::init.
        let prefixes = paths.old_backup_prefixes();
        let leftovers: Vec<String> = std::fs::read_dir(&paths.home)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|name| prefixes.iter().any(|p| name.starts_with(p)))
                    .collect()
            })
            .unwrap_or_default();
        if !leftovers.is_empty() {
            println!();
            println!(
                "Note: {} pre-rebuild vault file(s) remain; each old key still decrypts its old \
                 store, so if the rebuild was to flush a compromise, delete them:",
                leftovers.len()
            );
            for name in leftovers {
                println!("  {}/{}", paths.home.display(), name);
            }
        }
    }
    println!();
    println!(
        "master password is only used to encrypt and restore `export` backups; writes/rotation/serve never need it."
    );
    println!("Next steps:");
    println!("  keysink route add claude --base-url https://api.anthropic.com");
    println!(
        "  # in a terminal the key is prompted (hidden echo); in scripts: printf %s \"$KEY\" | keysink route add ..."
    );
    println!("  keysink serve");
    Ok(())
}

#[derive(Subcommand, Debug)]
pub enum RouteCmd {
    /// Create a route and generate a virtual key
    Add(RouteAddArgs),
    /// List routes (vkey masked)
    Ls,
    /// Show a single route (vkey masked)
    Show {
        name: String,
    },
    /// Rotate the virtual key
    Rotate {
        name: String,
    },
    /// Update a route (keeps the vkey; only the given fields change)
    Update(RouteUpdateArgs),
    /// Remove a route
    Rm {
        name: String,
    },
    Enable {
        name: String,
    },
    Disable {
        name: String,
    },
}

#[derive(Args, Debug)]
pub struct RouteAddArgs {
    /// Prompt for it in the terminal when omitted (TTY only; scripts must pass it explicitly)
    pub name: Option<String>,
    #[arg(long)]
    pub base_url: Option<String>,
    /// route-only key value: `--route-key VALUE` passes it directly (VALUE is visible in ps/history; scripts should use `-`),
    /// `--route-key -` reads from stdin, bare `--route-key` or omitted prompts hidden on a TTY / reads stdin off-TTY
    #[arg(long, num_args = 0..=1, value_name = "VALUE")]
    pub route_key: Option<Option<String>>,
    #[arg(long, value_enum, default_value = "bearer")]
    pub auth: AuthKind,
    /// Header name for header auth, e.g. x-goog-api-key
    #[arg(long)]
    pub auth_header: Option<String>,
    /// Value prefix for header auth, e.g. "Bearer "
    #[arg(long)]
    pub auth_prefix: Option<String>,
    /// Username for basic auth
    #[arg(long)]
    pub auth_user: Option<String>,
    /// Query parameter name for query auth, e.g. key
    #[arg(long)]
    pub auth_param: Option<String>,
    /// Upstream headers injected verbatim; repeatable, format KEY:VALUE
    #[arg(long = "header", value_name = "KEY:VALUE")]
    pub headers: Vec<String>,
    #[arg(long)]
    pub max_retries: Option<u8>,
    /// Override the default retryable status codes (default 429/503/504); repeatable
    #[arg(long = "retry-on-status", value_name = "CODE")]
    pub retry_on_status: Vec<u16>,
    #[arg(long, value_enum, default_value = "auto")]
    pub sse_terminator: TerminatorArg,
    /// upstream proxy: http(s)://URL or direct (force a direct connection); defaults to following system proxy environment variables
    #[arg(long)]
    pub proxy: Option<String>,
    #[arg(long)]
    pub note: Option<String>,
}

#[derive(Args, Debug)]
pub struct RouteUpdateArgs {
    pub name: String,
    #[arg(long)]
    pub base_url: Option<String>,
    /// Replace the route-only key value: `--route-key VALUE` (visible in ps/history; scripts should use `-`) /
    /// `--route-key -` / bare `--route-key`
    #[arg(long, num_args = 0..=1, value_name = "VALUE")]
    pub route_key: Option<Option<String>>,
    /// Auth method; when given, the matching --auth-* arguments must be supplied
    #[arg(long, value_enum)]
    pub auth: Option<AuthKind>,
    #[arg(long)]
    pub auth_header: Option<String>,
    #[arg(long)]
    pub auth_prefix: Option<String>,
    #[arg(long)]
    pub auth_user: Option<String>,
    #[arg(long)]
    pub auth_param: Option<String>,
    /// Append to / override the fixed injected upstream headers; repeatable, format KEY:VALUE
    #[arg(long = "header", value_name = "KEY:VALUE")]
    pub headers: Vec<String>,
    /// Clear existing static headers first, then apply this run's --header
    #[arg(long)]
    pub clear_headers: bool,
    #[arg(long)]
    pub max_retries: Option<u8>,
    /// Replace the retryable status codes wholesale; repeatable
    #[arg(long = "retry-on-status", value_name = "CODE")]
    pub retry_on_status: Vec<u16>,
    /// Restore max_retries / retry_on_status to the global defaults
    #[arg(long)]
    pub clear_retry: bool,
    #[arg(long, value_enum)]
    pub sse_terminator: Option<TerminatorArg>,
    /// upstream proxy: http(s)://URL or direct (force a direct connection)
    #[arg(long)]
    pub proxy: Option<String>,
    /// Restore following the system proxy environment variables
    #[arg(long)]
    pub clear_proxy: bool,
    #[arg(long)]
    pub note: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum AuthKind {
    Bearer,
    XApiKey,
    Header,
    Basic,
    Query,
    None,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum TerminatorArg {
    Auto,
    Openai,
    Anthropic,
    None,
}

#[derive(Args, Debug)]
pub struct ServeArgs {
    #[arg(long, default_value = "127.0.0.1:8787")]
    pub listen: String,
    /// Audit log path (off by default)
    #[arg(long)]
    pub audit_log: Option<PathBuf>,
    /// Allow binding a non-loopback address (not recommended; add TLS yourself)
    #[arg(long)]
    pub allow_remote: bool,
    #[arg(long, default_value_t = 32)]
    pub body_limit_mb: usize,
    /// Bound on concurrent in-flight requests (body read + upstream header wait); extra requests queue
    #[arg(long, default_value_t = 64)]
    pub max_concurrent: usize,
    #[arg(long, default_value_t = crate::retry::DEFAULT_MAX_RETRIES)]
    pub max_retries: u8,
    /// Start even when the primary store is undecryptable and the vault data
    /// comes from the older .bak backup (revoked/removed vkeys may work again)
    #[arg(long)]
    pub accept_degraded: bool,
    /// Seconds to wait for in-flight requests while shutting down before
    /// dropping them (0 = wait forever). Keep the service manager's stop
    /// timeout above this, or it will SIGKILL the drain.
    #[arg(long, default_value_t = proxy::DRAIN_TIMEOUT.as_secs())]
    pub drain_timeout_secs: u64,
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    #[arg(long)]
    pub output: PathBuf,
    /// Read the export file's passphrase from a file (first line); defaults to reusing the master password
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
    /// Read the master password from stdin (non-interactive environments)
    #[arg(long)]
    pub password_stdin: bool,
}

pub(crate) fn cmd_route(paths: &Paths, cmd: RouteCmd) -> Result<()> {
    match cmd {
        RouteCmd::Add(args) => {
            let name =
                resolve_required(args.name.clone(), "Route name (e.g. claude)", "route name")?;
            validate_name(&name, "route")?;
            let base_url = resolve_required(
                args.base_url.clone(),
                "Upstream base URL (e.g. https://api.anthropic.com)",
                "--base-url",
            )?;
            let base_url = base_url.trim_end_matches('/').to_string();
            if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
                return Err(Error::msg("base_url must start with http:// or https://"));
            }
            let auth = resolve_auth(&args)?;
            let proxy = guide_proxy(args.proxy.clone())?;
            let headers = parse_headers(&args.headers)?;
            let token = vkey::generate();
            let terminator = Terminator::parse(args.sse_terminator.as_str())?;
            let token_out = token.clone();
            let auth_out = auth.clone();
            let given_key = match &args.route_key {
                Some(Some(v)) => Some(Zeroizing::new(v.clone())),
                _ => None,
            };
            let key_value = read_key_value(given_key)?;
            store::update(paths, |store| {
                if store.routes.contains_key(&name) {
                    return Err(Error::msg(format!("route `{name}` already exists")));
                }
                let mut route = Route::new(
                    token.clone(),
                    base_url.clone(),
                    key_value.as_str().to_string(),
                    auth.clone(),
                    headers.clone(),
                );
                route.max_retries = args.max_retries;
                if !args.retry_on_status.is_empty() {
                    route.retry_on_status = Some(args.retry_on_status.clone());
                }
                route.sse_terminator = terminator;
                route.proxy = proxy;
                route.note = args.note.clone().unwrap_or_default();
                store.routes.insert(name.clone(), route);
                Ok(())
            })?;
            println!("route `{name}` created (key goes in, never out: cannot be read/exported)");
            println!("auth: {}    base_url: {}", auth_out.describe(), base_url);
            println!("vkey: {token_out}");
            println!(
                "(vkey is shown only this once; if lost, only `keysink route rotate {name}` can issue a new one)"
            );
            match current_gateway(paths) {
                Some((gw, alive)) => {
                    println!(
                        "gateway: http://{gw} ({})",
                        if alive {
                            "running"
                        } else {
                            "not responding — make sure serve is running"
                        }
                    );
                    println!(
                        "agent-side config (OpenAI-compatible clients usually need /v1 in base_url):"
                    );
                    println!("  BASE_URL=http://{gw}");
                    println!("  TOKEN={token_out}");
                }
                None => {
                    // gateway.addr is removed when serve exits: no trustworthy address
                    // exists, so never substitute the compile-time default port here
                    println!("gateway: (not running — address unknown)");
                    println!(
                        "agent-side config: start `keysink serve` and point the agent at the address it prints (OpenAI-compatible clients usually need /v1 appended):"
                    );
                    println!("  TOKEN={token_out}");
                }
            }
            Ok(())
        }
        RouteCmd::Ls => {
            let unlocked = store::unlock(paths)?;
            warn_if_degraded(paths, unlocked.from_backup);
            if unlocked.store.routes.is_empty() {
                println!("(empty)");
                return Ok(());
            }
            println!(
                "{:<20} {:<8} {:<22} {:<22} {:<14} VKEY",
                "NAME", "ENABLED", "BASE_URL", "KEY", "AUTH"
            );
            for (name, route) in &unlocked.store.routes {
                println!(
                    "{:<20} {:<8} {:<22} {:<22} {:<14} {}",
                    name,
                    if route.enabled { "yes" } else { "no" },
                    truncate(&route.base_url, 22),
                    route_key_label(route),
                    route.auth.describe(),
                    vkey::mask(&route.vkey)
                );
            }
            Ok(())
        }
        RouteCmd::Show { name } => {
            let unlocked = store::unlock(paths)?;
            warn_if_degraded(paths, unlocked.from_backup);
            let route = unlocked
                .store
                .routes
                .get(&name)
                .ok_or_else(|| Error::msg(format!("route `{name}` does not exist")))?;
            println!("name:        {name}");
            println!("enabled:     {}", route.enabled);
            println!("base_url:    {}", route.base_url);
            println!("key:         {}", route_key_label(route));
            println!("auth:        {}", route.auth.describe());
            println!("vkey:        {}", vkey::mask(&route.vkey));
            println!("terminator:  {}", route.sse_terminator.as_str());
            println!(
                "proxy:       {}",
                match route.proxy.as_deref() {
                    None => "(follows system proxy environment variables)",
                    Some(p) => p,
                }
            );
            println!(
                "max_retries: {}",
                route
                    .max_retries
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "default".into())
            );
            if let Some(statuses) = &route.retry_on_status {
                println!(
                    "retry_status: {}",
                    statuses
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            if !route.headers.is_empty() {
                println!("headers:");
                for (k, v) in &route.headers {
                    println!("  {k}: {v}");
                }
            }
            if !route.note.is_empty() {
                println!("note:        {}", route.note);
            }
            println!("created:     {}", util::ts(route.created));
            Ok(())
        }
        RouteCmd::Rotate { name } => {
            let token = vkey::generate();
            let token_out = token.clone();
            store::update(paths, |store| {
                let route = store
                    .routes
                    .get_mut(&name)
                    .ok_or_else(|| Error::msg(format!("route `{name}` does not exist")))?;
                route.vkey = token.clone();
                Ok(())
            })?;
            println!("route `{name}` rotated; the old vkey is invalid immediately");
            println!("vkey: {token_out}");
            println!("(update the vkey in the agent config to the new value)");
            Ok(())
        }
        RouteCmd::Update(args) => {
            let new_base = args
                .base_url
                .as_ref()
                .map(|u| u.trim_end_matches('/').to_string());
            if let Some(base) = &new_base
                && !(base.starts_with("http://") || base.starts_with("https://"))
            {
                return Err(Error::msg("base_url must start with http:// or https://"));
            }
            let new_auth = match args.auth {
                Some(kind) => Some(build_auth_from(
                    kind,
                    args.auth_header.clone(),
                    args.auth_prefix.clone(),
                    args.auth_user.clone(),
                    args.auth_param.clone(),
                )?),
                None => None,
            };
            let new_headers = parse_headers(&args.headers)?;
            let new_terminator = match args.sse_terminator {
                Some(t) => Some(Terminator::parse(t.as_str())?),
                None => None,
            };
            if args.clear_proxy && args.proxy.is_some() {
                return Err(Error::msg(
                    "--proxy and --clear-proxy are mutually exclusive",
                ));
            }
            let new_inline_key = if args.route_key.is_some() {
                let given = match &args.route_key {
                    Some(Some(v)) => Some(Zeroizing::new(v.clone())),
                    _ => None,
                };
                Some(read_key_value(given)?)
            } else {
                None
            };
            if args.clear_retry && (args.max_retries.is_some() || !args.retry_on_status.is_empty())
            {
                return Err(Error::msg(
                    "--clear-retry and --max-retries / --retry-on-status are mutually exclusive",
                ));
            }
            store::update(paths, |store| {
                let route = store
                    .routes
                    .get_mut(&args.name)
                    .ok_or_else(|| Error::msg(format!("route `{}` does not exist", args.name)))?;
                if let Some(base) = &new_base {
                    route.base_url = base.clone();
                }
                if let Some(value) = &new_inline_key {
                    route.inline_key = Some(value.as_str().to_string());
                }
                if let Some(auth) = &new_auth {
                    route.auth = auth.clone();
                }
                if args.clear_headers {
                    route.headers.clear();
                }
                for (key, value) in &new_headers {
                    route.headers.insert(key.clone(), value.clone());
                }
                if args.clear_retry {
                    route.max_retries = None;
                    route.retry_on_status = None;
                }
                if args.max_retries.is_some() {
                    route.max_retries = args.max_retries;
                }
                if !args.retry_on_status.is_empty() {
                    route.retry_on_status = Some(args.retry_on_status.clone());
                }
                if let Some(t) = new_terminator {
                    route.sse_terminator = t;
                }
                if args.clear_proxy {
                    route.proxy = None;
                } else if let Some(p) = &args.proxy {
                    route.proxy = Some(p.clone());
                }
                if let Some(note) = &args.note {
                    route.note = note.clone();
                }
                Ok(())
            })?;
            println!("route `{}` updated (vkey unchanged)", args.name);
            Ok(())
        }
        RouteCmd::Rm { name } => {
            store::update(paths, |store| {
                store
                    .routes
                    .remove(&name)
                    .ok_or_else(|| Error::msg(format!("route `{name}` does not exist")))?;
                Ok(())
            })?;
            println!("route `{name}` deleted (its vkey stops working immediately)");
            println!("to bring it back, re-create it: `keysink route add {name} --base-url ...`");
            Ok(())
        }
        RouteCmd::Enable { name } => set_route_enabled(paths, &name, true),
        RouteCmd::Disable { name } => set_route_enabled(paths, &name, false),
    }
}

fn set_route_enabled(paths: &Paths, name: &str, enable: bool) -> Result<()> {
    store::update(paths, |store| {
        let route = store
            .routes
            .get_mut(name)
            .ok_or_else(|| Error::msg(format!("route `{name}` does not exist")))?;
        route.enabled = enable;
        Ok(())
    })?;
    println!(
        "route `{name}` {}",
        if enable { "enabled" } else { "disabled" }
    );
    Ok(())
}

/// Auth parameters resolved by guide_auth; the fields map directly to build_auth_from's inputs.
struct AuthChoice {
    kind: AuthKind,
    header: Option<String>,
    prefix: Option<String>,
    user: Option<String>,
    param: Option<String>,
}

/// Auth method: explicit arguments win (non-default bearer, or any --auth-* helper argument);
/// otherwise prompt on a TTY (Enter = OpenAI-compatible), keeping the default unchanged off-TTY.
/// No domain auto-detection — a relay may support several protocols, so the protocol is the
/// user's explicit choice. The prompt follows the user's mental model of "what interface is
/// the upstream": auth only decides where the key gets injected and is independent of the wire
/// protocol — OpenAI and responses both use Bearer, Claude/Anthropic uses x-api-key.
fn resolve_auth(args: &RouteAddArgs) -> Result<Auth> {
    let explicit = !matches!(args.auth, AuthKind::Bearer)
        || args.auth_header.is_some()
        || args.auth_prefix.is_some()
        || args.auth_user.is_some()
        || args.auth_param.is_some();
    if explicit || !interactive() {
        return build_auth_from(
            args.auth,
            args.auth_header.clone(),
            args.auth_prefix.clone(),
            args.auth_user.clone(),
            args.auth_param.clone(),
        );
    }
    let choice = guide_auth_prompt()?;
    build_auth_from(
        choice.kind,
        choice.header,
        choice.prefix,
        choice.user,
        choice.param,
    )
}

/// TTY prompt phrased to the user's mental model: "what interface is the upstream".
fn guide_auth_prompt() -> Result<AuthChoice> {
    let choice = prompt_line(
        "Upstream interface [1]OpenAI-compatible (incl. responses, default) [2]Claude/Anthropic [3]Gemini [4]other",
        Some("1"),
    )?;
    match choice.as_str() {
        "1" | "openai" | "responses" => Ok(AuthChoice {
            kind: AuthKind::Bearer,
            header: None,
            prefix: None,
            user: None,
            param: None,
        }),
        "2" | "claude" | "anthropic" => Ok(AuthChoice {
            kind: AuthKind::XApiKey,
            header: None,
            prefix: None,
            user: None,
            param: None,
        }),
        "3" | "gemini" => Ok(AuthChoice {
            kind: AuthKind::Header,
            header: Some("x-goog-api-key".into()),
            prefix: None,
            user: None,
            param: None,
        }),
        "4" | "other" => prompt_auth_detail(),
        other => Err(Error::msg(format!("invalid interface type: {other}"))),
    }
}

/// Auth primitives expanded from the "other" choice, for non-mainstream upstreams (basic, query parameters, etc.).
fn prompt_auth_detail() -> Result<AuthChoice> {
    let choice = prompt_line(
        "Auth method [1]bearer (default) [2]x-api-key [3]custom header [4]basic [5]query [6]none",
        Some("1"),
    )?;
    let out = match choice.as_str() {
        "1" | "bearer" => AuthChoice {
            kind: AuthKind::Bearer,
            header: None,
            prefix: None,
            user: None,
            param: None,
        },
        "2" | "x-api-key" => AuthChoice {
            kind: AuthKind::XApiKey,
            header: None,
            prefix: None,
            user: None,
            param: None,
        },
        "3" | "header" => {
            let name = prompt_line("Header name (e.g. x-goog-api-key)", None)?;
            let prefix = prompt_line("Value prefix (Enter=none, e.g. Bearer )", Some(""))?;
            AuthChoice {
                kind: AuthKind::Header,
                header: Some(name),
                prefix: (!prefix.is_empty()).then_some(prefix),
                user: None,
                param: None,
            }
        }
        "4" | "basic" => {
            let user = prompt_line("Basic username", None)?;
            AuthChoice {
                kind: AuthKind::Basic,
                header: None,
                prefix: None,
                user: Some(user),
                param: None,
            }
        }
        "5" | "query" => {
            let param = prompt_line("Query parameter name (e.g. key)", None)?;
            AuthChoice {
                kind: AuthKind::Query,
                header: None,
                prefix: None,
                user: None,
                param: Some(param),
            }
        }
        "6" | "none" => AuthChoice {
            kind: AuthKind::None,
            header: None,
            prefix: None,
            user: None,
            param: None,
        },
        other => return Err(Error::msg(format!("invalid auth method: {other}"))),
    };
    Ok(out)
}

/// upstream proxy: use it when the argument is given; prompt when missing on a TTY (Enter = follow system proxy environment variables).
fn guide_proxy(given: Option<String>) -> Result<Option<String>> {
    if let Some(p) = given {
        return Ok(Some(p));
    }
    if !interactive() {
        return Ok(None);
    }
    let v = prompt_line(
        "Upstream proxy (Enter=follow system proxy; direct=force a direct connection; or http(s)://URL)",
        Some(""),
    )?;
    Ok((!v.is_empty()).then_some(v))
}

fn build_auth_from(
    auth: AuthKind,
    auth_header: Option<String>,
    auth_prefix: Option<String>,
    auth_user: Option<String>,
    auth_param: Option<String>,
) -> Result<Auth> {
    match auth {
        AuthKind::Bearer => Ok(Auth::Bearer),
        AuthKind::XApiKey => Ok(Auth::XApiKey),
        AuthKind::Header => {
            let name =
                auth_header.ok_or_else(|| Error::msg("header auth requires --auth-header"))?;
            Ok(Auth::Header {
                name,
                prefix: auth_prefix.unwrap_or_default(),
            })
        }
        AuthKind::Basic => {
            let username =
                auth_user.ok_or_else(|| Error::msg("basic auth requires --auth-user"))?;
            Ok(Auth::Basic { username })
        }
        AuthKind::Query => {
            let param = auth_param.ok_or_else(|| Error::msg("query auth requires --auth-param"))?;
            Ok(Auth::Query { param })
        }
        AuthKind::None => Ok(Auth::None),
    }
}

fn parse_headers(raws: &[String]) -> Result<BTreeMap<String, String>> {
    let mut headers = BTreeMap::new();
    for raw in raws {
        let (key, value) = raw
            .split_once(':')
            .ok_or_else(|| Error::msg(format!("header requires KEY:VALUE format: `{raw}`")))?;
        headers.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(headers)
}

impl TerminatorArg {
    fn as_str(self) -> &'static str {
        match self {
            TerminatorArg::Auto => "auto",
            TerminatorArg::Openai => "openai",
            TerminatorArg::Anthropic => "anthropic",
            TerminatorArg::None => "none",
        }
    }
}

/// Key values stay in Zeroizing throughout: zeroed on drop, aligned with the proxy side's handling.
fn read_key_value(value: Option<Zeroizing<String>>) -> Result<Zeroizing<String>> {
    let mut text = match value {
        Some(v) if v.as_str() != "-" => v,
        Some(_) => read_stdin()?,
        None => {
            if std::io::stdin().is_terminal() {
                prompt_hidden_twice()?
            } else {
                read_stdin()?
            }
        }
    };
    while text.ends_with('\n') || text.ends_with('\r') {
        text.pop();
    }
    if text.is_empty() {
        return Err(Error::msg("key value is empty"));
    }
    Ok(text)
}

/// Prompt hidden twice and require the entries to match; the value is never echoed and never lands on the command line.
fn prompt_hidden_twice() -> Result<Zeroizing<String>> {
    let first = Zeroizing::new(
        rpassword::prompt_password("Key value: ")
            .map_err(|e| Error::msg(format!("failed to read input: {e}")))?,
    );
    let second = Zeroizing::new(
        rpassword::prompt_password("Repeat: ")
            .map_err(|e| Error::msg(format!("failed to read input: {e}")))?,
    );
    if first != second {
        return Err(Error::msg("the two entries do not match"));
    }
    if first.is_empty() {
        return Err(Error::msg("key value is empty"));
    }
    Ok(first)
}

/// Whether stdin is an interactive terminal: decides between prompting and erroring on missing arguments.
/// Script / agent pipelines must keep explicit arguments + non-zero exits; never hang waiting for input.
fn interactive() -> bool {
    std::io::stdin().is_terminal()
}

/// Prompt for one line: the prompt goes to stderr (stdout stays machine-readable); a bare Enter takes the default.
fn prompt_line(label: &str, default: Option<&str>) -> Result<String> {
    use std::io::{BufRead as _, Write as _};
    match default {
        Some(d) => eprint!("{label} (Enter={d}): "),
        None => eprint!("{label}: "),
    }
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let line = line.trim_end_matches(['\n', '\r']);
    if line.is_empty()
        && let Some(d) = default
    {
        return Ok(d.to_string());
    }
    Ok(line.to_string())
}

/// Prompt on a TTY when the argument is missing / error off-TTY; never hang.
fn resolve_required(given: Option<String>, label: &str, flag: &str) -> Result<String> {
    if let Some(v) = given {
        let v = v.trim();
        if !v.is_empty() {
            return Ok(v.to_string());
        }
    }
    if interactive() {
        prompt_line(label, None)
    } else {
        Err(Error::msg(format!(
            "missing {flag} (non-interactive environments must pass it explicitly)"
        )))
    }
}

fn read_stdin() -> Result<Zeroizing<String>> {
    // One line, as documented: a key is a single credential, and reading to
    // EOF used to silently turn a multi-line pipe into a key containing
    // newlines (which then failed in every forwarded header).
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(Zeroizing::new(buf))
}

/// master password check before export; returns the password read so the export can reuse it.
fn check_master_password(paths: &Paths, from_stdin: bool) -> Result<Zeroizing<String>> {
    let unlocked = store::unlock(paths)?;
    warn_if_degraded(paths, unlocked.from_backup);
    let Some(hash) = unlocked.store.password_hash.as_deref() else {
        return Err(Error::msg(
            "master password not set; run init --force first to reinitialize and set one",
        ));
    };
    let password = Zeroizing::new(crate::password::read_existing_password(from_stdin)?);
    if !crate::password::verify_password(&password, hash)? {
        return Err(Error::msg("incorrect master password"));
    }
    Ok(password)
}

pub(crate) fn cmd_serve(paths: Paths, args: ServeArgs) -> Result<()> {
    #[cfg(unix)]
    unsafe {
        // bootstrap restores SIGPIPE to SIG_DFL for CLI pipe semantics, but hyper/tokio rely
        // on std's default SIG_IGN (no MSG_NOSIGNAL on Linux); serve is a long-lived process,
        // and writing to the socket when a client aborts an SSE stream returns EPIPE, so
        // SIGPIPE must be ignored or the whole gateway gets killed by signal 13 (this also
        // overrides systemd's IgnoreSIGPIPE).
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    let addr: std::net::SocketAddr = args
        .listen
        .parse()
        .map_err(|e| Error::msg(format!("invalid listen address `{}`: {e}", args.listen)))?;
    if !addr.ip().is_loopback() && !args.allow_remote {
        return Err(Error::msg(
            "listen address is not loopback; for remote access add --allow-remote and put TLS in front yourself",
        ));
    }
    if args.body_limit_mb == 0 || args.body_limit_mb > 1024 {
        return Err(Error::msg("body-limit-mb must be within 1..=1024"));
    }
    if args.max_concurrent == 0 || args.max_concurrent > 4096 {
        return Err(Error::msg("max-concurrent must be within 1..=4096"));
    }
    if args.drain_timeout_secs > 600 {
        return Err(Error::msg("drain-timeout-secs must be within 0..=600"));
    }
    // Every in-flight request may buffer its whole body in memory, so the two
    // knobs multiply: warn when the worst case is large enough to invite the
    // OOM killer on a small host, rather than discovering it under load.
    // (u64: the product exceeds a 32-bit usize at the largest allowed values.)
    let worst_case_bytes = (args.body_limit_mb as u64) * 1024 * 1024 * (args.max_concurrent as u64);
    if worst_case_bytes > 2 * 1024 * 1024 * 1024 {
        tracing::warn!(
            body_limit_mb = args.body_limit_mb,
            max_concurrent = args.max_concurrent,
            worst_case_gib = worst_case_bytes / (1024 * 1024 * 1024),
            "worst-case buffered request bodies is large; lower --body-limit-mb or --max-concurrent if this host is small"
        );
    }
    let audit = match &args.audit_log {
        Some(path) => {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            if !parent.exists() {
                return Err(Error::msg(format!(
                    "audit log directory does not exist: {}",
                    parent.display()
                )));
            }
            crate::audit::probe(path)?;
            let audit = Audit::new(path.clone());
            if !audit.is_enabled() {
                // Audit::new only logs on a failed writer-thread spawn; with
                // --audit-log explicitly requested, running without audit is a
                // configuration error, not a silent degradation.
                return Err(Error::msg(
                    "failed to start the audit writer thread; refusing to run with auditing silently disabled",
                ));
            }
            audit
        }
        None => Audit::disabled(),
    };

    // standalone experience: when uninitialized in an interactive terminal, run init on the
    // spot (setting the master password) and continue starting up.
    // Never hang in non-interactive use: error out directly with the init command.
    if !paths.master_key().exists() {
        if !std::io::stdin().is_terminal() {
            return Err(Error::msg(format!(
                "vault not initialized ({} missing). Re-running serve in an interactive terminal \
                 auto-initializes it; non-interactive environments must run `keysink init [--password-stdin]` first",
                paths.master_key().display()
            )));
        }
        println!(
            "==> vault not initialized, initializing now: {}",
            paths.home.display()
        );
        cmd_init(&paths, false, false)?;
    }

    let unlocked = store::unlock(&paths)?;
    if unlocked.from_backup && !confirm_degraded_start(&paths, args.accept_degraded)? {
        return Err(Error::msg("aborted: not serving the stale backup"));
    }
    let table = vkey::RouteTable::build(&unlocked.store)?;
    let routes = table.len();
    let from_backup = unlocked.from_backup;
    let store_path = paths.store();

    let clients = proxy::ProxyClients::new()?;

    let retry = RetryPolicy {
        max_retries: args.max_retries.min(10),
        ..RetryPolicy::default()
    };

    let counters = Arc::new(proxy::ServeCounters::default());
    let state = Arc::new(AppState {
        snapshot: ArcSwap::from_pointee(Snapshot {
            store: Arc::new(unlocked.store),
            table,
            from_backup,
        }),
        clients,
        retry,
        body_limit: args.body_limit_mb * 1024 * 1024,
        body_read_idle: proxy::BODY_READ_IDLE,
        inbound_body_timeout: proxy::CLIENT_BODY_TIMEOUT,
        permit_queue_timeout: proxy::PERMIT_QUEUE_TIMEOUT,
        body_total_budget: proxy::BODY_TOTAL_BUDGET,
        reload: Arc::new(proxy::ReloadStatus::default()),
        counters: counters.clone(),
        inbound_permits: Arc::new(tokio::sync::Semaphore::new(args.max_concurrent)),
        audit,
        started: Instant::now(),
    });

    let drain_timeout =
        (args.drain_timeout_secs > 0).then(|| Duration::from_secs(args.drain_timeout_secs));

    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| Error::msg(format!("failed to create tokio runtime: {e}")))?;
    let audit_state = state.clone();
    let result = runtime.block_on(async move {
        proxy::spawn_watcher(state.clone(), paths.clone());
        let app = proxy::build_app(state);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| {
                let hint = if e.kind() == std::io::ErrorKind::AddrInUse {
                    // platform-appropriate way to see what holds the port
                    let probe = if cfg!(target_os = "macos") {
                        "`lsof -iTCP -sTCP:LISTEN | grep keysink`"
                    } else if cfg!(target_os = "linux") {
                        "`systemctl status keysink` (system installs) or `ss -ltnp | grep keysink`"
                    } else {
                        "check what is listening on the port"
                    };
                    format!(
                        " (port already in use: another keysink may be running; {probe}, or change --listen)"
                    )
                } else {
                    String::new()
                };
                Error::msg(format!("failed to listen on {addr}: {e}{hint}"))
            })?;
        // Record the actual bound address as soon as the bind succeeds: route
        // add relies on it to report where the gateway is listening. This must
        // be the listener's address, not the requested one — `--listen
        // 127.0.0.1:0` (any free port) would otherwise be recorded as `:0`.
        let bound = listener.local_addr().unwrap_or(addr);
        util::atomic_write(
            &paths.gateway_addr(),
            format!("{bound}\n").as_bytes(),
            0o600,
        )?;
        tracing::info!(addr = %bound, routes, from_backup, store = %store_path.display(), "keysink started");
        if let Some(path) = args.audit_log {
            tracing::info!(audit = %path.display(), "audit enabled");
        } else {
            tracing::info!("audit disabled (enable with --audit-log)");
        }
        let serve_result = proxy::serve_inbound(
            listener,
            app,
            proxy::InboundLimits {
                header_timeout: proxy::CLIENT_HEADER_TIMEOUT,
                // Connections legitimately outnumber in-flight requests:
                // idle keep-alive and long-lived SSE hold a connection but
                // no request permit.
                max_connections: (args.max_concurrent * 8).clamp(256, 16_384),
                drain_timeout,
                loop_iterations: None,
                live_connections: None,
                counters: Some(counters.clone()),
            },
            shutdown_signal(),
        )
        .await
        .map_err(|e| Error::msg(format!("server exited abnormally: {e}")));
        // Remove gateway.addr on shutdown; it can still linger after SIGKILL, so route add falls back to TCP probing
        let _ = std::fs::remove_file(paths.gateway_addr());
        serve_result
    });
    // Drain the audit queue on shutdown and wait for the writer thread to flush, to avoid losing trailing audit lines.
    audit_state.audit.close();
    result
}

/// Degraded-start gate: the primary store failed to decrypt, so `serve` would
/// run on the .bak backup, which lags one write behind — vkeys rotated or
/// removed since that write become valid again. Availability-first still
/// holds for non-interactive runs (systemd restarts must not wedge), but a
/// human at a terminal gets the decision; either way the banner goes to
/// stderr so it lands in the journal too. Returns true = proceed.
fn confirm_degraded_start(paths: &Paths, accepted: bool) -> Result<bool> {
    eprintln!();
    eprintln!("=================================================================");
    eprintln!(" DEGRADED VAULT: the primary store failed to decrypt.");
    eprintln!(" The gateway would serve the .bak backup, which is one write");
    eprintln!(" behind: vkeys rotated or removed since then WORK AGAIN.");
    eprintln!("=================================================================");
    eprintln!(" store:    {}", paths.store().display());
    eprintln!(" backup:   {}", paths.store_bak().display());
    eprintln!(" inspect:  keysink doctor");
    eprintln!(
        " recover:  cp {} {}",
        paths.store_bak().display(),
        paths.store().display()
    );
    if accepted {
        eprintln!(" (--accept-degraded given; starting)");
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        eprintln!(" (non-interactive: starting anyway — fix the store as soon as possible)");
        return Ok(true);
    }
    eprint!("Start on the stale backup anyway? [y/N] ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    if matches!(line.trim(), "y" | "Y" | "yes" | "YES") {
        Ok(true)
    } else {
        eprintln!(
            "rerun with --accept-degraded to force, or restore the backup over the store first"
        );
        Ok(false)
    }
}

async fn shutdown_signal() {
    wait_for_shutdown_signal().await;
    // tokio's libc signal handler stays registered for the process lifetime
    // (its docs: once registered, never unregistered), so after this future
    // resolves and the Signal streams drop, further SIGINT/SIGTERM are
    // swallowed by a broadcast with no receivers. The graceful drain could
    // then wait on a long-lived SSE stream forever with no way out short of
    // SIGKILL — so re-arm and treat a second signal as an immediate exit.
    // Exit code 128 + signum (130 = SIGINT, 143 = SIGTERM): the process was
    // ordered to die, not to finish cleanly, and the shell sees the same $?
    // it would for a kill by that signal; tail audit lines (≤50ms of buffer)
    // may be lost.
    tokio::spawn(async {
        let signum = wait_for_shutdown_signal().await;
        // Bounded drain of the log queue first: process::exit does not wait
        // for the non-blocking log thread, so without this whatever is still
        // queued is lost. Short — the user asked to leave now. The notice
        // itself goes to stderr via writeln! (not the log, which may be the
        // thing that is backed up, and not eprintln!, which panics if the
        // stderr write fails).
        util::flush_logs(Duration::from_millis(500));
        let _ = writeln!(
            std::io::stderr(),
            "keysink: second shutdown signal; exiting now (in-flight connections dropped)"
        );
        std::process::exit(128 + signum as i32);
    });
}

/// Resolves with the caught signal's number (2 = SIGINT, 15 = SIGTERM), so
/// the second-signal exit can report the code matching what actually fired.
async fn wait_for_shutdown_signal() -> u8 {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
        2
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
        15
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<u8>();
    tokio::select! {
        signum = ctrl_c => signum,
        signum = terminate => signum,
    }
}

pub(crate) fn cmd_status(paths: &Paths) -> Result<()> {
    let unlocked = store::unlock(paths)?;
    warn_if_degraded(paths, unlocked.from_backup);
    let store = &unlocked.store;
    println!("home:        {}", paths.home.display());
    println!("store:       {}", paths.store().display());
    println!(
        "backup:      {}",
        if paths.store_bak().exists() {
            "yes"
        } else {
            "no"
        }
    );
    println!("schema:      {}", store.version);
    println!(
        "routes:      {} (enabled {})",
        store.routes.len(),
        store.routes.values().filter(|r| r.enabled).count()
    );
    Ok(())
}

pub(crate) fn cmd_doctor(paths: &Paths) -> Result<()> {
    let mut failures = 0usize;
    let mut check = |ok: bool, label: &str, detail: String| {
        println!("{} {:<28} {}", if ok { "✓" } else { "✗" }, label, detail);
        if !ok {
            failures += 1;
        }
    };

    check(
        paths.home.is_dir(),
        "home",
        paths.home.display().to_string(),
    );
    if paths.home.is_dir() {
        match util::ensure_private_dir(&paths.home) {
            Ok(()) => check(true, "home perms", "0700".into()),
            Err(e) => check(false, "home perms", e.to_string()),
        }
        // When root manages the vault directly with sudo, files end up root-owned and the
        // service user cannot read them — surfacing as every vkey suddenly failing with 401.
        // Warn early when an owner mismatches the directory.
        for (path, label) in [
            (paths.master_key(), "vault.key owner"),
            (paths.store(), "vault.age owner"),
            (paths.store_bak(), "vault.age.bak owner"),
        ] {
            if !path.exists() {
                continue;
            }
            match util::owner_matches_dir(&path) {
                Ok(true) => check(true, label, "ok".into()),
                Ok(false) => check(
                    false,
                    label,
                    format!(
                        "owner does not match {} (possibly written directly with sudo); the service user cannot read it",
                        paths.home.display()
                    ),
                ),
                Err(e) => check(false, label, e.to_string()),
            }
        }
    }

    let identity = match store::load_identity(paths) {
        Ok(identity) => {
            check(true, "vault.key", "parse ok".into());
            Some(identity)
        }
        Err(e) => {
            check(false, "vault.key", e.to_string());
            None
        }
    };

    if let Some(identity) = &identity {
        match store::load_store_file(&paths.store(), identity) {
            Ok(store) => {
                check(true, "vault.age", "decrypt ok".into());
                match store.validate() {
                    Ok(()) => check(true, "schema", "validate ok".into()),
                    Err(e) => check(false, "schema", e.to_string()),
                }
                match vkey::RouteTable::build(&store) {
                    Ok(table) => check(true, "route table", format!("{} routes", table.len())),
                    Err(e) => check(false, "route table", e.to_string()),
                }
            }
            Err(e) => check(false, "vault.age", e.to_string()),
        }

        if paths.store_bak().exists() {
            match store::load_store_file(&paths.store_bak(), identity) {
                Ok(_) => check(true, "vault.age.bak", "decrypt ok".into()),
                Err(e) => check(false, "vault.age.bak", e.to_string()),
            }
        } else {
            check(
                true,
                "vault.age.bak",
                "missing (created after the first write)".into(),
            );
        }
    } else {
        check(false, "vault.age", "skipped: vault.key unavailable".into());
    }

    if failures == 0 {
        println!("\nall checks passed");
        Ok(())
    } else {
        Err(Error::msg(format!("{failures} checks failed")))
    }
}

/// System-install locations shared by deploy and uninstall (single source of truth).
const SYSTEM_VAULT_HOME: &str = "/var/lib/keysink";
const SYSTEM_BIN: &str = "/usr/local/bin/keysink";
const SYSTEM_UNIT: &str = "/etc/systemd/system/keysink.service";
const SYSTEM_SUDOERS: &str = "/etc/sudoers.d/keysink";

const SYSTEMD_UNIT: &str = r#"[Unit]
Description=keysink vault gateway
Documentation=https://github.com/wusende/keysink
After=network-online.target
Wants=network-online.target
# Don't start before the vault exists (deploy initializes it interactively;
# avoids a crash-restart loop on a fresh install)
ConditionPathExists=/var/lib/keysink/vault.key

[Service]
Type=simple
User=keysink
Group=keysink
ExecStart=/usr/local/bin/keysink serve --listen 127.0.0.1:8787
# Headroom for the serve loop's connection cap (max 16384) plus upstream
# sockets; the Linux default (often 1024) would be the real ceiling long
# before the gateway's own limits.
LimitNOFILE=16384
Environment=KEYSINK_VAULT_HOME=/var/lib/keysink
Environment=RUST_LOG=info
StateDirectory=keysink
StateDirectoryMode=0700
UMask=0077
Restart=on-failure
RestartSec=2
# Graceful shutdown: `serve` stops accepting, tells every live connection to
# finish and close, and drains for at most --drain-timeout-secs (default 10s)
# before dropping what is left. This is the backstop above that: long enough
# for the drain to finish on its own, short enough that a wedged process still
# goes away. Keep it above the drain timeout.
TimeoutStopSec=30

# Hardening: no core dumps, no privilege regain, read-only home
LimitCORE=0
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/keysink
# If you enable auditing, also allow the audit directory:
# ReadWritePaths=/var/log/keysink

[Install]
WantedBy=multi-user.target
"#;

/// `__ADMIN__` is substituted with the invoking admin (SUDO_USER) at deploy time.
const SUDOERS_TEMPLATE: &str = r#"# /etc/sudoers.d/keysink
#
# Vault administration: requires the admin's login password, and every
# command re-authenticates. Never add NOPASSWD; never widen with wildcards.

Cmnd_Alias KEYSINK_CMDS = /usr/local/bin/keysink

Defaults!KEYSINK_CMDS timestamp_timeout=0, timestamp_type=tty

__ADMIN__ ALL=(keysink) KEYSINK_CMDS
"#;

fn run_checked(what: &str, program: &str, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new(program)
        .args(args)
        .status()
        .map_err(|e| Error::msg(format!("failed to execute {program}: {e}")))?;
    if !status.success() {
        return Err(Error::msg(format!("{what} failed (exit {status})")));
    }
    Ok(())
}

pub(crate) fn cmd_deploy() -> Result<()> {
    if !std::path::Path::new("/run/systemd/system").exists() {
        return Err(Error::msg(
            "system-level deploy supports only Linux + systemd; for personal use just run `keysink serve`",
        ));
    }
    #[cfg(unix)]
    let root = unsafe { libc::geteuid() } == 0;
    #[cfg(not(unix))]
    let root = false;
    if !root {
        return Err(Error::msg("run with sudo: sudo keysink deploy"));
    }
    // sudoers allows only the admin who initiated the deploy; refuse when unknown,
    // to avoid allowlisting the wrong person
    let admin = std::env::var("SUDO_USER").map_err(|_| {
        Error::msg("run via the admin account's sudo (SUDO_USER is needed to generate the sudoers allowlist)")
    })?;

    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|e| Error::msg(format!("failed to locate the current binary: {e}")))?;
    let exe = exe.to_string_lossy();

    // leftovers from the old dual-binary deploy, clean them up
    let _ = std::fs::remove_file("/usr/local/bin/keysink-admin");
    let _ = std::fs::remove_file("/etc/sudoers.d/keysink-admin");

    let user_exists = std::process::Command::new("id")
        .arg("keysink")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !user_exists {
        run_checked(
            "create keysink user",
            "useradd",
            &[
                "--system",
                "--home-dir",
                SYSTEM_VAULT_HOME,
                "--shell",
                "/usr/sbin/nologin",
                "keysink",
            ],
        )?;
    }
    run_checked(
        "create vault directory",
        "install",
        &[
            "-d",
            "-o",
            "keysink",
            "-g",
            "keysink",
            "-m",
            "0700",
            SYSTEM_VAULT_HOME,
        ],
    )?;
    run_checked(
        "install binary",
        "install",
        &["-m", "0755", &exe, SYSTEM_BIN],
    )?;

    std::fs::write(SYSTEM_UNIT, SYSTEMD_UNIT)
        .map_err(|e| Error::msg(format!("failed to write unit: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(SYSTEM_UNIT, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| Error::msg(format!("failed to set unit permissions: {e}")))?;
    }

    // sudoers goes to a temp file first and is put in place only after visudo
    // validates it: a syntax error never leaves a broken config behind
    let tmp = format!("{SYSTEM_SUDOERS}.new");
    std::fs::write(&tmp, SUDOERS_TEMPLATE.replace("__ADMIN__", &admin))
        .map_err(|e| Error::msg(format!("failed to write sudoers: {e}")))?;
    let valid = std::process::Command::new("visudo")
        .args(["-cf", &tmp])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !valid {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::msg(
            "sudoers validation failed; aborted (existing file untouched)",
        ));
    }
    std::fs::rename(&tmp, SYSTEM_SUDOERS)
        .map_err(|e| Error::msg(format!("failed to install sudoers: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(SYSTEM_SUDOERS, std::fs::Permissions::from_mode(0o440))
            .map_err(|e| Error::msg(format!("failed to set sudoers permissions: {e}")))?;
    }

    // --home must be explicit: without vault.key the default-directory probe falls
    // back to the caller's own standalone directory, and runuser's HOME drift would
    // write the first init to the wrong place.
    if !std::path::Path::new(&format!("{SYSTEM_VAULT_HOME}/vault.key")).exists() {
        if std::io::stdin().is_terminal() {
            println!(
                "==> initializing vault (set the master password; used only for backup export/restore)"
            );
            run_checked(
                "initialize vault",
                "runuser",
                &[
                    "-u",
                    "keysink",
                    "--",
                    SYSTEM_BIN,
                    "--home",
                    SYSTEM_VAULT_HOME,
                    "init",
                ],
            )?;
        } else {
            eprintln!("vault not yet initialized and no terminal is available; run manually:");
            eprintln!("  runuser -u keysink -- {SYSTEM_BIN} --home {SYSTEM_VAULT_HOME} init");
        }
    }

    // a new binary/unit requires a restart: enable --now won't touch a running old instance
    run_checked("systemctl daemon-reload", "systemctl", &["daemon-reload"])?;
    let active = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "keysink"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if active {
        run_checked("restart service", "systemctl", &["restart", "keysink"])?;
    } else {
        run_checked(
            "start service",
            "systemctl",
            &["enable", "--now", "keysink"],
        )?;
    }

    println!();
    println!("Installation complete.");
    println!();
    println!("Next steps (add a route, admin {admin}):");
    println!("  sudo -u keysink keysink route add claude --base-url https://api.anthropic.com");
    println!(
        "  # in a terminal each field is prompted in turn: name / base URL / upstream auth / key value (hidden echo, goes in but never out)"
    );
    println!(
        "  # in scripts: printf %s \"$KEY\" | sudo -u keysink keysink route add <name> --base-url ..."
    );
    println!();
    println!("agent-side config (route add prints these two lines at the end):");
    println!("  BASE_URL=http://127.0.0.1:8787");
    println!("  TOKEN=ks_...");
    println!();
    println!("vault files: {SYSTEM_VAULT_HOME}");
    println!("service status: systemctl status keysink");
    println!("uninstall: keysink uninstall");
    Ok(())
}

pub(crate) fn cmd_uninstall(paths: &Paths, yes: bool) -> Result<()> {
    let home = paths.home.clone();
    let system = home == std::path::Path::new(SYSTEM_VAULT_HOME);

    #[cfg(unix)]
    let root = unsafe { libc::geteuid() } == 0;
    #[cfg(not(unix))]
    let root = false;

    if system && !root {
        return Err(Error::msg(
            "this is a system-level install; run as root: sudo keysink uninstall",
        ));
    }

    // The vault directory comes straight from --home / KEYSINK_VAULT_HOME, and
    // this command recursively deletes it. Never trust the path alone: a typo
    // (`--home .`, a shared project directory) would erase unrelated files.
    // A system install is anchored at the deploy path, so the marker check is
    // skipped there; everything else must actually look like a vault.
    if home.exists() {
        match std::fs::symlink_metadata(&home) {
            Ok(md) if md.file_type().is_symlink() => {
                return Err(Error::msg(format!(
                    "refusing to uninstall through a symlink: {}",
                    home.display()
                )));
            }
            Ok(md) if !md.is_dir() => {
                return Err(Error::msg(format!(
                    "refusing to uninstall: {} is not a directory",
                    home.display()
                )));
            }
            Ok(_) => {}
            Err(e) => return Err(Error::from(e)),
        }
        if !system && !looks_like_vault(&home) {
            return Err(Error::msg(format!(
                "refusing to delete {}: it does not look like a keysink vault (no vault.key/vault.age). \
                 Point --home at the vault directory, or remove the directory yourself if you are sure.",
                home.display()
            )));
        }
    }

    if !yes {
        if !std::io::stdin().is_terminal() {
            return Err(Error::msg("non-interactive mode requires --yes"));
        }
        eprintln!(
            "This will delete the vault ({}) — all keys and routes will be lost for good.",
            home.display()
        );
        if system {
            eprintln!("This also removes the systemd unit, sudoers and /usr/local/bin/keysink.");
        }
        eprint!("Continue? [y/N] ");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if !matches!(line.trim(), "y" | "Y" | "yes" | "YES") {
            return Err(Error::msg("cancelled"));
        }
    }

    // stop the service before deleting files; the unit may not exist, ignore failures
    if system {
        for args in [
            ("systemctl", ["stop", "keysink"].as_slice()),
            ("systemctl", ["disable", "keysink"].as_slice()),
            ("systemctl", ["daemon-reload"].as_slice()),
        ] {
            let _ = std::process::Command::new(args.0).args(args.1).status();
        }
    }

    let mut removed: Vec<PathBuf> = Vec::new();
    if home.exists() {
        std::fs::remove_dir_all(&home)
            .map_err(|e| Error::msg(format!("failed to delete {}: {e}", home.display())))?;
        removed.push(home.clone());
    }
    if system {
        for f in [SYSTEM_UNIT, SYSTEM_SUDOERS, SYSTEM_BIN] {
            let p = PathBuf::from(f);
            if p.exists() {
                std::fs::remove_file(&p)
                    .map_err(|e| Error::msg(format!("failed to delete {}: {e}", p.display())))?;
                removed.push(p);
            }
        }
    }

    if removed.is_empty() {
        println!(
            "nothing to delete (vault does not exist: {})",
            home.display()
        );
        return Ok(());
    }
    println!("Uninstalled. Removed:");
    for p in &removed {
        println!("  - {}", p.display());
    }
    if !system {
        // the standalone binary was placed by the user (manually/cargo install/brew);
        // deleting it for them could break the package manager
        if let Ok(exe) = std::env::current_exe() {
            println!(
                "the binary itself was not deleted: {}; clean it up yourself",
                exe.display()
            );
        }
        println!(
            "if serve is still running, stop it separately; if --audit-log was used, delete the audit file yourself as well."
        );
    }
    Ok(())
}

/// Whether a directory carries the files keysink itself writes. Used by
/// `uninstall` as a guard: the command recursively deletes `--home`, so a
/// mistyped or shared path must not erase unrelated data.
fn looks_like_vault(home: &std::path::Path) -> bool {
    const MARKERS: [&str; 4] = ["vault.key", "vault.age", "vault.age.bak", "vault.lock"];
    if MARKERS.iter().any(|name| home.join(name).exists()) {
        return true;
    }
    // A failed `init --force` can leave only the renamed `.old.<millis>` pairs.
    std::fs::read_dir(home).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("vault.key.old.")
                || name.starts_with("vault.age.old.")
                || name.starts_with("vault.key.bak.old.")
                || name.starts_with("vault.age.bak.old.")
        })
    })
}

pub(crate) fn cmd_rekey(paths: &Paths, yes: bool) -> Result<()> {
    if store::external_identity_configured() {
        return Err(Error::msg(
            "refusing to rotate the master key while KEYSINK_MASTER_KEY / KEYSINK_MASTER_KEY_FILE \
             is set: rekey replaces vault.key, but the running gateway keeps using the external \
             identity and could no longer decrypt the store. Rotate the external credential first \
             (or unset it and use the vault file), then retry.",
        ));
    }
    if !yes {
        if !std::io::stdin().is_terminal() {
            return Err(Error::msg("non-interactive mode requires --yes"));
        }
        eprintln!(
            "This will generate a new vault.key and re-encrypt the vault. The old key stays in vault.key.bak."
        );
        eprint!("Continue? [y/N] ");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if !matches!(line.trim(), "y" | "Y" | "yes" | "YES") {
            return Err(Error::msg("cancelled"));
        }
    }
    store::rekey(paths)?;
    println!(
        "Master key rotated. Old key: {}",
        paths.master_key_bak().display()
    );
    println!(
        "Note: old backups can still be decrypted with the old key; back up vault.key + vault.age again."
    );
    Ok(())
}

pub(crate) fn cmd_export(paths: &Paths, args: ExportArgs) -> Result<()> {
    let master = check_master_password(paths, args.password_stdin)?;
    let passphrase: Zeroizing<String> = if let Some(file) = &args.passphrase_file {
        let bytes = Zeroizing::new(std::fs::read(file)?);
        let text = Zeroizing::new(
            String::from_utf8(bytes.to_vec())
                .map_err(|_| Error::msg("passphrase file is not UTF-8"))?,
        );
        Zeroizing::new(text.lines().next().unwrap_or("").to_string())
    } else {
        master
    };
    if passphrase.is_empty() {
        return Err(Error::msg("passphrase must not be empty"));
    }
    let stripped = store::export(paths, &args.output, &passphrase)?;
    println!("exported: {}", args.output.display());
    println!(
        "Note: the export contains the working vkeys of every route — anyone who can decrypt it \
         can use your gateway while it runs. Store it as carefully as the keys themselves."
    );
    if stripped > 0 {
        println!(
            "Note: the export contains no key values (route-only keys of {stripped} routes were stripped); \
             re-enter each one with `route update <name> --route-key` after restoring"
        );
    }
    Ok(())
}

/// Current gateway location: serve writes the actual listen address into `<home>/gateway.addr`
/// at startup and removes the file on exit; `None` here means the gateway is not running and
/// no trustworthy address is known — callers must not substitute the compile-time default.
/// `Some((host:port, reachable))`: the address serve actually bound, plus a TCP probe.
fn current_gateway(paths: &Paths) -> Option<(String, bool)> {
    let addr = std::fs::read_to_string(paths.gateway_addr())
        .ok()
        .and_then(|text| {
            let line = text.lines().next()?.trim();
            (!line.is_empty()).then(|| line.to_string())
        })?;
    let reachable = addr
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|a| std::net::TcpStream::connect_timeout(&a, Duration::from_millis(300)).is_ok())
        .unwrap_or(false);
    Some((addr, reachable))
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_string()
    } else {
        let mut out: String = value.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn route_key_label(route: &Route) -> String {
    match &route.inline_key {
        Some(_) => "(route-only, cannot be read/exported)".to_string(),
        None => "(missing)".to_string(),
    }
}

/// Surfaces the `.bak` fallback on read-only commands. Writes are refused
/// outright in [`store::update`] / [`store::rekey`] / [`store::export`]; a
/// read can still be useful for inspection, but the operator must know that
/// the data is one generation behind and may revive revoked vkeys.
fn warn_if_degraded(paths: &Paths, from_backup: bool) {
    if from_backup {
        eprintln!(
            "warning: the primary store {} could not be decrypted; showing the older backup {}. \
             Revoked or rotated vkeys may work again from it. Run `keysink doctor`, repair the \
             primary, and retry before making changes.",
            paths.store().display(),
            paths.store_bak().display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_home_prefers_absolute_xdg_then_home() {
        use std::ffi::OsStr;
        // An absolute XDG path wins; on Windows an absolute path needs a
        // drive prefix — "/xdg/data" is rooted but driveless and NOT absolute.
        let xdg = if cfg!(windows) {
            "C:/xdg/data"
        } else {
            "/xdg/data"
        };
        assert_eq!(
            standalone_home_from(Some(OsStr::new(xdg)), Some(OsStr::new("/home/u"))),
            PathBuf::from(format!("{xdg}/keysink"))
        );
        #[cfg(unix)]
        {
            assert_eq!(
                standalone_home_from(None, Some(OsStr::new("/home/u"))),
                PathBuf::from("/home/u/.local/share/keysink")
            );
            // A relative XDG path is untrustworthy; ignore it
            assert_eq!(
                standalone_home_from(Some(OsStr::new("rel")), Some(OsStr::new("/home/u"))),
                PathBuf::from("/home/u/.local/share/keysink")
            );
        }
    }

    #[test]
    fn resolve_required_prefers_given_and_errors_without_tty() {
        assert_eq!(
            resolve_required(Some("  x  ".into()), "label", "--flag").unwrap(),
            "x"
        );
        // The non-TTY error branch is only observable when the test process's
        // stdin is not a terminal; from a real terminal resolve_required(None)
        // would block in prompt_line waiting for a line and the suite appears
        // to hang. CI and non-interactive runs (no TTY) still cover the branch.
        if std::io::stdin().is_terminal() {
            return;
        }
        let err = resolve_required(None, "label", "--flag")
            .unwrap_err()
            .to_string();
        assert!(err.contains("--flag"), "{err}");
    }

    #[test]
    fn uninstall_refuses_a_directory_that_is_not_a_vault() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("not-a-vault");
        std::fs::create_dir(&home).unwrap();
        std::fs::write(home.join("keep.txt"), b"unrelated").unwrap();

        let err = cmd_uninstall(&Paths::vault(home.clone()), true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not look like a keysink vault"), "{err}");
        assert!(
            home.join("keep.txt").exists(),
            "the unrelated directory must be untouched"
        );
    }

    #[test]
    fn uninstall_removes_a_real_vault() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("vault");
        let paths = Paths::vault(home.clone());
        store::init(&paths, false, "test-password").unwrap();
        cmd_uninstall(&paths, true).unwrap();
        assert!(!home.exists());
    }

    #[cfg(unix)]
    #[test]
    fn uninstall_refuses_a_symlinked_home() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("vault.key"), b"key").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = cmd_uninstall(&Paths::vault(link), true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("symlink"), "{err}");
        assert!(target.join("vault.key").exists());
    }

    #[test]
    fn current_gateway_reads_runtime_file_and_probes() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::vault(dir.path().join("v"));
        util::create_private_dir_all(&paths.home).unwrap();
        // no runtime file: serve is not running and the address is unknown —
        // callers must not fall back to the compile-time default port
        assert_eq!(current_gateway(&paths), None);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let live = listener.local_addr().unwrap();
        util::atomic_write(&paths.gateway_addr(), format!("{live}\n").as_bytes(), 0o600).unwrap();
        let (addr, alive) = current_gateway(&paths)
            .expect("gateway.addr written, current_gateway must return Some");
        assert_eq!(addr, live.to_string());
        assert!(alive);

        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        util::atomic_write(
            &paths.gateway_addr(),
            format!("{dead_addr}\n").as_bytes(),
            0o600,
        )
        .unwrap();
        let (_, alive) = current_gateway(&paths)
            .expect("gateway.addr written, current_gateway must return Some");
        assert!(!alive);
    }
}
