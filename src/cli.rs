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
use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(
    name = "keysink",
    version,
    about = "本地凭证网关：agent 只认 vkey，上游 key 只进不出（不可读取/导出）",
    long_about = None
)]
pub struct Cli {
    /// vault directory (default: $KEYSINK_VAULT_HOME or /var/lib/keysink)
    #[arg(long, global = true, env = "KEYSINK_VAULT_HOME", value_name = "DIR")]
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
    let password = crate::password::read_new_password(password_stdin)?;
    store::init(paths, force, &password)?;
    println!("vault 初始化完成: {}", paths.home.display());
    println!("  {}  0600", paths.master_key().display());
    println!("  {}  0600", paths.store().display());
    println!();
    println!("master password 只用于 `export` 备份的加密与恢复；写入/轮换/serve 都不需要它。");
    println!("下一步：");
    println!("  keysink route add claude --base-url https://api.anthropic.com");
    println!(
        "  # 终端里引导输入 key（隐藏回显）；脚本里：printf %s \"$KEY\" | keysink route add ..."
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
    #[arg(long, default_value_t = crate::retry::DEFAULT_MAX_RETRIES)]
    pub max_retries: u8,
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
                resolve_required(args.name.clone(), "Route 名称（例：claude）", "route 名称")?;
            validate_name(&name, "route")?;
            let base_url = resolve_required(
                args.base_url.clone(),
                "上游 base URL（例：https://api.anthropic.com）",
                "--base-url",
            )?;
            let base_url = base_url.trim_end_matches('/').to_string();
            if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
                return Err(Error::msg("base_url 必须以 http:// 或 https:// 开头"));
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
                    return Err(Error::msg(format!("route `{name}` 已存在")));
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
            println!("route `{name}` 已创建（key 只进不出：不可读取/导出）");
            println!("auth: {}    base_url: {}", auth_out.describe(), base_url);
            println!("vkey: {token_out}");
            println!("（vkey 只显示这一次；丢失后只能 `keysink route rotate {name}` 换新）");
            let (gw, alive) = current_gateway(paths);
            println!(
                "网关: http://{gw}（{}）",
                if alive {
                    "运行中"
                } else {
                    "未响应——确认 serve 已启动"
                }
            );
            println!("agent 侧配置（OpenAI 兼容客户端的 base_url 通常带 /v1）：");
            println!("  BASE_URL=http://{gw}");
            println!("  TOKEN={token_out}");
            Ok(())
        }
        RouteCmd::Ls => {
            let unlocked = store::unlock(paths)?;
            if unlocked.store.routes.is_empty() {
                println!("（空）");
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
            let route = unlocked
                .store
                .routes
                .get(&name)
                .ok_or_else(|| Error::msg(format!("route `{name}` 不存在")))?;
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
                    None => "（跟随系统代理环境变量）",
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
                    .ok_or_else(|| Error::msg(format!("route `{name}` 不存在")))?;
                route.vkey = token.clone();
                Ok(())
            })?;
            println!("route `{name}` 已轮换，旧 vkey 立即失效");
            println!("vkey: {token_out}");
            println!("（把 agent 配置里的 vkey 更新为新值）");
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
                return Err(Error::msg("base_url 必须以 http:// 或 https:// 开头"));
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
                return Err(Error::msg("--proxy 与 --clear-proxy 互斥"));
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
                    "--clear-retry 与 --max-retries / --retry-on-status 互斥",
                ));
            }
            store::update(paths, |store| {
                let route = store
                    .routes
                    .get_mut(&args.name)
                    .ok_or_else(|| Error::msg(format!("route `{}` 不存在", args.name)))?;
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
            println!("route `{}` 已更新（vkey 不变）", args.name);
            Ok(())
        }
        RouteCmd::Rm { name } => {
            store::update(paths, |store| {
                store
                    .routes
                    .remove(&name)
                    .ok_or_else(|| Error::msg(format!("route `{name}` 不存在")))?;
                Ok(())
            })?;
            println!("route `{name}` 已删除");
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
            .ok_or_else(|| Error::msg(format!("route `{name}` 不存在")))?;
        route.enabled = enable;
        Ok(())
    })?;
    println!("route `{name}` 已{}", if enable { "启用" } else { "禁用" });
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
        "上游接口 [1]OpenAI 兼容(含responses,默认) [2]Claude/Anthropic [3]Gemini [4]其他",
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
        other => Err(Error::msg(format!("无效的接口类型: {other}"))),
    }
}

/// Auth primitives expanded from the "other" choice, for non-mainstream upstreams (basic, query parameters, etc.).
fn prompt_auth_detail() -> Result<AuthChoice> {
    let choice = prompt_line(
        "认证方式 [1]bearer(默认) [2]x-api-key [3]自定义header [4]basic [5]query [6]none",
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
            let name = prompt_line("header 名（例：x-goog-api-key）", None)?;
            let prefix = prompt_line("值前缀（回车=无，例：Bearer ）", Some(""))?;
            AuthChoice {
                kind: AuthKind::Header,
                header: Some(name),
                prefix: (!prefix.is_empty()).then_some(prefix),
                user: None,
                param: None,
            }
        }
        "4" | "basic" => {
            let user = prompt_line("Basic 用户名", None)?;
            AuthChoice {
                kind: AuthKind::Basic,
                header: None,
                prefix: None,
                user: Some(user),
                param: None,
            }
        }
        "5" | "query" => {
            let param = prompt_line("query 参数名（例：key）", None)?;
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
        other => return Err(Error::msg(format!("无效的认证方式: {other}"))),
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
        "上游代理（回车=跟随系统代理；direct=强制直连；或 http(s)://URL）",
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
            let name = auth_header.ok_or_else(|| Error::msg("header 认证需要 --auth-header"))?;
            Ok(Auth::Header {
                name,
                prefix: auth_prefix.unwrap_or_default(),
            })
        }
        AuthKind::Basic => {
            let username = auth_user.ok_or_else(|| Error::msg("basic 认证需要 --auth-user"))?;
            Ok(Auth::Basic { username })
        }
        AuthKind::Query => {
            let param = auth_param.ok_or_else(|| Error::msg("query 认证需要 --auth-param"))?;
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
            .ok_or_else(|| Error::msg(format!("header 需要 KEY:VALUE 格式: `{raw}`")))?;
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
        return Err(Error::msg("key 值为空"));
    }
    Ok(text)
}

/// Prompt hidden twice and require the entries to match; the value is never echoed and never lands on the command line.
fn prompt_hidden_twice() -> Result<Zeroizing<String>> {
    let first = Zeroizing::new(
        rpassword::prompt_password("Key value: ")
            .map_err(|e| Error::msg(format!("读取输入失败: {e}")))?,
    );
    let second = Zeroizing::new(
        rpassword::prompt_password("Repeat: ")
            .map_err(|e| Error::msg(format!("读取输入失败: {e}")))?,
    );
    if first != second {
        return Err(Error::msg("两次输入不一致"));
    }
    if first.is_empty() {
        return Err(Error::msg("key 值为空"));
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
        Some(d) => eprint!("{label}（回车={d}）: "),
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
        Err(Error::msg(format!("缺少 {flag}（非交互环境必须显式传参）")))
    }
}

fn read_stdin() -> Result<Zeroizing<String>> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(Zeroizing::new(buf))
}

/// master password check before export; returns the password read so the export can reuse it.
fn check_master_password(paths: &Paths, from_stdin: bool) -> Result<Zeroizing<String>> {
    let unlocked = store::unlock(paths)?;
    let Some(hash) = unlocked.store.password_hash.as_deref() else {
        return Err(Error::msg(
            "未设置 master password；请先 init --force 重新初始化并设置密码",
        ));
    };
    let password = Zeroizing::new(crate::password::read_existing_password(from_stdin)?);
    if !crate::password::verify_password(&password, hash)? {
        return Err(Error::msg("master password 错误"));
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
        .map_err(|e| Error::msg(format!("listen 地址非法 `{}`: {e}", args.listen)))?;
    if !addr.ip().is_loopback() && !args.allow_remote {
        return Err(Error::msg(
            "listen 不是 loopback；确需远程请加 --allow-remote，并自行在前面加 TLS",
        ));
    }
    if args.body_limit_mb == 0 || args.body_limit_mb > 1024 {
        return Err(Error::msg("body-limit-mb 必须在 1..=1024"));
    }
    let audit = match &args.audit_log {
        Some(path) => {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            if !parent.exists() {
                return Err(Error::msg(format!(
                    "审计日志目录不存在: {}",
                    parent.display()
                )));
            }
            Audit::new(path.clone())
        }
        None => Audit::disabled(),
    };

    // standalone experience: when uninitialized in an interactive terminal, run init on the
    // spot (setting the master password) and continue starting up.
    // Never hang in non-interactive use: error out directly with the init command.
    if !paths.master_key().exists() {
        if !std::io::stdin().is_terminal() {
            return Err(Error::msg(format!(
                "vault 未初始化（{} 缺失）。交互终端重跑 serve 会自动初始化；\
                 非交互环境请先 `keysink init [--password-stdin]`",
                paths.master_key().display()
            )));
        }
        println!("==> vault 未初始化，开始初始化: {}", paths.home.display());
        cmd_init(&paths, false, false)?;
    }

    let unlocked = store::unlock(&paths)?;
    if unlocked.from_backup {
        tracing::error!(
            "主 store 解密失败，本次以 .bak 备份启动；备份可能过期（已吊销/删除的 vkey 可能重新生效），请尽快修复"
        );
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

    let state = Arc::new(AppState {
        snapshot: ArcSwap::from_pointee(Snapshot {
            store: Arc::new(unlocked.store),
            table,
            from_backup,
        }),
        clients,
        retry,
        body_limit: args.body_limit_mb * 1024 * 1024,
        audit,
        started: Instant::now(),
    });

    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| Error::msg(format!("创建 tokio runtime 失败: {e}")))?;
    let audit_state = state.clone();
    let result = runtime.block_on(async move {
        proxy::spawn_watcher(state.clone(), paths.clone());
        let app = proxy::build_app(state);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| {
                let hint = if e.kind() == std::io::ErrorKind::AddrInUse {
                    "（端口已被占用：可能已有一个 keysink 在跑，`systemctl status keysink` 或换 --listen）"
                } else {
                    ""
                };
                Error::msg(format!("监听 {addr} 失败: {e}{hint}"))
            })?;
        // Record the actual listen address as soon as the bind succeeds: route add relies on it to report where it is listening.
        util::atomic_write(&paths.gateway_addr(), format!("{addr}\n").as_bytes(), 0o600)?;
        tracing::info!(%addr, routes, from_backup, store = %store_path.display(), "keysink 已启动");
        if let Some(path) = args.audit_log {
            tracing::info!(audit = %path.display(), "审计已开启");
        } else {
            tracing::info!("审计未开启（--audit-log 可开启）");
        }
        let serve_result = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(|e| Error::msg(format!("服务异常退出: {e}")));
        // Remove gateway.addr on shutdown; it can still linger after SIGKILL, so route add falls back to TCP probing
        let _ = std::fs::remove_file(paths.gateway_addr());
        serve_result
    });
    // Drain the audit queue on shutdown and wait for the writer thread to flush, to avoid losing trailing audit lines.
    audit_state.audit.close();
    result
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

pub(crate) fn cmd_status(paths: &Paths) -> Result<()> {
    let unlocked = store::unlock(paths)?;
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
                        "属主与 {} 不一致（可能用 sudo 直接写入），服务用户会读不到",
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
            check(true, "vault.age.bak", "missing（首次写入后生成）".into());
        }
    } else {
        check(false, "vault.age", "skipped: vault.key 不可用".into());
    }

    if failures == 0 {
        println!("\n全部通过");
        Ok(())
    } else {
        Err(Error::msg(format!("{failures} 项检查失败")))
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
Environment=KEYSINK_VAULT_HOME=/var/lib/keysink
Environment=RUST_LOG=info
StateDirectory=keysink
StateDirectoryMode=0700
UMask=0077
Restart=on-failure
RestartSec=2
# Graceful shutdown waits at most 10s: long SSE streams can't stall a stop
# forever; SIGKILL is the backstop
TimeoutStopSec=10

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
        .map_err(|e| Error::msg(format!("执行 {program} 失败: {e}")))?;
    if !status.success() {
        return Err(Error::msg(format!("{what}失败(exit {status})")));
    }
    Ok(())
}

pub(crate) fn cmd_deploy() -> Result<()> {
    if !std::path::Path::new("/run/systemd/system").exists() {
        return Err(Error::msg(
            "系统级部署仅支持 Linux + systemd;个人使用直接 `keysink serve` 即可",
        ));
    }
    #[cfg(unix)]
    let root = unsafe { libc::geteuid() } == 0;
    #[cfg(not(unix))]
    let root = false;
    if !root {
        return Err(Error::msg("请用 sudo 运行:sudo keysink deploy"));
    }
    // sudoers 只放行发起部署的管理员;不知道是谁就拒绝,避免白名单写错人
    let admin = std::env::var("SUDO_USER").map_err(|_| {
        Error::msg("请通过管理员账号的 sudo 运行(需要 SUDO_USER 生成 sudoers 白名单)")
    })?;

    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|e| Error::msg(format!("定位当前二进制失败: {e}")))?;
    let exe = exe.to_string_lossy();

    // 旧版双二进制部署的残留,清掉
    let _ = std::fs::remove_file("/usr/local/bin/keysink-admin");
    let _ = std::fs::remove_file("/etc/sudoers.d/keysink-admin");

    let user_exists = std::process::Command::new("id")
        .arg("keysink")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !user_exists {
        run_checked(
            "创建 keysink 用户",
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
        "创建 vault 目录",
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
    run_checked("安装二进制", "install", &["-m", "0755", &exe, SYSTEM_BIN])?;

    std::fs::write(SYSTEM_UNIT, SYSTEMD_UNIT)
        .map_err(|e| Error::msg(format!("写入 unit 失败: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(SYSTEM_UNIT, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| Error::msg(format!("设置 unit 权限失败: {e}")))?;
    }

    // sudoers 先写临时文件、visudo 校验通过再就位:语法错误不会留下坏配置
    let tmp = format!("{SYSTEM_SUDOERS}.new");
    std::fs::write(&tmp, SUDOERS_TEMPLATE.replace("__ADMIN__", &admin))
        .map_err(|e| Error::msg(format!("写入 sudoers 失败: {e}")))?;
    let valid = std::process::Command::new("visudo")
        .args(["-cf", &tmp])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !valid {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::msg("sudoers 校验未通过,已放弃(原文件未动)"));
    }
    std::fs::rename(&tmp, SYSTEM_SUDOERS)
        .map_err(|e| Error::msg(format!("sudoers 就位失败: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(SYSTEM_SUDOERS, std::fs::Permissions::from_mode(0o440))
            .map_err(|e| Error::msg(format!("设置 sudoers 权限失败: {e}")))?;
    }

    // --home 必须显式:vault.key 不存在时默认目录探测会回落到调用方自己的
    // standalone 目录,runuser 的 HOME 漂移会把首次 init 写进错误位置。
    if !std::path::Path::new(&format!("{SYSTEM_VAULT_HOME}/vault.key")).exists() {
        if std::io::stdin().is_terminal() {
            println!("==> 初始化 vault(设置 master password,只用于备份导出/恢复)");
            run_checked(
                "初始化 vault",
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
            eprintln!("vault 尚未初始化,且当前无终端;请手动执行:");
            eprintln!("  runuser -u keysink -- {SYSTEM_BIN} --home {SYSTEM_VAULT_HOME} init");
        }
    }

    // 换新二进制/新 unit 必须重启:enable --now 不会动在跑的旧实例
    run_checked("systemctl daemon-reload", "systemctl", &["daemon-reload"])?;
    let active = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "keysink"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if active {
        run_checked("重启服务", "systemctl", &["restart", "keysink"])?;
    } else {
        run_checked("启动服务", "systemctl", &["enable", "--now", "keysink"])?;
    }

    println!();
    println!("安装完成。");
    println!();
    println!("下一步(添加路由,管理员 {admin}):");
    println!("  sudo -u keysink keysink route add claude --base-url https://api.anthropic.com");
    println!("  # 终端里依次引导:名称 / base URL / 上游认证 / key 值(隐藏回显,只进不出)");
    println!(
        "  # 脚本里:printf %s \"$KEY\" | sudo -u keysink keysink route add <name> --base-url ..."
    );
    println!();
    println!("agent 侧配置(route add 末尾会打印这两行):");
    println!("  BASE_URL=http://127.0.0.1:8787");
    println!("  TOKEN=ks_...");
    println!();
    println!("vault 文件:{SYSTEM_VAULT_HOME}");
    println!("服务状态:systemctl status keysink");
    println!("卸载:keysink uninstall");
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
            "这是系统级部署,请用 root 运行:sudo keysink uninstall",
        ));
    }

    if !yes {
        if !std::io::stdin().is_terminal() {
            return Err(Error::msg("非交互环境请加 --yes"));
        }
        eprintln!(
            "将删除 vault({})——所有 key 与路由就此丢失,不可恢复。",
            home.display()
        );
        if system {
            eprintln!("同时移除 systemd unit、sudoers 与 /usr/local/bin/keysink。");
        }
        eprint!("继续? [y/N] ");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if !matches!(line.trim(), "y" | "Y" | "yes" | "YES") {
            return Err(Error::msg("已取消"));
        }
    }

    // 先停服务再删文件;unit 可能本来就不存在,失败忽略
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
            .map_err(|e| Error::msg(format!("删除 {} 失败: {e}", home.display())))?;
        removed.push(home.clone());
    }
    if system {
        for f in [SYSTEM_UNIT, SYSTEM_SUDOERS, SYSTEM_BIN] {
            let p = PathBuf::from(f);
            if p.exists() {
                std::fs::remove_file(&p)
                    .map_err(|e| Error::msg(format!("删除 {} 失败: {e}", p.display())))?;
                removed.push(p);
            }
        }
    }

    if removed.is_empty() {
        println!("没有找到可删除的文件(vault 不存在:{})", home.display());
        return Ok(());
    }
    println!("已卸载,删除了:");
    for p in &removed {
        println!("  - {}", p.display());
    }
    if !system {
        // standalone 的二进制是用户自己放的(手动/cargo install/brew),替他删可能弄坏包管理器
        if let Ok(exe) = std::env::current_exe() {
            println!("二进制本身未删除:{},请自行清理", exe.display());
        }
        println!("若 serve 仍在运行请另行结束;启用过 --audit-log 的话审计文件也需自行删除。");
    }
    Ok(())
}

pub(crate) fn cmd_rekey(paths: &Paths, yes: bool) -> Result<()> {
    if !yes {
        if !std::io::stdin().is_terminal() {
            return Err(Error::msg("非交互环境请加 --yes"));
        }
        eprintln!("将生成新的 vault.key，并把 vault 重新加密。旧 key 会留在 vault.key.bak。");
        eprint!("继续? [y/N] ");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if !matches!(line.trim(), "y" | "Y" | "yes" | "YES") {
            return Err(Error::msg("已取消"));
        }
    }
    store::rekey(paths)?;
    println!("已换主密钥。旧 key: {}", paths.master_key_bak().display());
    println!("注意：旧备份仍可用旧 key 解开；请重新备份 vault.key + vault.age。");
    Ok(())
}

pub(crate) fn cmd_export(paths: &Paths, args: ExportArgs) -> Result<()> {
    let master = check_master_password(paths, args.password_stdin)?;
    let passphrase: Zeroizing<String> = if let Some(file) = &args.passphrase_file {
        let bytes = Zeroizing::new(std::fs::read(file)?);
        let text = Zeroizing::new(
            String::from_utf8(bytes.to_vec()).map_err(|_| Error::msg("口令文件不是 UTF-8"))?,
        );
        Zeroizing::new(text.lines().next().unwrap_or("").to_string())
    } else {
        master
    };
    if passphrase.is_empty() {
        return Err(Error::msg("口令不能为空"));
    }
    let stripped = store::export(paths, &args.output, &passphrase)?;
    println!("已导出: {}", args.output.display());
    if stripped > 0 {
        println!(
            "注意：导出不包含任何 key 值（{stripped} 条路由的 route-only key 已剥离）；\
             恢复后需逐条 `route update <name> --route-key` 重新输入"
        );
    }
    Ok(())
}

/// Current gateway location: serve writes the actual listen address into `<home>/gateway.addr`
/// at startup; read it here and probe TCP reachability, falling back to the default listen
/// address when the runtime file is absent. Returns (host:port, reachable).
fn current_gateway(paths: &Paths) -> (String, bool) {
    let fallback = "127.0.0.1:8787".to_string();
    let addr = std::fs::read_to_string(paths.gateway_addr())
        .ok()
        .and_then(|text| {
            let line = text.lines().next()?.trim();
            (!line.is_empty()).then(|| line.to_string())
        })
        .unwrap_or(fallback);
    let reachable = addr
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|a| std::net::TcpStream::connect_timeout(&a, Duration::from_millis(300)).is_ok())
        .unwrap_or(false);
    (addr, reachable)
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
        Some(_) => "（route-only，不可读取/导出）".to_string(),
        None => "（缺失）".to_string(),
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
        // The argument wins: use it when given (including the trim)
        assert_eq!(
            resolve_required(Some("  x  ".into()), "标签", "--flag").unwrap(),
            "x"
        );
        // The test process's stdin is not a TTY: a missing argument must fail immediately, never hang waiting for input
        let err = resolve_required(None, "标签", "--flag")
            .unwrap_err()
            .to_string();
        assert!(err.contains("--flag"), "{err}");
    }

    #[test]
    fn current_gateway_reads_runtime_file_and_probes() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::vault(dir.path().join("v"));
        util::create_private_dir_all(&paths.home).unwrap();
        let (addr, _) = current_gateway(&paths);
        assert_eq!(addr, "127.0.0.1:8787");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let live = listener.local_addr().unwrap();
        util::atomic_write(&paths.gateway_addr(), format!("{live}\n").as_bytes(), 0o600).unwrap();
        let (addr, alive) = current_gateway(&paths);
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
        let (_, alive) = current_gateway(&paths);
        assert!(!alive);
    }
}
