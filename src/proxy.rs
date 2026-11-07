use crate::audit::{Audit, AuditEntry};
use crate::error::{Error, Result};
use crate::model::{Auth, Route, Store, Terminator};
use crate::retry::{RetryPolicy, parse_retry_after};
use crate::store::Paths;
use crate::vkey::{self, RouteTable};
use arc_swap::ArcSwap;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use bytes::Bytes;
use futures_util::{StreamExt, stream};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, ReadBuf};
use tracing::Instrument;

static REQ_SEQ: AtomicU64 = AtomicU64::new(1);

/// Read-idle timeout for streaming (SSE) clients: if the upstream sends no
/// bytes for this long, it is deemed hung. Applies only to the streaming
/// client — at the client level, non-streaming requests must not set a read
/// idle, because reqwest applies it to the response-header wait too: slow
/// models that only send response headers after generation completes
/// (non-streaming long reasoning) would be killed at 60s and then retried as
/// a network error POST (double billing). The header wait is backstopped by
/// the outer header_timeout (tokio timeout) instead.
const STREAM_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Read-idle bound for a non-streaming response body, applied per chunk at
/// the passthrough layer (see `idle_bounded`). The plain client has no
/// client-level read_timeout (see STREAM_READ_TIMEOUT), so without this an
/// upstream that sends response headers and then goes silent mid-body would
/// hang the handler forever — and with it, graceful shutdown. Aligned with
/// the header-phase bound on purpose: one story, "no upstream progress ⇒
/// give up". SSE bodies are bounded by STREAM_READ_TIMEOUT instead.
pub const BODY_READ_IDLE: Duration = crate::retry::DEFAULT_HEADER_TIMEOUT;

/// Whole-response budget for a non-streaming body, on top of the per-chunk
/// read idle. The idle bound alone only catches an upstream that goes silent:
/// one that trickles a byte every minute is "alive" forever, and each such
/// connection occupies a connection slot for the process lifetime. SSE bodies
/// are deliberately exempt (a stream may legitimately last for minutes).
pub const BODY_TOTAL_BUDGET: Duration = Duration::from_secs(10 * 60);

/// Whole-head bound on the inbound request from an agent client: a
/// connection that never finishes sending its head (slowloris) is closed
/// within this window. Bounds the head as a whole, matching hyper-util's
/// semantics (not per read).
pub const CLIENT_HEADER_TIMEOUT: Duration = Duration::from_secs(30);

/// Whole-body bound on the handler reading the inbound request body: a
/// client that trickles a body forever gets a 408 instead of holding the
/// handler (and its buffered bytes) indefinitely. Generous next to the 32MB
/// byte limit — legit payloads are small (LLM prompts) and, once flowing,
/// arrive continuously. Streaming responses are NOT affected: this bounds
/// reads from the client only.
pub const CLIENT_BODY_TIMEOUT: Duration = Duration::from_secs(120);

/// Inbound h2 keep-alive cadence: after this long without inbound frames the
/// server PINGs the peer; see serve_inbound for why h2 needs its own bound.
const HTTP2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// How long the server waits for the keep-alive PING ACK before closing an
/// unresponsive h2 connection. A peer that answers is actively maintaining
/// the connection (equivalent to sending traffic), so only silent stalers
/// are reaped.
const HTTP2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(15);

/// Bound on how long a request may queue for an inbound permit. A wedged
/// upstream (accepts TCP, never sends response headers) holds every permit
/// for up to attempts × header_timeout + backoff, so an open-ended queue
/// would hang agents with no server-side error at all; past this bound the
/// request is shed with an explicit 503 + Retry-After instead of waiting
/// for the client's own timeout.
pub const PERMIT_QUEUE_TIMEOUT: Duration = Duration::from_secs(30);

/// Hard bound on the graceful drain: how long in-flight connections (a long
/// non-streaming generation, an SSE stream, an idle keep-alive socket) may
/// hold shutdown before they are dropped. Without it the drain lasts until
/// every client goes away on its own — an idle keep-alive connection alone
/// held it for its 30s header timeout, past the service manager's stop
/// timeout, so every restart ended in SIGKILL (no audit flush, no cleanup).
/// Single source of truth for the `--drain-timeout-secs` default; keep the
/// systemd unit's `TimeoutStopSec` above this.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// TCP keepalive on inbound connections: dead-peer insurance for sockets
/// that never deliver a full request head — an HTTP/2 client stalling
/// after the connection preface is invisible to header_read_timeout
/// (http1-only), and without keepalive it would hold its connection slot
/// until process exit.
const TCP_KEEPALIVE: Duration = Duration::from_secs(60);

const RID_DIGITS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn next_rid() -> String {
    let n = REQ_SEQ.fetch_add(1, Ordering::Relaxed);
    rid_from(n)
}

/// At least 4 base36 digits; it naturally lengthens past 36^4, avoiding duplicate rids after wraparound.
pub(crate) fn rid_from(n: u64) -> String {
    let mut digits = Vec::with_capacity(4);
    let mut m = n;
    loop {
        digits.push(RID_DIGITS[(m % 36) as usize]);
        m /= 36;
        if m == 0 {
            break;
        }
    }
    while digits.len() < 4 {
        digits.push(b'0');
    }
    digits.reverse();
    String::from_utf8(digits).unwrap_or_else(|_| "0000".into())
}

pub struct Snapshot {
    pub store: Arc<Store>,
    pub table: RouteTable,
    /// Whether this snapshot came from the `.bak` backup (main store failed to decrypt).
    /// Surfaced as `degraded` on the health endpoint; revoked/deleted vkeys may become effective again.
    pub from_backup: bool,
}

/// Hot-reload health, shared between the watcher, the health endpoint and the
/// watcher watchdog.
///
/// The watcher can fail for as long as the vault stays broken (an
/// undecryptable or corrupt store, a permission change) while the gateway
/// happily serves the last good snapshot — "the gateway answers" is not "the
/// vault is being tracked". These counters make that gap visible instead of
/// leaving it in a log line.
#[derive(Default)]
pub struct ReloadStatus {
    /// `AppState::started.elapsed()` in seconds at the last successful
    /// snapshot publish. 0 = the snapshot loaded at startup.
    pub last_ok_secs: AtomicU64,
    /// `started.elapsed()` at the last watcher tick (watchdog liveness).
    pub last_tick_secs: AtomicU64,
    /// Consecutive failed reloads (reset by a success).
    pub failures: AtomicU32,
    /// Reload attempts since startup, successful or not.
    pub attempts: AtomicU64,
}

pub struct AppState {
    pub snapshot: ArcSwap<Snapshot>,
    pub clients: ProxyClients,
    pub retry: RetryPolicy,
    pub body_limit: usize,
    /// Per-chunk read-idle bound for non-streaming upstream bodies (BODY_READ_IDLE in production; tests inject a small value).
    pub body_read_idle: Duration,
    /// Whole-body bound on reading the inbound request body (CLIENT_BODY_TIMEOUT in production; tests inject a small value).
    pub inbound_body_timeout: Duration,
    /// Bound on queueing for an inbound permit (PERMIT_QUEUE_TIMEOUT in production; tests inject a small value).
    pub permit_queue_timeout: Duration,
    /// Whole-body budget for a non-streaming upstream response (BODY_TOTAL_BUDGET in production; tests inject a small value).
    pub body_total_budget: Duration,
    /// Hot-reload health, published for the health endpoint and the watcher watchdog.
    pub reload: Arc<ReloadStatus>,
    /// Serve-loop counters (shed connections, per-connection accept errors),
    /// published on the health endpoint.
    pub counters: Arc<ServeCounters>,
    /// Bounds concurrent handler executions — the memory-heavy phase (whole
    /// inbound body buffered + waiting for upstream response headers). The
    /// permit is held until the handler returns; the response body, including
    /// long-lived SSE, streams afterwards without one, so streams can never
    /// starve new requests. The health endpoint is not routed through the
    /// handler and stays available under load.
    pub inbound_permits: Arc<tokio::sync::Semaphore>,
    pub audit: Audit,
    pub started: Instant,
}

/// Builds an upstream HTTP client; `proxy` decides proxy semantics and
/// `read_timeout` decides read idle:
/// - `None` → follow system proxy environment variables (reqwest default behavior)
/// - `Some("direct")` → clear proxy and skip system proxy pickup, forcing a direct connection
/// - `Some(url)` → use the specified proxy (reqwest semantics: an explicit proxy disables system proxy pickup)
///
/// read_timeout is for the streaming client only; non-streaming clients must
/// pass None: reqwest's read_timeout also applies to the "waiting for response
/// headers" phase, so if non-streaming also set 60s, a slow non-streaming
/// request (response headers sent only after generation completes) would be
/// cut off and retried as a network error POST.
pub fn build_upstream_client(
    proxy: Option<&str>,
    read_timeout: Option<Duration>,
) -> Result<reqwest::Client> {
    // reqwest 0.13 uses rustls-no-provider: pick ring as the process-wide
    // crypto provider before the first client is built (idempotent; covers
    // every entry path including tests that bypass bootstrap()).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut builder = reqwest::Client::builder()
        .pool_max_idle_per_host(64)
        // Deliberately below the idle timeouts common in front of an LLM API
        // (60s at most load balancers): a pooled connection the peer has
        // already closed fails the next request that picks it, and a POST is
        // not replayed, so the agent sees a 502 for a request that never
        // reached the upstream. Shorter idle reuse trades a TLS handshake for
        // not handing out dead sockets.
        .pool_idle_timeout(Duration::from_secs(30))
        .tcp_keepalive(Duration::from_secs(60))
        .tcp_nodelay(true)
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(rt) = read_timeout {
        builder = builder.read_timeout(rt);
    }
    builder = match proxy {
        None => builder,
        Some(crate::model::PROXY_DIRECT) => builder.no_proxy(),
        Some(url) => builder.proxy(
            reqwest::Proxy::all(url)
                .map_err(|e| Error::msg(format!("invalid proxy URL `{url}`: {e}")))?,
        ),
    };
    builder
        .build()
        .map_err(|e| Error::msg(format!("failed to build HTTP client: {e}")))
}

/// Two clients under the same proxy config: streaming / non-streaming timeout semantics differ, so they must be built separately.
#[derive(Clone)]
struct ClientPair {
    /// Non-streaming: no client-level read idle (see STREAM_READ_TIMEOUT); the header wait is backstopped by the outer header_timeout (tokio timeout), the body phase by the per-chunk BODY_READ_IDLE at the passthrough layer.
    plain: reqwest::Client,
    /// Streaming: 60s read idle, used to detect hung SSE.
    streaming: reqwest::Client,
}

impl ClientPair {
    fn build(proxy: Option<&str>) -> Result<Self> {
        Ok(Self {
            plain: build_upstream_client(proxy, None)?,
            streaming: build_upstream_client(proxy, Some(STREAM_READ_TIMEOUT))?,
        })
    }

    fn pick(&self, is_stream: bool) -> reqwest::Client {
        if is_stream {
            self.streaming.clone()
        } else {
            self.plain.clone()
        }
    }
}

/// Client pool cached per route proxy config. reqwest has no per-request
/// proxy override and proxy URLs are hot-reload mutable, so cache by
/// "proxy config → client": base/direct prebuilt, URLs built lazily. Reads
/// are lock-free (ArcSwap copy-on-write): the per-request path never takes a
/// lock; first use and hot-reload cleanup publish whole new maps.
/// After a successful hot reload, retain_urls converges to the URLs still in
/// use, releasing clients (and their connection pools) left behind by
/// obsolete configs.
pub struct ProxyClients {
    base: ClientPair,
    direct: ClientPair,
    by_url: ArcSwap<HashMap<String, ClientPair>>,
}

impl ProxyClients {
    pub fn new() -> Result<Self> {
        Ok(Self {
            base: ClientPair::build(None)?,
            direct: ClientPair::build(Some(crate::model::PROXY_DIRECT))?,
            by_url: ArcSwap::from_pointee(HashMap::new()),
        })
    }

    /// Route proxy decision: the route.proxy config wins; the default follows the system proxy.
    pub fn for_route(&self, route: &Route, is_stream: bool) -> Result<reqwest::Client> {
        match route.proxy.as_deref() {
            None => Ok(self.base.pick(is_stream)),
            Some(crate::model::PROXY_DIRECT) => Ok(self.direct.pick(is_stream)),
            Some(url) => {
                if let Some(pair) = self.by_url.load().get(url) {
                    return Ok(pair.pick(is_stream));
                }
                let pair = ClientPair::build(Some(url))?;
                let client = pair.pick(is_stream);
                // Publish copy-on-write; under a race with another builder the
                // first insertion wins and the duplicate client is dropped.
                // rcu hands the closure &Arc<HashMap>, hence HashMap::clone.
                self.by_url.rcu(|cache| {
                    let mut next = HashMap::clone(cache);
                    next.entry(url.to_string()).or_insert_with(|| pair.clone());
                    next
                });
                Ok(client)
            }
        }
    }

    /// Called after a successful hot reload: drops cached proxy URLs no longer referenced by any route.
    /// In-flight requests hold Client clones (Arc) and are unaffected.
    pub fn retain_urls(&self, live: &HashSet<String>) {
        self.by_url.rcu(|cache| {
            cache
                .iter()
                .filter(|(url, _)| live.contains(url.as_str()))
                .map(|(url, pair)| (url.clone(), pair.clone()))
                .collect::<HashMap<_, _>>()
        });
    }
}

pub fn build_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/__keysink/health", get(health))
        .fallback(handler)
        .with_state(state)
}

/// Inbound read bounds applied by serve_inbound.
#[derive(Clone)]
pub struct InboundLimits {
    /// Whole-head bound: a client that does not finish sending its request
    /// head within this time is disconnected (slowloris defense).
    pub header_timeout: Duration,
    /// Cap on concurrently open client connections: excess connections are
    /// closed on accept instead of accumulating tasks and file descriptors
    /// (matters once the gateway is exposed with --allow-remote). Higher
    /// than the request bound on purpose: idle keep-alive and long-lived SSE
    /// connections hold a connection slot but no request permit.
    pub max_connections: usize,
    /// Bound on the graceful drain (DRAIN_TIMEOUT in production; None waits
    /// for every connection to finish on its own).
    pub drain_timeout: Option<Duration>,
    /// Test instrumentation: counts accept-loop iterations. An idle loop must
    /// pend on accept (single digits over seconds); an always-ready select
    /// arm spins it into the millions. Production passes None.
    pub loop_iterations: Option<Arc<AtomicU64>>,
    /// Test instrumentation: the JoinSet length after each accept/reap step.
    /// Finished connection tasks must be reaped as they finish — JoinSet
    /// retains every finished entry until `join_next` consumes it, so a serve
    /// loop that only drains at shutdown grows with the cumulative connection
    /// count (the memory creep v0.1.4 fixed). Production passes None.
    pub live_connections: Option<Arc<AtomicU64>>,
    /// Counters surfaced on the health endpoint. Production passes `Some`;
    /// tests that assert on them pass their own.
    pub counters: Option<Arc<ServeCounters>>,
}

/// Serve-loop counters the health endpoint publishes: the accept loop is
/// otherwise invisible to monitoring, and per-connection accept errors used
/// to be either fatal (visible, wrong) or retried in debug-only log lines
/// (invisible).
#[derive(Default)]
pub struct ServeCounters {
    /// Connections shed at the connection cap.
    pub shed: AtomicU64,
    /// accept(2) failures classified as per-connection (retried in place).
    pub accept_errors: AtomicU64,
}

/// The h2 prior-knowledge preface. hyper-util's auto builder reads it — or a
/// first diverging byte — to pick http1 vs h2, and that sniff phase obeys
/// neither inbound bound: http1's header_read_timeout only arms once http1 is
/// selected, and the h2 keep-alive PING only starts after the h2 handshake
/// completes. A peer that connects and then sends nothing (or stalls
/// mid-preface) therefore holds its connection slot until process exit, and
/// silently parking max_connections of them is the same one-shot remote DoS
/// the h2 keep-alive closed — at lower cost, since not a single byte needs
/// to be sent. So the first bytes are read here, under the same whole-head
/// deadline as http1, and replayed into hyper.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Reads from `io` until the protocol is decidable — `H2_PREFACE` complete
/// (h2), a divergence from it (http1), or EOF — under one whole-phase
/// deadline (a slowloris trickling one byte per window gets nowhere, same
/// semantics as CLIENT_HEADER_TIMEOUT). TimedOut on deadline; read errors
/// propagate.
async fn sniff_protocol(
    io: &mut (impl tokio::io::AsyncRead + Unpin),
    head_timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + head_timeout;
    let mut seen = Vec::with_capacity(H2_PREFACE.len());
    let mut chunk = [0u8; H2_PREFACE.len() + 8];
    while seen.len() < H2_PREFACE.len() {
        let read = tokio::time::timeout_at(deadline, io.read(&mut chunk))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "protocol sniff timed out")
            })??;
        if read == 0 {
            // EOF: replay what arrived so hyper reports the closed peer itself.
            break;
        }
        seen.extend_from_slice(&chunk[..read]);
        // Compare only the prefix-length part: a burst can carry the preface
        // plus the first h2 frames in one read, and that overshoot is legal.
        let decided = &seen[..seen.len().min(H2_PREFACE.len())];
        if !H2_PREFACE.starts_with(decided) {
            break; // cannot be h2 → http1; header_read_timeout takes over
        }
    }
    Ok(seen)
}

/// Middleware that fires a one-shot notification when the first request on a
/// connection arrives.
///
/// `serve_inbound` uses it to bound the phase before the first request: hyper
/// completes the h2 handshake only after the peer's SETTINGS frame, and the
/// h2 keep-alive PING (which is the bound for an established h2 connection)
/// starts only after the handshake. `header_read_timeout` is http1-only. A
/// peer that sends the 24-byte h2 preface (or stalls inside the SETTINGS
/// frame) would otherwise hold its connection slot forever — a cheap one-shot
/// DoS on `--allow-remote` deployments. Once the first request is dispatched,
/// the deadline is disarmed and the normal per-request/drain bounds apply.
async fn note_first_request(
    State((first, seen)): State<(Arc<tokio::sync::Notify>, Arc<AtomicBool>)>,
    req: Request,
    next: axum::middleware::Next,
) -> Response {
    if !seen.swap(true, Ordering::Relaxed) {
        first.notify_one();
    }
    next.run(req).await
}

/// Replays the sniffed bytes ahead of the live socket so hyper sees the exact
/// byte stream it would have read itself. Writes pass straight through
/// (WebSocket upgrades included).
struct PrefaceIo<T> {
    io: T,
    preface: Vec<u8>,
    pos: usize,
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefaceIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.preface.len() {
            let n = (self.preface.len() - self.pos).min(buf.remaining());
            buf.put_slice(&self.preface[self.pos..self.pos + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PrefaceIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}

/// Serves the gateway on `listener` until `shutdown` resolves — the same
/// shape as axum::serve(listener, app).with_graceful_shutdown(shutdown),
/// except the inbound head read is time-bounded: axum::serve exposes no
/// header_read_timeout, so a client that opens a connection and stalls
/// mid-head would hold a task + socket forever. That matters once the
/// gateway is exposed with --allow-remote, but reaping dead connections is
/// cheap insurance everywhere. The body phase is bounded app-side (see
/// CLIENT_BODY_TIMEOUT), where it can never touch streaming responses.
pub async fn serve_inbound(
    listener: tokio::net::TcpListener,
    app: Router,
    limits: InboundLimits,
    shutdown: impl std::future::Future<Output = ()>,
) -> std::io::Result<()> {
    let mut shutdown = std::pin::pin!(shutdown);
    let mut conns = tokio::task::JoinSet::new();
    let conn_slots = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    // Shutdown is propagated into every live connection, not just into this
    // accept loop. hyper's connection future does not stop on its own: without
    // this a draining gateway kept answering NEW requests on existing
    // keep-alive connections, and an idle keep-alive socket held the drain
    // until its header_read_timeout (30s) expired — past the service
    // manager's stop timeout, so every restart ended in SIGKILL.
    let (drain_tx, drain_rx) = tokio::sync::watch::channel(false);
    let mut shed = 0u64;
    let mut accept_errors = 0u64;
    loop {
        if let Some(counter) = &limits.loop_iterations {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        let accepted = tokio::select! {
            _ = &mut shutdown => None,
            // Reap connection tasks as they finish: JoinSet retains each
            // entry (the JoinHandle plus the task's harness allocation,
            // sized to hold hyper's connection future) until join_next
            // consumes it, so without this branch memory would grow with
            // the cumulative number of accepted connections over the
            // process lifetime. The arm must be disabled while the set is
            // empty: join_next returns Ready(None) immediately for an empty
            // set (it only pends while tasks are still running), and an
            // always-ready arm would spin the loop and starve
            // listener.accept() — the gateway would stop serving entirely.
            res = conns.join_next(), if !conns.is_empty() => {
                // A panicking connection task would otherwise vanish without
                // a trace: the JoinSet is the only place its JoinError is seen.
                if let Some(Err(e)) = res
                    && e.is_panic()
                {
                    tracing::error!("inbound connection task panicked: {e}");
                }
                if let Some(gauge) = &limits.live_connections {
                    gauge.store(conns.len() as u64, Ordering::Relaxed);
                }
                continue;
            }
            accepted = listener.accept() => Some(accepted),
        };
        let Some(accepted) = accepted else {
            break;
        };
        let (stream, _peer) = match accepted {
            Ok(ok) => ok,
            Err(e) => {
                // Transient resource pressure (fd or kernel memory): back
                // off and keep serving instead of turning it into a full
                // outage.
                if is_resource_pressure_accept_error(&e) {
                    tracing::warn!(error = %e, "transient accept error (resource pressure); backing off 1s");
                    // Shutdown stays live during the backoff: an uninterruptible
                    // sleep would delay a stop by up to 1s per burst.
                    tokio::select! {
                        _ = &mut shutdown => break,
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                    continue;
                }
                // accept(2) reports per-connection failures from the backlog
                // (a handshake the peer aborted, protocol/route errors) as
                // errors on the listener. They say nothing about the listener
                // itself, so retrying is the documented behavior; treating
                // them as fatal turned one dropped handshake into a full
                // gateway restart.
                if is_connection_level_accept_error(&e) {
                    accept_errors += 1;
                    if let Some(counters) = &limits.counters {
                        counters
                            .accept_errors
                            .store(accept_errors, Ordering::Relaxed);
                    }
                    if accept_errors == 1 {
                        // First one at warn: the old code treated these as
                        // fatal, so they were at least visible — this keeps
                        // the signal an operator can actually notice.
                        tracing::warn!(error = %e, "per-connection accept error; still accepting");
                    } else if accept_errors.is_multiple_of(100) {
                        tracing::debug!(
                            error = %e,
                            count = accept_errors,
                            "per-connection accept error; still accepting"
                        );
                    }
                    continue;
                }
                return Err(e);
            }
        };
        // Shed beyond the connection cap: close immediately instead of
        // accumulating tasks and fds. The permit lives exactly as long as
        // the connection task. Warn cadence matches the audit-drop counter:
        // a flood sheds fast, so one line per 100 keeps the default info
        // log sane while still leaving evidence a cap was ever hit.
        let Ok(_conn_slot) = conn_slots.clone().try_acquire_owned() else {
            shed += 1;
            if let Some(counters) = &limits.counters {
                counters.shed.store(shed, Ordering::Relaxed);
            }
            if shed % 100 == 1 {
                tracing::warn!(
                    shed,
                    "connection cap reached; dropping incoming connections"
                );
            }
            drop(stream);
            continue;
        };
        let _ = stream.set_nodelay(true);
        // Best-effort like nodelay: keepalive is dead-peer hardening, not a
        // prerequisite for serving. SockRef borrows the stream, so the socket
        // config lands before the stream moves into the connection task.
        // Interval must be explicit: Windows maps it straight onto
        // SIO_KEEPALIVE_VALS, and socket2 turns an unset interval into a 0ms
        // probe gap — undefined winsock input, where one dropped packet on a
        // busy link could reap a healthy connection.
        let socket = socket2::SockRef::from(&stream);
        let _ = socket.set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(TCP_KEEPALIVE)
                .with_interval(Duration::from_secs(15)),
        );
        // The connection future owns its builder (cheap config clone) so it
        // stays 'static and can outlive this loop while draining.
        let app = app.clone();
        let mut drain_rx = drain_rx.clone();
        conns.spawn(async move {
            // Hold the connection slot for the task's whole life: dropped
            // when the connection ends, freeing the slot for the next accept.
            let _conn_slot = _conn_slot;
            let mut stream = stream;
            let preface = match sniff_protocol(&mut stream, limits.header_timeout).await {
                Ok(preface) => preface,
                Err(e) => {
                    // Silent peers are the DoS shape this bounds; aborts and
                    // resets are routine client noise in both cases.
                    tracing::debug!(error = %e, "inbound connection dropped before speaking");
                    return;
                }
            };
            let mut builder =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            builder.http1().timer(hyper_util::rt::TokioTimer::new());
            builder
                .http1()
                .header_read_timeout(Some(limits.header_timeout));
            // The http1 bounds above do not reach h2c connections (the auto
            // builder accepts prior-knowledge h2): without a keep-alive an
            // established h2 connection that goes silent holds its connection
            // slot forever, and silently parking max_connections of them is a
            // one-shot remote DoS on an --allow-remote deployment. The server
            // PINGs after the interval and closes the connection when the
            // PING is not ACKed within the timeout (timer required — the
            // default () timer makes both options inert).
            builder.http2().timer(hyper_util::rt::TokioTimer::new());
            builder
                .http2()
                .keep_alive_interval(Some(HTTP2_KEEPALIVE_INTERVAL));
            builder.http2().keep_alive_timeout(HTTP2_KEEPALIVE_TIMEOUT);
            // The h2 PING above only starts after the handshake completes.
            // Until the first request is dispatched, a peer can hold the
            // connection slot by sending just the preface (or stalling in the
            // SETTINGS frame), so arm a first-request deadline around the
            // connection future. The middleware notifies and disarms it as
            // soon as the first request reaches the router.
            let first_request = Arc::new(tokio::sync::Notify::new());
            let app = app.layer(axum::middleware::from_fn_with_state(
                (first_request.clone(), Arc::new(AtomicBool::new(false))),
                note_first_request,
            ));
            let conn = builder.serve_connection_with_upgrades(
                hyper_util::rt::TokioIo::new(PrefaceIo {
                    io: stream,
                    preface,
                    pos: 0,
                }),
                hyper_util::service::TowerToHyperService::new(app),
            );
            let mut conn = std::pin::pin!(conn);
            let served = tokio::select! {
                res = &mut conn => res,
                _ = first_request.notified() => {
                    // The connection is past the handshake and has served its
                    // first request; the per-request bounds and the h2
                    // keep-alive (or http1 header timer) own it from here.
                    tokio::select! {
                        res = &mut conn => res,
                        _ = drain_rx.changed() => {
                            // Shutdown started: stop accepting requests on this
                            // connection and close it once the in-flight response
                            // finishes (an idle keep-alive connection closes now).
                            // h2 peers get a GOAWAY instead.
                            conn.as_mut().graceful_shutdown();
                            conn.await
                        }
                    }
                }
                // No request ever arrived: close the stalled handshake. This is
                // the whole-phase analogue of the http1 header timeout.
                _ = tokio::time::sleep(limits.header_timeout) => {
                    tracing::debug!("inbound connection sent no request before the head timeout; closing");
                    return;
                }
                _ = drain_rx.changed() => {
                    // Shutdown while still waiting for the first request: there
                    // is no response to drain, so drop the connection now.
                    return;
                }
            };
            if let Err(e) = served {
                // Client aborts mid-stream are routine for a proxy; keep the
                // noise down but leave a trace for debugging.
                tracing::debug!(error = %e, "inbound connection ended");
            }
        });
        if let Some(gauge) = &limits.live_connections {
            gauge.store(conns.len() as u64, Ordering::Relaxed);
        }
    }
    // Graceful: stop accepting, tell every live connection to finish and
    // close, then wait for them — bounded by drain_timeout, because a
    // long-lived SSE stream or a client that simply never goes away would
    // otherwise hold shutdown until the service manager SIGKILLs the
    // process (losing the audit flush and the runtime file cleanup). The
    // count tells the operator what is still holding the drain; a second
    // signal exits immediately (see shutdown_signal — tokio swallows further
    // signals once the shutdown future resolved).
    let _ = drain_tx.send(true);
    tracing::info!(
        connections = conns.len(),
        "shutdown: draining in-flight connections (a second signal exits immediately)"
    );
    let deadline = limits
        .drain_timeout
        .map(|limit| tokio::time::Instant::now() + limit);
    loop {
        let joined = match deadline {
            Some(deadline) => match tokio::time::timeout_at(deadline, conns.join_next()).await {
                Ok(joined) => joined,
                Err(_) => {
                    tracing::warn!(
                        remaining = conns.len(),
                        "drain timeout reached; dropping the remaining connections"
                    );
                    conns.shutdown().await;
                    break;
                }
            },
            None => conns.join_next().await,
        };
        match joined {
            Some(Err(e)) if e.is_panic() => {
                tracing::error!("inbound connection task panicked during drain: {e}");
            }
            Some(_) => {}
            None => break,
        }
    }
    Ok(())
}

/// Whether an accept error is transient resource pressure to back off from
/// (1s), rather than a fatal condition or a per-connection retry: the listener
/// is healthy, but the process or the kernel is out of a resource, so an
/// immediate re-accept would just fail again and spin a core. Unix:
/// EMFILE/ENFILE (a burst above the fd limit) plus ENOBUFS/ENOMEM (kernel
/// memory/buffer pressure). Windows: the winsock equivalents WSAEMFILE (10024)
/// / WSAENOBUFS (10055) as raw codes, because libc there carries neither the
/// errno nor the winsock constants portably.
fn is_resource_pressure_accept_error(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(
            e.raw_os_error(),
            Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
        )
    }
    #[cfg(not(unix))]
    {
        matches!(e.raw_os_error(), Some(10024 | 10055))
    }
}

/// Whether an accept error belongs to the *connection* that was being
/// accepted, not to the listener. Linux and the BSDs pass pending-socket
/// errors up through accept(2) (a peer that reset between SYN and accept, a
/// protocol/route failure); accept(2) itself documents that the application
/// should treat them like EAGAIN and keep accepting. Anything else stays
/// fatal, because it means the listener is unusable.
fn is_connection_level_accept_error(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        let Some(code) = e.raw_os_error() else {
            return false;
        };
        let known = [
            libc::ECONNABORTED,
            libc::EPROTO,
            libc::ENETDOWN,
            libc::ENETUNREACH,
            libc::EHOSTUNREACH,
            libc::ENOPROTOOPT,
            libc::EOPNOTSUPP,
        ];
        if known.contains(&code) {
            return true;
        }
        // ENONET is in libc's Linux set only; keep the reference behind the cfg
        // so the Apple/Windows builds do not look for it.
        #[cfg(target_os = "linux")]
        {
            if code == libc::ENONET {
                return true;
            }
        }
        false
    }
    #[cfg(not(unix))]
    {
        // winsock reports per-connection failures as WSAECONNABORTED (10053)
        // / WSAECONNRESET (10054) / WSAENETDOWN (10050) / WSAENETUNREACH
        // (10051) / WSAEHOSTUNREACH (10065).
        matches!(
            e.raw_os_error(),
            Some(10053 | 10054 | 10050 | 10051 | 10065)
        )
    }
}

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let snap = state.snapshot.load();
    let uptime = state.started.elapsed().as_secs();
    let last_ok = state.reload.last_ok_secs.load(Ordering::Relaxed);
    Json(json!({
        "ok": true,
        "degraded": snap.from_backup,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": uptime,
        "routes": snap.table.len(),
        // The gateway answers with the last good snapshot even while the
        // hot reload is failing (undecryptable store, permissions, a watcher
        // that stopped) — without these the outage was invisible to
        // monitoring until someone noticed a rotated key still working.
        "snapshot_age_secs": uptime.saturating_sub(last_ok),
        "reload_failures": state.reload.failures.load(Ordering::Relaxed),
        "reload_attempts": state.reload.attempts.load(Ordering::Relaxed),
        "audit": state.audit.is_enabled(),
        "audit_ok": state.audit.healthy(),
        "audit_dropped": state.audit.dropped(),
        // Accept-loop visibility: the shed count is the only trace a connection
        // flood leaves, and per-connection accept errors used to be either
        // fatal (visible, wrong) or retried in debug-only lines (invisible).
        "shed_connections": state.counters.shed.load(Ordering::Relaxed),
        "accept_errors": state.counters.accept_errors.load(Ordering::Relaxed),
    }))
}

pub async fn handler(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    let rid = next_rid();
    let span = tracing::info_span!("req", rid = %rid);
    async move { handle_inner(state, req, rid).await }
        .instrument(span)
        .await
}

async fn handle_inner(state: Arc<AppState>, req: Request<Body>, rid: String) -> Response {
    let started = Instant::now();
    let (parts, body) = req.into_parts();
    // Borrowed views into `parts` (the header map moves out, method and URI
    // stay borrowed): a rejected request — the common flood case — allocates
    // nothing at all, and an accepted one clones the method only when it
    // actually forwards. The method/URI borrows live as long as `parts`, which
    // outlives every use below.
    let method = &parts.method;
    let path = parts.uri.path();
    let query = parts.uri.query();
    let in_headers = parts.headers;

    // Rejected requests are audited too (route `-` means no route matched).
    let deny = |route: &str,
                hash: Option<&[u8; 32]>,
                status: StatusCode,
                kind: &'static str,
                msg: &str|
     -> Response {
        record_reject(
            state.as_ref(),
            &rid,
            route,
            hash,
            method,
            path,
            status,
            started,
        );
        error_response(status, kind, msg, &rid)
    };

    // Cheap head screening comes BEFORE the request permit: everything
    // rejected below needs no body read and no upstream work, so a
    // credential-less flood (or a peer dribbling an oversized declared
    // body) must not occupy permits — with the permit first, such a flood
    // could pin every permit for CLIENT_BODY_TIMEOUT each and starve
    // legitimate traffic while it queues. Declared is the operative word:
    // the screen reads Content-Length, so a chunked request still takes a
    // permit before its size is knowable — bounded then by body_limit +
    // CLIENT_BODY_TIMEOUT once the read starts, which is the pre-existing
    // exposure, strictly narrowed by this screen.
    if in_headers.contains_key(header::UPGRADE) {
        return deny(
            "-",
            None,
            StatusCode::NOT_IMPLEMENTED,
            "unsupported",
            "keysink does not support WebSocket / Upgrade",
        );
    }

    // Cheap head screening, same tier as the Upgrade refusal: both are refused
    // before any body read or upstream work, so a flood of them cannot occupy
    // permits. A TRACE the upstream implements would echo the forwarded
    // headers — including the injected real key — back into the agent's view,
    // which is exactly the channel the vault exists to close; CONNECT is
    // meaningless without the Upgrade support refused above.
    if matches!(method.as_str(), "CONNECT" | "TRACE" | "TRACK") {
        let mut response = deny(
            "-",
            None,
            StatusCode::METHOD_NOT_ALLOWED,
            "unsupported",
            "keysink does not proxy CONNECT/TRACE/TRACK",
        );
        response.headers_mut().insert(
            header::ALLOW,
            HeaderValue::from_static("GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"),
        );
        return response;
    }

    if !path.is_empty() && !path.starts_with('/') {
        // Asterisk-form ("OPTIONS *") and every other non-origin-form target:
        // refused as the client error it is, instead of falling through to the
        // URL builder and surfacing as a 500 configuration_error.
        return deny(
            "-",
            None,
            StatusCode::BAD_REQUEST,
            "invalid_path",
            "request target must be origin-form (a path starting with /)",
        );
    }

    if path_has_dot_segment(path) {
        // The downstream URL parser removes dot segments while resolving the
        // final upstream URL, so forwarding one would let `/../x` or
        // `/v1/%2e%2e/x` escape the route's base_url prefix and reach
        // arbitrary paths on the upstream host with the real key attached.
        // Refused outright: what the agent addressed is what the upstream sees.
        return deny(
            "-",
            None,
            StatusCode::NOT_FOUND,
            "invalid_path",
            "request path contains dot segments",
        );
    }

    let Some(token) = extract_vkey(&in_headers) else {
        return deny(
            "-",
            None,
            StatusCode::UNAUTHORIZED,
            "authentication_error",
            "missing valid virtual key (Authorization: Bearer ks_... or x-api-key)",
        );
    };

    let snapshot = state.snapshot.load_full();
    let hash = vkey::hash(&token);
    let Some(resolved) = snapshot.table.lookup_hash(&hash) else {
        // an unknown vkey is indistinguishable from one whose hot reload (fs-watch
        // debounce, ~1s) has not reached this gateway yet — say so instead of
        // blaming a rotation the caller may not have done
        return deny(
            "-",
            Some(&hash),
            StatusCode::UNAUTHORIZED,
            "authentication_error",
            "virtual key is invalid or has been rotated (if it was just added or rotated, hot reload may not have reached the gateway yet — retry in a second)",
        );
    };
    let route = &resolved.route;
    let route_name = resolved.name.as_str();
    if !route.enabled {
        return deny(
            route_name,
            Some(&hash),
            StatusCode::FORBIDDEN,
            "permission_error",
            "route is disabled",
        );
    }

    // Borrowed straight from the snapshot's route table (held via `resolved`
    // for the rest of the handler): the request path makes no copy of the raw
    // key — the forwarded header/URL values below are the only copies, and
    // they are what goes on the wire anyway.
    let Some(key) = route.inline_key.as_deref() else {
        // validate guarantees non-empty; reaching here means the snapshot came from old data that never passed validate.
        tracing::error!(route = route_name, "route is missing route-only key");
        return deny(
            route_name,
            Some(&hash),
            StatusCode::INTERNAL_SERVER_ERROR,
            "configuration_error",
            "incomplete route configuration",
        );
    };

    if let Some(len) = in_headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        && len > state.body_limit
    {
        return deny(
            route_name,
            Some(&hash),
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_too_large",
            &format!("request body exceeds limit of {} bytes", state.body_limit),
        );
    }

    // Queue until a permit frees up: saturating the gateway makes extra
    // requests wait rather than pile up unbounded memory. The wait is
    // bounded (permit_queue_timeout): a wedged upstream (accepts TCP, never
    // sends response headers) holds every permit for up to attempts ×
    // header_timeout + backoff, so an open-ended queue would hang agents
    // with no server-side error at all — past the bound the request is shed
    // with 503 + Retry-After.
    let permit = tokio::time::timeout(
        state.permit_queue_timeout,
        state.inbound_permits.clone().acquire_owned(),
    )
    .await;
    let _permit = match permit {
        Ok(Ok(permit)) => permit,
        Err(_elapsed) => {
            record_reject(
                state.as_ref(),
                &rid,
                route_name,
                Some(&hash),
                method,
                path,
                StatusCode::SERVICE_UNAVAILABLE,
                started,
            );
            let mut response = error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "overloaded",
                "gateway is at capacity; retry shortly",
                &rid,
            );
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            return response;
        }
        // The semaphore is never closed; this arm only fires in a shutdown race.
        Ok(Err(_closed)) => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "overloaded",
                "gateway is not accepting requests",
                &rid,
            );
        }
    };

    let read = tokio::time::timeout(
        state.inbound_body_timeout,
        axum::body::to_bytes(body, state.body_limit),
    )
    .await;
    let body = match read {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            let too_large = is_length_limit_error(&e);
            let (status, kind, message) = if too_large {
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request_too_large",
                    "request body exceeds limit",
                )
            } else {
                (
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "failed to read request body",
                )
            };
            return deny(route_name, Some(&hash), status, kind, message);
        }
        // The client never finished sending its body: 408, and drop it.
        Err(_elapsed) => {
            return deny(
                route_name,
                Some(&hash),
                StatusCode::REQUEST_TIMEOUT,
                "request_timeout",
                "timed out reading request body",
            );
        }
    };

    let is_stream = is_stream_request(&body);

    let fwd_headers = match forward_headers(&in_headers, route, key, is_stream) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, route = route_name, "failed to build upstream headers");
            return deny(
                route_name,
                Some(&hash),
                StatusCode::INTERNAL_SERVER_ERROR,
                "configuration_error",
                "invalid route header configuration",
            );
        }
    };

    let url = match build_upstream_url(&route.base_url, path, query, &route.auth, key) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, route = route_name, "failed to build upstream URL");
            return deny(
                route_name,
                Some(&hash),
                StatusCode::INTERNAL_SERVER_ERROR,
                "configuration_error",
                "invalid route URL configuration",
            );
        }
    };

    // debug, not info: at ~60k RPS the per-request info line wrote ~12MB/s
    // (6.4GB over a 10-minute soak) and its formatting + stdout-lock cost
    // showed up as a measurable throughput hit. The audit log (--audit-log)
    // is the per-request record; RUST_LOG=keysink=debug restores this line.
    tracing::debug!(
        route = route_name,
        %method,
        %path,
        is_stream,
        bytes_in = body.len(),
        "forwarding request"
    );

    let client = match state.clients.for_route(route, is_stream) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, route = route_name, "failed to build route proxy client");
            return deny(
                route_name,
                Some(&hash),
                StatusCode::INTERNAL_SERVER_ERROR,
                "configuration_error",
                "invalid route proxy configuration",
            );
        }
    };

    let forward = forward_with_retry(
        &state,
        &client,
        route,
        route_name,
        method.clone(),
        url,
        fwd_headers,
        body.clone(),
        is_stream,
        &rid,
    )
    .await;

    let mut response = forward.response;
    response.headers_mut().insert(
        "x-keysink-request-id",
        HeaderValue::from_str(&rid).unwrap_or(HeaderValue::from_static("0000")),
    );

    // AuditEntry::new formats an RFC3339 local timestamp and allocates a
    // handful of Strings per request — pure waste on the default audit-off
    // path, so check first. The writer is fixed at startup (--audit-log or
    // not), so the answer cannot flip between here and record().
    if state.audit.is_enabled() {
        let mut entry = AuditEntry::new(
            rid.clone(),
            route_name,
            vkey::fingerprint(&hash),
            method.to_string(),
            path,
            body.len(),
            is_stream,
        );
        entry.status = response.status().as_u16();
        entry.ms = started.elapsed().as_millis() as u64;
        entry.attempts = forward.attempts;
        state.audit.record(entry);
    }

    response
}

/// Audit row for a rejected request: `route` `-` means no route matched;
/// record the fingerprint (not invertible) when the token hash is available, `-` otherwise.
#[allow(clippy::too_many_arguments)]
fn record_reject(
    state: &AppState,
    rid: &str,
    route: &str,
    hash: Option<&[u8; 32]>,
    method: &Method,
    path: &str,
    status: StatusCode,
    started: Instant,
) {
    // The common case is audit disabled; rejection rows are also the highest
    // frequency requests under a credential flood. Do not build an AuditEntry
    // (RFC3339 timestamp + several Strings) for a row that can never be
    // written.
    if !state.audit.is_enabled() {
        return;
    }
    let mut entry = AuditEntry::new(
        rid.to_string(),
        route.to_string(),
        hash.map(vkey::fingerprint).unwrap_or_else(|| "-".into()),
        method.to_string(),
        path.to_string(),
        0,
        false,
    );
    entry.status = status.as_u16();
    entry.ms = started.elapsed().as_millis() as u64;
    // Rejection rows are attacker-rateable without any credential, so they go
    // through the throttled entry point instead of plain record().
    state.audit.record_reject(entry);
}

struct Forwarded {
    response: Response,
    attempts: u8,
}

/// Whether a network-class error may be replayed: for connect errors the
/// request certainly never arrived (zero side effects upstream); replaying
/// idempotent methods has no side effects. In the remaining cases (timeout /
/// disconnect mid-send) the upstream may have already processed and billed it.
fn network_retry_allowed(is_connect: bool, idempotent_method: bool) -> bool {
    is_connect || idempotent_method
}

/// Whether a to_bytes error is a length-limit breach: downcast along the
/// source chain to http_body_util::LengthLimitError (axum wraps it in
/// axum::Error), keeping the message match as a fallback in case axum's
/// wording changes between versions.
fn is_length_limit_error(e: &axum::Error) -> bool {
    let mut cur: Option<&dyn std::error::Error> = Some(e);
    while let Some(err) = cur {
        if err
            .downcast_ref::<http_body_util::LengthLimitError>()
            .is_some()
            || err.to_string().contains("length limit")
        {
            return true;
        }
        cur = err.source();
    }
    false
}

/// Bounded read that discards a retryable response body to give the
/// connection back: past the limit it simply gives up (drop the connection,
/// no reuse), preventing a misbehaving upstream from blowing up memory with a
/// huge body. The whole drain is bounded by `budget` because the non-streaming
/// client carries no client-level read timeout: an upstream that answers
/// 429/503 and then stalls the body used to park the handler — and with it the
/// inbound permit — forever, so `max_concurrent` such responses wedged the
/// whole gateway.
const DISCARD_BODY_LIMIT: usize = 64 * 1024;

async fn discard_body_limited(mut resp: reqwest::Response, budget: Duration) {
    let drain = async {
        let mut remaining = DISCARD_BODY_LIMIT;
        while let Ok(Some(chunk)) = resp.chunk().await {
            if chunk.len() >= remaining {
                return;
            }
            remaining -= chunk.len();
        }
    };
    if tokio::time::timeout(budget, drain).await.is_err() {
        tracing::warn!(
            "retryable upstream response body did not drain within the read idle; dropping the connection"
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward_with_retry(
    state: &AppState,
    client: &reqwest::Client,
    route: &Route,
    route_name: &str,
    method: Method,
    url: String,
    headers: HeaderMap,
    body: Bytes,
    is_stream: bool,
    rid: &str,
) -> Forwarded {
    let policy = state.retry.for_route(route);
    let max_retries = policy.max_retries;
    // POST replay safety (§4.2): on a response-header timeout or a network
    // error mid-send, the request may already have reached the upstream and
    // been billed, so a retry is a second POST. Only connect-class errors
    // (request definitely not delivered, including connect timeout) or
    // idempotent methods (GET/HEAD/OPTIONS) are retried; everything else
    // fails immediately for the caller.
    let idempotent = matches!(method, Method::GET | Method::HEAD | Method::OPTIONS);

    for attempt in 0..=max_retries {
        let req = client
            .request(method.clone(), &url)
            .headers(headers.clone());
        let req = if body.is_empty() {
            req
        } else {
            req.body(body.clone())
        };

        let send = tokio::time::timeout(policy.header_timeout, req.send()).await;

        let resp = match send {
            Err(_) => {
                tracing::warn!(
                    attempt,
                    route = route_name,
                    "timed out waiting for upstream response headers"
                );
                if idempotent && attempt < max_retries {
                    tokio::time::sleep(policy.backoff(attempt as u32, None)).await;
                    continue;
                }
                return Forwarded {
                    response: error_response(
                        StatusCode::GATEWAY_TIMEOUT,
                        "upstream_timeout",
                        "upstream response header timeout",
                        rid,
                    ),
                    attempts: attempt + 1,
                };
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    attempt,
                    route = route_name,
                    timeout = e.is_timeout(),
                    connect = e.is_connect(),
                    "upstream request failed"
                );
                if network_retry_allowed(e.is_connect(), idempotent) && attempt < max_retries {
                    tokio::time::sleep(policy.backoff(attempt as u32, None)).await;
                    continue;
                }
                return Forwarded {
                    response: error_response(
                        StatusCode::BAD_GATEWAY,
                        "upstream_error",
                        "upstream unreachable",
                        rid,
                    ),
                    attempts: attempt + 1,
                };
            }
            Ok(Ok(resp)) => resp,
        };

        let status = resp.status().as_u16();
        if policy.is_retryable(status) && attempt < max_retries {
            let retry_after = resp
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_retry_after);
            tracing::warn!(
                attempt,
                status,
                route = route_name,
                "upstream returned retryable status"
            );
            discard_body_limited(resp, state.body_read_idle).await;
            tokio::time::sleep(policy.backoff(attempt as u32, retry_after)).await;
            continue;
        }

        let response = if is_stream {
            stream_response(
                resp,
                route.sse_terminator,
                rid.to_string(),
                state.body_read_idle,
                state.body_total_budget,
            )
            .await
        } else {
            // Plain non-streaming response: per-chunk idle + whole-body budget.
            pass_through_response(resp, state.body_read_idle, Some(state.body_total_budget)).await
        };
        return Forwarded {
            response,
            attempts: attempt + 1,
        };
    }

    Forwarded {
        response: error_response(
            StatusCode::BAD_GATEWAY,
            "internal_error",
            "retry loop exited unexpectedly",
            rid,
        ),
        attempts: max_retries + 1,
    }
}

pub(crate) fn extract_vkey(headers: &HeaderMap) -> Option<String> {
    // Same set forward_headers strips: a client credential arriving under any
    // of these names is either the vkey (recognized) or dropped at forward
    // time — there is no name the gateway strips outbound but ignores inbound.
    for name in [
        "authorization",
        "x-api-key",
        "x-goog-api-key",
        "api-key",
        "anthropic-api-key",
        "openai-api-key",
    ] {
        let Some(value) = headers.get(name) else {
            continue;
        };
        let Ok(text) = value.to_str() else {
            continue;
        };
        let text = text.trim();
        let text = if name == "authorization" {
            match text.get(..7) {
                // RFC 7235 wants exactly one SP after the scheme, but clients
                // have been seen sending more ("Bearer  ks_…"); any run of
                // whitespace after the first is stripped. The scheme must
                // still be separated by at least one space, so a glued
                // `Bearersk_…` stays unrecognized.
                Some(prefix) if prefix.eq_ignore_ascii_case("bearer ") => text[7..].trim_start(),
                _ => text,
            }
        } else {
            text
        };
        if text.starts_with(vkey::PREFIX) {
            return Some(text.to_string());
        }
    }
    None
}

fn is_hop_by_hop(name: &str) -> bool {
    const HOP: &[&str] = &[
        "host",
        "content-length",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    HOP.iter().any(|h| h.eq_ignore_ascii_case(name))
}

fn is_auth_header(name: &str) -> bool {
    const AUTH: &[&str] = &[
        "authorization",
        "x-api-key",
        "x-goog-api-key",
        "api-key",
        "anthropic-api-key",
        "openai-api-key",
    ];
    AUTH.iter().any(|h| h.eq_ignore_ascii_case(name))
}

pub(crate) fn forward_headers(
    src: &HeaderMap,
    route: &Route,
    upstream_key: &str,
    is_stream: bool,
) -> Result<HeaderMap> {
    let mut out = HeaderMap::with_capacity(src.len() + 2);
    for (name, value) in src.iter() {
        let n = name.as_str();
        if is_hop_by_hop(n) || is_auth_header(n) {
            continue;
        }
        // Streaming responses need plain-text scanning for SSE terminators;
        // once the upstream compresses according to the client-negotiated
        // Accept-Encoding (zstd/gzip/br), the scan goes blind, falsely flags
        // truncation, and then appends plain-text events to the tail of the
        // compressed stream, corrupting it. The gateway does not decompress,
        // so streaming requests declare no content encoding to the upstream in
        // exchange for inspectable plain-text SSE.
        if is_stream && n.eq_ignore_ascii_case("accept-encoding") {
            continue;
        }
        out.append(name.clone(), value.clone());
    }

    for (key, value) in &route.headers {
        // Streaming requests must not negotiate a compressed encoding upstream
        // (same rationale as the inbound accept-encoding strip above); static
        // route config gets no exemption.
        if is_stream && key.eq_ignore_ascii_case("accept-encoding") {
            continue;
        }
        let name = HeaderName::from_bytes(key.as_bytes())
            .map_err(|e| Error::msg(format!("invalid header name `{key}`: {e}")))?;
        let value = HeaderValue::from_str(value)
            .map_err(|e| Error::msg(format!("invalid value for header `{key}`: {e}")))?;
        // Static headers are only filled in when the client didn't send them, to avoid overriding version/tracing headers the client negotiated itself.
        out.entry(name).or_insert(value);
    }

    match &route.auth {
        Auth::Bearer => {
            out.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {upstream_key}"))
                    .map_err(|e| Error::msg(format!("invalid Bearer value: {e}")))?,
            );
        }
        Auth::XApiKey => {
            out.insert(
                HeaderName::from_static("x-api-key"),
                HeaderValue::from_str(upstream_key)
                    .map_err(|e| Error::msg(format!("invalid x-api-key value: {e}")))?,
            );
        }
        Auth::Header { name, prefix } => {
            let header_name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| Error::msg(format!("invalid auth header name `{name}`: {e}")))?;
            out.insert(
                header_name,
                HeaderValue::from_str(&format!("{prefix}{upstream_key}"))
                    .map_err(|e| Error::msg(format!("invalid auth header value: {e}")))?,
            );
        }
        Auth::Basic { username } => {
            let raw = format!("{username}:{upstream_key}");
            let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
            out.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Basic {encoded}"))
                    .map_err(|e| Error::msg(format!("invalid Basic value: {e}")))?,
            );
        }
        Auth::Query { .. } | Auth::None => {}
    }

    Ok(out)
}

/// Whether the request path contains a dot segment: a segment that, after
/// percent-decoding (and splitting on `\` too — the WHATWG URL parser treats
/// a backslash as a path separator for the http(s) schemes this gateway
/// forwards to), equals `.` or `..`.
///
/// The downstream URL parser (reqwest/url) removes such segments while
/// resolving the final upstream URL — including the percent-encoded `%2e`
/// variants the standard defines as dot segments — so forwarding one would
/// let the request escape the route's base_url prefix and reach arbitrary
/// paths on the upstream host with the real key attached. Defense in depth:
/// the handler refuses these with a 404 before auth work; this check also
/// guards `build_upstream_url` directly so the invariant is testable at the
/// URL-building layer alone.
pub(crate) fn path_has_dot_segment(path: &str) -> bool {
    path.split(['/', '\\']).any(|seg| {
        if !seg.contains('%') {
            matches!(seg, "." | "..")
        } else {
            // Decode the segment the way a URL parser would see it: %XX
            // escapes resolved (case-insensitive hex), invalid escapes left
            // as literal bytes. A segment that then reads "." or ".." is a
            // dot segment per RFC 3986 / WHATWG ("..", ".%2e", "%2e.",
            // "%2e%2e" — longer runs like "..%2f" or "%2e%2e%2e" are literal
            // segments no parser collapses).
            let mut decoded = Vec::with_capacity(seg.len());
            let bytes = seg.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'%'
                    && let Some(hex) = bytes.get(i + 1..i + 3)
                    && let Ok(byte) = u8::from_str_radix(std::str::from_utf8(hex).unwrap_or(""), 16)
                {
                    decoded.push(byte);
                    i += 3;
                } else {
                    decoded.push(bytes[i]);
                    i += 1;
                }
            }
            matches!(decoded.as_slice(), b"." | b"..")
        }
    })
}

pub(crate) fn build_upstream_url(
    base_url: &str,
    path: &str,
    query: Option<&str>,
    auth: &Auth,
    upstream_key: &str,
) -> Result<String> {
    let base = base_url.trim_end_matches('/');
    let path = if path.is_empty() {
        "/"
    } else if path.starts_with('/') {
        if path_has_dot_segment(path) {
            return Err(Error::msg("inbound path contains dot segments"));
        }
        path
    } else {
        return Err(Error::msg("inbound path does not start with /"));
    };

    let mut url =
        String::with_capacity(base.len() + path.len() + 64 + query.map_or(0, |q| q.len()));
    url.push_str(base);
    url.push_str(path);

    let query_auth = match auth {
        Auth::Query { param } => Some(param.as_str()),
        _ => None,
    };

    let mut parts: Vec<String> = Vec::new();
    if let Some(q) = query {
        for pair in q.split('&') {
            if pair.is_empty() {
                continue;
            }
            if let Some(param) = query_auth {
                let key = pair.split('=').next().unwrap_or("");
                if key == param {
                    continue;
                }
            }
            parts.push(pair.to_string());
        }
    }
    if let Some(param) = query_auth {
        parts.push(format!(
            "{param}={}",
            crate::util::percent_encode(upstream_key)
        ));
    }

    if !parts.is_empty() {
        url.push('?');
        url.push_str(&parts.join("&"));
    }
    Ok(url)
}

pub(crate) fn is_stream_request(body: &[u8]) -> bool {
    // Byte-level pre-filter first: a body not containing the `"stream"`
    // substring cannot be stream:true, which avoids scanning a body of up to
    // 32MB just to probe one field.
    if memchr::memmem::find(body, b"\"stream\"").is_none() {
        return false;
    }
    top_level_stream_true(body)
}

/// Whether the top-level JSON object contains a `stream` member whose value
/// is the literal `true`. Byte-level scan: member names and value extents
/// are tokenized with full JSON semantics (memchr-jumped strings with
/// escapes, numbers, literals, string-aware nesting), so a `"stream"` inside
/// a string value or a nested object can never be mistaken for a member,
/// and the scan answers at the first `stream: true` instead of walking the
/// remaining body — a full `from_slice::<Probe>` used to tokenize up to the
/// 32MB limit on every request, the gateway's largest self-inflicted CPU
/// cost. Nesting depth stays off the call stack (iterative skips).
///
/// Compared to the old full parse this deliberately diverges only on bodies
/// that are not valid LLM requests (which upstream will 4xx anyway; the
/// verdict merely selects the client pair):
/// - the first `stream: true` decides; later `stream` members and a
///   malformed tail do not void it
/// - a wrong-typed `stream` member is skipped instead of failing the probe
/// - array-topped bodies report false (the old probe accepted serde's
///   struct-from-seq quirk where `[true]` meant stream:true)
fn top_level_stream_true(body: &[u8]) -> bool {
    let mut i = skip_ws(body, 0);
    if body.get(i) != Some(&b'{') {
        return false;
    }
    i += 1;
    loop {
        i = skip_ws(body, i);
        match body.get(i) {
            Some(b'}') => return false,
            Some(b'"') => {}
            _ => return false,
        }
        let name_start = i + 1;
        let Some(name_end) = skip_string(body, i) else {
            return false;
        };
        let name = &body[name_start..name_end - 1];
        i = skip_ws(body, name_end);
        if body.get(i) != Some(&b':') {
            return false;
        }
        i = skip_ws(body, i + 1);
        if name == b"stream" || unescapes_to_stream(name) {
            // The literal `true` followed by a structural char decides;
            // anything else (false, null, string, ...) is skipped below.
            if body[i..].starts_with(b"true")
                && matches!(
                    body.get(i + 4),
                    None | Some(b',' | b'}' | b' ' | b'\t' | b'\n' | b'\r')
                )
            {
                return true;
            }
        }
        let Some(next) = skip_value(body, i) else {
            return false;
        };
        i = skip_ws(body, next);
        match body.get(i) {
            Some(b',') => i += 1,
            _ => return false, // '}' ends the object; anything else is malformed
        }
    }
}

/// Only consulted for names that failed the exact `stream` compare: whether
/// the escaped JSON string interior decodes to `stream` (e.g. `stre\u0061m`).
fn unescapes_to_stream(name: &[u8]) -> bool {
    if !name.contains(&b'\\') {
        return false;
    }
    // Re-quote and let serde_json do the (rare) unescaping.
    let mut quoted = Vec::with_capacity(name.len() + 2);
    quoted.push(b'"');
    quoted.extend_from_slice(name);
    quoted.push(b'"');
    serde_json::from_slice::<String>(&quoted).is_ok_and(|s| s == "stream")
}

fn skip_ws(body: &[u8], mut i: usize) -> usize {
    while matches!(body.get(i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        i += 1;
    }
    i
}

/// `at` is the opening quote; returns the index just past the closing quote,
/// or None when the string never ends. memchr jumps between escapes so a
/// plain megabyte string costs a handful of SIMD scans.
fn skip_string(body: &[u8], at: usize) -> Option<usize> {
    let mut i = at + 1;
    loop {
        i += memchr::memchr2(b'"', b'\\', &body[i..])?;
        match body.get(i)? {
            b'"' => return Some(i + 1),
            _ => i += 2, // backslash: skip it and the escaped byte
        }
    }
}

/// Skips one JSON value starting at `i`; returns the index just past it.
/// Structural tokenization: strings, numbers, the three literals, and
/// nested containers with string-aware tracking of the outer pair — inner
/// same-type brackets nest, other bracket types are inert data positions.
/// Malformed input yields None (the caller reports false, matching the old
/// parse-error path).
fn skip_value(body: &[u8], i: usize) -> Option<usize> {
    match *body.get(i)? {
        b'"' => skip_string(body, i),
        b'[' | b'{' => {
            let (open, close) = if body[i] == b'[' {
                (b'[', b']')
            } else {
                (b'{', b'}')
            };
            let mut depth = 0usize;
            let mut j = i;
            loop {
                match body.get(j)? {
                    b'"' => {
                        j = skip_string(body, j)?;
                        continue;
                    }
                    &c if c == open => depth += 1,
                    &c if c == close => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(j + 1);
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
        }
        b't' if body[i..].starts_with(b"true") => Some(i + 4),
        b'f' if body[i..].starts_with(b"false") => Some(i + 5),
        b'n' if body[i..].starts_with(b"null") => Some(i + 4),
        c if c == b'-' || c.is_ascii_digit() => {
            let mut j = i + 1;
            while matches!(
                body.get(j),
                Some(b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
            ) {
                j += 1;
            }
            Some(j)
        }
        _ => None,
    }
}

/// Drops hop-by-hop entries from an upstream response's header map in place.
/// The map was moved out of the response wholesale, so header values (the
/// byte-expensive part) are never copied; only the few matching names are
/// cloned (refcount bumps) on their way to `remove`.
fn drop_hop_by_hop(headers: &mut HeaderMap) {
    let hop: Vec<HeaderName> = headers
        .iter()
        .filter(|(name, _)| is_hop_by_hop(name.as_str()))
        .map(|(name, _)| name.clone())
        .collect();
    for name in hop {
        headers.remove(&name);
    }
}

/// Whether the response carries a content encoding (`identity` counts as
/// unencoded). When encoded, the body is compressed bytes that cannot be
/// scanned for SSE terminators as plain text, so it can only be passed through as-is.
pub(crate) fn is_encoded(headers: &HeaderMap) -> bool {
    match headers.get(header::CONTENT_ENCODING) {
        None => false,
        Some(value) => match value.to_str() {
            Ok(v) => {
                let v = v.trim();
                !v.is_empty() && !v.eq_ignore_ascii_case("identity")
            }
            Err(_) => true,
        },
    }
}

async fn pass_through_response(
    mut resp: reqwest::Response,
    body_idle: Duration,
    total_budget: Option<Duration>,
) -> Response {
    let status = resp.status();
    // Move the header map out of the upstream response and drop hop-by-hop
    // entries in place; build_response then moves the map straight into the
    // client response. The old path cloned every header twice (once into a
    // fresh map, again through the response builder).
    let mut headers = std::mem::take(resp.headers_mut());
    drop_hop_by_hop(&mut headers);
    let stream = idle_bounded(resp.bytes_stream(), body_idle, total_budget);
    build_response(status, headers, Body::from_stream(stream))
}

/// Per-chunk read-idle bound for a forwarded response body: chunks pass
/// through unchanged; if the upstream goes silent past `idle`, or errors, the
/// body ends with an error so hyper aborts the response instead of hanging on
/// it forever. `total` bounds the body as a whole: an upstream trickling one
/// byte just under the idle bound is "alive" forever and would hold its
/// connection slot for the process lifetime. `None` skips the whole-body
/// budget — used for streams that may legitimately run for hours (SSE,
/// including its content-encoded passthrough fallbacks). Ends after the first
/// error rather than looping errors if the consumer polls again.
fn idle_bounded<S>(
    inner: S,
    idle: Duration,
    total: Option<Duration>,
) -> impl futures_util::Stream<Item = std::result::Result<Bytes, std::io::Error>>
where
    S: futures_util::Stream<Item = reqwest::Result<Bytes>>,
{
    let inner = Box::pin(inner);
    let deadline = total.map(|total| tokio::time::Instant::now() + total);
    stream::unfold(
        (inner, false, deadline),
        move |(mut inner, done, deadline)| {
            async move {
                if done {
                    return None;
                }
                let until = match deadline {
                    Some(deadline) => (tokio::time::Instant::now() + idle).min(deadline),
                    None => tokio::time::Instant::now() + idle,
                };
                match tokio::time::timeout_at(until, inner.next()).await {
                    Ok(Some(Ok(chunk))) => Some((Ok(chunk), (inner, false, deadline))),
                    Ok(Some(Err(e))) => {
                        if e.is_timeout() {
                            tracing::warn!(
                                "upstream stopped sending the response body (read idle); aborting the response"
                            );
                        } else {
                            // Summary fields only, deliberately not the error object:
                            // reqwest Display appends "for url (<url>)" when one is
                            // attached, and with Auth::Query that URL carries the
                            // upstream key. Today body-kind errors carry no URL, but
                            // logging the full object would turn that reqwest
                            // invariant into a silent leak the next time it changes.
                            tracing::warn!(
                                timeout = e.is_timeout(),
                                connect = e.is_connect(),
                                status = e.status().map(|s| s.as_u16()),
                                "failed to read upstream response body"
                            );
                        }
                        Some((
                            Err(std::io::Error::other("upstream body error")),
                            (inner, true, deadline),
                        ))
                    }
                    Ok(None) => None,
                    Err(_) => {
                        // The min() above means firing past `until` can be the
                        // idle bound or the total budget; a None deadline is
                        // always the idle bound.
                        let expired = deadline.is_some_and(|d| tokio::time::Instant::now() >= d);
                        let message = if expired {
                            tracing::warn!(
                                "upstream response body exceeded the total budget; aborting the response"
                            );
                            "upstream body total budget exceeded"
                        } else {
                            tracing::warn!(
                                "upstream response body stalled past the read idle; aborting the response"
                            );
                            "upstream body read idle timeout"
                        };
                        Some((
                            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, message)),
                            (inner, true, deadline),
                        ))
                    }
                }
            }
        },
    )
}

async fn stream_response(
    mut resp: reqwest::Response,
    terminator: Terminator,
    rid: String,
    body_idle: Duration,
    non_stream_budget: Duration,
) -> Response {
    // The passthrough fallbacks below consume `resp` whole, so the content
    // checks borrow its headers before the map is moved out for the SSE path.
    let is_sse = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().starts_with("text/event-stream"))
        .unwrap_or(false);

    if !is_sse {
        // Not a stream after all: the whole-body budget applies as usual.
        return pass_through_response(resp, body_idle, Some(non_stream_budget)).await;
    }

    // From here on it IS an SSE stream: it may legitimately run for hours, so
    // the whole-body budget never applies — only the per-chunk read idle does.
    // Terminator::None routes skip scanning entirely and pass through raw.
    if terminator == Terminator::None {
        return pass_through_response(resp, body_idle, None).await;
    }

    // A content-encoded response is compressed bytes, so terminator scanning
    // is guaranteed to miss; pass it through as-is — better to give up
    // truncation detection than to append plain-text events to a compressed
    // stream (that corrupts the frame tail and makes the client's decoder
    // error out, e.g. Bun's ZstdDecompressionError).
    //
    // The trickle test (Terminator::None) covers the budget exemption for the
    // SSE passthrough family; this branch shares it, so the test guards both.
    if is_encoded(resp.headers()) {
        tracing::debug!(rid = %rid, "response is content-encoded, skipping SSE terminator detection");
        return pass_through_response(resp, body_idle, None).await;
    }

    let status = resp.status();
    // Same in-place hop-by-hop filter as pass_through_response: the map is
    // moved out of the upstream response instead of cloned per header.
    let mut headers = std::mem::take(resp.headers_mut());
    drop_hop_by_hop(&mut headers);

    // Terminator scanning rides an unfold that owns all scan state: each
    // upstream chunk is scanned in place (plus a fixed stack window at the
    // chunk boundary) and passed through unmodified. The previous scan
    // closure had to own its captures per invocation, so every chunk of every
    // stream cloned the rid String and copied carry + chunk into a fresh Vec.
    let inner = Box::pin(resp.bytes_stream());
    let mapped = stream::unfold(
        (inner, SseScan::new(terminator, rid)),
        move |(mut inner, mut scan)| async move {
            if scan.done {
                return None;
            }
            match inner.next().await {
                Some(Ok(chunk)) => {
                    scan.feed(&chunk);
                    Some((Ok::<Bytes, std::io::Error>(chunk), (inner, scan)))
                }
                Some(Err(_)) => {
                    tracing::warn!(rid = %scan.rid, "upstream SSE stream interrupted");
                    let event = sse_error_event("upstream stream error", scan.dialect());
                    scan.finish();
                    Some((Ok(event), (inner, scan)))
                }
                None => {
                    if scan.seen {
                        return None;
                    }
                    tracing::warn!(
                        rid = %scan.rid,
                        "SSE stream ended early without terminator marker, treating as truncated"
                    );
                    let event =
                        sse_error_event("upstream stream ended prematurely", scan.dialect());
                    scan.finish();
                    Some((Ok(event), (inner, scan)))
                }
            }
        },
    );
    build_response(status, headers, Body::from_stream(mapped))
}

/// Longest terminator needle searched by `contains_terminator` (the needle-fit
/// test keeps it honest). The carry window keeps one fewer byte, so a marker
/// split across a chunk boundary always fits in the stack window below.
const TERMINATOR_MAX_NEEDLE: usize = 21;

/// Per-stream state for SSE terminator detection, owned by the response
/// stream's unfold: no Arcs, no Mutex, and nothing allocated per chunk.
struct SseScan {
    terminator: Terminator,
    /// Terminator marker seen (or the stream ended/errored): scanning stops.
    seen: bool,
    /// The stream must end after the synthetic error event has been emitted.
    done: bool,
    /// Tail of the previous chunk, at most `TERMINATOR_MAX_NEEDLE - 1` bytes.
    carry: Vec<u8>,
    /// Whether the stream has shown an Anthropic-style event. Only consulted
    /// by `Terminator::Auto`, to give a truncated Anthropic stream an
    /// Anthropic-shaped error event instead of an OpenAI `data: [DONE]` tail.
    saw_anthropic: bool,
    /// Request id for the (cold) interruption/truncation log lines.
    rid: String,
}

impl SseScan {
    fn new(terminator: Terminator, rid: String) -> Self {
        Self {
            terminator,
            seen: false,
            done: false,
            carry: Vec::with_capacity(TERMINATOR_MAX_NEEDLE - 1),
            saw_anthropic: false,
            rid,
        }
    }

    /// Marks the stream complete: one more item (the synthetic error event)
    /// is emitted, the next poll ends the stream.
    fn finish(&mut self) {
        self.seen = true;
        self.done = true;
    }

    /// The dialect the synthetic error event must be shaped as.
    ///
    /// `Auto` normally defaults to the OpenAI shape, but an `Auto` stream that
    /// showed Anthropic `event:` lines is an Anthropic stream: appending
    /// `data: [DONE]` to it would be a shape the client does not understand.
    fn dialect(&self) -> Terminator {
        if self.terminator == Terminator::Auto && self.saw_anthropic {
            Terminator::Anthropic
        } else {
            self.terminator
        }
    }

    /// Scans one upstream chunk. The chunk itself is searched in place; a
    /// marker straddling the previous carry and this chunk can only start
    /// within the last L-1 carry bytes and reach at most L-1 bytes into the
    /// chunk, so a fixed stack window of 2·(L-1) bytes covers the boundary
    /// and the chunk body is never copied.
    fn feed(&mut self, chunk: &[u8]) {
        if self.seen || self.terminator == Terminator::None {
            return;
        }
        // Dialect detection for `Auto`: Anthropic streams are the only ones
        // that emit `event:` lines. Only the first hit is recorded, and only
        // until it is found.
        if self.terminator == Terminator::Auto && !self.saw_anthropic && looks_anthropic(chunk) {
            self.saw_anthropic = true;
        }
        if contains_terminator(chunk, self.terminator) {
            self.seen = true;
            return;
        }
        let overlap = TERMINATOR_MAX_NEEDLE - 1;
        let head = chunk.len().min(overlap);
        if !self.carry.is_empty() && head > 0 {
            let mut window = [0u8; 2 * (TERMINATOR_MAX_NEEDLE - 1)];
            window[..self.carry.len()].copy_from_slice(&self.carry);
            window[self.carry.len()..self.carry.len() + head].copy_from_slice(&chunk[..head]);
            if contains_terminator(&window[..self.carry.len() + head], self.terminator) {
                self.seen = true;
                return;
            }
        }
        if chunk.len() >= overlap {
            self.carry.clear();
            self.carry
                .extend_from_slice(&chunk[chunk.len() - overlap..]);
        } else {
            let total = self.carry.len() + chunk.len();
            if total > overlap {
                self.carry.drain(..total - overlap);
            }
            self.carry.extend_from_slice(chunk);
        }
    }
}

/// Cheap dialect hint for `Terminator::Auto`: does this chunk contain an SSE
/// event name only Anthropic emits? OpenAI-style and OpenAI-compatible streams
/// send bare `data:` lines; Anthropic sends `event: message_start`,
/// `event: content_block_delta`, `event: message_delta`, ... . A generic
/// `event:` field is *not* enough (proxies use it for OpenAI streams too).
///
/// Best effort on purpose: a marker split across chunks is missed, and the
/// only consequence is the previous behavior (an OpenAI-shaped error tail).
fn looks_anthropic(chunk: &[u8]) -> bool {
    const EVENT_NAMES: [&[u8]; 3] = [
        b"event: message_start",
        b"event: content_block_",
        b"event: message_delta",
    ];
    EVENT_NAMES.iter().any(|needle| find_memmem(chunk, needle))
}

fn sse_error_event(message: &str, terminator: Terminator) -> Bytes {
    // Inject an Anthropic-shaped error event into Anthropic streams; the others (OpenAI/auto/none) use the OpenAI shape.
    if matches!(terminator, Terminator::Anthropic) {
        let payload = json!({
            "type": "error",
            "error": { "type": "api_error", "message": message }
        });
        Bytes::from(format!("event: error\ndata: {payload}\n\n"))
    } else {
        let payload = json!({ "error": { "type": "upstream_stream_error", "message": message } });
        Bytes::from(format!("data: {payload}\n\ndata: [DONE]\n\n"))
    }
}

/// Every terminator marker the scanner searches for, in one place: the
/// boundary window only covers straddling markers up to
/// TERMINATOR_MAX_NEEDLE, and the fit assertion reads this same array — a
/// needle added here without raising the const fails that test instead of
/// silently blinding the chunk-boundary check. [0] is the OpenAI marker,
/// [1..] the Anthropic ones.
const TERMINATOR_NEEDLES: [&[u8]; 3] = [
    b"data: [DONE]",
    b"event: message_stop",
    b"\"type\":\"message_stop\"",
];

pub(crate) fn contains_terminator(chunk: &[u8], terminator: Terminator) -> bool {
    let needles = match terminator {
        Terminator::Openai => &TERMINATOR_NEEDLES[..1],
        Terminator::Anthropic => &TERMINATOR_NEEDLES[1..],
        Terminator::Auto => &TERMINATOR_NEEDLES[..],
        Terminator::None => return false,
    };
    needles
        .iter()
        .any(|needle| find_memmem(chunk, needle) || find_memmem_ci(chunk, needle))
}

fn find_memmem(haystack: &[u8], needle: &[u8]) -> bool {
    memchr::memmem::find(haystack, needle).is_some()
}

/// ASCII case-insensitive search, memchr-accelerated: a case-insensitive hit
/// at position `i` requires `haystack[i]` to equal the needle's first byte in
/// either case, so SIMD memchr2 locates the only positions worth verifying —
/// an O(n) scan plus a handful of O(m) checks, instead of an O(n*m) windows
/// sweep on every chunk of every SSE stream until the terminator shows up.
fn find_memmem_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let first = needle[0];
    let (cand1, cand2) = if first.is_ascii_alphabetic() {
        (first.to_ascii_lowercase(), first.to_ascii_uppercase())
    } else {
        // Non-letter first byte (e.g. '"' for the anthropic json marker):
        // case folding never touches it, so the exact byte is the candidate.
        (first, first)
    };
    let mut from = 0;
    while let Some(at) = memchr::memchr2(cand1, cand2, &haystack[from..]) {
        let start = from + at;
        if start + needle.len() > haystack.len() {
            return false;
        }
        if haystack[start..start + needle.len()].eq_ignore_ascii_case(needle) {
            return true;
        }
        from = start + 1;
    }
    false
}

fn build_response(status: reqwest::StatusCode, headers: HeaderMap, body: Body) -> Response {
    // Assemble from parts: the status and the already-filtered header map
    // move in wholesale instead of being re-copied header by header through a
    // response builder. Infallible, so the old builder-failure fallback is
    // gone too.
    let mut out = Response::new(body);
    *out.status_mut() = StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    *out.headers_mut() = headers;
    out
}

pub fn error_response(status: StatusCode, kind: &str, message: &str, rid: &str) -> Response {
    let body = json!({
        "error": {
            "type": kind,
            "message": message,
            "request_id": rid,
        }
    })
    .to_string();
    let mut response = (status, [(header::CONTENT_TYPE, "application/json")], body).into_response();
    if let Ok(value) = HeaderValue::from_str(rid) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-keysink-request-id"), value);
    }
    response
}

/// Whether to adopt a hot-reloaded new snapshot: never let .bak overwrite a
/// "good" snapshot still being served (.bak lags one generation and would
/// revive revoked/deleted vkeys). Adopt a backup only when there is no
/// current snapshot, or the current snapshot itself came from .bak (old and
/// new are both backups; swapping in the newer one is not a downgrade).
fn adopt_snapshot(incoming_from_backup: bool, current_from_backup: Option<bool>) -> bool {
    !incoming_from_backup || current_from_backup.is_none_or(|current| current)
}

/// Poll cadence for the store watcher while things are healthy.
const RELOAD_POLL: Duration = Duration::from_secs(1);
/// Backoff ceiling for repeated hot-reload failures on the same on-disk
/// state: a corrupt or undecryptable store would otherwise be re-read and
/// re-decrypted every second forever. Any success restores the 1s cadence,
/// so a fix is picked up within one backoff window (≤30s) of landing.
const MAX_RELOAD_BACKOFF: Duration = Duration::from_secs(30);

/// Next wait after a failed reload: doubles per consecutive failure, capped.
fn next_reload_backoff(after: Duration) -> Duration {
    after.saturating_mul(2).min(MAX_RELOAD_BACKOFF)
}

/// How often the supervisor checks that the watcher is still alive.
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(5);
/// A watcher that has not ticked for this long is wedged (a blocking disk read
/// that never returns, for instance). Reported, not killed: the tick is
/// published before the blocking part of the round, so a stale tick means the
/// watcher is stuck inside it and respawning would only park another blocking
/// task behind the same hung read.
const WATCHDOG_STALE: Duration = Duration::from_secs(120);

/// Runs the store watcher under a supervisor: a watcher task that dies (a
/// panic in the reload path) is restarted instead of silently leaving the
/// gateway on a snapshot nothing tracks any more, and a wedged watcher is
/// reported with its tick age. Both are also visible on the health endpoint
/// through `ReloadStatus`, so "the gateway answers" no longer hides "the vault
/// is no longer being watched".
pub fn spawn_watcher(state: Arc<AppState>, paths: Paths) {
    tokio::spawn(async move {
        loop {
            let watcher = tokio::spawn(watcher_loop(state.clone(), paths.clone()));
            tokio::pin!(watcher);
            let mut stale_warned = false;
            let joined = loop {
                tokio::select! {
                    res = &mut watcher => break Some(res),
                    _ = tokio::time::sleep(WATCHDOG_INTERVAL) => {
                        let age = tick_age(&state);
                        if age > WATCHDOG_STALE.as_secs() && !stale_warned {
                            tracing::error!(
                                age_secs = age,
                                "store watcher has not ticked; the vault may no longer be tracked (hung disk read?)"
                            );
                            stale_warned = true;
                        }
                    }
                }
            };
            match joined {
                Some(Ok(())) => tracing::error!("store watcher exited; restarting"),
                Some(Err(e)) => tracing::error!(error = %e, "store watcher failed; restarting"),
                None => break,
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}

fn tick_age(state: &AppState) -> u64 {
    state
        .started
        .elapsed()
        .as_secs()
        .saturating_sub(state.reload.last_tick_secs.load(Ordering::Relaxed))
}

/// Polls the vault.age / vault.key mtime+size and swaps in a whole new snapshot on change.
async fn watcher_loop(state: Arc<AppState>, paths: Paths) {
    // Zeroed so the first round after startup always reloads once,
    // covering the race where the CLI modified the store between serve
    // finishing the initial store load and the watcher starting.
    let mut last = (0u64, 0u64, 0u64);
    let mut failures = 0u32;
    let mut backup_warned = false;
    let mut delay = RELOAD_POLL;
    loop {
        tokio::time::sleep(delay).await;
        // Liveness tick, published before the blocking part of the round so
        // the watchdog can tell "nothing to reload" from "stuck reloading".
        state
            .reload
            .last_tick_secs
            .store(state.started.elapsed().as_secs(), Ordering::Relaxed);
        let now = stamp(&paths);
        if now == last {
            continue;
        }
        state.reload.attempts.fetch_add(1, Ordering::Relaxed);
        // File I/O + age decryption + JSON parse + validate are blocking:
        // run them on the blocking pool so a slow disk or a large vault
        // never occupies a tokio worker while requests are being forwarded.
        let unlocked = {
            let paths = paths.clone();
            tokio::task::spawn_blocking(move || crate::store::unlock(&paths))
                .await
                .unwrap_or_else(|e| Err(Error::msg(format!("hot reload worker failed: {e}"))))
        };
        match unlocked {
            Ok(unlocked) => match RouteTable::build(&unlocked.store) {
                Ok(table) => {
                    let from_backup = unlocked.from_backup;
                    if !adopt_snapshot(from_backup, Some(state.snapshot.load().from_backup)) {
                        // .bak wants to overwrite a good in-memory snapshot: refuse the
                        // downgrade. .bak lags one generation and would revive
                        // revoked/deleted vkeys; memory still holds the latest good data.
                        last = now;
                        delay = RELOAD_POLL;
                        failures += 1;
                        state.reload.failures.store(failures, Ordering::Relaxed);
                        if !backup_warned {
                            tracing::error!(
                                "main store failed to decrypt, refusing to overwrite in-memory snapshot with stale .bak (continuing to serve the latest good data); fix the main store ASAP"
                            );
                            backup_warned = true;
                        }
                        continue;
                    }
                    let routes = table.len();
                    let live_urls: HashSet<String> = unlocked
                        .store
                        .routes
                        .values()
                        .filter_map(|r| r.proxy.clone())
                        .filter(|p| p.as_str() != crate::model::PROXY_DIRECT)
                        .collect();
                    state.snapshot.store(Arc::new(Snapshot {
                        store: Arc::new(unlocked.store),
                        table,
                        from_backup,
                    }));
                    state.clients.retain_urls(&live_urls);
                    last = now;
                    failures = 0;
                    delay = RELOAD_POLL;
                    backup_warned = false;
                    state.reload.failures.store(0, Ordering::Relaxed);
                    state
                        .reload
                        .last_ok_secs
                        .store(state.started.elapsed().as_secs(), Ordering::Relaxed);
                    if from_backup {
                        tracing::error!(
                            "hot reload fell back to .bak backup (main store failed to decrypt): revoked/deleted vkeys may become effective again; fix ASAP"
                        );
                    }
                    tracing::info!(routes, from_backup, "store hot-reloaded");
                }
                Err(e) => {
                    failures += 1;
                    state.reload.failures.store(failures, Ordering::Relaxed);
                    delay = next_reload_backoff(delay);
                    if failures % 10 == 1 {
                        tracing::warn!(error = %e, "hot reload validation failed, keeping old snapshot");
                    }
                }
            },
            Err(e) => {
                failures += 1;
                state.reload.failures.store(failures, Ordering::Relaxed);
                delay = next_reload_backoff(delay);
                if failures % 10 == 1 {
                    tracing::warn!(error = %e, "hot reload decryption failed, keeping old snapshot");
                }
            }
        }
    }
}

fn stamp(paths: &Paths) -> (u64, u64, u64) {
    fn one(path: &std::path::Path) -> u64 {
        let Ok(md) = std::fs::metadata(path) else {
            return 0;
        };
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        // Mix in the inode: atomic writes go through rename, which always
        // changes the inode, so even with coarse filesystem mtime granularity
        // (e.g. 1s) and identical sizes across two writes the change is not
        // missed.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            mtime ^ md.len().rotate_left(17) ^ md.ino().rotate_left(41)
        }
        #[cfg(not(unix))]
        {
            mtime ^ md.len().rotate_left(17)
        }
    }
    (
        one(&paths.store()),
        one(&paths.master_key()),
        one(&paths.store_bak()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Auth;
    use std::collections::BTreeMap;

    fn route(auth: Auth) -> Route {
        Route::new(
            vkey::generate(),
            "https://api.example.com".into(),
            "real-key-123".into(),
            auth,
            BTreeMap::new(),
        )
    }

    #[test]
    fn extracts_vkey_case_insensitive_and_from_alt_headers() {
        let token = vkey::generate();
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("BEARER {token}")).unwrap(),
        );
        assert_eq!(extract_vkey(&h).as_deref(), Some(token.as_str()));

        // Extra spaces between the scheme and the token are tolerated
        // (some HTTP clients send more than RFC 7235's single SP).
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer   {token}")).unwrap(),
        );
        assert_eq!(extract_vkey(&h).as_deref(), Some(token.as_str()));
        // …but a scheme glued to the token is not the Bearer scheme.
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer{token}")).unwrap(),
        );
        assert_eq!(extract_vkey(&h).as_deref(), None);

        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_str(&token).unwrap());
        assert_eq!(extract_vkey(&h).as_deref(), Some(token.as_str()));

        // The rest of the outbound strip list is inbound-recognized too.
        for name in ["anthropic-api-key", "openai-api-key"] {
            let mut h = HeaderMap::new();
            h.insert(name, HeaderValue::from_str(&token).unwrap());
            assert_eq!(extract_vkey(&h).as_deref(), Some(token.as_str()), "{name}");
        }

        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer sk-real"),
        );
        assert!(extract_vkey(&h).is_none());
    }

    #[test]
    fn rejects_forbidden_static_headers() {
        let mut r = route(Auth::Bearer);
        r.headers.insert("host".into(), "evil".into());
        assert!(r.validate("r").is_err());
    }

    #[test]
    fn dot_segment_detection_covers_every_form_the_url_parser_collapses() {
        for path in [
            "/../x",
            "/v1/../x",
            "/a/./b",
            "/a/b/.",
            "/..",
            "/.",
            ".",
            "..",
            // percent-encoded variants (case-insensitive), per RFC 3986/WHATWG
            "/x/%2e/y",
            "/x/%2E%2e/z",
            "/x/.%2e/w",
            "/x/%2e./w",
            // backslash is a path separator for http(s) in the WHATWG parser
            "/a\\..\\b",
            "\\..",
            "/x\\..\\y",
        ] {
            assert!(path_has_dot_segment(path), "{path:?} must be flagged");
        }
        for path in [
            "",
            "/",
            "/v1/models",
            "/a/b/c",
            "//",
            // "..." and friends are literal segments no parser collapses
            "/a/.../b",
            "/a/..%2fx",
            "/a/%2e%2e%2e/x",
            "/a/%2fx",
        ] {
            assert!(!path_has_dot_segment(path), "{path:?} must pass");
        }
    }

    #[test]
    fn build_upstream_url_refuses_dot_segments() {
        for path in ["/../x", "/v1/%2e%2e/x", "/a\\..\\b"] {
            assert!(
                build_upstream_url("https://up.test/v1", path, None, &Auth::None, "k").is_err(),
                "{path:?} must be refused"
            );
        }
        assert!(build_upstream_url("https://up.test/v1", "/v1/ok", None, &Auth::None, "k").is_ok());
    }

    #[test]
    fn detects_stream_flag() {
        assert!(is_stream_request(br#"{"stream":true}"#));
        assert!(is_stream_request(br#"{"stream": true, "x": 1}"#));
        assert!(!is_stream_request(br#"{"stream":false}"#));
        assert!(!is_stream_request(br#"{"model":"x"}"#));
        assert!(!is_stream_request(b"not json"));
        assert!(!is_stream_request(b""));
    }

    #[test]
    fn terminator_needles_fit_the_carry_window() {
        for needle in TERMINATOR_NEEDLES {
            assert!(
                needle.len() <= TERMINATOR_MAX_NEEDLE,
                "needle {needle:?} is longer than TERMINATOR_MAX_NEEDLE; raise the const so the boundary window still covers straddling markers"
            );
        }
    }

    #[test]
    fn scan_finds_markers_split_at_every_point() {
        for marker in TERMINATOR_NEEDLES {
            // two-chunk split at every interior point
            for split in 1..marker.len() {
                let mut scan = SseScan::new(Terminator::Auto, "R".into());
                scan.feed(&marker[..split]);
                assert!(
                    !scan.seen,
                    "{marker:?} split {split}: a partial marker must not match"
                );
                scan.feed(&marker[split..]);
                assert!(
                    scan.seen,
                    "{marker:?} split {split}: a completed marker must be found"
                );
            }
            // byte-by-byte arrival
            let mut scan = SseScan::new(Terminator::Auto, "R".into());
            for (i, byte) in marker.iter().enumerate() {
                scan.feed(std::slice::from_ref(byte));
                assert_eq!(
                    scan.seen,
                    i + 1 == marker.len(),
                    "{marker:?} byte {i}: seen must flip exactly at the last byte"
                );
            }
            // an ordinary event stream must not trip the scanner
            let mut scan = SseScan::new(Terminator::Auto, "R".into());
            scan.feed(b"event: delta\ndata: {\"i\":0}\n\n");
            assert!(!scan.seen);
            // terminator disabled: never scans, carry stays empty
            let mut scan = SseScan::new(Terminator::None, "R".into());
            scan.feed(b"event: message_stop\n\n");
            assert!(!scan.seen && scan.carry.is_empty());
        }
    }

    #[test]
    fn auto_dialect_follows_the_observed_stream_style() {
        // An Anthropic-looking stream truncated mid-flight must get the
        // Anthropic error shape, not an OpenAI `data: [DONE]` tail.
        let mut scan = SseScan::new(Terminator::Auto, "R".into());
        scan.feed(b"event: message_start\ndata: {}\n\n");
        assert_eq!(scan.dialect(), Terminator::Anthropic);
        let event = sse_error_event("boom", scan.dialect());
        let text = std::str::from_utf8(&event).unwrap();
        assert!(text.starts_with("event: error\n"), "{text}");
        assert!(!text.contains("[DONE]"), "{text}");

        // OpenAI-style data-only stream keeps the OpenAI shape.
        let mut scan = SseScan::new(Terminator::Auto, "R".into());
        scan.feed(b"data: {\"i\":0}\n\n");
        assert_eq!(scan.dialect(), Terminator::Auto);

        // A generic `event:` field is not an Anthropic signal: OpenAI
        // compatible proxies emit those too, and they kept the OpenAI tail.
        let mut scan = SseScan::new(Terminator::Auto, "R".into());
        scan.feed(b"event: delta\ndata: {\"i\":0}\n\n");
        assert_eq!(scan.dialect(), Terminator::Auto);

        // Explicit terminators are never overridden by observation.
        let mut scan = SseScan::new(Terminator::Openai, "R".into());
        scan.feed(b"event: message_start\n\n");
        assert_eq!(scan.dialect(), Terminator::Openai);
    }

    #[test]
    fn builds_url_with_path_and_query() {
        let url = build_upstream_url(
            "https://api.example.com/",
            "/v1/messages",
            Some("a=1&b=2"),
            &Auth::Bearer,
            "secret",
        )
        .unwrap();
        assert_eq!(url, "https://api.example.com/v1/messages?a=1&b=2");
    }

    #[test]
    fn query_auth_replaces_existing_param() {
        let url = build_upstream_url(
            "https://generativelanguage.googleapis.com",
            "/v1beta/models/x:generateContent",
            Some("alt=sse&key=old"),
            &Auth::Query {
                param: "key".into(),
            },
            "a b&c",
        )
        .unwrap();
        assert_eq!(
            url,
            "https://generativelanguage.googleapis.com/v1beta/models/x:generateContent?alt=sse&key=a%20b%26c"
        );
    }

    #[test]
    fn injects_bearer_and_strips_inbound_auth() {
        let mut src = HeaderMap::new();
        src.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer ks_xxx"),
        );
        src.insert("x-api-key", HeaderValue::from_static("ks_xxx"));
        src.insert("x-custom", HeaderValue::from_static("ok"));
        let out = forward_headers(&src, &route(Auth::Bearer), "real-secret", false).unwrap();
        assert_eq!(
            out.get(header::AUTHORIZATION).unwrap(),
            "Bearer real-secret"
        );
        assert!(out.get("x-api-key").is_none());
        assert_eq!(out.get("x-custom").unwrap(), "ok");
    }

    #[test]
    fn injects_x_api_key_and_static_headers() {
        let mut r = route(Auth::XApiKey);
        r.headers
            .insert("anthropic-version".into(), "2023-06-01".into());
        let out = forward_headers(&HeaderMap::new(), &r, "real", false).unwrap();
        assert_eq!(out.get("x-api-key").unwrap(), "real");
        assert_eq!(out.get("anthropic-version").unwrap(), "2023-06-01");
    }

    #[test]
    fn strips_accept_encoding_only_for_streaming_requests() {
        let mut src = HeaderMap::new();
        src.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        let r = route(Auth::Bearer);

        let streamed = forward_headers(&src, &r, "k", true).unwrap();
        assert!(streamed.get(header::ACCEPT_ENCODING).is_none());

        let plain = forward_headers(&src, &r, "k", false).unwrap();
        assert_eq!(
            plain.get(header::ACCEPT_ENCODING).unwrap(),
            "gzip, deflate, br, zstd"
        );
    }

    #[test]
    fn streaming_route_static_accept_encoding_is_dropped() {
        // A statically configured accept-encoding blinds the SSE terminator
        // scan just the same, so streaming must drop it too.
        let mut r = route(Auth::Bearer);
        r.headers.insert("accept-encoding".into(), "gzip".into());
        r.headers.insert("ACCEPT-ENCODING".into(), "br".into());
        let out = forward_headers(&HeaderMap::new(), &r, "k", true).unwrap();
        assert!(out.get(header::ACCEPT_ENCODING).is_none());
        let plain = forward_headers(&HeaderMap::new(), &r, "k", false).unwrap();
        assert_eq!(plain.get(header::ACCEPT_ENCODING).unwrap(), "br");
    }

    #[test]
    fn detects_content_encoding_but_not_identity() {
        let mut headers = HeaderMap::new();
        assert!(!is_encoded(&headers));

        headers.insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        assert!(!is_encoded(&headers));

        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("zstd"));
        assert!(is_encoded(&headers));

        headers.insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip, br"),
        );
        assert!(is_encoded(&headers));
    }

    #[test]
    fn basic_auth_encodes_pair() {
        let out = forward_headers(
            &HeaderMap::new(),
            &route(Auth::Basic {
                username: "user".into(),
            }),
            "pass",
            false,
        )
        .unwrap();
        assert_eq!(
            out.get(header::AUTHORIZATION).unwrap(),
            "Basic dXNlcjpwYXNz"
        );
    }

    #[test]
    fn detects_sse_terminators() {
        assert!(contains_terminator(b"data: [DONE]\n\n", Terminator::Auto));
        assert!(contains_terminator(
            b"event: message_stop\ndata: {}\n\n",
            Terminator::Auto
        ));
        assert!(!contains_terminator(
            b"data: {\"i\":0}\n\n",
            Terminator::Auto
        ));
        assert!(contains_terminator(b"DATA: [done]\n\n", Terminator::Openai));
        assert!(!contains_terminator(
            b"data: [DONE]\n\n",
            Terminator::Anthropic
        ));
        assert!(!contains_terminator(b"data: [DONE]\n\n", Terminator::None));
    }

    #[test]
    fn stream_probe_semantics() {
        // shapes real clients send
        assert!(is_stream_request(br#"{"model":"m","stream":true}"#));
        assert!(is_stream_request(br#"{"stream":true,"model":"m"}"#));
        assert!(!is_stream_request(br#"{"stream":null}"#));
        assert!(!is_stream_request(br#"{"stream":"true"}"#));
        assert!(!is_stream_request(br#"{"stream":1}"#));
        // escaped keys decode to the same member name; the prefilter needs a
        // literal `"stream"` somewhere, so pair the escaped key with one
        assert!(is_stream_request(
            br#"{"stre\u0061m":true,"note":"stream"}"#
        ));
        assert!(!is_stream_request(br#"{"stre\u0061m":true}"#));
        // documented divergences from the old full-parse probe (see
        // top_level_stream_true): only reachable on bodies that are not
        // valid LLM requests
        assert!(is_stream_request(br#"{"stream":true} trailing garbage"#));
        assert!(is_stream_request(br#"{"stream":true,"stream":false}"#));
        assert!(!is_stream_request(b"[true]"));
    }

    #[test]
    fn finds_sse_terminators_in_all_case_variants() {
        // find_memmem_ci edge positions: exact-length haystack (hit at 0),
        // hit at the very end, dense candidate bytes exercising the rescan
        // loop, non-letter first byte ('"' for the anthropic json marker),
        // and the miss paths (needle does not fit, no candidate at all).
        assert!(find_memmem_ci(b"data: [DONE]", b"data: [DONE]"));
        assert!(find_memmem_ci(
            b"xxxxxxxxxxxxxdata: [DONE]",
            b"data: [DONE]"
        ));
        let dense: Vec<u8> = [vec![b'd'; 30], b"data: [DONE]".to_vec()].concat();
        assert!(find_memmem_ci(&dense, b"data: [DONE]"));
        assert!(find_memmem_ci(
            b"{\"i\":0} \"TYPE\":\"MESSAGE_STOP\"",
            b"\"type\":\"message_stop\""
        ));
        // candidate present but the needle does not fit past it
        assert!(!find_memmem_ci(b"xxdata: [DON", b"data: [DONE]"));
        assert!(!find_memmem_ci(b"data: [DON", b"data: [DONE]"));
        assert!(!find_memmem_ci(b"no marker here", b"data: [DONE]"));
    }

    #[test]
    fn rid_grows_past_four_digits() {
        assert_eq!(rid_from(0), "0000");
        assert_eq!(rid_from(1), "0001");
        assert_eq!(rid_from(1679615), "ZZZZ");
        assert_eq!(rid_from(1679616), "10000");
        assert_eq!(rid_from(u64::MAX).len(), 13);
    }

    #[test]
    fn sse_error_event_matches_protocol() {
        let anthropic = sse_error_event("boom", Terminator::Anthropic);
        let text = std::str::from_utf8(&anthropic).unwrap();
        assert!(text.starts_with("event: error\n"));
        assert!(text.contains("\"type\":\"error\""));
        assert!(!text.contains("[DONE]"));

        let openai = sse_error_event("boom", Terminator::Openai);
        let text = std::str::from_utf8(&openai).unwrap();
        assert!(text.starts_with("data: {"));
        assert!(text.ends_with("data: [DONE]\n\n"));

        let auto = sse_error_event("boom", Terminator::Auto);
        assert_eq!(auto, openai);
    }

    #[test]
    fn proxy_clients_follow_route_config() {
        let clients = ProxyClients::new().unwrap();
        let mut r = route(Auth::Bearer);

        r.proxy = None;
        assert!(clients.for_route(&r, false).is_ok());
        assert!(clients.for_route(&r, true).is_ok());
        r.proxy = Some("direct".into());
        assert!(clients.for_route(&r, false).is_ok());
        r.proxy = Some("http://127.0.0.1:7890".into());
        assert!(clients.for_route(&r, true).is_ok());
        assert!(clients.for_route(&r, false).is_ok()); // cache-hit path

        r.proxy = Some("http://".into()); // valid scheme but empty host in the URL
        assert!(clients.for_route(&r, false).is_err());
    }

    #[test]
    fn retain_urls_evicts_stale_proxy_clients() {
        let clients = ProxyClients::new().unwrap();
        let mut r = route(Auth::Bearer);
        r.proxy = Some("http://127.0.0.1:7890".into());
        assert!(clients.for_route(&r, false).is_ok());

        let mut live = HashSet::new();
        clients.retain_urls(&live);
        assert!(clients.for_route(&r, false).is_ok()); // rebuilt (i.e. it had been evicted)

        live.insert("http://127.0.0.1:7890".into());
        clients.for_route(&r, false).unwrap();
        clients.retain_urls(&live);
        clients.for_route(&r, false).unwrap();
    }

    #[tokio::test]
    async fn classifies_length_limit_by_type_not_string_only() {
        // LengthLimitError is #[non_exhaustive] and cannot be constructed
        // directly in tests; take the real path: when to_bytes exceeds the
        // limit, it is in the axum::Error source chain.
        let e = axum::body::to_bytes(axum::body::Body::from("hello"), 2)
            .await
            .unwrap_err();
        assert!(is_length_limit_error(&e));
        let other = axum::Error::new(std::io::Error::other("boom"));
        assert!(!is_length_limit_error(&other));
    }

    #[test]
    fn watcher_never_downgrades_good_snapshot_to_backup() {
        // new snapshot is the main store → adopt unconditionally
        assert!(adopt_snapshot(false, Some(false)));
        // .bak wants to overwrite a good snapshot still being served → refuse
        assert!(!adopt_snapshot(true, Some(false)));
        // no current snapshot (startup path) → adopt
        assert!(adopt_snapshot(true, None));
        // the current snapshot itself is from .bak → a peer replacement is not a downgrade
        assert!(adopt_snapshot(true, Some(true)));
    }

    #[test]
    fn network_errors_retry_only_when_replay_safe() {
        // connect-class error: request definitely not delivered → replayable
        assert!(network_retry_allowed(true, false));
        // idempotent method: any network error is replayable
        assert!(network_retry_allowed(false, true));
        // POST + non-connect error (timeout/disconnect): upstream may have billed → not replayable
        assert!(!network_retry_allowed(false, false));
    }

    #[test]
    fn reload_backoff_doubles_and_caps() {
        let mut d = RELOAD_POLL;
        for _ in 0..10 {
            d = next_reload_backoff(d);
        }
        assert_eq!(d, MAX_RELOAD_BACKOFF);
        assert_eq!(
            next_reload_backoff(d),
            d,
            "once capped, backoff stays capped"
        );
    }

    #[cfg(unix)]
    #[test]
    fn accept_errors_split_into_pressure_connection_and_fatal() {
        // Resource pressure (fd or kernel memory): back off, the listener is
        // fine. ENOBUFS/ENOMEM belong here, not in the retry-now bucket:
        // under pressure a re-accept usually fails again, and an immediate
        // retry would hot-spin a core.
        for code in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            let e = std::io::Error::from_raw_os_error(code);
            assert!(
                is_resource_pressure_accept_error(&e),
                "errno {code} is resource pressure"
            );
            assert!(!is_connection_level_accept_error(&e));
        }

        // Per-connection errors accept(2) passes up from the backlog: the
        // aborted connection is gone, the listener still works. Treating
        // these as fatal (the old behavior) turned one dropped handshake into
        // a full gateway restart.
        for code in [
            libc::ECONNABORTED,
            libc::EPROTO,
            libc::ENETDOWN,
            libc::ENETUNREACH,
            libc::EHOSTUNREACH,
            libc::EOPNOTSUPP,
        ] {
            let e = std::io::Error::from_raw_os_error(code);
            assert!(
                is_connection_level_accept_error(&e),
                "errno {code} is per-connection, not fatal"
            );
            assert!(!is_resource_pressure_accept_error(&e));
        }

        // Anything else still means the listener is unusable.
        assert!(!is_connection_level_accept_error(&std::io::Error::other(
            "boom"
        )));
        assert!(!is_connection_level_accept_error(
            &std::io::Error::from_raw_os_error(libc::EINVAL)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn idle_bounded_passes_chunks_and_ends_cleanly() {
        let inner = stream::iter(vec![
            Ok::<Bytes, reqwest::Error>(Bytes::from_static(b"a")),
            Ok(Bytes::from_static(b"b")),
        ]);
        let mut s = Box::pin(idle_bounded(
            inner,
            Duration::from_secs(60),
            Some(Duration::from_secs(600)),
        ));
        assert_eq!(s.next().await.unwrap().unwrap(), Bytes::from_static(b"a"));
        assert_eq!(s.next().await.unwrap().unwrap(), Bytes::from_static(b"b"));
        assert!(s.next().await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_bounded_aborts_stalled_body_and_stops() {
        // one chunk, then the upstream goes silent forever
        let inner = stream::once(async { Ok::<Bytes, reqwest::Error>(Bytes::from_static(b"x")) })
            .chain(stream::pending::<reqwest::Result<Bytes>>());
        let mut s = Box::pin(idle_bounded(
            inner,
            Duration::from_secs(30),
            Some(Duration::from_secs(600)),
        ));
        assert_eq!(s.next().await.unwrap().unwrap(), Bytes::from_static(b"x"));
        let err = s.next().await.unwrap().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        // after the timeout error the stream must end, not loop errors
        assert!(s.next().await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_bounded_tolerates_slow_but_alive_upstream() {
        // gaps well under the idle bound must not trip the abort
        let inner = stream::iter(0u8..3).then(|i| async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok::<Bytes, reqwest::Error>(Bytes::from(vec![i]))
        });
        let mut s = Box::pin(idle_bounded(
            inner,
            Duration::from_secs(60),
            Some(Duration::from_secs(600)),
        ));
        for i in 0u8..3 {
            assert_eq!(s.next().await.unwrap().unwrap(), Bytes::from(vec![i]));
        }
        assert!(s.next().await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_bounded_enforces_the_total_budget() {
        // A trickle that never trips the per-chunk idle bound (every chunk
        // arrives well within it) must still end at the total budget: without
        // it such an upstream held its connection slot forever.
        let inner = stream::iter(0u8..10).then(|i| async move {
            tokio::time::sleep(Duration::from_secs(20)).await;
            Ok::<Bytes, reqwest::Error>(Bytes::from(vec![i]))
        });
        let mut s = Box::pin(idle_bounded(
            inner,
            Duration::from_secs(60),
            Some(Duration::from_secs(90)),
        ));
        // chunks at t=20, 40, 60, 80 — each one inside the 60s idle bound
        for i in 0u8..4 {
            assert_eq!(s.next().await.unwrap().unwrap(), Bytes::from(vec![i]));
        }
        // the next chunk would land at t=100, past the 90s total budget
        let err = s.next().await.unwrap().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            err.to_string().contains("total budget"),
            "the total-budget abort must be distinguishable from the idle one: {err}"
        );
        assert!(s.next().await.is_none());
    }
}

#[cfg(test)]
mod serve_inbound_tests {
    use super::*;
    use crate::model::Store;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState {
            snapshot: ArcSwap::from_pointee(Snapshot {
                store: Arc::new(Store::new()),
                table: RouteTable::build(&Store::new()).unwrap(),
                from_backup: false,
            }),
            clients: ProxyClients::new().unwrap(),
            retry: RetryPolicy::default(),
            body_limit: 1 << 20,
            body_read_idle: BODY_READ_IDLE,
            inbound_body_timeout: CLIENT_BODY_TIMEOUT,
            permit_queue_timeout: PERMIT_QUEUE_TIMEOUT,
            body_total_budget: BODY_TOTAL_BUDGET,
            reload: Arc::new(ReloadStatus::default()),
            counters: Arc::new(ServeCounters::default()),
            inbound_permits: Arc::new(tokio::sync::Semaphore::new(8)),
            audit: Audit::disabled(),
            started: Instant::now(),
        })
    }

    /// Regression: the reaping arm of the accept select must be disabled while
    /// the JoinSet is empty. `join_next` returns Ready(None) immediately for an
    /// empty set, so an unguarded arm is always ready — the loop spins on it
    /// and `listener.accept()` is never polled: the gateway accepts nothing
    /// (connections pile up in the kernel backlog) while burning CPU. A real
    /// round trip through serve_inbound is the only way to see it; handler-level
    /// tests bypass the accept loop entirely. The timeout guard turns the
    /// regression into a fast failure instead of a hang.
    #[tokio::test]
    async fn serve_inbound_accepts_and_answers_while_reaping() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_inbound(
            listener,
            build_app(test_state()),
            InboundLimits {
                header_timeout: CLIENT_HEADER_TIMEOUT,
                max_connections: 64,
                drain_timeout: Some(Duration::from_secs(5)),
                loop_iterations: None,
                live_connections: None,
                counters: None,
            },
            std::future::pending(),
        ));

        // First connection is served (the empty-set spin never gets here).
        let buf = tokio::time::timeout(Duration::from_secs(10), async {
            let mut s = tokio::net::TcpStream::connect(addr).await?;
            s.write_all(b"GET /__keysink/health HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n")
                .await?;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await?;
            Ok::<Vec<u8>, std::io::Error>(buf)
        })
        .await
        .expect("serve_inbound must accept and answer connections")
        .unwrap();
        assert!(
            buf.starts_with(b"HTTP/1.1 200"),
            "health must answer 200, got: {}",
            String::from_utf8_lossy(&buf)
        );

        // A finished connection task must be reaped: after the connection
        // closes, the JoinSet drains back to empty and the loop returns to
        // accept() — proven indirectly by a second full round trip.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                // The server task is polled concurrently; sleep a tick per probe.
                tokio::time::sleep(Duration::from_millis(20)).await;
                // Indirect probe: a second request must also be served, which
                // proves the loop returned to accept() after reaping.
                let mut s = tokio::net::TcpStream::connect(addr).await?;
                s.write_all(
                    b"GET /__keysink/health HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n",
                )
                .await?;
                let mut buf = Vec::new();
                s.read_to_end(&mut buf).await?;
                if buf.starts_with(b"HTTP/1.1 200") {
                    return Ok::<(), std::io::Error>(());
                }
            }
        })
        .await
        .expect("second connection must also be served after the first was reaped")
        .unwrap();

        server.abort();
    }

    /// Regression (idle spin): the same unguarded reaping arm spins the loop
    /// even with NO connections — join_next is always ready on an empty set,
    /// so the loop burns a core while idle and the round-trip test above
    /// cannot see it (its connections arrive fast enough that accept wins
    /// the select races anyway). The loop counter makes the spin directly
    /// assertable: an idle loop must pend on accept, not iterate.
    #[tokio::test]
    async fn serve_inbound_idle_loop_pends_instead_of_spinning() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let iterations = Arc::new(AtomicU64::new(0));
        let server = tokio::spawn(serve_inbound(
            listener,
            build_app(test_state()),
            InboundLimits {
                header_timeout: CLIENT_HEADER_TIMEOUT,
                max_connections: 8,
                drain_timeout: Some(Duration::from_secs(5)),
                loop_iterations: Some(iterations.clone()),
                live_connections: None,
                counters: None,
            },
            std::future::pending(),
        ));

        // Idle for 300ms: with the guard the loop sits in accept (1-2
        // iterations); the spin bug produces ~1e6 iterations per second.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let count = iterations.load(Ordering::Relaxed);
        assert!(
            count < 1_000,
            "idle accept loop must pend on accept, not spin; iterations in 300ms: {count}"
        );

        // Still healthy afterwards: one round trip through the same loop.
        let buf = tokio::time::timeout(Duration::from_secs(10), async {
            let mut s = tokio::net::TcpStream::connect(addr).await?;
            s.write_all(b"GET /__keysink/health HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n")
                .await?;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await?;
            Ok::<Vec<u8>, std::io::Error>(buf)
        })
        .await
        .expect("idle loop must still accept and answer")
        .unwrap();
        assert!(buf.starts_with(b"HTTP/1.1 200"));

        server.abort();
    }

    /// Regression (sniff DoS): a connection that never sends a byte must be
    /// dropped within the head timeout. Before the sniff read, such a
    /// connection parked a connection slot forever — hyper-util's auto
    /// builder polls for the 24-byte h2 preface with no bound, and neither
    /// header_read_timeout (http1-only) nor the h2 keep-alive PING
    /// (post-handshake only) reaches that phase.
    #[tokio::test]
    async fn serve_inbound_drops_silent_connection_within_head_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let head_timeout = Duration::from_millis(300);
        let server = tokio::spawn(serve_inbound(
            listener,
            build_app(test_state()),
            InboundLimits {
                header_timeout: head_timeout,
                max_connections: 8,
                drain_timeout: Some(Duration::from_secs(5)),
                loop_iterations: None,
                live_connections: None,
                counters: None,
            },
            std::future::pending(),
        ));

        // Connect and say nothing: the server must close the socket.
        // Without the sniff bound this read hangs until the test timeout —
        // exactly the parked-slot DoS. (The trickle variant is covered
        // deterministically, with paused time, in sniff_protocol_decides_or_times_out.)
        let closed = tokio::time::timeout(head_timeout * 10, async {
            let mut s = tokio::net::TcpStream::connect(addr).await?;
            let mut buf = [0u8; 16];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) => return Ok::<(), std::io::Error>(()),
                    Ok(_) => continue,
                    Err(e) => return Err(e),
                }
            }
        })
        .await
        .expect("silent connection must be dropped within the head timeout");
        assert!(
            closed.is_ok(),
            "expected clean EOF, got {:?}",
            closed.unwrap_err()
        );

        server.abort();
    }

    /// Regression (h2 handshake DoS): sending only the 24-byte h2 preface
    /// used to hold a connection slot forever. The preface satisfied the
    /// sniff, hyper then waited for the client SETTINGS frame, and the h2
    /// keep-alive PING only starts after that handshake completes. The
    /// first-request deadline must close the connection instead.
    #[tokio::test]
    async fn serve_inbound_drops_h2_handshake_stall_within_head_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let head_timeout = Duration::from_millis(300);
        let server = tokio::spawn(serve_inbound(
            listener,
            build_app(test_state()),
            InboundLimits {
                header_timeout: head_timeout,
                max_connections: 8,
                drain_timeout: Some(Duration::from_secs(5)),
                loop_iterations: None,
                live_connections: None,
                counters: None,
            },
            std::future::pending(),
        ));

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(H2_PREFACE).await.unwrap();
        let _closed = tokio::time::timeout(head_timeout * 10, async {
            let mut buf = [0u8; 16];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) => return Ok::<(), std::io::Error>(()),
                    Ok(_) => continue,
                    Err(e) => return Err(e),
                }
            }
        })
        .await
        .expect("an h2 handshake stall must be dropped within the head timeout");

        server.abort();
    }

    /// sniff_protocol hands h2 bursts through whole (preface + first frames
    /// in one read is legal client behavior), stops at the first divergence
    /// (http1 needs no further sniffing), EOFs cleanly, and — the whole
    /// point — drops a silent or trickling peer at the whole-phase deadline
    /// instead of parking the connection slot forever.
    #[tokio::test(start_paused = true)]
    async fn sniff_protocol_decides_or_times_out() {
        // h2 burst: preface + a settings frame payload in one write; the
        // overshoot must come back intact for hyper to parse.
        let (mut client, mut server) = tokio::io::duplex(64);
        let mut burst = H2_PREFACE.to_vec();
        burst.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0]);
        client.write_all(&burst).await.unwrap();
        let seen = sniff_protocol(&mut server, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(seen, burst, "preface burst must pass through unmodified");

        // http1 divergence: first byte already decides, one read is enough.
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(b"GET /x HTTP/1.1\r\n").await.unwrap();
        let seen = sniff_protocol(&mut server, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(seen, b"GET /x HTTP/1.1\r\n".to_vec());

        // Silent peer: the deadline must fire, not hang.
        let (_client, mut server) = tokio::io::duplex(64);
        let err = sniff_protocol(&mut server, Duration::from_secs(30))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);

        // Trickle: preface bytes one at a time keeps the prefix forever
        // undecided, so only the whole-phase deadline (not a per-read one)
        // can end the sniff.
        let (mut client, mut server) = tokio::io::duplex(64);
        let dribble = tokio::spawn(async move {
            loop {
                for byte in H2_PREFACE {
                    if client.write_all(&[*byte]).await.is_err() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
        });
        let err = sniff_protocol(&mut server, Duration::from_secs(30))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        dribble.abort();
    }

    /// Regression guard for the memory creep class: finished connection tasks
    /// must be reaped as they finish. `JoinSet` keeps every finished entry
    /// (handle plus the task's harness allocation, sized to hold hyper's
    /// connection future) until `join_next` consumes it, so a loop that only
    /// drains at shutdown grows with the cumulative connection count even at
    /// flat concurrency. The gauge is the JoinSet length after each accept and
    /// each reap: sequential connect/close cycles must return it to zero
    /// instead of accumulating.
    #[tokio::test]
    async fn serve_inbound_reaps_finished_connection_tasks() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let live = Arc::new(AtomicU64::new(0));
        let server = tokio::spawn(serve_inbound(
            listener,
            build_app(test_state()),
            InboundLimits {
                header_timeout: CLIENT_HEADER_TIMEOUT,
                max_connections: 16,
                drain_timeout: Some(Duration::from_secs(5)),
                loop_iterations: None,
                live_connections: Some(live.clone()),
                counters: None,
            },
            std::future::pending(),
        ));

        for _ in 0..50 {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.write_all(b"GET /__keysink/health HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            assert!(buf.starts_with(b"HTTP/1.1 200"));
        }

        // Every closed connection's task must be consumed by the reaping arm.
        let reaped = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if live.load(Ordering::Relaxed) == 0 {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or(false);
        assert!(
            reaped,
            "finished connection tasks must be reaped, JoinSet still holds {}",
            live.load(Ordering::Relaxed)
        );

        server.abort();
    }

    /// Regression: shutdown used to wait for every connection to end on its
    /// own. An idle keep-alive socket only ends when hyper's
    /// header_read_timeout (30s) expires, so a stop took ~30s — past the
    /// service manager's stop timeout, which SIGKILLed the process every time
    /// (losing the audit flush and the runtime-file cleanup). Shutdown is now
    /// propagated into each connection: an idle one closes immediately.
    #[tokio::test]
    async fn serve_inbound_shutdown_reaps_idle_keep_alive_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve_inbound(
            listener,
            build_app(test_state()),
            InboundLimits {
                header_timeout: CLIENT_HEADER_TIMEOUT,
                max_connections: 8,
                drain_timeout: Some(Duration::from_secs(5)),
                loop_iterations: None,
                live_connections: None,
                counters: None,
            },
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        // One request, then stay connected and idle (an agent's pooled socket).
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /__keysink/health HTTP/1.1\r\nhost: t\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 1024];
        let n = s.read(&mut buf).await.unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"),
            "health must answer before shutdown"
        );

        let started = Instant::now();
        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("shutdown must not wait for the 30s idle keep-alive reap")
            .unwrap()
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "drain took {:?}",
            started.elapsed()
        );

        // The connection must be closed, not left lingering: the client sees EOF.
        let closed = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await;
        assert!(
            matches!(closed, Ok(Ok(0))),
            "the drained connection must be closed, got {closed:?}"
        );
    }

    #[tokio::test]
    async fn health_reports_reload_and_audit_state() {
        let state = test_state();
        state.reload.failures.store(3, Ordering::Relaxed);
        state.counters.shed.store(7, Ordering::Relaxed);
        state.counters.accept_errors.store(2, Ordering::Relaxed);
        let resp = health(State(state)).await.into_response();
        let bytes = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["reload_failures"], 3);
        assert!(
            v["snapshot_age_secs"].as_u64().is_some(),
            "snapshot age must be reported: {v}"
        );
        assert_eq!(v["audit"], false);
        // audit off is not an unhealthy audit; only a dead writer is
        assert_eq!(v["audit_ok"], true);
        assert_eq!(v["audit_dropped"], 0);
        assert_eq!(v["shed_connections"], 7);
        assert_eq!(v["accept_errors"], 2);
    }

    /// PrefaceIo must replay the sniffed bytes before the live stream, then
    /// disappear — hyper sees exactly the byte stream it would have read
    /// itself, across replay-buffer boundaries.
    #[tokio::test]
    async fn preface_io_replays_then_passes_through() {
        let (mut client, server) = tokio::io::duplex(8);
        let mut io = PrefaceIo {
            io: server,
            preface: b"PRI * HTTP/2.0".to_vec(),
            pos: 0,
        };
        client.write_all(b"|live|").await.unwrap();
        drop(client); // read_to_end needs the peer's EOF

        let mut seen = Vec::new();
        io.read_to_end(&mut seen).await.unwrap();
        assert_eq!(
            seen,
            b"PRI * HTTP/2.0|live|".to_vec(),
            "replayed preface must precede live bytes"
        );
    }
}
