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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::Instrument;
use zeroize::Zeroizing;

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

pub struct AppState {
    pub snapshot: ArcSwap<Snapshot>,
    pub clients: ProxyClients,
    pub retry: RetryPolicy,
    pub body_limit: usize,
    /// Per-chunk read-idle bound for non-streaming upstream bodies (BODY_READ_IDLE in production; tests inject a small value).
    pub body_read_idle: Duration,
    /// Whole-body bound on reading the inbound request body (CLIENT_BODY_TIMEOUT in production; tests inject a small value).
    pub inbound_body_timeout: Duration,
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
        .pool_idle_timeout(Duration::from_secs(90))
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
#[derive(Clone, Copy)]
pub struct InboundLimits {
    /// Whole-head bound: a client that does not finish sending its request
    /// head within this time is disconnected (slowloris defense).
    pub header_timeout: Duration,
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
    loop {
        let accepted = tokio::select! {
            _ = &mut shutdown => None,
            accepted = listener.accept() => Some(accepted),
        };
        let Some(accepted) = accepted else {
            break;
        };
        let (stream, _peer) = accepted?;
        let _ = stream.set_nodelay(true);
        // The connection future owns its builder (cheap config clone) so it
        // stays 'static and can outlive this loop while draining.
        let app = app.clone();
        conns.spawn(async move {
            let mut builder =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            builder.http1().timer(hyper_util::rt::TokioTimer::new());
            builder
                .http1()
                .header_read_timeout(Some(limits.header_timeout));
            if let Err(e) = builder
                .serve_connection_with_upgrades(
                    hyper_util::rt::TokioIo::new(stream),
                    hyper_util::service::TowerToHyperService::new(app.clone()),
                )
                .await
            {
                // Client aborts mid-stream are routine for a proxy; keep the
                // noise down but leave a trace for debugging.
                tracing::debug!(error = %e, "inbound connection ended");
            }
        });
    }
    // Graceful: stop accepting, then let in-flight requests (including long
    // SSE streams) run to completion on their own — same semantics as
    // axum::serve's graceful shutdown; the service manager's stop timeout is
    // the hard cap.
    while conns.join_next().await.is_some() {}
    Ok(())
}

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let snap = state.snapshot.load();
    Json(json!({
        "ok": true,
        "degraded": snap.from_backup,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": state.started.elapsed().as_secs(),
        "routes": snap.table.len(),
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
    // Queue until a permit frees up: saturating the gateway makes extra
    // requests wait rather than pile up unbounded memory. Never closed, so
    // acquisition only fails in a shutdown race.
    let Ok(_permit) = state.inbound_permits.clone().acquire_owned().await else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "overloaded",
            "gateway is not accepting requests",
            &rid,
        );
    };
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().map(str::to_string);
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
            &method,
            &path,
            status,
            started,
        );
        error_response(status, kind, msg, &rid)
    };

    if in_headers.contains_key(header::UPGRADE) {
        return deny(
            "-",
            None,
            StatusCode::NOT_IMPLEMENTED,
            "unsupported",
            "keysink does not support WebSocket / Upgrade",
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

    let Some(value) = &route.inline_key else {
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
    let key = Zeroizing::new(value.clone());

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

    let fwd_headers = match forward_headers(&in_headers, route, key.as_str(), is_stream) {
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

    let url = match build_upstream_url(
        &route.base_url,
        &path,
        query.as_deref(),
        &route.auth,
        key.as_str(),
    ) {
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

    tracing::info!(
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
    state.audit.record(entry);
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
/// huge body.
const DISCARD_BODY_LIMIT: usize = 64 * 1024;

async fn discard_body_limited(mut resp: reqwest::Response) {
    let mut remaining = DISCARD_BODY_LIMIT;
    while let Ok(Some(chunk)) = resp.chunk().await {
        if chunk.len() >= remaining {
            return;
        }
        remaining -= chunk.len();
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
            discard_body_limited(resp).await;
            tokio::time::sleep(policy.backoff(attempt as u32, retry_after)).await;
            continue;
        }

        let response = if is_stream {
            stream_response(
                resp,
                route.sse_terminator,
                rid.to_string(),
                state.body_read_idle,
            )
            .await
        } else {
            pass_through_response(resp, state.body_read_idle).await
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
    for name in ["authorization", "x-api-key", "x-goog-api-key", "api-key"] {
        let Some(value) = headers.get(name) else {
            continue;
        };
        let Ok(text) = value.to_str() else {
            continue;
        };
        let text = text.trim();
        let text = if name == "authorization" {
            match text.get(..7) {
                Some(prefix) if prefix.eq_ignore_ascii_case("bearer ") => &text[7..],
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
    #[derive(serde::Deserialize)]
    struct Probe {
        #[serde(default)]
        stream: Option<bool>,
    }
    // Byte-level pre-filter first: a body not containing the `"stream"`
    // substring cannot be stream:true, which avoids fully JSON-parsing a body
    // of up to 32MB just to probe one field.
    if memchr::memmem::find(body, b"\"stream\"").is_none() {
        return false;
    }
    serde_json::from_slice::<Probe>(body)
        .ok()
        .and_then(|p| p.stream)
        .unwrap_or(false)
}

fn convert_resp_headers(src: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(src.len());
    for (name, value) in src.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
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

async fn pass_through_response(resp: reqwest::Response, body_idle: Duration) -> Response {
    let status = resp.status();
    let headers = convert_resp_headers(resp.headers());
    let stream = idle_bounded(resp.bytes_stream(), body_idle);
    build_response(status, headers, Body::from_stream(stream))
}

/// Per-chunk read-idle bound for a forwarded response body: chunks pass
/// through unchanged; if the upstream goes silent past `idle`, or errors, the
/// body ends with an error so hyper aborts the response instead of hanging on
/// it forever. Ends after the first error rather than looping errors if the
/// consumer polls again.
fn idle_bounded<S>(
    inner: S,
    idle: Duration,
) -> impl futures_util::Stream<Item = std::result::Result<Bytes, std::io::Error>>
where
    S: futures_util::Stream<Item = reqwest::Result<Bytes>>,
{
    let inner = Box::pin(inner);
    stream::unfold((inner, false), move |(mut inner, done)| async move {
        if done {
            return None;
        }
        match tokio::time::timeout(idle, inner.next()).await {
            Ok(Some(Ok(chunk))) => Some((Ok(chunk), (inner, false))),
            Ok(Some(Err(e))) => {
                if e.is_timeout() {
                    tracing::warn!(
                        "upstream stopped sending the response body (read idle); aborting the response"
                    );
                } else {
                    tracing::warn!(error = %e, "failed to read upstream response body");
                }
                Some((
                    Err(std::io::Error::other("upstream body error")),
                    (inner, true),
                ))
            }
            Ok(None) => None,
            Err(_) => {
                tracing::warn!(
                    "upstream response body stalled past the read idle; aborting the response"
                );
                Some((
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "upstream body read idle timeout",
                    )),
                    (inner, true),
                ))
            }
        }
    })
}

async fn stream_response(
    resp: reqwest::Response,
    terminator: Terminator,
    rid: String,
    body_idle: Duration,
) -> Response {
    let status = resp.status();
    let headers = convert_resp_headers(resp.headers());

    let is_sse = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().starts_with("text/event-stream"))
        .unwrap_or(false);

    if !is_sse || terminator == Terminator::None {
        return pass_through_response(resp, body_idle).await;
    }

    // A content-encoded response is compressed bytes, so terminator scanning
    // is guaranteed to miss; pass it through as-is — better to give up
    // truncation detection than to append plain-text events to a compressed
    // stream (that corrupts the frame tail and makes the client's decoder
    // error out, e.g. Bun's ZstdDecompressionError).
    if is_encoded(&headers) {
        tracing::debug!(rid = %rid, "response is content-encoded, skipping SSE terminator detection");
        return pass_through_response(resp, body_idle).await;
    }

    let seen_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let errored = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let seen_for_scan = seen_done.clone();
    let errored_for_scan = errored.clone();
    let rid_for_scan = rid.clone();
    // carry keeps the tail of the previous chunk so a terminator marker split across a chunk boundary is not missed.
    let carry = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let carry_for_scan = carry.clone();
    let stream = resp.bytes_stream();
    let mapped = stream.scan((), move |(), res| {
        let seen = seen_for_scan.clone();
        let errored = errored_for_scan.clone();
        let rid = rid_for_scan.clone();
        let carry = carry_for_scan.clone();
        async move {
            if errored.load(Ordering::Relaxed) {
                return None;
            }
            match res {
                Ok(chunk) => {
                    if !seen.load(Ordering::Relaxed) {
                        let mut carry = carry.lock().unwrap_or_else(|e| e.into_inner());
                        let mut window = Vec::with_capacity(carry.len() + chunk.len());
                        window.extend_from_slice(&carry);
                        window.extend_from_slice(&chunk);
                        if contains_terminator(&window, terminator) {
                            seen.store(true, Ordering::Relaxed);
                        }
                        let keep = window.len().min(64);
                        carry.clear();
                        carry.extend_from_slice(&window[window.len() - keep..]);
                    }
                    Some(Ok::<Bytes, std::io::Error>(chunk))
                }
                Err(_) => {
                    tracing::warn!(rid = %rid, "upstream SSE stream interrupted");
                    seen.store(true, Ordering::Relaxed);
                    errored.store(true, Ordering::Relaxed);
                    Some(Ok(sse_error_event("upstream stream error", terminator)))
                }
            }
        }
    });

    let seen_for_tail = seen_done.clone();
    let tail = stream::once(async move {
        if seen_for_tail.load(Ordering::Relaxed) {
            Ok::<Bytes, std::io::Error>(Bytes::new())
        } else {
            tracing::warn!(rid = %rid, "SSE stream ended early without terminator marker, treating as truncated");
            Ok(sse_error_event(
                "upstream stream ended prematurely",
                terminator,
            ))
        }
    });
    build_response(status, headers, Body::from_stream(mapped.chain(tail)))
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

pub(crate) fn contains_terminator(chunk: &[u8], terminator: Terminator) -> bool {
    let openai = || find_memmem(chunk, b"data: [DONE]") || find_memmem_ci(chunk, b"data: [DONE]");
    let anthropic = || {
        find_memmem(chunk, b"event: message_stop")
            || find_memmem(chunk, b"\"type\":\"message_stop\"")
            || find_memmem_ci(chunk, b"event: message_stop")
            || find_memmem_ci(chunk, b"\"type\":\"message_stop\"")
    };
    match terminator {
        Terminator::Openai => openai(),
        Terminator::Anthropic => anthropic(),
        Terminator::Auto => openai() || anthropic(),
        Terminator::None => false,
    }
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
    let mut out = Response::builder()
        .status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY));
    for (name, value) in headers.iter() {
        out = out.header(name, value);
    }
    out.body(body).unwrap_or_else(|_| {
        error_response(
            StatusCode::BAD_GATEWAY,
            "internal_error",
            "failed to build response",
            "0000",
        )
    })
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

/// Polls the store.age / master.key mtime+size and swaps in a whole new snapshot on change.
pub fn spawn_watcher(state: Arc<AppState>, paths: Paths) {
    tokio::spawn(async move {
        // Zeroed so the first round after startup always reloads once,
        // covering the race where the CLI modified the store between serve
        // finishing the initial store load and the watcher starting.
        let mut last = (0u64, 0u64, 0u64);
        let mut failures = 0u32;
        let mut backup_warned = false;
        let mut delay = RELOAD_POLL;
        loop {
            tokio::time::sleep(delay).await;
            let now = stamp(&paths);
            if now == last {
                continue;
            }
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
                        if from_backup {
                            tracing::error!(
                                "hot reload fell back to .bak backup (main store failed to decrypt): revoked/deleted vkeys may become effective again; fix ASAP"
                            );
                        }
                        tracing::info!(routes, from_backup, "store hot-reloaded");
                    }
                    Err(e) => {
                        failures += 1;
                        delay = next_reload_backoff(delay);
                        if failures % 10 == 1 {
                            tracing::warn!(error = %e, "hot reload validation failed, keeping old snapshot");
                        }
                    }
                },
                Err(e) => {
                    failures += 1;
                    delay = next_reload_backoff(delay);
                    if failures % 10 == 1 {
                        tracing::warn!(error = %e, "hot reload decryption failed, keeping old snapshot");
                    }
                }
            }
        }
    });
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

        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_str(&token).unwrap());
        assert_eq!(extract_vkey(&h).as_deref(), Some(token.as_str()));

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
    fn detects_stream_flag() {
        assert!(is_stream_request(br#"{"stream":true}"#));
        assert!(is_stream_request(br#"{"stream": true, "x": 1}"#));
        assert!(!is_stream_request(br#"{"stream":false}"#));
        assert!(!is_stream_request(br#"{"model":"x"}"#));
        assert!(!is_stream_request(b"not json"));
        assert!(!is_stream_request(b""));
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

    #[tokio::test(start_paused = true)]
    async fn idle_bounded_passes_chunks_and_ends_cleanly() {
        let inner = stream::iter(vec![
            Ok::<Bytes, reqwest::Error>(Bytes::from_static(b"a")),
            Ok(Bytes::from_static(b"b")),
        ]);
        let mut s = Box::pin(idle_bounded(inner, Duration::from_secs(60)));
        assert_eq!(s.next().await.unwrap().unwrap(), Bytes::from_static(b"a"));
        assert_eq!(s.next().await.unwrap().unwrap(), Bytes::from_static(b"b"));
        assert!(s.next().await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_bounded_aborts_stalled_body_and_stops() {
        // one chunk, then the upstream goes silent forever
        let inner = stream::once(async { Ok::<Bytes, reqwest::Error>(Bytes::from_static(b"x")) })
            .chain(stream::pending::<reqwest::Result<Bytes>>());
        let mut s = Box::pin(idle_bounded(inner, Duration::from_secs(30)));
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
        let mut s = Box::pin(idle_bounded(inner, Duration::from_secs(60)));
        for i in 0u8..3 {
            assert_eq!(s.next().await.unwrap().unwrap(), Bytes::from(vec![i]));
        }
        assert!(s.next().await.is_none());
    }
}
