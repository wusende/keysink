//! End-to-end proxy fuzzing against a mock upstream, SSE marker-split
//! fuzzing over real chunked streams, and performance scenarios.
//!
//! Everything here drives the real HTTP stack (axum server → keysink handler
//! → reqwest → mock upstream); invariants focus on credential isolation,
//! request fidelity, and the SSE truncation detector.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use base64::Engine;
use bytes::Bytes;
use futures_util::{StreamExt, future::join_all};
use keysink::model::{Auth, Route, Store, Terminator};
use keysink::retry::RetryPolicy;
use keysink::vkey;
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

const REAL_KEY: &str = "real-upstream-key-123";

/// Deterministic splitmix-style generator so failures reproduce.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

// ---------- mock upstream ----------

async fn spawn_mock() -> (SocketAddr, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .fallback(mock_handler)
        .with_state(hits.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, hits)
}

async fn mock_handler(State(hits): State<Arc<AtomicUsize>>, req: Request<Body>) -> Response {
    hits.fetch_add(1, Ordering::Relaxed);
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().unwrap_or("").to_string();
    let method = parts.method.to_string();

    if path == "/hang" {
        std::future::pending::<()>().await;
        unreachable!();
    }
    if path == "/stall-body" {
        // Headers arrive, one chunk is delivered, then the upstream goes
        // silent forever — the non-streaming body read idle must abort it.
        let stream = futures_util::stream::once(async {
            Ok::<_, std::io::Error>(Bytes::from_static(b"partial-"))
        })
        .chain(futures_util::stream::pending());
        return (
            StatusCode::OK,
            [("content-type", "application/json")],
            Body::from_stream(stream),
        )
            .into_response();
    }
    if let Some(code) = path.strip_prefix("/status/") {
        let status = StatusCode::from_u16(code.parse().unwrap_or(500)).unwrap_or(StatusCode::OK);
        return status.into_response();
    }
    if path == "/sse" {
        return sse_response(&query).await;
    }

    let headers: BTreeMap<String, String> = parts
        .headers
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let bytes = axum::body::to_bytes(body, 64 * 1024 * 1024)
        .await
        .unwrap_or_default();
    Json(json!({
        "method": method,
        "path": path,
        "query": query,
        "headers": headers,
        "body_b64": base64::engine::general_purpose::STANDARD.encode(&bytes),
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
struct Echo {
    method: String,
    path: String,
    query: String,
    headers: BTreeMap<String, String>,
    body_b64: String,
}

async fn sse_response(query: &str) -> Response {
    let mut marker_kind = "openai";
    let mut seed = 0u64;
    let mut truncate = false;
    let mut tail = false;
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        match (kv.next(), kv.next()) {
            (Some("marker"), Some(v)) => marker_kind = v,
            (Some("seed"), Some(v)) => seed = v.parse().unwrap_or(0),
            (Some("truncate"), Some(v)) => truncate = v == "1",
            (Some("tail"), Some(v)) => tail = v == "1",
            _ => {}
        }
    }
    let marker: &[u8] = match marker_kind {
        "anth_ev" => b"event: message_stop\n\n",
        "anth_json" => b"data: {\"type\":\"message_stop\"}\n\n",
        _ => b"data: [DONE]\n\n",
    };
    let chunks = plan_sse(seed, marker, truncate, tail);
    let stream = futures_util::stream::unfold(chunks, |mut remaining| async move {
        if remaining.is_empty() {
            return None;
        }
        let (bytes, sleep) = remaining.remove(0);
        if sleep {
            tokio::time::sleep(Duration::from_millis(8)).await;
        }
        Some((Ok::<_, std::io::Error>(Bytes::from(bytes)), remaining))
    });
    (
        StatusCode::OK,
        [("content-type", "text/event-stream")],
        Body::from_stream(stream),
    )
        .into_response()
}

/// Chunk plan for one SSE response: the marker is deliberately split at
/// random interior points and continuation chunks are delayed, forcing the
/// terminator to straddle separate TCP reads at the keysink scanner.
fn plan_sse(seed: u64, marker: &[u8], truncate: bool, tail: bool) -> Vec<(Vec<u8>, bool)> {
    let mut rng = Lcg(seed | 1);
    let prefix: Vec<u8> = b"event: delta\ndata: {\"i\":0}\n\ndata: {\"i\":1}\n\n".to_vec();

    let mut chunks: Vec<(Vec<u8>, bool)> = Vec::new();
    if truncate {
        let mut body = prefix;
        body.extend_from_slice(&marker[..marker.len() / 2]);
        chunks.push((body, false));
        return chunks;
    }

    // prefix split into up to 3 pieces (no sleeps needed)
    let mut cuts = [rng.below(prefix.len()), rng.below(prefix.len())];
    cuts.sort_unstable();
    let mut start = 0;
    for cut in cuts {
        if cut > start {
            chunks.push((prefix[start..cut].to_vec(), false));
            start = cut;
        }
    }
    chunks.push((prefix[start..].to_vec(), false));

    // marker split at 1-2 interior points; continuation pieces are delayed so
    // they arrive as separate reads
    let mut points = vec![
        1 + rng.below(marker.len() - 2),
        1 + rng.below(marker.len() - 2),
    ];
    points.sort_unstable();
    points.dedup();
    let mut mstart = 0;
    for (i, p) in points.into_iter().enumerate() {
        chunks.push((marker[mstart..p].to_vec(), i > 0));
        mstart = p;
    }
    chunks.push((marker[mstart..].to_vec(), !chunks.is_empty()));

    if tail {
        chunks.push((b"data: {\"i\":2}\n\n".to_vec(), false));
    }
    chunks
}

fn raw_sse_body(seed: u64, marker: &[u8], truncate: bool, tail: bool) -> Vec<u8> {
    plan_sse(seed, marker, truncate, tail)
        .into_iter()
        .flat_map(|(c, _)| c)
        .collect()
}

// ---------- keysink gateway ----------

fn route_to(base: &str, terminator: Terminator, auth: Auth, enabled: bool) -> Route {
    let mut r = Route::new(
        vkey::generate(),
        base.to_string(),
        REAL_KEY.into(),
        auth,
        BTreeMap::new(),
    );
    r.sse_terminator = terminator;
    r.enabled = enabled;
    r
}

async fn spawn_gateway(
    store: Store,
    retry: RetryPolicy,
    body_limit: usize,
) -> (SocketAddr, HashMap<String, String>) {
    spawn_gateway_with_idle(store, retry, body_limit, keysink::proxy::BODY_READ_IDLE).await
}

fn build_state(
    store: Store,
    retry: RetryPolicy,
    body_limit: usize,
    body_read_idle: Duration,
    inbound_body_timeout: Duration,
    max_inbound: usize,
    permit_queue_timeout: Duration,
) -> (Arc<keysink::proxy::AppState>, HashMap<String, String>) {
    let mut vkeys = HashMap::new();
    for (name, r) in &store.routes {
        vkeys.insert(name.clone(), r.vkey.clone());
    }
    let table = keysink::vkey::RouteTable::build(&store).unwrap();
    let snapshot = keysink::proxy::Snapshot {
        store: Arc::new(store),
        table,
        from_backup: false,
    };
    let state = Arc::new(keysink::proxy::AppState {
        snapshot: arc_swap::ArcSwap::from_pointee(snapshot),
        clients: keysink::proxy::ProxyClients::new().unwrap(),
        retry,
        body_limit,
        body_read_idle,
        inbound_body_timeout,
        permit_queue_timeout,
        inbound_permits: Arc::new(tokio::sync::Semaphore::new(max_inbound)),
        audit: keysink::audit::Audit::disabled(),
        started: Instant::now(),
    });
    (state, vkeys)
}

async fn spawn_gateway_with_idle(
    store: Store,
    retry: RetryPolicy,
    body_limit: usize,
    body_read_idle: Duration,
) -> (SocketAddr, HashMap<String, String>) {
    let (state, vkeys) = build_state(
        store,
        retry,
        body_limit,
        body_read_idle,
        keysink::proxy::CLIENT_BODY_TIMEOUT,
        64,
        keysink::proxy::PERMIT_QUEUE_TIMEOUT,
    );
    let app = keysink::proxy::build_app(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, vkeys)
}

// ---------- e2e request fuzz ----------

#[tokio::test]
async fn proxy_end_to_end_fuzz() {
    let (mock, _hits) = spawn_mock().await;
    let mut store = Store::new();
    store.routes.insert(
        "main".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Auto,
            Auth::Bearer,
            true,
        ),
    );
    store.routes.insert(
        "disabled".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Auto,
            Auth::Bearer,
            false,
        ),
    );
    let (gw, vks) = spawn_gateway(store, RetryPolicy::default(), 1 << 20).await;
    let vk_main = vks["main"].clone();
    let vk_disabled = vks["disabled"].clone();

    let client = reqwest::Client::new();
    let mut rng = Lcg(0xBEEF_0001);

    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
    let paths: Vec<String> = vec![
        "/v1/chat/completions".into(),
        "/v1/messages".into(),
        "/seg-1".into(),
        "/a//b".into(),
        "/x%20y".into(),
        "/v1/embedded%2Fslash".into(),
        format!("/{}", "p".repeat(512)),
        "/".into(),
    ];
    let queries = ["", "a=1&b=2", "alt=sse&key=stale", "x=1%202&flag"];

    for case in 0..60 {
        let method = *rng.pick(&methods);
        let path = rng.pick(&paths).clone();
        let query = *rng.pick(&queries);
        let url_path = if query.is_empty() {
            path.clone()
        } else {
            format!("{path}?{query}")
        };
        let body: Option<Vec<u8>> = if matches!(method, "POST" | "PUT" | "PATCH" | "DELETE") {
            match rng.below(4) {
                0 => Some(b"{}".to_vec()),
                1 => Some(br#"{"stream":false,"model":"m"}"#.to_vec()),
                2 => Some((0..1024).map(|i| (i % 251) as u8).collect()),
                _ => Some(vec![0x61u8; 100_000]),
            }
        } else {
            None
        };

        // which header carries the vkey, or whether it is present at all
        let channel = rng.below(7);
        let auth_header = match channel {
            0 => Some(("authorization", format!("Bearer {vk_main}"))),
            1 => Some(("x-api-key", vk_main.clone())),
            2 => Some(("api-key", vk_main.clone())),
            3 => Some(("x-goog-api-key", vk_main.clone())),
            4 => None, // missing
            5 => Some((
                "authorization",
                "Bearer ks_fffffffffffffffffffffffffffffffffffffffffff0".into(),
            )), // unknown token
            _ => Some(("authorization", format!("Bearer {vk_disabled}"))), // disabled route
        };

        let mut req = client.request(
            reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
            format!("http://{gw}{url_path}"),
        );
        if let Some((h, v)) = &auth_header {
            req = req.header(*h, v.clone());
        }
        if case % 3 == 0 {
            req = req.header("x-custom-trace", "trace-42");
        }
        if let Some(b) = &body {
            req = req.body(b.clone());
        }
        // Early rejects (401/403) answer before the request body is drained,
        // so the gateway closes that connection while body bytes may still be
        // in flight → the OS turns the close into an RST, and under load the
        // very next request can be handed the just-died pooled connection and
        // fail with a SendRequest error even though nothing was delivered.
        // No response was received, so one retry on a fresh connection is
        // faithful to the invariant under test (this used to flake ~50% under
        // parallel test load).
        let retry = req.try_clone().expect("request must be cloneable");
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) if e.status().is_none() && !e.is_timeout() => {
                retry.send().await.expect("gateway must answer")
            }
            Err(e) => panic!("gateway must answer: {e}"),
        };
        let rid = resp
            .headers()
            .get("x-keysink-request-id")
            .map(|v| v.to_str().unwrap().to_string());
        assert!(
            rid.map(|r| !r.is_empty()).unwrap_or(false),
            "case {case}: missing x-keysink-request-id"
        );

        match channel {
            4 | 5 => assert_eq!(
                resp.status(),
                401,
                "case {case}: unauthenticated must be 401"
            ),
            6 => assert_eq!(
                resp.status(),
                403,
                "case {case}: disabled route must be 403"
            ),
            _ => {
                assert_eq!(resp.status(), 200, "case {case}: proxied request failed");
                if method == "HEAD" {
                    // hyper strips the body of HEAD responses; nothing to echo
                    continue;
                }
                let echo: Echo = resp.json().await.expect("case {case}: echo must be JSON");
                assert_eq!(echo.method, method, "case {case}");
                assert_eq!(echo.path, path, "case {case}: path fidelity");
                assert_eq!(echo.query, query, "case {case}: query fidelity");
                // credential isolation: upstream sees exactly the injected
                // bearer, never the vkey or any inbound auth material
                assert_eq!(
                    echo.headers.get("authorization").map(String::as_str),
                    Some("Bearer real-upstream-key-123"),
                    "case {case}: upstream authorization must be the injected key"
                );
                assert!(
                    !echo.headers.contains_key("x-api-key"),
                    "case {case}: x-api-key must not leak upstream"
                );
                assert!(
                    !echo
                        .headers
                        .values()
                        .any(|v| v.contains(&vk_main) || v.contains(&vk_disabled)),
                    "case {case}: vkey leaked upstream"
                );
                if case % 3 == 0 {
                    assert_eq!(
                        echo.headers.get("x-custom-trace").map(String::as_str),
                        Some("trace-42"),
                        "case {case}: benign headers must pass through"
                    );
                }
                if let Some(b) = &body {
                    let got = base64::engine::general_purpose::STANDARD
                        .decode(&echo.body_b64)
                        .expect("case {case}: body_b64 must decode");
                    assert_eq!(got, *b, "case {case}: body fidelity");
                }
            }
        }
    }
}

// ---------- targeted error paths ----------

#[tokio::test]
async fn rejects_oversized_bodies_both_framings() {
    let (mock, _hits) = spawn_mock().await;
    let mut store = Store::new();
    store.routes.insert(
        "main".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Auto,
            Auth::Bearer,
            true,
        ),
    );
    let (gw, vks) = spawn_gateway(store, RetryPolicy::default(), 1024).await;
    let vk = &vks["main"];
    let client = reqwest::Client::new();

    // content-length framing: rejected by the early header check
    let resp = client
        .post(format!("http://{gw}/v1/x"))
        .header("authorization", format!("Bearer {vk}"))
        .body(vec![0x61; 4096])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["type"], "request_too_large");

    // chunked framing (no content-length): rejected by the bounded read
    let stream = futures_util::stream::iter(vec![
        Ok::<_, std::io::Error>(Bytes::from(vec![0x62; 800])),
        Ok(Bytes::from(vec![0x63; 800])),
    ]);
    let resp = client
        .post(format!("http://{gw}/v1/x"))
        .header("authorization", format!("Bearer {vk}"))
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
}

#[tokio::test]
async fn rejects_websocket_upgrade_before_auth() {
    let (mock, _hits) = spawn_mock().await;
    let mut store = Store::new();
    store.routes.insert(
        "main".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Auto,
            Auth::Bearer,
            true,
        ),
    );
    let (gw, _vks) = spawn_gateway(store, RetryPolicy::default(), 1 << 20).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{gw}/v1/x"))
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 501);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["type"], "unsupported");
}

#[tokio::test]
async fn upstream_failures_map_to_clean_errors() {
    // unreachable host → 502 upstream_error (POST: connect errors are
    // replay-safe but max_retries=0 keeps the test fast)
    let mut store = Store::new();
    store.routes.insert(
        "dead".into(),
        route_to("http://127.0.0.1:1", Terminator::Auto, Auth::Bearer, true),
    );
    let policy = RetryPolicy {
        max_retries: 0,
        ..RetryPolicy::default()
    };
    let (gw, vks) = spawn_gateway(store, policy, 1 << 20).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{gw}/v1/x"))
        .header("authorization", format!("Bearer {}", vks["dead"]))
        .body(b"{}".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 502);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["type"], "upstream_error");

    // hanging upstream → 504 once the header timeout fires
    let (mock, _hits) = spawn_mock().await;
    let mut store = Store::new();
    store.routes.insert(
        "slow".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Auto,
            Auth::Bearer,
            true,
        ),
    );
    let policy = RetryPolicy {
        max_retries: 0,
        header_timeout: Duration::from_millis(400),
        ..RetryPolicy::default()
    };
    let (gw, vks) = spawn_gateway(store, policy, 1 << 20).await;
    let started = Instant::now();
    let resp = client
        .post(format!("http://{gw}/hang"))
        .header("authorization", format!("Bearer {}", vks["slow"]))
        .body(b"{}".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 504);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["type"], "upstream_timeout");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "timeout must fire promptly"
    );
}

#[tokio::test]
async fn stalled_non_streaming_body_aborts_instead_of_hanging() {
    // Regression: an upstream that sent response headers and then went
    // silent mid-body used to hang the handler forever on the non-streaming
    // path (the plain client has no client-level read idle) — and a hung
    // handler also stalled graceful shutdown.
    let (mock, _hits) = spawn_mock().await;
    let mut store = Store::new();
    store.routes.insert(
        "main".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Auto,
            Auth::Bearer,
            true,
        ),
    );
    let (gw, vks) = spawn_gateway_with_idle(
        store,
        RetryPolicy::default(),
        1 << 20,
        Duration::from_millis(300),
    )
    .await;
    let client = reqwest::Client::new();

    let started = Instant::now();
    let resp = client
        .post(format!("http://{gw}/stall-body"))
        .header("authorization", format!("Bearer {}", vks["main"]))
        .body(b"{}".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "response headers must still arrive");
    let body = resp.bytes().await;
    assert!(
        body.is_err(),
        "stalled body must be aborted, not delivered: {body:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "abort must be prompt, took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn retry_policy_replays_and_returns_final_status() {
    let (mock, hits) = spawn_mock().await;
    let mut store = Store::new();
    store.routes.insert(
        "main".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Auto,
            Auth::Bearer,
            true,
        ),
    );
    let policy = RetryPolicy {
        max_retries: 2,
        statuses: vec![503].into(),
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(30),
        header_timeout: Duration::from_secs(5),
    };
    let (gw, vks) = spawn_gateway(store, policy, 1 << 20).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{gw}/status/503"))
        .header("authorization", format!("Bearer {}", vks["main"]))
        .body(b"{}".to_vec())
        .send()
        .await
        .unwrap();
    // status-based retries are not method-gated by design: a 503 means the
    // upstream refused the request before processing it
    assert_eq!(resp.status(), 503);
    assert_eq!(
        hits.load(Ordering::Relaxed),
        3,
        "POST + 503 must be retried twice"
    );
}

#[tokio::test]
async fn broken_static_header_maps_to_configuration_error() {
    let (mock, _hits) = spawn_mock().await;
    let mut store = Store::new();
    let mut r = route_to(
        &format!("http://{mock}"),
        Terminator::Auto,
        Auth::Bearer,
        true,
    );
    r.headers.insert("x-trace".into(), "bad\nvalue".into());
    store.routes.insert("broken".into(), r);
    let (gw, vks) = spawn_gateway(store, RetryPolicy::default(), 1 << 20).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{gw}/v1/x"))
        .header("authorization", format!("Bearer {}", vks["broken"]))
        .body(b"{}".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 500);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["type"], "configuration_error");
}

#[tokio::test]
async fn query_auth_replaces_inbound_param() {
    let (mock, _hits) = spawn_mock().await;
    let mut store = Store::new();
    store.routes.insert(
        "q".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Auto,
            Auth::Query {
                param: "key".into(),
            },
            true,
        ),
    );
    let (gw, vks) = spawn_gateway(store, RetryPolicy::default(), 1 << 20).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{gw}/v1/x?key=stale&alt=sse"))
        .header("authorization", format!("Bearer {}", vks["q"]))
        .body(b"{}".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let echo: Echo = resp.json().await.unwrap();
    assert_eq!(echo.query, "alt=sse&key=real-upstream-key-123");
    assert!(
        !echo.headers.contains_key("authorization"),
        "query auth must not inject a header credential"
    );
}

#[tokio::test]
async fn deeply_nested_body_survives_the_full_proxy_path() {
    // Stack-overflow audit PoC, kept as a regression: an attacker-controlled
    // request body can be arbitrarily deep JSON. serde_json's ignored-field
    // skipper is iterative, so the real axum → handler → reqwest path must
    // survive it — this drives the full stack, not just the parser.
    let (mock, _hits) = spawn_mock().await;
    let mut store = Store::new();
    store.routes.insert(
        "main".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Auto,
            Auth::Bearer,
            true,
        ),
    );
    let (gw, vks) = spawn_gateway(store, RetryPolicy::default(), 1 << 20).await;
    let client = reqwest::Client::new();

    let depth = 100_000usize;
    let deep = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    let body = format!(r#"{{"pad":{deep},"stream":false}}"#).into_bytes();
    assert!(body.len() < 1 << 20, "PoC body must fit the 1MB test limit");

    let resp = client
        .post(format!("http://{gw}/v1/x"))
        .header("authorization", format!("Bearer {}", vks["main"]))
        .body(body)
        .send()
        .await
        .expect("gateway must survive a deeply nested body");
    assert_eq!(resp.status(), 200);
    let echo: Echo = resp.json().await.unwrap();
    assert_eq!(echo.path, "/v1/x");
}

// ---------- inbound read bounds (serve_inbound) ----------

#[tokio::test]
async fn serve_inbound_reaps_stalled_request_head() {
    // slowloris defense: a client that opens a connection and stalls mid-head
    // must be disconnected within the header bound — while healthy requests
    // on other connections keep working.
    let (mock, _hits) = spawn_mock().await;
    let mut store = Store::new();
    store.routes.insert(
        "main".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Auto,
            Auth::Bearer,
            true,
        ),
    );
    let (state, _vks) = build_state(
        store,
        RetryPolicy::default(),
        1 << 20,
        keysink::proxy::BODY_READ_IDLE,
        keysink::proxy::CLIENT_BODY_TIMEOUT,
        64,
        keysink::proxy::PERMIT_QUEUE_TIMEOUT,
    );
    let app = keysink::proxy::build_app(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(keysink::proxy::serve_inbound(
        listener,
        app,
        keysink::proxy::InboundLimits {
            header_timeout: Duration::from_millis(300),
            max_connections: 16,
        },
        std::future::pending(),
    ));

    // healthy requests on other connections are unaffected
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/__keysink/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // stalled head: hyper closes the connection within the bound
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"GET /__keysink/health HTTP/1.1\r\nHost: gw\r\n")
        .await
        .unwrap(); // head deliberately not terminated (no final CRLF)
    let started = Instant::now();
    let mut buf = [0u8; 64];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
            .await
            .expect("connection must close within the header bound")
            .unwrap_or(0);
        if n == 0 {
            break; // EOF or reset: the server reaped the stalled connection
        }
    }
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "reap must be prompt, took {:?}",
        started.elapsed()
    );
    server.abort();
}

#[tokio::test]
async fn serve_inbound_sheds_connections_beyond_the_cap() {
    // --allow-remote hardening: connections beyond the cap are closed on
    // accept instead of accumulating tasks and fds. A held idle connection
    // occupies its slot; the next one is shed; after it closes, the slot
    // frees and new connections are served again.
    let (mock, _hits) = spawn_mock().await;
    let mut store = Store::new();
    store.routes.insert(
        "main".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Auto,
            Auth::Bearer,
            true,
        ),
    );
    let (state, _vks) = build_state(
        store,
        RetryPolicy::default(),
        1 << 20,
        keysink::proxy::BODY_READ_IDLE,
        keysink::proxy::CLIENT_BODY_TIMEOUT,
        64,
        keysink::proxy::PERMIT_QUEUE_TIMEOUT,
    );
    let app = keysink::proxy::build_app(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(keysink::proxy::serve_inbound(
        listener,
        app,
        keysink::proxy::InboundLimits {
            header_timeout: Duration::from_secs(30),
            max_connections: 1,
        },
        std::future::pending(),
    ));

    use tokio::io::AsyncReadExt;
    // Slot holder: an open connection parked before sending anything.
    let mut holder = tokio::net::TcpStream::connect(addr).await.unwrap();
    // Next connection is shed (closed promptly, no response).
    let mut shed = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 16];
    let closed = tokio::time::timeout(Duration::from_secs(3), shed.read(&mut buf)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "connection beyond the cap must be closed promptly, got {closed:?}"
    );
    // The slot holder is untouched and can still complete a request over its
    // own socket (reqwest would open a new connection, which is shed).
    let req = b"GET /__keysink/health HTTP/1.1\r\nHost: gw\r\nConnection: close\r\n\r\n";
    use tokio::io::AsyncWriteExt;
    holder.write_all(req).await.unwrap();
    let mut response = Vec::new();
    loop {
        let n = tokio::time::timeout(Duration::from_secs(3), holder.read(&mut buf))
            .await
            .expect("holder connection must stay usable")
            .unwrap();
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "slot holder must still be served, got: {text}"
    );
    server.abort();
}

#[tokio::test]
async fn inbound_body_trickle_times_out() {
    // A client that sends the head and then trickles the body forever must
    // get a 408 instead of holding the handler — the byte limit alone does
    // not provide this bound.
    let (mock, _hits) = spawn_mock().await;
    let mut store = Store::new();
    store.routes.insert(
        "main".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Auto,
            Auth::Bearer,
            true,
        ),
    );
    let (state, vks) = build_state(
        store,
        RetryPolicy::default(),
        1 << 20,
        keysink::proxy::BODY_READ_IDLE,
        Duration::from_millis(300),
        64,
        keysink::proxy::PERMIT_QUEUE_TIMEOUT,
    );
    let app = keysink::proxy::build_app(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST /v1/x HTTP/1.1\r\nHost: gw\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: 1000000\r\n\r\n{{",
        vks["main"]
    );
    sock.write_all(head.as_bytes()).await.unwrap();

    let started = Instant::now();
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut chunk))
            .await
            .expect("response must arrive within the body bound")
            .unwrap();
        if n == 0 {
            break; // server closed the connection after the 408
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let text = String::from_utf8_lossy(&buf);
    assert!(text.starts_with("HTTP/1.1 408"), "got: {text}");
    assert!(text.contains("request_timeout"), "got: {text}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "timeout must fire promptly, took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn serve_inbound_passes_sse_streams() {
    // serve_inbound is the production serve loop: an SSE request must stream
    // through it byte-for-byte, terminator detection included.
    let (mock, _hits) = spawn_mock().await;
    let mut store = Store::new();
    store.routes.insert(
        "openai".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Openai,
            Auth::Bearer,
            true,
        ),
    );
    let (state, vks) = build_state(
        store,
        RetryPolicy::default(),
        1 << 20,
        keysink::proxy::BODY_READ_IDLE,
        keysink::proxy::CLIENT_BODY_TIMEOUT,
        64,
        keysink::proxy::PERMIT_QUEUE_TIMEOUT,
    );
    let app = keysink::proxy::build_app(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(keysink::proxy::serve_inbound(
        listener,
        app,
        keysink::proxy::InboundLimits {
            header_timeout: Duration::from_secs(30),
            max_connections: 64,
        },
        std::future::pending(),
    ));

    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "http://{addr}/sse?marker=openai&seed=1&truncate=0&tail=1"
        ))
        .header("authorization", format!("Bearer {}", vks["openai"]))
        .body(br#"{"stream":true,"model":"m"}"#.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let got = resp.bytes().await.unwrap();
    let raw = raw_sse_body(1, b"data: [DONE]\n\n", false, true);
    assert_eq!(
        got.as_ref(),
        raw.as_slice(),
        "SSE bytes must pass through serve_inbound untouched"
    );
    server.abort();
}

#[tokio::test]
async fn concurrent_requests_bounded_by_inbound_permits() {
    // The permit spans body read + upstream response-header wait: a second
    // request must queue while the first is still waiting for its upstream,
    // and proceed as soon as the permit is released. (SSE body streaming
    // happens after the handler returns, so streams never hold a permit.)
    let gate = Arc::new(tokio::sync::Notify::new());
    let gate_for_mock = gate.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let app: Router = Router::new().fallback(move |req: axum::extract::Request<Body>| {
            let gate = gate_for_mock.clone();
            async move {
                if req.uri().path() == "/gate" {
                    gate.notified().await;
                }
                (StatusCode::OK, "ok").into_response()
            }
        });
        axum::serve(listener, app).await.unwrap();
    });

    let mut store = Store::new();
    store.routes.insert(
        "main".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Auto,
            Auth::Bearer,
            true,
        ),
    );
    let (state, vks) = build_state(
        store,
        RetryPolicy {
            max_retries: 0,
            ..RetryPolicy::default()
        },
        1 << 20,
        keysink::proxy::BODY_READ_IDLE,
        keysink::proxy::CLIENT_BODY_TIMEOUT,
        1,
        keysink::proxy::PERMIT_QUEUE_TIMEOUT,
    );
    let app = keysink::proxy::build_app(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::new();
    let vk = vks["main"].clone();

    // A takes the only permit and parks on the gated upstream.
    let a = {
        let client = client.clone();
        let vk = vk.clone();
        tokio::spawn(async move {
            client
                .post(format!("http://{gw}/gate"))
                .header("authorization", format!("Bearer {vk}"))
                .body(b"{}".to_vec())
                .send()
                .await
                .unwrap()
                .status()
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;

    // B must still be queued while A holds the permit.
    let b = {
        let client = client.clone();
        let vk = vk.clone();
        tokio::spawn(async move {
            client
                .post(format!("http://{gw}/echo"))
                .header("authorization", format!("Bearer {vk}"))
                .body(b"{}".to_vec())
                .send()
                .await
                .unwrap()
                .status()
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!b.is_finished(), "B must queue while A holds the permit");

    gate.notify_one();
    assert_eq!(a.await.unwrap(), 200);
    let b_status = tokio::time::timeout(Duration::from_secs(5), b)
        .await
        .expect("B must proceed once the permit frees")
        .unwrap();
    assert_eq!(b_status, 200);
}

#[tokio::test]
async fn health_endpoint_reports_route_count() {
    let (mock, _hits) = spawn_mock().await;
    let mut store = Store::new();
    for i in 0..3 {
        store.routes.insert(
            format!("r{i}"),
            route_to(
                &format!("http://{mock}"),
                Terminator::Auto,
                Auth::Bearer,
                true,
            ),
        );
    }
    let (gw, _vks) = spawn_gateway(store, RetryPolicy::default(), 1 << 20).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{gw}/__keysink/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["routes"], 3);
    assert_eq!(v["degraded"], false);
}

// ---------- SSE marker-split fuzz ----------

#[tokio::test]
async fn sse_split_and_truncation_fuzz() {
    let (mock, _hits) = spawn_mock().await;
    let mut store = Store::new();
    for name in ["openai", "anth-ev", "anth-json", "auto", "none"] {
        let terminator = match name {
            "openai" => Terminator::Openai,
            "anth-ev" | "anth-json" => Terminator::Anthropic,
            "auto" => Terminator::Auto,
            _ => Terminator::None,
        };
        store.routes.insert(
            name.into(),
            route_to(&format!("http://{mock}"), terminator, Auth::Bearer, true),
        );
    }
    let (gw, vks) = spawn_gateway(store, RetryPolicy::default(), 1 << 20).await;
    let client = reqwest::Client::new();

    let markers: &[(&str, &[u8])] = &[
        ("openai", b"data: [DONE]\n\n"),
        ("anth_ev", b"event: message_stop\n\n"),
        ("anth_json", b"data: {\"type\":\"message_stop\"}\n\n"),
    ];

    for (kind, marker) in markers {
        let matching_route = if *kind == "openai" {
            "openai"
        } else {
            "anth-ev"
        };
        for term_route in [matching_route, "auto", "none"] {
            for truncate in [false, true] {
                for seed in 0..3u64 {
                    let url = format!(
                        "http://{gw}/sse?marker={kind}&seed={seed}&truncate={}&tail=1",
                        u8::from(truncate)
                    );
                    let resp = client
                        .post(url)
                        .header("authorization", format!("Bearer {}", vks[term_route]))
                        .body(br#"{"stream":true,"model":"m"}"#.to_vec())
                        .send()
                        .await
                        .unwrap();
                    assert_eq!(resp.status(), 200);
                    let got = resp.bytes().await.unwrap();
                    let raw = raw_sse_body(seed, marker, truncate, true);
                    let label = format!("{kind}/{term_route}/truncate={truncate}/seed={seed}");

                    match (term_route, truncate) {
                        ("none", _) | (_, false) => {
                            // terminator disabled, or terminator seen: bytes
                            // must pass through untouched
                            assert_eq!(got.as_ref(), raw.as_slice(), "case {label}");
                        }
                        (_, true) => {
                            // truncated without terminator: the injected error
                            // tail must appear exactly once, after the raw bytes
                            assert!(
                                got.starts_with(&raw),
                                "case {label}: injected tail must follow the raw prefix"
                            );
                            assert!(got.len() > raw.len(), "case {label}: tail missing");
                            let tail_text = String::from_utf8_lossy(&got[raw.len()..]);
                            let anthropic_shape =
                                term_route == "anth-ev" || term_route == "anth-json";
                            if !anthropic_shape {
                                assert!(
                                    tail_text.ends_with("data: [DONE]\n\n")
                                        && tail_text.contains("upstream_stream_error"),
                                    "case {label}: openai tail shape wrong: {tail_text:?}"
                                );
                            } else {
                                assert!(
                                    tail_text.contains("event: error")
                                        && tail_text.contains("api_error")
                                        && !tail_text.contains("message_stop"),
                                    "case {label}: anthropic tail shape wrong: {tail_text:?}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // non-streaming requests must never get an injected tail, even when the
    // upstream stream is cut short
    let resp = client
        .post(format!(
            "http://{gw}/sse?marker=openai&seed=7&truncate=1&tail=1"
        ))
        .header("authorization", format!("Bearer {}", vks["openai"]))
        .body(b"{}".to_vec())
        .send()
        .await
        .unwrap();
    let got = resp.bytes().await.unwrap();
    let raw = raw_sse_body(7, b"data: [DONE]\n\n", true, true);
    assert_eq!(
        got.as_ref(),
        raw.as_slice(),
        "non-stream requests pass through untouched"
    );
}

// ---------- performance scenarios ----------

fn timed(name: &str, budget: Duration, elapsed: Duration) {
    println!("perf/{name}: {elapsed:?} (budget {budget:?})");
    assert!(
        elapsed <= budget,
        "{name} exceeded budget: {elapsed:?} > {budget:?}"
    );
}

#[test]
fn perf_route_table_10k() {
    let mut store = Store::new();
    for i in 0..10_000 {
        store.routes.insert(
            format!("route-{i}"),
            Route::new(
                vkey::generate(),
                "https://up.invalid".into(),
                "k".into(),
                Auth::Bearer,
                BTreeMap::new(),
            ),
        );
    }
    let t0 = Instant::now();
    let table = keysink::vkey::RouteTable::build(&store).unwrap();
    timed("build_10k_routes", Duration::from_secs(5), t0.elapsed());

    let hashes: Vec<[u8; 32]> = store
        .routes
        .values()
        .take(2_000)
        .map(|r| vkey::hash(&r.vkey))
        .collect();
    let t1 = Instant::now();
    for _ in 0..100 {
        for h in &hashes {
            assert!(table.lookup_hash(h).is_some());
        }
    }
    timed("lookup_200k_hits", Duration::from_secs(3), t1.elapsed());
}

#[test]
fn perf_audit_flood_never_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let audit = keysink::audit::Audit::new(dir.path().join("audit.jsonl"));
    let t0 = Instant::now();
    for i in 0..5_000 {
        let mut entry = keysink::audit::AuditEntry::new(
            format!("rid{i}"),
            "route",
            "fp",
            "POST",
            format!("/v1/entry-{i}/emoji-🦀"),
            128,
            i % 2 == 0,
        );
        entry.status = 200;
        audit.record(entry);
    }
    audit.close();
    timed("audit_5k_records", Duration::from_secs(10), t0.elapsed());

    let text = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert!(
        !lines.is_empty() && lines.len() <= 5_000,
        "queue drops are allowed but lines must be valid"
    );
    for l in lines {
        let v: serde_json::Value = serde_json::from_str(l)
            .unwrap_or_else(|e| panic!("audit line is not valid JSON: {e}: {l}"));
        assert!(v["path"].as_str().unwrap().contains("entry-"));
    }
}

#[tokio::test]
async fn perf_concurrent_e2e_throughput() {
    let (mock, _hits) = spawn_mock().await;
    let mut store = Store::new();
    store.routes.insert(
        "main".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Auto,
            Auth::Bearer,
            true,
        ),
    );
    let (gw, vks) = spawn_gateway(store, RetryPolicy::default(), 1 << 20).await;
    let client = reqwest::Client::new();
    let vk = vks["main"].clone();

    let t0 = Instant::now();
    let futs = (0..100).map(|i| {
        let client = client.clone();
        let vk = vk.clone();
        async move {
            let req = client
                .post(format!("http://{gw}/v1/concurrent-{i}"))
                .header("authorization", format!("Bearer {vk}"))
                .body(b"{\"stream\":false}".to_vec());
            // Same pooled-connection race as the e2e fuzz below: with all 100
            // requests in flight on one runtime, a pooled connection can die
            // between checkout and send and POST is not retried by the client.
            // No response was received, so one retry is faithful to the
            // throughput invariant under test.
            let retry = req.try_clone().expect("request must be cloneable");
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) if e.status().is_none() && !e.is_timeout() => {
                    retry.send().await.expect("gateway must answer")
                }
                Err(e) => panic!("gateway must answer: {e}"),
            };
            assert_eq!(resp.status(), 200);
            let echo: Echo = resp.json().await.unwrap();
            assert_eq!(echo.path, format!("/v1/concurrent-{i}"));
        }
    });
    join_all(futs).await;
    timed(
        "concurrent_100_requests",
        Duration::from_secs(30),
        t0.elapsed(),
    );
}

// ---------- admission control ----------

/// Head screening (missing/unknown vkey, disabled route, oversized declared
/// body) must reject BEFORE queueing for a permit: with the permit first, a
/// credential-less flood could pin every permit and turn its cheap 401/403
/// rejects into queue hangs. Zero permits + a short queue bound makes any
/// permit-dependent path answer 503, so fast non-503 answers prove the
/// screening happens pre-permit.
#[tokio::test]
async fn head_screening_rejects_before_permit() {
    let (mock, _hits) = spawn_mock().await;
    let mut store = Store::new();
    store.routes.insert(
        "main".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Auto,
            Auth::Bearer,
            true,
        ),
    );
    store.routes.insert(
        "off".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Auto,
            Auth::Bearer,
            false,
        ),
    );
    let (state, vks) = build_state(
        store,
        RetryPolicy::default(),
        1 << 20,
        keysink::proxy::BODY_READ_IDLE,
        keysink::proxy::CLIENT_BODY_TIMEOUT,
        0,
        Duration::from_millis(200),
    );
    let vk_off = vks["off"].clone();

    let cases: Vec<(&'static str, String, StatusCode)> = vec![
        (
            "authorization",
            "Bearer ks_fffffffffffffffffffffffffffffffffffffffffff0".into(),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "authorization",
            "Bearer no ks prefix at all".into(),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "authorization",
            format!("Bearer {vk_off}"),
            StatusCode::FORBIDDEN,
        ),
    ];
    for (header, value, want) in cases {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header(header, value)
            .body(Body::empty())
            .unwrap();
        let started = Instant::now();
        let resp = keysink::proxy::handler(State(state.clone()), req).await;
        assert_eq!(resp.status(), want);
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "{want} must reject before the permit queue, took {:?}",
            started.elapsed()
        );
    }

    // Oversized declared Content-Length is also screenable from the head
    // alone: 2 MiB against a 1 MiB limit.
    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("authorization", format!("Bearer {}", vks["main"]))
        .header("content-length", (2 << 20).to_string())
        .body(Body::empty())
        .unwrap();
    let started = Instant::now();
    let resp = keysink::proxy::handler(State(state.clone()), req).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(started.elapsed() < Duration::from_millis(150));
}

/// A valid request past an exhausted permit pool must be shed at the queue
/// bound (503 + Retry-After), not hang until the client's own timeout —
/// the scenario of a wedged upstream pinning every permit for
/// attempts × header_timeout + backoff.
#[tokio::test]
async fn queue_bound_sheds_valid_request_with_503() {
    let (mock, _hits) = spawn_mock().await;
    let mut store = Store::new();
    store.routes.insert(
        "main".into(),
        route_to(
            &format!("http://{mock}"),
            Terminator::Auto,
            Auth::Bearer,
            true,
        ),
    );
    let (state, vks) = build_state(
        store,
        RetryPolicy::default(),
        1 << 20,
        keysink::proxy::BODY_READ_IDLE,
        keysink::proxy::CLIENT_BODY_TIMEOUT,
        0,
        Duration::from_millis(200),
    );

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("authorization", format!("Bearer {}", vks["main"]))
        .body(Body::empty())
        .unwrap();
    let started = Instant::now();
    let resp = keysink::proxy::handler(State(state), req).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        resp.headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok()),
        Some("1"),
        "shed responses must carry Retry-After"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(195),
        "shed must happen at the queue bound, not before: {:?}",
        started.elapsed()
    );
}
