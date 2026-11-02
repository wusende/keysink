//! ksbench — keysink 的性能测试工具(方案见 docs/perf-test-plan.md)。
//!
//! 两个子命令,配合 scripts/perf.sh 三进程分离部署(client / upstream / gateway):
//!
//! * `ksbench upstream` — 进程内假上游。axum 服务器,提供可控延迟/大小的 echo、
//!   可配置块数/块大小/间隔的 SSE 流、固定大小 JSON,用于替代真实 LLM 上游。
//! * `ksbench bench` — 负载客户端。reqwest 并发压测,分桶统计 TTFB 与总延迟
//!   (SSE 额外统计块到达间隔),stdout 输出单行 JSON 供 perf.sh 汇总。
//!
//! 复用主 crate 的依赖(axum / reqwest / tokio / clap / serde_json),不引入新依赖。

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::response::IntoResponse;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use tokio::net::TcpListener;

fn main() {
    // Same provider the gateway installs (proxy.rs): the crate builds reqwest
    // with rustls-no-provider, so a Client cannot exist without one.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async move {
            match cli.command {
                Command::Upstream(args) => run_upstream(args).await,
                Command::Bench(args) => run_bench(args).await,
            }
        });
}

#[derive(Parser)]
#[command(name = "ksbench", about = "keysink performance test tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the fake upstream server.
    Upstream(UpstreamArgs),
    /// Run the load generator against a target URL.
    Bench(BenchArgs),
}

// ---------------------------------------------------------------------------
// upstream
// ---------------------------------------------------------------------------

#[derive(Parser)]
struct UpstreamArgs {
    /// Listen port (0 picks a free port; the bound port is printed).
    #[arg(long, default_value_t = 19191)]
    port: u16,
}

async fn run_upstream(args: UpstreamArgs) {
    let listener = TcpListener::bind(("127.0.0.1", args.port))
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("local addr");
    println!("upstream listening on {addr}");

    let app = axum::Router::new()
        .route("/echo", axum::routing::get(echo).post(echo))
        .route("/json", axum::routing::get(json_fixed))
        .route("/sse", axum::routing::get(sse));
    axum::serve(listener, app).await.expect("upstream serve");
}

fn query_usize(q: &HashMap<String, String>, key: &str, default: usize) -> usize {
    q.get(key).and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn query_u64(q: &HashMap<String, String>, key: &str, default: u64) -> u64 {
    q.get(key).and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Echo: reads the full request body (so the gateway's forward cost is exercised),
/// waits `delay_ms`, then answers a JSON body padded to `size` bytes.
async fn echo(
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
    _body: axum::body::Bytes,
) -> axum::response::Response {
    let delay_ms = query_u64(&q, "delay_ms", 0);
    let size = query_usize(&q, "size", 1024).max(16);
    if delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
    let body = serde_json::json!({ "ok": true, "pad": "x".repeat(size - 16) });
    axum::Json(body).into_response()
}

/// Fixed-size JSON response, GET-friendly (no request body read).
async fn json_fixed(
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
) -> axum::response::Response {
    let size = query_usize(&q, "size", 1024).max(16);
    let body = serde_json::json!({ "ok": true, "pad": "x".repeat(size - 16) });
    axum::Json(body).into_response()
}

/// SSE stream: `first_delay_ms` before the first chunk, then `chunks` payload
/// chunks of `chunk_size` bytes each, `interval_ms` apart, closed by [DONE].
async fn sse(
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
) -> axum::response::Response {
    let chunks = query_usize(&q, "chunks", 10);
    let chunk_size = query_usize(&q, "chunk_size", 64);
    let interval_ms = query_u64(&q, "interval_ms", 0);
    let first_delay_ms = query_u64(&q, "first_delay_ms", 0);

    let payload = Bytes::from(format!("data: {}\n\n", "x".repeat(chunk_size)));
    let done = Bytes::from_static(b"data: [DONE]\n\n");

    // State = (index of the chunk about to be emitted, payload, done);
    // chunks+1 items total. Payloads travel in the state because the FnMut
    // closure cannot move captured variables into the async block.
    let stream = futures_util::stream::unfold(
        (0usize, payload, done),
        move |(i, payload, done)| async move {
            if i > chunks {
                return None;
            }
            if i == 0 {
                if first_delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(first_delay_ms)).await;
                }
            } else if interval_ms > 0 {
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;
            }
            let item = if i == chunks {
                done.clone()
            } else {
                payload.clone()
            };
            Some((Ok::<Bytes, io::Error>(item), (i + 1, payload, done)))
        },
    );

    let mut resp = axum::response::Response::new(axum::body::Body::from_stream(stream));
    let headers = resp.headers_mut();
    headers.insert("content-type", "text/event-stream".parse().unwrap());
    headers.insert("cache-control", "no-cache".parse().unwrap());
    resp
}

// ---------------------------------------------------------------------------
// bench
// ---------------------------------------------------------------------------

#[derive(Parser)]
struct BenchArgs {
    /// Target URL (path + query included).
    #[arg(long)]
    target: String,

    /// Parallel workers; each loops send→complete until the deadline.
    #[arg(long, default_value_t = 1)]
    concurrency: usize,

    /// Run length in seconds.
    #[arg(long, default_value_t = 15)]
    duration: u64,

    /// Stop after roughly this many requests overall (0 = no cap).
    #[arg(long, default_value_t = 0)]
    max_requests: u64,

    /// HTTP method.
    #[arg(long, default_value = "POST")]
    method: String,

    /// Header to send, "Name: Value" (repeatable) — used for the vkey.
    #[arg(long = "header", value_name = "NAME: VALUE")]
    headers: Vec<String>,

    /// Synthetic request body: total size in bytes.
    #[arg(long, default_value_t = 1024)]
    body_size: usize,

    /// Synthetic body shape: plain (no stream marker), stream_true
    /// ("stream":true at top level), marker_in_string (the exact bytes
    /// "stream":true escaped inside a huge string value — the tokenizer's
    /// worst case, since the memchr prefilter still hits).
    #[arg(long, default_value = "plain")]
    body_kind: String,

    /// Load the request body from a file instead of synthesizing it.
    #[arg(long)]
    body_file: Option<String>,

    /// SSE mode: consume the response as a chunk stream and record
    /// time-to-first-chunk plus inter-chunk gaps.
    #[arg(long)]
    sse: bool,

    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 120)]
    timeout: u64,

    /// Scenario label copied into the JSON output.
    #[arg(long, default_value = "")]
    label: String,
}

/// Deterministic synthetic request body. Keysink's `is_stream_request` decides
/// which upstream client (and read timeout) a request gets, so the three shapes
/// exercise distinct paths through the scanner.
fn synth_body(size: usize, kind: &str) -> Vec<u8> {
    let fill = |n: usize| "x".repeat(n);
    let body = match kind {
        "stream_true" => {
            let n = size.saturating_sub(r#"{"model":"m","stream":true,"prompt":""}"#.len());
            format!(r#"{{"model":"m","stream":true,"prompt":"{}"}}"#, fill(n))
        }
        "marker_in_string" => {
            // "stream":true as escaped bytes inside the string value.
            let marker = r#"\"stream\":true"#;
            let n = size.saturating_sub(r#"{"model":"m","prompt":""}"#.len() + marker.len());
            format!(
                r#"{{"model":"m","prompt":"{}{}{}"}}"#,
                fill(n / 2),
                marker,
                fill(n - n / 2)
            )
        }
        _ => {
            let n = size.saturating_sub(r#"{"model":"m","prompt":""}"#.len());
            format!(r#"{{"model":"m","prompt":"{}"}}"#, fill(n))
        }
    };
    body.into_bytes()
}

#[derive(Default)]
struct Samples {
    /// (ttfb_us, total_us) per completed request.
    latencies: Vec<(u64, u64)>,
    /// Microseconds between consecutive chunk arrivals (SSE only).
    chunk_gaps_us: Vec<u64>,
    ok: u64,
    http_errors: u64,
    transport_errors: u64,
    bytes: u64,
    chunks: u64,
    error_samples: Vec<String>,
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx]
}

fn stats_json(values: &mut Vec<u64>) -> serde_json::Value {
    values.sort_unstable();
    let n = values.len() as u64;
    let sum: u64 = values.iter().sum();
    serde_json::json!({
        "n": n,
        "p50": percentile(values, 50.0),
        "p90": percentile(values, 90.0),
        "p99": percentile(values, 99.0),
        "max": values.last().copied().unwrap_or(0),
        "mean": if n > 0 { sum / n } else { 0 },
    })
}

async fn run_bench(args: BenchArgs) {
    // reqwest::Body is not Clone, so keep the (cheap-to-clone) Bytes handle
    // and build a fresh Body per request.
    let body: Bytes = match &args.body_file {
        Some(path) => Bytes::from(std::fs::read(path).expect("read body file")),
        None => Bytes::from(synth_body(args.body_size, &args.body_kind)),
    };

    let client = reqwest::Client::builder()
        // The client must not be the bottleneck: pool wide enough for all workers.
        .pool_max_idle_per_host(args.concurrency + 16)
        .pool_idle_timeout(Duration::from_secs(120))
        .tcp_nodelay(true)
        .build()
        .expect("build client");

    let mut req_headers = reqwest::header::HeaderMap::new();
    for h in &args.headers {
        let (name, value) = h.split_once(':').expect("header must be 'Name: Value'");
        req_headers.insert(
            reqwest::header::HeaderName::from_bytes(name.trim().as_bytes()).expect("header name"),
            value.trim().parse().expect("header value"),
        );
    }

    let deadline = Instant::now() + Duration::from_secs(args.duration);
    let sent = Arc::new(AtomicU64::new(0));
    let timeout = Duration::from_secs(args.timeout);
    let is_sse = args.sse;
    let has_body_cap = args.max_requests;
    let method =
        reqwest::Method::from_bytes(args.method.to_uppercase().as_bytes()).expect("method");

    let workers: Vec<_> = (0..args.concurrency)
        .map(|_| {
            let client = client.clone();
            let target = args.target.clone();
            let body = body.clone();
            let headers = req_headers.clone();
            let sent = sent.clone();
            let is_sse = is_sse;
            let has_body_cap = has_body_cap;
            let method = method.clone();
            tokio::spawn(async move {
                let mut s = Samples::default();
                loop {
                    if Instant::now() >= deadline {
                        break;
                    }
                    // Soft cap: workers race the counter, so slightly more may fire.
                    if has_body_cap > 0 && sent.load(Ordering::Relaxed) >= has_body_cap {
                        break;
                    }
                    sent.fetch_add(1, Ordering::Relaxed);

                    let started = Instant::now();
                    let mut req = client
                        .request(method.clone(), target.as_str())
                        .headers(headers.clone());
                    if method != reqwest::Method::GET {
                        req = req
                            .body(reqwest::Body::from(body.clone()))
                            .header("content-type", "application/json");
                    }
                    let resp = match tokio::time::timeout(timeout, req.send()).await {
                        Ok(Ok(r)) => r,
                        Ok(Err(e)) => {
                            s.transport_errors += 1;
                            if s.error_samples.len() < 5 {
                                s.error_samples.push(format!("transport: {e}"));
                            }
                            continue;
                        }
                        Err(_) => {
                            s.transport_errors += 1;
                            if s.error_samples.len() < 5 {
                                s.error_samples.push("transport: client timeout".into());
                            }
                            continue;
                        }
                    };
                    if !resp.status().is_success() {
                        s.http_errors += 1;
                        if s.error_samples.len() < 5 {
                            s.error_samples
                                .push(format!("http {} via {}", resp.status(), target));
                        }
                        // Drain so the connection can be reused.
                        let _ = resp.bytes().await;
                        continue;
                    }

                    if is_sse {
                        let mut stream = resp.bytes_stream();
                        let mut ttfb: Option<u64> = None;
                        let mut last: Option<Instant> = None;
                        while let Some(item) = stream.next().await {
                            match item {
                                Ok(chunk) => {
                                    if ttfb.is_none() {
                                        ttfb = Some(started.elapsed().as_micros() as u64);
                                        last = Some(Instant::now());
                                    } else if let Some(prev) = last.replace(Instant::now()) {
                                        s.chunk_gaps_us.push(prev.elapsed().as_micros() as u64);
                                    }
                                    s.bytes += chunk.len() as u64;
                                    s.chunks += 1;
                                }
                                Err(e) => {
                                    s.transport_errors += 1;
                                    if s.error_samples.len() < 5 {
                                        s.error_samples.push(format!("stream: {e}"));
                                    }
                                    break;
                                }
                            }
                        }
                        let total = started.elapsed().as_micros() as u64;
                        s.latencies.push((ttfb.unwrap_or(total), total));
                    } else {
                        let ttfb = started.elapsed().as_micros() as u64;
                        match resp.bytes().await {
                            Ok(b) => {
                                s.bytes += b.len() as u64;
                                s.latencies
                                    .push((ttfb, started.elapsed().as_micros() as u64));
                            }
                            Err(e) => {
                                s.transport_errors += 1;
                                if s.error_samples.len() < 5 {
                                    s.error_samples.push(format!("body: {e}"));
                                }
                            }
                        }
                    }
                    s.ok += 1;
                }
                s
            })
        })
        .collect();

    let wall = Instant::now();
    let mut merged = Samples::default();
    for w in workers {
        let s = w.await.expect("worker join");
        merged.latencies.extend(s.latencies);
        merged.chunk_gaps_us.extend(s.chunk_gaps_us);
        merged.ok += s.ok;
        merged.http_errors += s.http_errors;
        merged.transport_errors += s.transport_errors;
        merged.bytes += s.bytes;
        merged.chunks += s.chunks;
        merged.error_samples.extend(s.error_samples);
    }
    let elapsed = wall.elapsed().as_secs_f64();

    let (mut ttfb, mut total): (Vec<u64>, Vec<u64>) = merged.latencies.iter().copied().unzip();
    let mut gaps = std::mem::take(&mut merged.chunk_gaps_us);

    let out = serde_json::json!({
        "label": args.label,
        "target": args.target,
        "method": method.as_str(),
        "concurrency": args.concurrency,
        "duration_s": elapsed,
        "requests": merged.ok + merged.http_errors + merged.transport_errors,
        "ok": merged.ok,
        "http_errors": merged.http_errors,
        "transport_errors": merged.transport_errors,
        "rps": if elapsed > 0.0 { merged.ok as f64 / elapsed } else { 0.0 },
        "resp_bytes": merged.bytes,
        "ttfb_us": stats_json(&mut ttfb),
        "total_us": stats_json(&mut total),
        "sse": if is_sse {
            serde_json::json!({
                "chunks": merged.chunks,
                "chunk_gap_us": stats_json(&mut gaps),
            })
        } else {
            serde_json::Value::Null
        },
        "errors": merged.error_samples,
    });
    println!("{out}");
}
