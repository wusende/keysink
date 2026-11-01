//! Seeded fuzzing for pure functions: random inputs hammering the targets,
//! asserting no panics and that key invariants hold.
//! Default seed is fixed for reproducibility. To scale up:
//! `KEYSINK_FUZZ_ITERS=200000 KEYSINK_FUZZ_SEED=<n> cargo test --release fuzz`.
//! On a hit the input lands in `fuzz/artifacts/`; shrink it into a minimal
//! regression case and commit it to the owning module's unit tests.

use crate::model::{Auth, Route, Store, Terminator, validate_name};
use crate::proxy::{
    build_upstream_url, contains_terminator, extract_vkey, forward_headers, is_encoded,
    is_stream_request, rid_from,
};
use crate::retry::{RetryPolicy, parse_retry_after};
use crate::store::decrypt;
use crate::util::{hex, percent_encode, ts};
use crate::vkey;
use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use rand::rngs::StdRng;
use rand::seq::IndexedRandom;
use rand::{RngExt, SeedableRng};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn iters(default: usize) -> usize {
    std::env::var("KEYSINK_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn fresh_rng() -> StdRng {
    let seed = std::env::var("KEYSINK_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0xC0FFEE);
    StdRng::seed_from_u64(seed)
}

fn artifacts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/artifacts")
}

/// Hand-curated historical hits replayed before random generation.
fn corpus(name: &str) -> Vec<Vec<u8>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/corpus")
        .join(name);
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            if let Ok(bytes) = std::fs::read(e.path()) {
                out.push(bytes);
            }
        }
    }
    out
}

type Case = (String, Box<dyn FnOnce()>);

fn run(name: &str, default_iters: usize, mut make_case: impl FnMut(&mut StdRng, usize) -> Case) {
    let n = iters(default_iters);
    let mut rng = fresh_rng();
    for i in 0..n {
        let (desc, exec) = make_case(&mut rng, i);
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(exec)) {
            let path = artifacts_dir().join(format!("{name}.{i}.txt"));
            let _ = std::fs::create_dir_all(artifacts_dir());
            let _ = std::fs::write(&path, format!("{desc}\n\npanic payload: {payload:?}"));
            panic!(
                "fuzz target `{name}` hit on case {i}, input saved to {} (panic: {payload:?})",
                path.display()
            );
        }
    }
}

// ---------- input generation ----------

const STRING_POOLS: &[&str] = &[
    "ks_",
    "abcXYZ019-_.",
    "परीक्षाทดสอบΣοφία", // 3-byte multibyte sequences (Devanagari/Thai/Greek)
    "🦀🎉é",            // combining characters and multibyte sequences
    "\0\x01\x08\x7f",
    " ",
    "%20%2F%zz",
    "&#x;&amp;",
    "\\\"'",
    "data: [DONE]",
    "event: message_stop",
    "\"stream\"",
    "://?#&=",
    "\u{2028}\u{feff}\u{0}",
    "Bearer ",
    "http://",
];

fn weird_string(rng: &mut StdRng) -> String {
    let pieces = rng.random_range(0..12);
    let mut s = String::new();
    for _ in 0..pieces {
        s.push_str(STRING_POOLS[rng.random_range(0..STRING_POOLS.len())]);
    }
    // Occasionally cut mid-byte and re-decode as UTF-8 to exercise multibyte
    // boundaries and replacement characters.
    if rng.random_bool(0.3) && !s.is_empty() {
        let cut = rng.random_range(0..s.len());
        s = String::from_utf8_lossy(&s.as_bytes()[..cut]).into_owned();
    }
    s
}

fn weird_value(rng: &mut StdRng) -> Vec<u8> {
    // Bytes legal in a HeaderValue: visible ASCII + obs-text + \t
    let len = rng.random_range(0..48);
    (0..len)
        .map(|_| match rng.random_range(0..10) {
            0..=6 => rng.random_range(0x20u8..0x7f),
            7..=8 => rng.random_range(0x80u16..0x100u16) as u8,
            _ => b'\t',
        })
        .collect()
}

const HEADER_NAMES: &[&str] = &[
    "authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "anthropic-api-key",
    "openai-api-key",
    "host",
    "content-length",
    "accept-encoding",
    "accept",
    "user-agent",
    "connection",
    "te",
    "transfer-encoding",
    "x-custom",
    "anthropic-version",
];

fn weird_header_name(rng: &mut StdRng) -> Option<HeaderName> {
    let raw = if rng.random_bool(0.8) {
        HEADER_NAMES[rng.random_range(0..HEADER_NAMES.len())].to_string()
    } else {
        let len = rng.random_range(1..16);
        let bytes: Vec<u8> = (0..len)
            .map(|_| {
                let pick = rng.random_range(0..4);
                match pick {
                    0 => rng.random_range(b'a'..=b'z'),
                    1 => rng.random_range(b'0'..=b'9'),
                    2 => b'-',
                    _ => rng.random_range(b'A'..=b'Z'),
                }
            })
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    };
    HeaderName::try_from(raw).ok()
}

fn weird_header_value(rng: &mut StdRng) -> Option<HeaderValue> {
    let bytes = if rng.random_bool(0.5) {
        let mut v = weird_value(rng);
        if rng.random_bool(0.4) {
            let token = vkey::generate();
            let at = rng.random_range(0..=v.len());
            v.splice(at..at, format!("{}Bearer ks_x", token).into_bytes());
        }
        v
    } else {
        weird_string(rng).into_bytes()
    };
    HeaderValue::from_bytes(&bytes).ok()
}

fn weird_headers(rng: &mut StdRng) -> HeaderMap {
    let mut map = HeaderMap::new();
    for _ in 0..rng.random_range(0..10) {
        let (Some(name), Some(value)) = (weird_header_name(rng), weird_header_value(rng)) else {
            continue;
        };
        if rng.random_bool(0.2) {
            map.append(name, value); // HeaderMap is a multimap: duplicate names must be exercised too
        } else {
            map.insert(name, value);
        }
    }
    map
}

fn weird_auth(rng: &mut StdRng) -> Auth {
    match rng.random_range(0..7) {
        0 => Auth::Bearer,
        1 => Auth::XApiKey,
        2 => Auth::Header {
            name: weird_string(rng),
            prefix: weird_string(rng),
        },
        3 => Auth::Basic {
            username: weird_string(rng),
        },
        4 => Auth::Query {
            param: weird_string(rng),
        },
        5 => Auth::None,
        _ => Auth::Header {
            name: HEADER_NAMES[rng.random_range(0..HEADER_NAMES.len())].into(),
            prefix: String::new(),
        },
    }
}

const TERMINATORS: &[Terminator] = &[
    Terminator::Auto,
    Terminator::Openai,
    Terminator::Anthropic,
    Terminator::None,
];

fn weird_route(rng: &mut StdRng) -> Route {
    let mut headers = BTreeMap::new();
    for _ in 0..rng.random_range(0..5) {
        let key = if rng.random_bool(0.7) {
            HEADER_NAMES[rng.random_range(0..HEADER_NAMES.len())].to_string()
        } else {
            weird_string(rng)
        };
        headers.insert(key, weird_string(rng));
    }
    let mut route = Route::new(
        weird_string(rng),
        weird_string(rng),
        weird_string(rng),
        weird_auth(rng),
        headers,
    );
    route.proxy = match rng.random_range(0..4) {
        0 => None,
        1 => Some("direct".into()),
        2 => Some(weird_string(rng)),
        _ => Some(format!("http://{}", weird_string(rng))),
    };
    route.sse_terminator = *TERMINATORS.choose(rng).unwrap_or(&Terminator::Auto);
    route
}

// ---------- targets ----------

#[test]
fn fuzz_vkey_mask_never_panics() {
    run("vkey_mask", 30_000, |rng, _| {
        let s = weird_string(rng);
        let desc = format!("mask({s:?})");
        let exec = Box::new(move || {
            let m = vkey::mask(&s);
            let chars = m.chars().count();
            let src = s.chars().count();
            if src <= 12 {
                assert_eq!(m, "ks_***");
            } else {
                // head 7 + ellipsis + tail 4; this is the multibyte-slice regression net
                assert_eq!(chars, 12, "mask length drifted: {m:?}");
            }
        });
        (desc, exec)
    });
}

#[test]
fn fuzz_percent_encode_roundtrip() {
    run("percent_encode", 30_000, |rng, _| {
        let s = weird_string(rng);
        let desc = format!("percent_encode({s:?})");
        let exec = Box::new(move || {
            let out = percent_encode(&s);
            assert!(
                out.bytes()
                    .all(|b| b.is_ascii_alphanumeric()
                        || matches!(b, b'-' | b'.' | b'_' | b'~' | b'%')),
                "output contains unescaped character: {out:?}"
            );
            // Byte-by-byte %XX decoding must restore the original input
            let decoded = decode_percent(&out);
            assert_eq!(decoded, s.as_bytes(), "roundtrip mismatch: {out:?}");
        });
        (desc, exec)
    });
}

fn decode_percent(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex2 = std::str::from_utf8(&b[i + 1..i + 3]).ok();
            if let Some(v) = hex2.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

#[test]
fn fuzz_extract_vkey_shape() {
    run("extract_vkey", 20_000, |rng, _| {
        let mut headers = weird_headers(rng);
        let token = vkey::generate();
        let scheme = match rng.random_range(0..5) {
            0 => format!("Bearer {token}"),
            1 => format!("bearer   {token}"), // extra spaces: only the 7-byte prefix is stripped
            2 => token.clone(),
            3 => format!("BEARER {token} extra"),
            _ => weird_string(rng),
        };
        if let Some((name, Ok(v))) = ["authorization", "x-api-key", "api-key", "x-goog-api-key"]
            .choose(rng)
            .map(|n| (n, HeaderValue::from_str(&scheme)))
        {
            headers.insert(*name, v);
        }
        let desc = format!("headers={headers:?}");
        let exec = Box::new(move || {
            if let Some(t) = extract_vkey(&headers) {
                assert!(
                    t.starts_with(vkey::PREFIX),
                    "extracted token lacks prefix: {t:?}"
                );
                assert_eq!(
                    t.trim(),
                    t,
                    "extracted token has surrounding whitespace: {t:?}"
                );
            }
        });
        (desc, exec)
    });
}

#[test]
fn fuzz_is_stream_request_matches_json_semantics() {
    run("is_stream_request", 8_000, |rng, _| {
        // Mutate JSON around the stream field and compare against naive parse semantics
        let mut body = match rng.random_range(0..4) {
            0 => format!(
                r#"{{"model":"x","stream":{},"seed":{}}}"#,
                rng.random_bool(0.5),
                rng.random::<u64>()
            )
            .into_bytes(),
            1 => format!(r#"{{"stream":"{}"}}"#, weird_string(rng)).into_bytes(),
            2 => {
                let pad = weird_string(rng);
                format!(r#"{{"{pad}":"v","stream":true,"m":"{pad}"}}"#).into_bytes()
            }
            _ => weird_value(rng),
        };
        if rng.random_bool(0.3) {
            // Prepend/append noise to stress the memchr prefilter boundaries
            let noise = weird_value(rng);
            body.splice(0..0, noise);
            body.extend_from_slice(&weird_value(rng));
        }
        let desc = format!("body={:?}", String::from_utf8_lossy(&body));
        let exec = Box::new(move || {
            #[derive(serde::Deserialize)]
            struct Probe {
                #[serde(default)]
                stream: Option<bool>,
            }
            let expect = serde_json::from_slice::<Probe>(&body)
                .ok()
                .and_then(|p| p.stream)
                .unwrap_or(false);
            assert_eq!(
                is_stream_request(&body),
                expect,
                "body={:?}",
                String::from_utf8_lossy(&body)
            );
        });
        (desc, exec)
    });
}

#[test]
fn fuzz_contains_terminator_finds_verbatim_and_case_variants() {
    run("contains_terminator", 10_000, |rng, _| {
        let terminator = *TERMINATORS.choose(rng).unwrap_or(&Terminator::Auto);
        let markers: &[&[u8]] = match terminator {
            Terminator::Openai => &[b"data: [DONE]"],
            Terminator::Anthropic => &[b"event: message_stop", b"\"type\":\"message_stop\""],
            Terminator::Auto => &[
                b"data: [DONE]",
                b"event: message_stop",
                b"\"type\":\"message_stop\"",
            ],
            Terminator::None => &[],
        };
        let prefix = weird_value(rng);
        let suffix = weird_value(rng);
        let pos = rng.random_range(0..=prefix.len());
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&prefix[..pos]);
        let marker = match markers.choose(rng) {
            Some(m) => {
                let mut m = m.to_vec();
                if rng.random_bool(0.4) {
                    for b in m.iter_mut() {
                        if rng.random_bool(0.5) && b.is_ascii_alphabetic() {
                            *b ^= 0x20; // case-mangled markers must still hit (ci scan)
                        }
                    }
                }
                m
            }
            None => Vec::new(),
        };
        chunk.extend_from_slice(&marker);
        chunk.extend_from_slice(&prefix[pos..]);
        chunk.extend_from_slice(&suffix);
        let expect_hit = !marker.is_empty() && terminator != Terminator::None;
        let desc = format!(
            "terminator={terminator:?} chunk={:?}",
            String::from_utf8_lossy(&chunk)
        );
        let exec = Box::new(move || {
            assert_eq!(
                contains_terminator(&chunk, terminator),
                expect_hit,
                "chunk={:?}",
                String::from_utf8_lossy(&chunk)
            );
        });
        (desc, exec)
    });
}

#[test]
fn fuzz_build_upstream_url_invariants() {
    run("build_upstream_url", 10_000, |rng, _| {
        let base = weird_string(rng);
        let path = match rng.random_range(0..4) {
            0 => format!("/{}", weird_string(rng)),
            1 => weird_string(rng), // may not start with '/' → must error, not panic
            2 => String::new(),
            _ => format!("/v1/{}/{}%2e%2e/..", weird_string(rng), rng.random::<u32>()),
        };
        let query = match rng.random_range(0..3) {
            0 => None,
            _ => Some(weird_string(rng)),
        };
        // Semantic assertions apply only to charset-legal params: validate
        // guarantees the charset in production, while garbage params (e.g.
        // containing ':'/'&') collide with base/path words and break the
        // "exactly once" count.
        let auth = if rng.random_bool(0.5) {
            let len = rng.random_range(1..=16);
            let charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.";
            let param: String = (0..len)
                .map(|_| charset[rng.random_range(0..charset.len())] as char)
                .collect();
            crate::model::Auth::Query { param }
        } else {
            weird_auth(rng)
        };
        let key = weird_string(rng);
        let base_trimmed = base.trim_end_matches('/').to_string();
        let desc = format!("base={base:?} path={path:?} query={query:?} auth={auth:?} key={key:?}");
        let exec = Box::new(move || {
            if let Ok(url) = build_upstream_url(&base, &path, query.as_deref(), &auth, &key) {
                assert!(
                    url.starts_with(&base_trimmed),
                    "URL does not start with base prefix: {url:?} base={base_trimmed:?}"
                );
                if let crate::model::Auth::Query { param } = &auth {
                    let sane = !param.is_empty()
                        && param
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
                    if sane {
                        // The injected pair is appended as the final query
                        // segment, so it must occur exactly once, anchored at
                        // a '?'/'&' boundary, at the very end of the URL.
                        // Parsing the query text back into pairs is not
                        // reliable here: fuzzed base_url values may contain
                        // '?' themselves. Same-name stripping semantics are
                        // covered by the e2e test with real URL parsing.
                        let enc = percent_encode(&key);
                        let injected = format!("{param}={enc}");
                        let boundary_anchored = url
                            .match_indices(&injected)
                            .filter(|(i, _)| {
                                *i == 0 || matches!(url.as_bytes()[*i - 1], b'?' | b'&')
                            })
                            .count();
                        assert_eq!(
                            boundary_anchored, 1,
                            "injected pair must appear exactly once: {url:?}"
                        );
                        assert!(
                            url.ends_with(&injected),
                            "key not appended percent-encoded at the end: {url:?}"
                        );
                    }
                }
            }
        });
        (desc, exec)
    });
}

#[test]
fn fuzz_forward_headers_auth_invariants() {
    run("forward_headers", 5_000, |rng, _| {
        let src = weird_headers(rng);
        let route = weird_route(rng);
        let key = weird_string(rng);
        let is_stream = rng.random_bool(0.5);
        let desc = format!("route={route:?} key={key:?} stream={is_stream}");
        let exec = Box::new(move || {
            if let Ok(out) = forward_headers(&src, &route, &key, is_stream) {
                // Injected auth must exactly match the config; insert semantics
                // guarantee it overrides any inbound residue.
                match &route.auth {
                    Auth::Bearer => {
                        assert_eq!(
                            out.get(header::AUTHORIZATION).map(|v| v.as_bytes()),
                            Some(format!("Bearer {key}").as_bytes())
                        );
                    }
                    Auth::Basic { username } => {
                        use base64::Engine;
                        let raw = format!("{username}:{key}");
                        let enc = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
                        assert_eq!(
                            out.get(header::AUTHORIZATION).map(|v| v.as_bytes()),
                            Some(format!("Basic {enc}").as_bytes())
                        );
                    }
                    Auth::XApiKey => {
                        assert_eq!(
                            out.get("x-api-key").map(|v| v.as_bytes()),
                            Some(key.as_bytes())
                        );
                    }
                    Auth::Header { name, prefix } => {
                        let expect = format!("{prefix}{key}");
                        let got = out.get(name.as_str()).map(|v| v.as_bytes());
                        if HeaderName::try_from(name.as_bytes()).is_ok()
                            && HeaderValue::from_str(&expect).is_ok()
                        {
                            assert_eq!(
                                got,
                                Some(expect.as_bytes()),
                                "auth header injection mismatch"
                            );
                        }
                    }
                    Auth::None | Auth::Query { .. } => {}
                }
                // Streaming requests must not negotiate a compressed encoding
                // upstream, or the SSE terminator scan goes blind; exception:
                // the route explicitly injects auth into accept-encoding
                // (validate only checks the charset, it does not block that).
                let auth_targets_ae = matches!(&route.auth, Auth::Header { name, .. }
                    if name.eq_ignore_ascii_case("accept-encoding"));
                if is_stream && !auth_targets_ae {
                    assert!(
                        out.get(header::ACCEPT_ENCODING).is_none(),
                        "streaming request leaked accept-encoding upstream"
                    );
                }
            }
        });
        (desc, exec)
    });
}

#[test]
fn fuzz_rid_total() {
    run("rid_from", 10_000, |rng, _| {
        let n: u64 = match rng.random_range(0..3) {
            0 => rng.random(),
            1 => rng.random_range(0..2000),
            _ => u64::MAX - rng.random_range(0..10),
        };
        let exec = Box::new(move || {
            let rid = rid_from(n);
            assert!(!rid.is_empty() && rid.bytes().all(|b| b.is_ascii_alphanumeric()));
        });
        (format!("rid_from({n})"), exec)
    });
}

#[test]
fn fuzz_parse_retry_after_bounded() {
    run("parse_retry_after", 20_000, |rng, _| {
        let s = match rng.random_range(0..3) {
            0 => weird_string(rng),
            1 => rng.random::<u64>().to_string(),
            _ => {
                let secs = rng.random_range(0..10_000_000u64);
                format!("{secs}")
            }
        };
        let desc = format!("parse_retry_after({s:?})");
        let exec = Box::new(move || {
            // Capping is backoff's contract (ra.min(MAX_RETRY_AFTER)); the
            // parser only guarantees non-zero.
            if let Some(d) = parse_retry_after(&s) {
                assert!(
                    d > std::time::Duration::ZERO,
                    "Retry-After of 0 must be dropped: {s:?}"
                );
            }
        });
        (desc, exec)
    });
}

#[test]
fn fuzz_backoff_bounded_and_total() {
    run("backoff", 10_000, |rng, _| {
        let attempt: u32 = match rng.random_range(0..3) {
            0 => rng.random(),
            1 => rng.random_range(0..64),
            _ => rng.random_range(0..300),
        };
        let ra = match rng.random_range(0..4) {
            0 => None,
            1 => Some(std::time::Duration::from_secs(rng.random())),
            2 => Some(std::time::Duration::from_nanos(rng.random())),
            _ => Some(std::time::Duration::MAX),
        };
        let desc = format!("backoff({attempt}, {ra:?})");
        let exec = Box::new(move || {
            let p = RetryPolicy::default();
            let d = p.backoff(attempt, ra);
            let cap = ra.map_or(p.max_backoff, |_| crate::retry::MAX_RETRY_AFTER);
            assert!(
                d <= cap,
                "backoff out of bounds: attempt={attempt} ra={ra:?} → {d:?} cap={cap:?}"
            );
        });
        (desc, exec)
    });
}

#[test]
fn fuzz_ts_hex_total() {
    run("ts_hex", 10_000, |rng, _| {
        let secs: u64 = rng.random();
        let bytes: Vec<u8> = (0..rng.random_range(0..40)).map(|_| rng.random()).collect();
        let exec = Box::new(move || {
            assert!(!ts(secs).is_empty());
            let h = hex(&bytes);
            assert_eq!(h.len(), bytes.len() * 2);
            assert!(
                h.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            );
        });
        (format!("ts({secs})"), exec)
    });
}

#[test]
fn fuzz_validate_name_matches_spec() {
    run("validate_name", 20_000, |rng, _| {
        let s = weird_string(rng);
        let desc = format!("validate_name({s:?})");
        let exec = Box::new(move || {
            let result = validate_name(&s, "x").is_ok();
            let expect = !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
            assert_eq!(result, expect, "validate_name deviates from spec: {s:?}");
        });
        (desc, exec)
    });
}

#[test]
fn fuzz_terminator_parse_roundtrip() {
    run("terminator_parse", 10_000, |rng, _| {
        let s = weird_string(rng);
        let desc = format!("Terminator::parse({s:?})");
        let exec = Box::new(move || {
            if let Ok(t) = Terminator::parse(&s) {
                assert!(
                    matches!(Terminator::parse(t.as_str()), Ok(x) if x == t),
                    "parse(as_str) must be reflexive: {s:?}"
                );
            }
        });
        (desc, exec)
    });
}

#[test]
fn fuzz_store_json_never_panics() {
    run("store_json", 3_000, |rng, _| {
        let (json, desc) = gen_store_json(rng);
        let exec = Box::new(move || {
            if let Ok(store) = serde_json::from_slice::<Store>(&json) {
                let _ = store.validate(); // only require no panic; validity itself is covered by e2e scenarios
                // Anything that parses must re-serialize
                serde_json::to_vec(&store).expect("a parsed Store must re-serialize");
            }
        });
        (desc, exec)
    });
}

/// Mutated store JSON: field-level corruption of a valid sample plus purely random JSON.
fn gen_store_json(rng: &mut StdRng) -> (Vec<u8>, String) {
    if rng.random_bool(0.25) {
        // Purely random JSON
        let depth = rng.random_range(1..4);
        let mut s = String::new();
        for _ in 0..depth {
            s.push_str(&format!("{{\"{}\":", weird_string(rng)));
        }
        s.push_str(&match rng.random_range(0..4) {
            0 => rng.random::<u64>().to_string(),
            1 => format!("\"{}\"", weird_string(rng)),
            2 => "null".into(),
            _ => format!("{}", rng.random::<f64>() * 1e300),
        });
        for _ in 0..depth {
            s.push('}');
        }
        let desc = format!("random-json {s}");
        return (s.into_bytes(), desc);
    }
    let mut store = Store::new();
    for i in 0..rng.random_range(1..4) {
        store.routes.insert(format!("r{i}"), weird_route(rng));
    }
    let mut value = serde_json::to_value(&store).unwrap();
    for _ in 0..rng.random_range(1..5) {
        mutate_json(rng, &mut value, 0);
    }
    (
        serde_json::to_vec(&value).unwrap(),
        format!("mutated {value}"),
    )
}

fn mutate_json(rng: &mut StdRng, v: &mut serde_json::Value, depth: u8) {
    match v {
        serde_json::Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            let pick = rng.random_range(0..5);
            match pick {
                0 if !keys.is_empty() => {
                    let k = keys.choose(rng).unwrap();
                    map[k] = weird_json_scalar(rng);
                }
                1 if !keys.is_empty() => {
                    let k = keys.choose(rng).unwrap();
                    map.remove(k);
                }
                2 => {
                    map.insert(weird_string(rng), weird_json_scalar(rng));
                }
                _ if depth < 4 => {
                    for (_, child) in map.iter_mut() {
                        if rng.random_bool(0.4) {
                            mutate_json(rng, child, depth + 1);
                        }
                    }
                }
                _ => {
                    map.insert("version".into(), weird_json_scalar(rng));
                }
            }
        }
        serde_json::Value::Array(items) => {
            if let Some(i) = (!items.is_empty()).then(|| rng.random_range(0..items.len())) {
                mutate_json(rng, &mut items[i], depth + 1);
            }
        }
        _ => *v = weird_json_scalar(rng),
    }
}

fn weird_json_scalar(rng: &mut StdRng) -> serde_json::Value {
    match rng.random_range(0..8) {
        0 => serde_json::Value::Null,
        1 => serde_json::Value::Bool(rng.random()),
        2 => serde_json::Value::from(weird_string(rng)),
        3 => serde_json::Value::from(u64::MAX - rng.random_range(0..1000)),
        4 => serde_json::Value::from(-(rng.random::<i32>() as i64) * 1_000_000_000i64),
        5 => serde_json::Value::from(weird_string(rng)),
        6 => serde_json::Value::Array(
            (0..rng.random_range(0..3))
                .map(|_| weird_json_scalar(rng))
                .collect(),
        ),
        _ => serde_json::Value::Object(
            [(weird_string(rng), weird_json_scalar(rng))]
                .into_iter()
                .collect(),
        ),
    }
}

#[test]
fn fuzz_route_validate_consistent_with_table_build() {
    run("route_validate", 3_000, |rng, _| {
        let mut store = Store::new();
        let names: Vec<String> = (0..rng.random_range(1..4))
            .map(|_| weird_string(rng))
            .collect();
        for name in &names {
            store.routes.insert(name.clone(), weird_route(rng));
        }
        // A store that passes validate must also build a RouteTable; a
        // mismatch between the two validation standards is exactly the
        // "doctor passes, serve refuses to start" bug class.
        let desc = format!("names={names:?}");
        let exec = Box::new(move || {
            if store.validate().is_ok() {
                crate::vkey::RouteTable::build(&store)
                    .unwrap_or_else(|e| panic!("validate passed but RouteTable rejected: {e}"));
            }
        });
        (desc, exec)
    });
}

#[test]
fn fuzz_age_decrypt_never_panics() {
    run("age_decrypt", 300, |rng, _| {
        let identity = age::x25519::Identity::generate();
        // Two lanes: mutated real ciphertext (truncate/bitflip/splice) and fully random bytes
        let (ciphertext, desc) = if rng.random_bool(0.5) {
            let mut pt = Vec::new();
            let mut store = Store::new();
            store.routes.insert(
                "r".into(),
                Route::new(
                    vkey::generate(),
                    "https://x.example".into(),
                    "k".into(),
                    Auth::Bearer,
                    Default::default(),
                ),
            );
            serde_json::to_writer(&mut pt, &store).unwrap();
            let ct = crate::store::encrypt_to(&pt, &[&identity]).unwrap();
            let mut bad = ct.clone();
            match rng.random_range(0..4) {
                0 => {
                    bad.truncate(rng.random_range(0..=bad.len()));
                }
                1 => {
                    for _ in 0..rng.random_range(1..8) {
                        let pos = rng.random_range(0..bad.len());
                        bad[pos] ^= rng.random::<u8>().max(1);
                    }
                }
                2 => {
                    let cut = rng.random_range(0..=bad.len());
                    bad.splice(0..cut, ct[..cut.max(ct.len() / 2)].to_vec());
                }
                _ => bad.extend_from_slice(&weird_value(rng)),
            }
            let desc = format!("mutated real ct len={}", bad.len());
            (bad, desc)
        } else {
            (weird_value(rng), "random bytes".into())
        };
        let exec = Box::new(move || {
            if let Ok(plain) = decrypt(&ciphertext, &identity) {
                // age returns Err on failure; only genuine ciphertext decrypts,
                // so the plaintext must be valid Store JSON.
                serde_json::from_slice::<Store>(&plain)
                    .unwrap_or_else(|e| panic!("decrypted plaintext is not a Store: {e}"));
            }
        });
        (desc, exec)
    });
}

#[test]
fn fuzz_password_verify_rejects_malformed() {
    run("password_verify", 150, |rng, _| {
        // log_n capped at 13: only well-formed inputs actually run scrypt;
        // huge log_n is a separate DoS hardening concern with its own test.
        let encoded = match rng.random_range(0..3) {
            0 => weird_string(rng),
            1 => format!(
                "scrypt${}$8$1${}${}$",
                rng.random_range(0..14),
                hex(&rng.random::<[u8; 4]>()),
                hex(&rng.random::<[u8; 4]>())
            ),
            _ => format!(
                "scrypt$13$8$1$deadbeefdeadbeefdeadbeefdeadbeef${}{}",
                hex(&rng.random::<[u8; 16]>()),
                weird_string(rng)
            ),
        };
        let desc = format!("verify_password(encoded={encoded:?})");
        let exec = Box::new(move || {
            let _ = crate::password::verify_password("pw", &encoded);
        });
        (desc, exec)
    });
}

#[test]
fn fuzz_audit_line_stays_single_line() {
    run("audit_line", 5_000, |rng, _| {
        let mut entry = crate::audit::AuditEntry::new(
            rid_from(rng.random()),
            weird_string(rng),
            weird_string(rng),
            weird_string(rng),
            weird_string(rng),
            rng.random::<u64>() as usize,
            rng.random_bool(0.5),
        );
        entry.status = rng.random();
        entry.ms = rng.random();
        entry.attempts = rng.random();
        let desc = format!("entry.route={:?}", entry.route);
        let exec = Box::new(move || {
            let line = serde_json::to_vec(&entry).expect("audit entry must serialize");
            assert!(
                !line.contains(&b'\n'),
                "embedded newline would tear the JSONL stream: {:?}",
                String::from_utf8_lossy(&line)
            );
        });
        (desc, exec)
    });
}

#[test]
fn fuzz_is_encoded_matches_spec() {
    run("is_encoded", 10_000, |rng, _| {
        let mut headers = HeaderMap::new();
        let kind = rng.random_range(0..3);
        if kind != 0 {
            let value = if kind == 2 {
                weird_value(rng)
            } else {
                match rng.random_range(0..3) {
                    0 => b"identity".to_vec(),
                    1 => b"IDENTITY ".to_vec(),
                    _ => b"gzip".to_vec(),
                }
            };
            if let Ok(v) = HeaderValue::from_bytes(&value) {
                headers.insert(header::CONTENT_ENCODING, v);
            }
        }
        let expect = match headers.get(header::CONTENT_ENCODING) {
            None => false,
            Some(v) => match v.to_str() {
                Ok(s) => {
                    let s = s.trim();
                    !s.is_empty() && !s.eq_ignore_ascii_case("identity")
                }
                Err(_) => true,
            },
        };
        let desc = format!("headers={headers:?}");
        let exec = Box::new(move || {
            assert_eq!(is_encoded(&headers), expect);
        });
        (desc, exec)
    });
}

/// Corpus replay for byte-oriented targets: each file under corpus/<name>/ is
/// fed through the target closure once.
fn replay_corpus(name: &str, mut target: impl FnMut(&[u8])) {
    for (i, input) in corpus(name).into_iter().enumerate() {
        if let Err(payload) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| target(&input)))
        {
            let path = artifacts_dir().join(format!("{name}.corpus.{i}.txt"));
            let _ = std::fs::create_dir_all(artifacts_dir());
            let _ = std::fs::write(&path, &input);
            panic!(
                "corpus replay `{name}[{i}]` hit, input saved to {} (panic: {payload:?})",
                path.display()
            );
        }
    }
}

#[test]
fn fuzz_is_stream_request_deep_nesting() {
    // Stack-overflow audit lock: serde_json's ignored-field skipper is
    // iterative (explicit heap stack, not call-stack recursion), so
    // attacker-controlled nesting depth must neither overflow the stack nor
    // change stream semantics. Regression guard for the depth direction,
    // which the generative targets above never reach (they stay 1-4 deep).
    for depth in [200usize, 10_000, 200_000] {
        let deep = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        let cases: [(String, bool); 4] = [
            // no "stream" substring anywhere: memchr prefilter short-circuits
            (format!(r#"{{"model":"m","pad":{deep}}}"#), false),
            // stream present after a deeply nested ignored field: full parse
            (format!(r#"{{"pad":{deep},"stream":true}}"#), true),
            // "stream" only inside a string value: must parse, result false
            (format!(r#"{{"noise":"stream","pad":{deep}}}"#), false),
            // deep nesting at the top level: struct probe fails fast
            (deep.clone(), false),
        ];
        for (i, (body, expect)) in cases.into_iter().enumerate() {
            let body = body.into_bytes();
            assert_eq!(
                is_stream_request(&body),
                expect,
                "case {i} depth={depth}: head={:?}",
                String::from_utf8_lossy(&body[..body.len().min(48)])
            );
        }
    }
}

#[test]
fn fuzz_is_stream_request_corpus() {
    replay_corpus("is_stream_request", |b| {
        let _ = is_stream_request(b);
    });
}

#[test]
fn fuzz_contains_terminator_corpus() {
    replay_corpus("contains_terminator", |b| {
        for t in TERMINATORS {
            let _ = contains_terminator(b, *t);
        }
    });
}

#[test]
fn fuzz_age_decrypt_corpus() {
    replay_corpus("age_decrypt", |b| {
        let identity = age::x25519::Identity::generate();
        let _ = decrypt(b, &identity);
    });
}

// ---------- performance scenarios for pure helpers ----------

fn timed(name: &str, budget: std::time::Duration, elapsed: std::time::Duration) {
    // Debug builds are 30-50x slower than release here (no inlining, bounds
    // checks, no SIMD in memchr), so the same absolute budget that is generous
    // for release flakes on a loaded CI runner. Scale instead of loosening the
    // release budget: a real regression still shows up as a multiple, not a few
    // percent.
    let budget = if cfg!(debug_assertions) {
        budget * 8
    } else {
        budget
    };
    println!("perf/{name}: {elapsed:?} (budget {budget:?})");
    assert!(
        elapsed <= budget,
        "{name} exceeded budget: {elapsed:?} > {budget:?}"
    );
}

#[test]
fn perf_forward_headers_throughput() {
    let mut route = Route::new(
        vkey::generate(),
        "https://up.invalid".into(),
        "k".into(),
        Auth::Bearer,
        BTreeMap::new(),
    );
    for i in 0..128 {
        route
            .headers
            .insert(format!("x-static-{i}"), format!("value-{i}"));
    }
    let mut src = HeaderMap::new();
    for i in 0..100 {
        src.insert(
            HeaderName::from_bytes(format!("x-in-{i}").as_bytes()).unwrap(),
            HeaderValue::from_str(&format!("v-{i}")).unwrap(),
        );
    }
    src.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str("Bearer ks_test").unwrap(),
    );

    let t0 = std::time::Instant::now();
    for _ in 0..2_000 {
        let out = forward_headers(&src, &route, "k", false).unwrap();
        assert_eq!(out.get("x-static-127").unwrap(), "value-127");
    }
    timed(
        "forward_headers_2k",
        std::time::Duration::from_secs(5),
        t0.elapsed(),
    );
}

#[test]
fn perf_build_upstream_url_large() {
    let path = format!("/v1/{}", "a".repeat(64 * 1024));
    let query = format!("q={}", "b".repeat(32 * 1024));
    let auth = Auth::Query {
        param: "key".into(),
    };
    let t0 = std::time::Instant::now();
    for _ in 0..500 {
        let url =
            build_upstream_url("https://api.example.com", &path, Some(&query), &auth, "k").unwrap();
        assert!(url.ends_with('k'));
    }
    timed(
        "url_500x96kb",
        std::time::Duration::from_secs(3),
        t0.elapsed(),
    );
}

#[test]
fn perf_is_stream_request_large_bodies() {
    // no marker anywhere: the memchr prefilter must reject without parsing
    let plain = vec![b'a'; 32 * 1024 * 1024];
    let t0 = std::time::Instant::now();
    assert!(!is_stream_request(&plain));
    timed(
        "scan_32mb_no_marker",
        std::time::Duration::from_secs(3),
        t0.elapsed(),
    );

    // marker present inside a string value: the full parse runs and must stay cheap
    let mut body = br#"{"k":"#.to_vec();
    body.extend(std::iter::repeat_n(b'x', 1024 * 1024));
    body.extend_from_slice(br#"... \"stream\" ...","tail":""#);
    body.extend(std::iter::repeat_n(b'y', 1024 * 1024));
    body.extend_from_slice(br#""}"#);
    let t1 = std::time::Instant::now();
    assert!(!is_stream_request(&body));
    timed(
        "parse_2mb_with_marker",
        std::time::Duration::from_secs(5),
        t1.elapsed(),
    );
}

#[test]
fn perf_contains_terminator_large_chunk() {
    let mut chunk = vec![b'x'; 2 * 1024 * 1024];
    chunk.extend_from_slice(b"no marker here");
    let t0 = std::time::Instant::now();
    for _ in 0..4 {
        assert!(!contains_terminator(&chunk, Terminator::Auto));
    }
    // The ci fallback used to sweep every window position byte-by-byte
    // (O(n*m) per chunk); the memchr2 candidate scan should hold this budget
    // with orders of magnitude to spare, even in debug builds.
    timed(
        "scan_2mb_x4",
        std::time::Duration::from_secs(1),
        t0.elapsed(),
    );
}
