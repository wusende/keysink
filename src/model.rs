use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroize;

pub const STORE_VERSION: u32 = 1;

/// Sentinel value for route.proxy: force a direct connection, ignoring the system proxy environment variables.
pub const PROXY_DIRECT: &str = "direct";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Store {
    pub version: u32,
    /// scrypt verification string for the master password; must be verified before export (passphrase-encrypted backup).
    #[serde(default)]
    pub password_hash: Option<String>,
    #[serde(default)]
    pub routes: BTreeMap<String, Route>,
}
impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    pub fn new() -> Self {
        Self {
            version: STORE_VERSION,
            password_hash: None,
            routes: BTreeMap::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != STORE_VERSION {
            return Err(Error::msg(format!(
                "store version {} is not supported (supported version: {})",
                self.version, STORE_VERSION
            )));
        }

        let mut vkeys = std::collections::HashSet::new();
        for (name, route) in &self.routes {
            validate_name(name, "route")?;
            route.validate(name)?;
            match &route.inline_key {
                Some(value) if !value.is_empty() => {}
                Some(_) => {
                    return Err(Error::msg(format!(
                        "route `{name}` has an empty route-only key"
                    )));
                }
                None => {
                    return Err(Error::msg(format!(
                        "route `{name}` is missing its key (use route update --route-key to re-enter it)"
                    )));
                }
            }
            if !vkeys.insert(route.vkey.clone()) {
                return Err(Error::msg(format!(
                    "route `{name}` has a vkey that duplicates another route"
                )));
            }
        }

        Ok(())
    }
}

impl Drop for Route {
    fn drop(&mut self) {
        if let Some(value) = &mut self.inline_key {
            value.zeroize();
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Route {
    pub vkey: String,
    pub base_url: String,
    /// route-only key: write-only (no get/export channel), injected only when forwarding.
    /// Option exists so that deserializing an old store yields a readable missing-field hint instead of serde erroring on null.
    #[serde(default)]
    pub inline_key: Option<String>,
    #[serde(default)]
    pub auth: Auth,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub max_retries: Option<u8>,
    #[serde(default)]
    pub retry_on_status: Option<Vec<u16>>,
    #[serde(default)]
    pub sse_terminator: Terminator,
    /// Upstream proxy: None follows the system proxy environment variables; `direct` forces a direct connection; a URL uses that proxy.
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub created: u64,
}

/// Debug that never prints the secret.
///
/// A derived impl would put `inline_key` (the real upstream credential) into
/// every `{:?}` — a fuzz artifact, a panic message, a log line added later.
/// The vault's whole promise is that the key cannot come out, so the type
/// itself must not hand it out.
impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("vkey", &crate::vkey::mask(&self.vkey))
            .field("base_url", &self.base_url)
            .field(
                "inline_key",
                &match &self.inline_key {
                    Some(_) => "<redacted>",
                    None => "<missing>",
                },
            )
            .field("auth", &self.auth)
            .field("headers", &self.headers)
            .field("enabled", &self.enabled)
            .field("max_retries", &self.max_retries)
            .field("retry_on_status", &self.retry_on_status)
            .field("sse_terminator", &self.sse_terminator)
            .field("proxy", &self.proxy)
            .field("note", &self.note)
            .field("created", &self.created)
            .finish()
    }
}

fn default_true() -> bool {
    true
}

impl Route {
    pub fn new(
        vkey: String,
        base_url: String,
        inline_key: String,
        auth: Auth,
        headers: BTreeMap<String, String>,
    ) -> Self {
        Self {
            vkey,
            base_url,
            inline_key: Some(inline_key),
            auth,
            headers,
            enabled: true,
            max_retries: None,
            retry_on_status: None,
            sse_terminator: Terminator::Auto,
            proxy: None,
            note: String::new(),
            created: crate::util::now_secs(),
        }
    }

    pub(crate) fn validate(&self, name: &str) -> Result<()> {
        // Same standard as RouteTable::build (ks_ + 43 chars of base64url).
        // Previously the CLI side only checked prefix + length >= 16, looser than serve: a malformed vkey could pass doctor
        // while serve refused to start, and the two sides' errors didn't line up.
        if !crate::vkey::is_well_formed(&self.vkey) {
            return Err(Error::msg(format!(
                "route `{name}` has an invalid vkey (expected ks_ + 43 chars of base64url)"
            )));
        }
        if !(self.base_url.starts_with("http://") || self.base_url.starts_with("https://")) {
            return Err(Error::msg(format!(
                "route `{name}` base_url must start with http:// or https://"
            )));
        }
        if self.base_url.ends_with('/') {
            return Err(Error::msg(format!(
                "route `{name}` base_url must not end with /"
            )));
        }
        if self.base_url.contains('?') || self.base_url.contains('#') {
            return Err(Error::msg(format!(
                "route `{name}` base_url must not contain a query or fragment"
            )));
        }
        match &self.auth {
            Auth::Bearer | Auth::XApiKey | Auth::None => {}
            Auth::Header {
                name: header,
                prefix,
            } => {
                if header.is_empty() {
                    return Err(Error::msg(format!(
                        "route `{name}` has an empty auth header name"
                    )));
                }
                if !header
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                {
                    return Err(Error::msg(format!(
                        "route `{name}` auth header name contains invalid characters"
                    )));
                }
                // Forward time builds `HeaderValue::from_str(prefix)` into the
                // auth header — reject now, at save time, instead of turning
                // every request on the route into a 500 later.
                if axum::http::HeaderValue::from_str(prefix).is_err() {
                    return Err(Error::msg(format!(
                        "route `{name}` auth header prefix contains invalid characters (visible ASCII only)"
                    )));
                }
            }
            Auth::Basic { username } => {
                if username.is_empty() {
                    return Err(Error::msg(format!(
                        "route `{name}` has an empty basic username"
                    )));
                }
                if axum::http::HeaderValue::from_str(username).is_err() {
                    return Err(Error::msg(format!(
                        "route `{name}` basic username contains invalid characters (visible ASCII only)"
                    )));
                }
            }
            Auth::Query { param } => {
                if param.is_empty() {
                    return Err(Error::msg(format!(
                        "route `{name}` has an empty query parameter name"
                    )));
                }
                // &, =, or spaces would build a broken URL or inject extra parameters.
                if !param
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                {
                    return Err(Error::msg(format!(
                        "route `{name}` query parameter name contains invalid characters (only letters, digits, -, _, . are allowed)"
                    )));
                }
            }
        }
        for (key, value) in &self.headers {
            if key.is_empty() {
                return Err(Error::msg(format!(
                    "route `{name}` has an empty header name"
                )));
            }
            if !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            {
                return Err(Error::msg(format!(
                    "route `{name}` header `{key}` name contains invalid characters"
                )));
            }
            if is_forbidden_static_header(key) {
                return Err(Error::msg(format!(
                    "route `{name}` must not override `{key}` with a static header"
                )));
            }
            // Forward time builds `HeaderValue::from_str(value)` — reject now,
            // at save time, instead of turning every request on the route
            // into a 500 later.
            if axum::http::HeaderValue::from_str(value).is_err() {
                return Err(Error::msg(format!(
                    "route `{name}` header `{key}` value contains invalid characters (visible ASCII only)"
                )));
            }
        }
        if let Some(retries) = self.max_retries
            && retries > 10
        {
            return Err(Error::msg(format!(
                "route `{name}` max_retries must not exceed 10"
            )));
        }
        // The route-only key is injected verbatim into a header for these auth
        // types. Validate it the same way as the other header fields: a key
        // with a control character (a newline from a multi-line stdin pipe,
        // for instance) would otherwise pass validation and turn every request
        // on the route into a 500 at forward time.
        if let Some(key) = &self.inline_key {
            let injected = match &self.auth {
                Auth::Bearer => Some(format!("Bearer {key}")),
                Auth::XApiKey => Some(key.clone()),
                Auth::Header { prefix, .. } => Some(format!("{prefix}{key}")),
                // Basic base64-encodes the pair, Query percent-encodes the
                // value, and None never injects it: control characters cannot
                // break those header/URL constructions.
                Auth::Basic { .. } | Auth::Query { .. } | Auth::None => None,
            };
            if let Some(value) = injected
                && axum::http::HeaderValue::from_str(&value).is_err()
            {
                return Err(Error::msg(format!(
                    "route `{name}` route-only key contains characters that cannot be sent in an HTTP header (control characters such as newlines are not allowed)"
                )));
            }
        }
        if let Some(statuses) = &self.retry_on_status
            && let Some(bad) = statuses.iter().find(|s| !(400..=599).contains(*s))
        {
            // A success code here would discard good responses and replay
            // POSTs (double billing); anything above 599 is not a status.
            return Err(Error::msg(format!(
                "route `{name}` retry_on_status contains {bad}: only status codes 400..=599 can be retried"
            )));
        }
        if let Some(proxy) = &self.proxy
            && proxy != PROXY_DIRECT
            && !(proxy.starts_with("http://") || proxy.starts_with("https://"))
        {
            return Err(Error::msg(format!(
                "route `{name}` proxy only supports an http(s):// URL or `direct` (default follows the system proxy)"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Auth {
    #[default]
    Bearer,
    XApiKey,
    Header {
        name: String,
        #[serde(default)]
        prefix: String,
    },
    Basic {
        username: String,
    },
    Query {
        param: String,
    },
    None,
}

impl Auth {
    pub fn describe(&self) -> String {
        match self {
            Auth::Bearer => "bearer".into(),
            Auth::XApiKey => "x-api-key".into(),
            Auth::Header { name, prefix } => {
                if prefix.is_empty() {
                    format!("header:{name}")
                } else {
                    format!("header:{name} (prefix)")
                }
            }
            Auth::Basic { username } => format!("basic:{username}"),
            Auth::Query { param } => format!("query:{param}"),
            Auth::None => "none".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Terminator {
    #[default]
    Auto,
    Openai,
    Anthropic,
    None,
}

impl Terminator {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "auto" => Ok(Self::Auto),
            "openai" => Ok(Self::Openai),
            "anthropic" => Ok(Self::Anthropic),
            "none" => Ok(Self::None),
            other => Err(Error::msg(format!(
                "unknown sse-terminator `{other}` (options: auto/openai/anthropic/none)"
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Openai => "openai",
            Self::Anthropic => "anthropic",
            Self::None => "none",
        }
    }
}

fn is_forbidden_static_header(name: &str) -> bool {
    const FORBIDDEN: &[&str] = &[
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
        "authorization",
        "x-api-key",
        "x-goog-api-key",
        "api-key",
        "anthropic-api-key",
        "openai-api-key",
    ];
    FORBIDDEN.iter().any(|h| h.eq_ignore_ascii_case(name))
}

pub fn validate_name(name: &str, what: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(Error::msg(format!(
            "{what} name length must be within 1..=64"
        )));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(Error::msg(format!(
            "{what} name `{name}` may only contain letters, digits, -, _, ."
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Store {
        let mut store = Store::new();
        store.routes.insert(
            "r".into(),
            Route::new(
                crate::vkey::generate(),
                "https://api.example.com".into(),
                "secret-value".into(),
                Auth::Bearer,
                BTreeMap::new(),
            ),
        );
        store
    }

    #[test]
    fn validates_ok() {
        sample().validate().unwrap();
    }

    #[test]
    fn route_debug_never_prints_the_secret() {
        let mut s = sample();
        s.routes.get_mut("r").unwrap().inline_key = Some("never-leak-me".into());
        let text = format!("{:?}", s);
        assert!(
            !text.contains("never-leak-me"),
            "Debug must redact the route-only key: {text}"
        );
        assert!(text.contains("<redacted>"), "{text}");
        // The Store Debug includes every route, so it must be covered too.
        let store_text = format!("{:?}", s.routes["r"]);
        assert!(!store_text.contains("never-leak-me"), "{store_text}");
    }

    #[test]
    fn rejects_missing_inline_key() {
        let mut s = sample();
        s.routes.get_mut("r").unwrap().inline_key = None;
        assert!(s.validate().is_err());
        let mut s = sample();
        s.routes.get_mut("r").unwrap().inline_key = Some(String::new());
        assert!(s.validate().is_err());
    }

    #[test]
    fn rejects_malformed_vkey_like_serve_does() {
        let mut s = sample();
        s.routes.get_mut("r").unwrap().vkey = "ks_short".into();
        assert!(s.validate().is_err());
        s.routes.get_mut("r").unwrap().vkey =
            "sk_0000000000000000000000000000000000000000000".into();
        assert!(s.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_vkey() {
        let mut s = sample();
        let vkey = s.routes["r"].vkey.clone();
        let mut route = s.routes["r"].clone();
        route.vkey = vkey;
        s.routes.insert("r2".into(), route);
        assert!(s.validate().is_err());
    }

    #[test]
    fn rejects_bad_query_param_names() {
        for bad in ["a=b", "a&b", "a b", "a/b"] {
            let mut s = sample();
            s.routes.get_mut("r").unwrap().auth = Auth::Query { param: bad.into() };
            assert!(s.validate().is_err(), "param `{bad}` should be rejected");
        }
        let mut s = sample();
        s.routes.get_mut("r").unwrap().auth = Auth::Query {
            param: "api_key-x.1".into(),
        };
        s.validate().unwrap();
    }

    #[test]
    fn rejects_header_values_headervalue_would_refuse() {
        // Forward time builds HeaderValue::from_str(value): a value it would
        // refuse used to brick the whole route at request time (500 on every
        // request); it must be rejected at save time instead. from_str
        // rejects control chars (<0x20 except \t) and DEL; obs-text
        // (0x80-0xFF) passes and stays legal to forward.
        for bad in [
            "bad\nvalue",
            "bad\rvalue",
            "bad\u{0}value",
            "bad\u{7f}value",
        ] {
            let mut s = sample();
            s.routes
                .get_mut("r")
                .unwrap()
                .headers
                .insert("x-trace".into(), bad.into());
            assert!(s.validate().is_err(), "value `{bad}` should be rejected");
        }
        let mut s = sample();
        s.routes
            .get_mut("r")
            .unwrap()
            .headers
            .insert("x-trace".into(), "2023-06-01".into());
        s.validate().unwrap();
    }

    #[test]
    fn rejects_auth_fields_headervalue_would_refuse() {
        let mut s = sample();
        s.routes.get_mut("r").unwrap().auth = Auth::Header {
            name: "x-custom-auth".into(),
            prefix: "Bearer\n".into(),
        };
        assert!(s.validate().is_err());
        let mut s = sample();
        s.routes.get_mut("r").unwrap().auth = Auth::Basic {
            username: "user\rname".into(),
        };
        assert!(s.validate().is_err());
        // An empty prefix is legal: raw key, no scheme.
        let mut s = sample();
        s.routes.get_mut("r").unwrap().auth = Auth::Header {
            name: "x-custom-auth".into(),
            prefix: String::new(),
        };
        s.validate().unwrap();
    }

    #[test]
    fn rejects_inline_key_the_auth_header_would_refuse() {
        // Bearer / x-api-key / custom-header inject the route-only key into a
        // header verbatim; a control character must be rejected at save time
        // instead of 500ing every request later.
        for auth in [
            Auth::Bearer,
            Auth::XApiKey,
            Auth::Header {
                name: "x-auth".into(),
                prefix: "Bearer ".into(),
            },
        ] {
            for bad in ["key\npart", "key\rpart", "key\u{0}part", "key\u{7f}part"] {
                let mut s = sample();
                s.routes.get_mut("r").unwrap().auth = auth.clone();
                s.routes.get_mut("r").unwrap().inline_key = Some(bad.into());
                assert!(
                    s.validate().is_err(),
                    "{auth:?} key {bad:?} should be rejected"
                );
            }
        }
        // Basic base64-encodes the pair and Query percent-encodes the value,
        // so the same bytes cannot break the constructed header/URL.
        for auth in [
            Auth::Basic {
                username: "user".into(),
            },
            Auth::Query {
                param: "key".into(),
            },
        ] {
            let mut s = sample();
            s.routes.get_mut("r").unwrap().auth = auth;
            s.routes.get_mut("r").unwrap().inline_key = Some("key\npart".into());
            s.validate().unwrap();
        }
    }

    #[test]
    fn rejects_retry_on_status_outside_4xx_5xx() {
        // A success code here would discard good responses and replay POSTs
        // (double billing); above 599 is not a status code at all.
        for bad in [200u16, 302, 399, 600] {
            let mut s = sample();
            s.routes.get_mut("r").unwrap().retry_on_status = Some(vec![bad]);
            assert!(s.validate().is_err(), "status {bad} should be rejected");
        }
        let mut s = sample();
        s.routes.get_mut("r").unwrap().retry_on_status = Some(vec![429, 500, 503]);
        s.validate().unwrap();
    }

    #[test]
    fn validates_route_proxy() {
        let mut s = sample();
        s.validate().unwrap();
        for ok in [
            None,
            Some("direct".into()),
            Some("http://127.0.0.1:7890".into()),
            Some("https://proxy.example.com".into()),
        ] {
            s.routes.get_mut("r").unwrap().proxy = ok;
            s.validate().unwrap();
        }
        for bad in ["127.0.0.1:7890", "socks5://127.0.0.1:7890", ""] {
            s.routes.get_mut("r").unwrap().proxy = Some(bad.into());
            assert!(s.validate().is_err(), "proxy `{bad}` should be rejected");
        }
    }
}
