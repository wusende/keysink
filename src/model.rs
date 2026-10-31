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
                "store 版本 {} 不受支持（当前支持 {}）",
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
                    return Err(Error::msg(format!("route `{name}` 的 route-only key 为空")));
                }
                None => {
                    return Err(Error::msg(format!(
                        "route `{name}` 缺少 key（用 route update --route-key 重新输入）"
                    )));
                }
            }
            if !vkeys.insert(route.vkey.clone()) {
                return Err(Error::msg(format!("route `{name}` 的 vkey 与其他路由重复")));
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
                "route `{name}` 的 vkey 格式非法（应为 ks_ + 43 字符 base64url）"
            )));
        }
        if !(self.base_url.starts_with("http://") || self.base_url.starts_with("https://")) {
            return Err(Error::msg(format!(
                "route `{name}` 的 base_url 必须以 http:// 或 https:// 开头"
            )));
        }
        if self.base_url.ends_with('/') {
            return Err(Error::msg(format!(
                "route `{name}` 的 base_url 不能以 / 结尾"
            )));
        }
        if self.base_url.contains('?') || self.base_url.contains('#') {
            return Err(Error::msg(format!(
                "route `{name}` 的 base_url 不能包含 query 或 fragment"
            )));
        }
        match &self.auth {
            Auth::Bearer | Auth::XApiKey | Auth::None => {}
            Auth::Header {
                name: header,
                prefix,
            } => {
                if header.is_empty() {
                    return Err(Error::msg(format!("route `{name}` 的 auth header 名为空")));
                }
                if !header
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                {
                    return Err(Error::msg(format!(
                        "route `{name}` 的 auth header 名包含非法字符"
                    )));
                }
                let _ = prefix;
            }
            Auth::Basic { username } => {
                if username.is_empty() {
                    return Err(Error::msg(format!("route `{name}` 的 basic 用户名为空")));
                }
            }
            Auth::Query { param } => {
                if param.is_empty() {
                    return Err(Error::msg(format!("route `{name}` 的 query 参数名为空")));
                }
                // &, =, or spaces would build a broken URL or inject extra parameters.
                if !param
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                {
                    return Err(Error::msg(format!(
                        "route `{name}` 的 query 参数名包含非法字符（只允许字母、数字、-、_、.）"
                    )));
                }
            }
        }
        for key in self.headers.keys() {
            if key.is_empty() {
                return Err(Error::msg(format!("route `{name}` 有空 header 名")));
            }
            if !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            {
                return Err(Error::msg(format!(
                    "route `{name}` 的 header `{key}` 名包含非法字符"
                )));
            }
            if is_forbidden_static_header(key) {
                return Err(Error::msg(format!(
                    "route `{name}` 不允许用静态 header 覆盖 `{key}`"
                )));
            }
        }
        if let Some(retries) = self.max_retries
            && retries > 10
        {
            return Err(Error::msg(format!(
                "route `{name}` 的 max_retries 不能超过 10"
            )));
        }
        if let Some(proxy) = &self.proxy
            && proxy != PROXY_DIRECT
            && !(proxy.starts_with("http://") || proxy.starts_with("https://"))
        {
            return Err(Error::msg(format!(
                "route `{name}` 的 proxy 只支持 http(s):// URL 或 `direct`（缺省跟随系统代理）"
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
                "未知的 sse-terminator `{other}`（可选 auto/openai/anthropic/none）"
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
        return Err(Error::msg(format!("{what} 名长度必须在 1..=64 之间")));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(Error::msg(format!(
            "{what} 名 `{name}` 只能包含字母、数字、-、_、."
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
            assert!(s.validate().is_err(), "param `{bad}` 应被拒绝");
        }
        let mut s = sample();
        s.routes.get_mut("r").unwrap().auth = Auth::Query {
            param: "api_key-x.1".into(),
        };
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
            assert!(s.validate().is_err(), "proxy `{bad}` 应被拒绝");
        }
    }
}
