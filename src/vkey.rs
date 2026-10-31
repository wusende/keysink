use crate::error::{Error, Result};
use crate::model::{Route, Store};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

pub const PREFIX: &str = "ks_";
const TOKEN_BYTES: usize = 32;

/// Generates a random 32-byte virtual key: `ks_` + base64url(no pad), 46 chars in total.
pub fn generate() -> String {
    let bytes = crate::util::random_bytes::<TOKEN_BYTES>();
    format!(
        "{PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

pub fn is_well_formed(token: &str) -> bool {
    token.starts_with(PREFIX) && token.len() == PREFIX.len() + 43
}

pub fn hash(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Short fingerprint used in audit; not reversible to the original token.
pub fn fingerprint(hash: &[u8; 32]) -> String {
    crate::util::hex(&hash[..4])
}

/// Slices by "characters" rather than bytes: if a vkey in the store is hand-edited into a
/// malformed value containing multibyte characters, a byte slice could land mid-character
/// and panic (route ls/show must not crash).
pub fn mask(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() <= 12 {
        return "ks_***".to_string();
    }
    let head: String = chars[..7].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

pub struct ResolvedRoute {
    pub name: String,
    pub route: Route,
}

/// Built at startup: vkey hash → route. Hash lookups keep plaintext tokens out of the resident index.
pub struct RouteTable {
    map: HashMap<[u8; 32], Arc<ResolvedRoute>>,
}

impl RouteTable {
    pub fn build(store: &Store) -> Result<Self> {
        let mut map = HashMap::with_capacity(store.routes.len());
        for (name, route) in &store.routes {
            if !is_well_formed(&route.vkey) {
                return Err(Error::msg(format!(
                    "route `{name}` 的 vkey 格式非法（应为 ks_ + 43 字符 base64url）"
                )));
            }
            let h = hash(&route.vkey);
            let resolved = Arc::new(ResolvedRoute {
                name: name.clone(),
                route: route.clone(),
            });
            if map.insert(h, resolved).is_some() {
                return Err(Error::msg(format!("route `{name}` 的 vkey 与其他路由重复")));
            }
        }
        Ok(Self { map })
    }

    #[allow(dead_code)]
    pub fn lookup(&self, token: &str) -> Option<Arc<ResolvedRoute>> {
        self.lookup_hash(&hash(token))
    }

    pub fn lookup_hash(&self, hash: &[u8; 32]) -> Option<Arc<ResolvedRoute>> {
        self.map.get(hash).cloned()
    }

    #[allow(clippy::len_without_is_empty)] // is_empty has no caller; dead code for a lint isn't worth it
    pub fn len(&self) -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Auth, Route, Store};
    use std::collections::BTreeMap;

    #[test]
    fn token_shape() {
        let t = generate();
        assert!(t.starts_with(PREFIX));
        assert_eq!(t.len(), 46);
        assert!(is_well_formed(&t));
        assert!(!is_well_formed("ks_short"));
    }

    #[test]
    fn hash_is_stable_and_distinct() {
        let a = generate();
        let b = generate();
        assert_eq!(hash(&a), hash(&a));
        assert_ne!(hash(&a), hash(&b));
        assert_eq!(fingerprint(&hash(&a)).len(), 8);
    }

    #[test]
    fn mask_hides_middle() {
        let t = "ks_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
        let m = mask(t);
        assert!(m.starts_with("ks_abcd"));
        assert!(m.contains('…'));
        assert_eq!(m.len(), 7 + '…'.len_utf8() + 4);
    }

    #[test]
    fn mask_is_safe_on_multibyte() {
        // A malformed vkey (multibyte char landing on the old byte-slice boundary) must not panic.
        let m = mask("ks_中文字符测试数据abcdefgh");
        assert!(m.contains('…'));
        assert!(mask("ks_短").is_ascii());
    }

    #[test]
    fn table_lookup() {
        let mut store = Store::new();
        let token = generate();
        store.routes.insert(
            "r".into(),
            Route::new(
                token.clone(),
                "https://example.com".into(),
                "v".into(),
                Auth::Bearer,
                BTreeMap::new(),
            ),
        );
        let table = RouteTable::build(&store).unwrap();
        assert!(table.lookup(&token).is_some());
        assert!(table.lookup(&generate()).is_none());
    }
}
