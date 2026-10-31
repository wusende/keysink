use crate::model::Route;
use std::time::{Duration, SystemTime};

pub const DEFAULT_MAX_RETRIES: u8 = 2;
pub const DEFAULT_STATUSES: &[u16] = &[429, 503, 504];
pub const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_millis(500);
pub const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(8);
pub const DEFAULT_HEADER_TIMEOUT: Duration = Duration::from_secs(120);
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_retries: u8,
    pub statuses: Vec<u16>,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub header_timeout: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_MAX_RETRIES,
            statuses: DEFAULT_STATUSES.to_vec(),
            initial_backoff: DEFAULT_INITIAL_BACKOFF,
            max_backoff: DEFAULT_MAX_BACKOFF,
            header_timeout: DEFAULT_HEADER_TIMEOUT,
        }
    }
}

impl RetryPolicy {
    pub fn for_route(&self, route: &Route) -> Self {
        let mut policy = self.clone();
        if let Some(retries) = route.max_retries {
            policy.max_retries = retries.min(10);
        }
        if let Some(statuses) = &route.retry_on_status {
            policy.statuses = statuses.clone();
        }
        policy
    }

    pub fn is_retryable(&self, status: u16) -> bool {
        self.statuses.contains(&status)
    }

    /// Wait before retry number `attempt` (attempt starts at 0).
    /// Retry-After takes precedence, but wait at most 60s so an enormous value cannot hang the request.
    pub fn backoff(&self, attempt: u32, retry_after: Option<Duration>) -> Duration {
        if let Some(ra) = retry_after {
            return ra.min(MAX_RETRY_AFTER);
        }
        let exp = 1u128.checked_shl(attempt).unwrap_or(u128::MAX);
        let base_ns = self.initial_backoff.as_nanos().saturating_mul(exp);
        let capped = Duration::from_nanos(base_ns.min(self.max_backoff.as_nanos()) as u64);
        apply_jitter(capped, attempt, self.max_backoff)
    }
}

fn apply_jitter(base: Duration, attempt: u32, max: Duration) -> Duration {
    let factor = 80 + (jitter_seed(attempt) % 40); // 80..119 => ±20%
    let ns = (base.as_nanos() * factor as u128) / 100;
    Duration::from_nanos(ns.min(u64::MAX as u128) as u64).min(max)
}

fn jitter_seed(attempt: u32) -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    c.wrapping_mul(0x9E3779B97F4A7C15)
        .rotate_left(attempt & 63)
        .wrapping_add(nanos)
}

/// Parse Retry-After: integer seconds or an HTTP-date.
pub fn parse_retry_after(value: &str) -> Option<Duration> {
    let trimmed = value.trim();
    if let Ok(secs) = trimmed.parse::<u64>() {
        return (secs > 0).then(|| Duration::from_secs(secs));
    }
    if let Ok(dt) = httpdate::parse_http_date(trimmed)
        && let Ok(dur) = dt.duration_since(SystemTime::now())
    {
        return Some(dur);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_statuses() {
        let p = RetryPolicy::default();
        assert!(p.is_retryable(429));
        assert!(p.is_retryable(503));
        assert!(p.is_retryable(504));
        assert!(!p.is_retryable(500));
        assert!(!p.is_retryable(502));
        assert!(!p.is_retryable(200));
    }

    #[test]
    fn backoff_respects_retry_after_and_cap() {
        let p = RetryPolicy::default();
        assert_eq!(
            p.backoff(0, Some(Duration::from_secs(2))),
            Duration::from_secs(2)
        );
        assert_eq!(
            p.backoff(0, Some(Duration::from_secs(600))),
            MAX_RETRY_AFTER
        );
    }

    #[test]
    fn backoff_grows_and_clamps() {
        let p = RetryPolicy::default();
        let d0 = p.backoff(0, None);
        assert!(d0 >= Duration::from_millis(400) && d0 <= Duration::from_millis(600));
        let d10 = p.backoff(10, None);
        assert!(d10 <= p.max_backoff);
    }

    #[test]
    fn parses_retry_after() {
        assert_eq!(parse_retry_after("5"), Some(Duration::from_secs(5)));
        assert_eq!(parse_retry_after("0"), None);
        assert_eq!(parse_retry_after("garbage"), None);
    }
}
