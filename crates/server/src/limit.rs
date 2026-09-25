//! Token-bucket rate limiting per source IP plus a global bucket.

use std::collections::HashMap;
use std::net::IpAddr;

use skyblock_proto::Micros;
use skyblock_proto::timing::SECOND;

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Micros,
}

impl Bucket {
    fn full(burst: f64, now: Micros) -> Self {
        Self {
            tokens: burst,
            last: now,
        }
    }

    fn take(&mut self, now: Micros, rate: f64, burst: f64) -> bool {
        let elapsed = now.saturating_sub(self.last) as f64 / SECOND as f64;
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct RateLimiter {
    per_ip: HashMap<IpAddr, Bucket>,
    ip_rate: f64,
    ip_burst: f64,
    global: Option<(Bucket, f64, f64)>,
}

impl RateLimiter {
    pub fn per_ip(rate: f64, burst: f64) -> Self {
        Self {
            per_ip: HashMap::new(),
            ip_rate: rate,
            ip_burst: burst,
            global: None,
        }
    }

    pub fn with_global(mut self, rate: f64, burst: f64) -> Self {
        self.global = Some((Bucket::full(burst, 0), rate, burst));
        self
    }

    pub fn allow(&mut self, now: Micros, ip: IpAddr) -> bool {
        let (rate, burst) = (self.ip_rate, self.ip_burst);
        let b = self
            .per_ip
            .entry(ip)
            .or_insert_with(|| Bucket::full(burst, now));
        if !b.take(now, rate, burst) {
            return false;
        }
        match &mut self.global {
            Some((g, rate, burst)) => g.take(now, *rate, *burst),
            None => true,
        }
    }

    /// Forgets sources whose bucket has refilled completely.
    pub fn cleanup(&mut self, now: Micros) {
        let (rate, burst) = (self.ip_rate, self.ip_burst);
        let refill = (burst / rate * SECOND as f64) as Micros;
        self.per_ip
            .retain(|_, b| now.saturating_sub(b.last) < refill);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4));
    const B: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(5, 6, 7, 8));

    #[test]
    fn burst_then_rate() {
        let mut l = RateLimiter::per_ip(5.0, 10.0);
        let allowed = (0..20).filter(|_| l.allow(0, A)).count();
        assert_eq!(allowed, 10);
        assert!(!l.allow(0, A));
        assert!(l.allow(SECOND / 5, A));
        assert!(l.allow(0, B), "other sources are independent");
    }

    #[test]
    fn global_cap() {
        let mut l = RateLimiter::per_ip(100.0, 100.0).with_global(1.0, 3.0);
        assert!(l.allow(0, A));
        assert!(l.allow(0, B));
        assert!(l.allow(0, A));
        assert!(!l.allow(0, B));
    }

    #[test]
    fn cleanup_forgets_idle_sources() {
        let mut l = RateLimiter::per_ip(5.0, 10.0);
        l.allow(0, A);
        l.cleanup(SECOND);
        assert_eq!(l.per_ip.len(), 1);
        l.cleanup(10 * SECOND);
        assert!(l.per_ip.is_empty());
    }
}
