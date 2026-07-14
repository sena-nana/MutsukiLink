use crate::{PairingError, PairingErrorKind};
use mutsuki_link_core::PeerId;
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingRateLimit {
    pub max_attempts: usize,
    pub max_failures: usize,
    pub max_peers: usize,
    pub window_ms: u64,
}

#[derive(Debug)]
pub struct PairingAttemptLimiter {
    limit: PairingRateLimit,
    attempts: BTreeMap<PeerId, VecDeque<u64>>,
    failures: BTreeMap<PeerId, VecDeque<u64>>,
}

impl PairingAttemptLimiter {
    pub fn new(limit: PairingRateLimit) -> Result<Self, PairingError> {
        if limit.max_attempts == 0
            || limit.max_failures == 0
            || limit.max_peers == 0
            || limit.window_ms == 0
        {
            return Err(rate_error("pairing rate limit must be positive"));
        }
        Ok(Self {
            limit,
            attempts: BTreeMap::new(),
            failures: BTreeMap::new(),
        })
    }

    pub fn begin(&mut self, peer_id: PeerId, now_unix_ms: u64) -> Result<(), PairingError> {
        admit(
            &mut self.attempts,
            peer_id,
            self.limit.max_attempts,
            self.limit.max_peers,
            self.limit.window_ms,
            now_unix_ms,
        )
    }

    pub fn record_failure(
        &mut self,
        peer_id: PeerId,
        now_unix_ms: u64,
    ) -> Result<(), PairingError> {
        admit(
            &mut self.failures,
            peer_id,
            self.limit.max_failures,
            self.limit.max_peers,
            self.limit.window_ms,
            now_unix_ms,
        )
    }
}

fn admit(
    peers: &mut BTreeMap<PeerId, VecDeque<u64>>,
    peer_id: PeerId,
    maximum: usize,
    max_peers: usize,
    window_ms: u64,
    now_unix_ms: u64,
) -> Result<(), PairingError> {
    peers.retain(|_, entries| {
        entries
            .back()
            .is_some_and(|entry| now_unix_ms.saturating_sub(*entry) < window_ms)
    });
    if !peers.contains_key(&peer_id) && peers.len() >= max_peers {
        return Err(rate_error("pairing peer limit was reached"));
    }
    let entries = peers.entry(peer_id).or_default();
    while entries
        .front()
        .is_some_and(|entry| now_unix_ms.saturating_sub(*entry) >= window_ms)
    {
        entries.pop_front();
    }
    if entries.len() >= maximum {
        return Err(rate_error("pairing request was rate limited"));
    }
    entries.push_back(now_unix_ms);
    Ok(())
}

fn rate_error(message: &'static str) -> PairingError {
    PairingError {
        kind: PairingErrorKind::RateLimited,
        public_message: message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempts_and_failures_are_independently_bounded() {
        let peer = PeerId::from_bytes([1; 32]);
        let mut limiter = PairingAttemptLimiter::new(PairingRateLimit {
            max_attempts: 1,
            max_failures: 1,
            max_peers: 1,
            window_ms: 100,
        })
        .unwrap();
        limiter.begin(peer, 0).unwrap();
        assert_eq!(
            limiter.begin(peer, 1).unwrap_err().kind,
            PairingErrorKind::RateLimited
        );
        limiter.record_failure(peer, 1).unwrap();
        assert_eq!(
            limiter.record_failure(peer, 2).unwrap_err().kind,
            PairingErrorKind::RateLimited
        );
        limiter.begin(peer, 100).unwrap();
    }

    #[test]
    fn unique_peer_storm_cannot_grow_rate_limiter_without_bound() {
        let mut limiter = PairingAttemptLimiter::new(PairingRateLimit {
            max_attempts: 2,
            max_failures: 2,
            max_peers: 2,
            window_ms: 100,
        })
        .unwrap();
        limiter.begin(PeerId::from_bytes([1; 32]), 0).unwrap();
        limiter.begin(PeerId::from_bytes([2; 32]), 0).unwrap();
        for value in 3..=u8::MAX {
            assert_eq!(
                limiter
                    .begin(PeerId::from_bytes([value; 32]), 1)
                    .unwrap_err()
                    .kind,
                PairingErrorKind::RateLimited
            );
        }
        limiter.begin(PeerId::from_bytes([3; 32]), 100).unwrap();
        assert!(limiter.attempts.len() <= 2);
        assert!(limiter.failures.len() <= 2);
    }
}
