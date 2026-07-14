//! Discovery produces untrusted endpoint candidates. It never creates a
//! `PeerId`, writes a trust record, or opens an application channel.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value
)]

use mutsuki_link_core::{EndpointAddress, SecurityLevel};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DiscoveryId([u8; 16]);

impl DiscoveryId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredEndpoint {
    pub address: EndpointAddress,
    pub priority: u16,
    pub advertised_security: SecurityLevel,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredPeer {
    /// Ephemeral candidate id; deliberately not a trusted `PeerId`.
    pub discovery_id: DiscoveryId,
    pub service_type: String,
    pub endpoints: Vec<DiscoveredEndpoint>,
    pub expires_at: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryEvent {
    Found(DiscoveredPeer),
    Expired(DiscoveryId),
    Stopped,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryRequest {
    pub service_type: String,
    pub max_results_per_poll: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryErrorKind {
    InvalidInput,
    RateLimited,
    AlreadyRunning,
    NotRunning,
    ProviderFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryError {
    pub kind: DiscoveryErrorKind,
    pub public_message: &'static str,
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.public_message)
    }
}

impl std::error::Error for DiscoveryError {}

pub trait DiscoveryProvider {
    fn start(&mut self, request: DiscoveryRequest, now: Instant) -> Result<(), DiscoveryError>;
    fn poll(&mut self, now: Instant) -> Result<Vec<DiscoveryEvent>, DiscoveryError>;
    fn stop(&mut self) -> Result<(), DiscoveryError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimit {
    pub attempts: usize,
    pub window: Duration,
    pub max_sources: usize,
    pub max_candidates: usize,
}

#[derive(Debug)]
pub struct AttemptRateLimiter {
    limit: RateLimit,
    attempts: BTreeMap<String, VecDeque<Instant>>,
}

impl AttemptRateLimiter {
    pub fn new(limit: RateLimit) -> Result<Self, DiscoveryError> {
        if limit.attempts == 0
            || limit.window.is_zero()
            || limit.max_sources == 0
            || limit.max_candidates == 0
        {
            return Err(error(
                DiscoveryErrorKind::InvalidInput,
                "rate limit must be positive",
            ));
        }
        Ok(Self {
            limit,
            attempts: BTreeMap::new(),
        })
    }

    pub fn allow(&mut self, source: &str, now: Instant) -> bool {
        self.attempts.retain(|_, attempts| {
            attempts
                .back()
                .is_some_and(|attempt| now.saturating_duration_since(*attempt) < self.limit.window)
        });
        if !self.attempts.contains_key(source) && self.attempts.len() >= self.limit.max_sources {
            return false;
        }
        let attempts = self.attempts.entry(source.to_owned()).or_default();
        while attempts
            .front()
            .is_some_and(|attempt| now.saturating_duration_since(*attempt) >= self.limit.window)
        {
            attempts.pop_front();
        }
        if attempts.len() >= self.limit.attempts {
            return false;
        }
        attempts.push_back(now);
        true
    }
}

#[derive(Debug)]
pub struct ManualDiscovery {
    request: Option<DiscoveryRequest>,
    pending: VecDeque<DiscoveryEvent>,
    active: BTreeMap<DiscoveryId, Instant>,
    limiter: AttemptRateLimiter,
}

impl ManualDiscovery {
    pub fn new(limit: RateLimit) -> Result<Self, DiscoveryError> {
        Ok(Self {
            request: None,
            pending: VecDeque::new(),
            active: BTreeMap::new(),
            limiter: AttemptRateLimiter::new(limit)?,
        })
    }

    pub fn add_address(
        &mut self,
        source: &str,
        discovery_id: DiscoveryId,
        endpoint: DiscoveredEndpoint,
        ttl: Duration,
        now: Instant,
    ) -> Result<(), DiscoveryError> {
        let request = self.request.as_ref().ok_or_else(|| {
            error(
                DiscoveryErrorKind::NotRunning,
                "manual discovery is not running",
            )
        })?;
        let at_capacity = !self.active.contains_key(&discovery_id)
            && self.active.len() >= self.limiter.limit.max_candidates;
        if ttl.is_zero() || at_capacity || !self.limiter.allow(source, now) {
            return Err(error(
                if ttl.is_zero() {
                    DiscoveryErrorKind::InvalidInput
                } else {
                    DiscoveryErrorKind::RateLimited
                },
                "manual discovery candidate was rejected",
            ));
        }
        let expires_at = now + ttl;
        self.pending.retain(
            |event| !matches!(event, DiscoveryEvent::Found(peer) if peer.discovery_id == discovery_id),
        );
        self.active.insert(discovery_id, expires_at);
        self.pending
            .push_back(DiscoveryEvent::Found(DiscoveredPeer {
                discovery_id,
                service_type: request.service_type.clone(),
                endpoints: vec![endpoint],
                expires_at,
            }));
        Ok(())
    }
}

impl DiscoveryProvider for ManualDiscovery {
    fn start(&mut self, request: DiscoveryRequest, _now: Instant) -> Result<(), DiscoveryError> {
        if self.request.is_some() {
            return Err(error(
                DiscoveryErrorKind::AlreadyRunning,
                "manual discovery is already running",
            ));
        }
        validate_request(&request)?;
        self.request = Some(request);
        Ok(())
    }

    fn poll(&mut self, now: Instant) -> Result<Vec<DiscoveryEvent>, DiscoveryError> {
        let request = self.request.as_ref().ok_or_else(|| {
            error(
                DiscoveryErrorKind::NotRunning,
                "manual discovery is not running",
            )
        })?;
        let mut events = Vec::new();
        let expired = self
            .active
            .iter()
            .filter_map(|(id, expires_at)| (*expires_at <= now).then_some(*id))
            .take(request.max_results_per_poll)
            .collect::<Vec<_>>();
        for id in expired {
            self.active.remove(&id);
            self.pending.retain(
                |event| !matches!(event, DiscoveryEvent::Found(peer) if peer.discovery_id == id),
            );
            events.push(DiscoveryEvent::Expired(id));
        }
        while events.len() < request.max_results_per_poll {
            let Some(event) = self.pending.pop_front() else {
                break;
            };
            match event {
                DiscoveryEvent::Found(peer) if peer.expires_at <= now => {
                    self.active.remove(&peer.discovery_id);
                    events.push(DiscoveryEvent::Expired(peer.discovery_id));
                }
                event => events.push(event),
            }
        }
        Ok(events)
    }

    fn stop(&mut self) -> Result<(), DiscoveryError> {
        if self.request.take().is_none() {
            return Err(error(
                DiscoveryErrorKind::NotRunning,
                "manual discovery is not running",
            ));
        }
        self.pending.clear();
        self.active.clear();
        Ok(())
    }
}

fn validate_request(request: &DiscoveryRequest) -> Result<(), DiscoveryError> {
    if request.service_type.is_empty() || request.max_results_per_poll == 0 {
        return Err(error(
            DiscoveryErrorKind::InvalidInput,
            "discovery request is invalid",
        ));
    }
    Ok(())
}

fn error(kind: DiscoveryErrorKind, public_message: &'static str) -> DiscoveryError {
    DiscoveryError {
        kind,
        public_message,
    }
}

#[cfg(feature = "mdns")]
#[allow(clippy::wildcard_imports)]
pub mod mdns {
    use super::*;
    use mdns_sd::{Receiver, ServiceDaemon, ServiceEvent, ServiceInfo};

    pub struct MdnsDiscovery {
        daemon: ServiceDaemon,
        receiver: Option<Receiver<ServiceEvent>>,
        request: Option<DiscoveryRequest>,
        ttl: Duration,
        limiter: AttemptRateLimiter,
        resolved: BTreeMap<String, DiscoveryId>,
    }

    impl MdnsDiscovery {
        /// Explicit construction starts the provider daemon. Merely enabling
        /// the feature does not start a thread, browse, or advertisement.
        pub fn new(ttl: Duration, limit: RateLimit) -> Result<Self, DiscoveryError> {
            if ttl.is_zero() {
                return Err(error(
                    DiscoveryErrorKind::InvalidInput,
                    "mDNS TTL must be positive",
                ));
            }
            Ok(Self {
                daemon: ServiceDaemon::new().map_err(provider_error)?,
                receiver: None,
                request: None,
                ttl,
                limiter: AttemptRateLimiter::new(limit)?,
                resolved: BTreeMap::new(),
            })
        }

        /// Advertises only protocol version and transport class. The API has
        /// no user, project, task, role, or free-form sensitive TXT fields.
        pub fn advertise(
            &self,
            service_type: &str,
            instance_token: &str,
            host_token: &str,
            port: u16,
            protocol_major: u16,
            transport: &str,
        ) -> Result<String, DiscoveryError> {
            let version = protocol_major.to_string();
            let properties = [("v", version.as_str()), ("t", transport)];
            let service = ServiceInfo::new(
                service_type,
                instance_token,
                host_token,
                "",
                port,
                &properties[..],
            )
            .map_err(provider_error)?
            .enable_addr_auto();
            let fullname = service.get_fullname().to_owned();
            self.daemon.register(service).map_err(provider_error)?;
            Ok(fullname)
        }

        pub fn unregister(&self, fullname: &str) -> Result<(), DiscoveryError> {
            self.daemon.unregister(fullname).map_err(provider_error)?;
            Ok(())
        }
    }

    impl DiscoveryProvider for MdnsDiscovery {
        fn start(&mut self, request: DiscoveryRequest, now: Instant) -> Result<(), DiscoveryError> {
            if self.request.is_some() {
                return Err(error(
                    DiscoveryErrorKind::AlreadyRunning,
                    "mDNS discovery is already running",
                ));
            }
            validate_request(&request)?;
            if !self.limiter.allow(&request.service_type, now) {
                return Err(error(
                    DiscoveryErrorKind::RateLimited,
                    "mDNS discovery request was rate limited",
                ));
            }
            let receiver = self
                .daemon
                .browse(&request.service_type)
                .map_err(provider_error)?;
            self.receiver = Some(receiver);
            self.request = Some(request);
            Ok(())
        }

        fn poll(&mut self, now: Instant) -> Result<Vec<DiscoveryEvent>, DiscoveryError> {
            let request = self.request.as_ref().ok_or_else(|| {
                error(
                    DiscoveryErrorKind::NotRunning,
                    "mDNS discovery is not running",
                )
            })?;
            let receiver = self.receiver.as_ref().expect("receiver set with request");
            let mut events = Vec::new();
            while events.len() < request.max_results_per_poll {
                let Ok(event) = receiver.try_recv() else {
                    break;
                };
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        let id = id_from_name(&info.fullname);
                        self.resolved.insert(info.fullname.clone(), id);
                        let transport = info.get_property_val_str("t").unwrap_or("tcp");
                        let endpoints = info
                            .addresses
                            .iter()
                            .map(|address| DiscoveredEndpoint {
                                address: EndpointAddress {
                                    scheme: transport.to_owned(),
                                    address: format!("{address}:{}", info.port),
                                },
                                priority: 100,
                                advertised_security: if transport == "quic" {
                                    SecurityLevel::AuthenticatedEncrypted
                                } else {
                                    SecurityLevel::Plaintext
                                },
                            })
                            .collect();
                        events.push(DiscoveryEvent::Found(DiscoveredPeer {
                            discovery_id: id,
                            service_type: info.ty_domain.clone(),
                            endpoints,
                            expires_at: now + self.ttl,
                        }));
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        if let Some(id) = self.resolved.remove(&fullname) {
                            events.push(DiscoveryEvent::Expired(id));
                        }
                    }
                    ServiceEvent::SearchStopped(_) => events.push(DiscoveryEvent::Stopped),
                    _ => {}
                }
            }
            Ok(events)
        }

        fn stop(&mut self) -> Result<(), DiscoveryError> {
            let request = self.request.take().ok_or_else(|| {
                error(
                    DiscoveryErrorKind::NotRunning,
                    "mDNS discovery is not running",
                )
            })?;
            self.daemon
                .stop_browse(&request.service_type)
                .map_err(provider_error)?;
            self.receiver = None;
            self.resolved.clear();
            Ok(())
        }
    }

    impl Drop for MdnsDiscovery {
        fn drop(&mut self) {
            if let Some(request) = self.request.take() {
                let _ = self.daemon.stop_browse(&request.service_type);
            }
            let _ = self.daemon.shutdown();
        }
    }

    fn id_from_name(name: &str) -> DiscoveryId {
        let mut left = 0xcbf2_9ce4_8422_2325_u64;
        let mut right = 0x8422_2325_cbf2_9ce4_u64;
        for byte in name.bytes() {
            left = (left ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3);
            right = (right ^ u64::from(byte.rotate_left(1))).wrapping_mul(0x100_0000_01b3);
        }
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&left.to_be_bytes());
        bytes[8..].copy_from_slice(&right.to_be_bytes());
        DiscoveryId::from_bytes(bytes)
    }

    fn provider_error<T>(_error: T) -> DiscoveryError {
        error(
            DiscoveryErrorKind::ProviderFailure,
            "mDNS provider operation failed",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_address_is_untrusted_bounded_candidate() {
        let now = Instant::now();
        let mut provider = ManualDiscovery::new(RateLimit {
            attempts: 1,
            window: Duration::from_secs(60),
            max_sources: 2,
            max_candidates: 2,
        })
        .unwrap();
        provider
            .start(
                DiscoveryRequest {
                    service_type: "_mutsuki-link._tcp.local.".to_owned(),
                    max_results_per_poll: 4,
                },
                now,
            )
            .unwrap();
        let endpoint = DiscoveredEndpoint {
            address: EndpointAddress {
                scheme: "tcp".to_owned(),
                address: "127.0.0.1:9000".to_owned(),
            },
            priority: 0,
            advertised_security: SecurityLevel::Plaintext,
        };
        provider
            .add_address(
                "local-user",
                DiscoveryId::from_bytes([1; 16]),
                endpoint.clone(),
                Duration::from_secs(30),
                now,
            )
            .unwrap();
        assert_eq!(
            provider
                .add_address(
                    "local-user",
                    DiscoveryId::from_bytes([2; 16]),
                    endpoint,
                    Duration::from_secs(30),
                    now,
                )
                .unwrap_err()
                .kind,
            DiscoveryErrorKind::RateLimited
        );
        let events = provider.poll(now).unwrap();
        assert!(
            matches!(&events[0], DiscoveryEvent::Found(peer) if peer.discovery_id == DiscoveryId::from_bytes([1; 16]))
        );
        assert_eq!(
            provider.poll(now + Duration::from_secs(31)).unwrap(),
            vec![DiscoveryEvent::Expired(DiscoveryId::from_bytes([1; 16]))]
        );
    }

    #[test]
    fn discovery_storm_is_bounded_by_source_candidate_and_pending_limits() {
        let now = Instant::now();
        let mut limiter = AttemptRateLimiter::new(RateLimit {
            attempts: 1,
            window: Duration::from_millis(1),
            max_sources: 2,
            max_candidates: 1,
        })
        .unwrap();
        assert!(limiter.allow("one", now));
        assert!(limiter.allow("two", now));
        for index in 0..10_000 {
            assert!(!limiter.allow(&format!("attacker-{index}"), now));
        }
        assert!(limiter.allow("after-expiry", now + Duration::from_millis(1)));

        let mut provider = ManualDiscovery::new(RateLimit {
            attempts: 1,
            window: Duration::from_millis(1),
            max_sources: 1,
            max_candidates: 1,
        })
        .unwrap();
        provider
            .start(
                DiscoveryRequest {
                    service_type: "_bounded._tcp.local.".to_owned(),
                    max_results_per_poll: 1,
                },
                now,
            )
            .unwrap();
        let endpoint = DiscoveredEndpoint {
            address: EndpointAddress {
                scheme: "tcp".to_owned(),
                address: "127.0.0.1:1".to_owned(),
            },
            priority: 0,
            advertised_security: SecurityLevel::Plaintext,
        };
        for index in 0..1_000 {
            provider
                .add_address(
                    "same-source",
                    DiscoveryId::from_bytes([1; 16]),
                    endpoint.clone(),
                    Duration::from_secs(60),
                    now + Duration::from_millis(index),
                )
                .unwrap();
            assert_eq!(provider.active.len(), 1);
            assert_eq!(provider.pending.len(), 1);
        }
        assert_eq!(
            provider
                .add_address(
                    "same-source",
                    DiscoveryId::from_bytes([2; 16]),
                    endpoint,
                    Duration::from_secs(60),
                    now + Duration::from_secs(2),
                )
                .unwrap_err()
                .kind,
            DiscoveryErrorKind::RateLimited
        );
    }
}
