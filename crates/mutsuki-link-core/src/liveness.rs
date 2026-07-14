use crate::TransportKind;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LivenessState {
    #[default]
    Healthy,
    LatencyElevated,
    TemporarilyUnreachable,
    Dead,
    PeerClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionActivityProfile {
    Idle,
    Active,
    Mobile,
    Background,
    LocalIpc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeartbeatPolicy {
    pub idle_interval_ms: u64,
    pub active_interval_ms: u64,
    pub mobile_interval_ms: u64,
    pub background_interval_ms: u64,
    pub local_ipc_interval_ms: u64,
    pub unreachable_after_ms: u64,
    pub dead_after_ms: u64,
}

impl Default for HeartbeatPolicy {
    fn default() -> Self {
        Self {
            idle_interval_ms: 30_000,
            active_interval_ms: 10_000,
            mobile_interval_ms: 45_000,
            background_interval_ms: 120_000,
            local_ipc_interval_ms: 60_000,
            unreachable_after_ms: 90_000,
            dead_after_ms: 180_000,
        }
    }
}

impl HeartbeatPolicy {
    pub const fn is_valid(self) -> bool {
        self.idle_interval_ms > 0
            && self.active_interval_ms > 0
            && self.mobile_interval_ms > 0
            && self.background_interval_ms > 0
            && self.local_ipc_interval_ms > 0
            && self.dead_after_ms > self.unreachable_after_ms
            && self.unreachable_after_ms > 0
    }

    pub const fn interval(self, profile: ConnectionActivityProfile) -> u64 {
        match profile {
            ConnectionActivityProfile::Idle => self.idle_interval_ms,
            ConnectionActivityProfile::Active => self.active_interval_ms,
            ConnectionActivityProfile::Mobile => self.mobile_interval_ms,
            ConnectionActivityProfile::Background => self.background_interval_ms,
            ConnectionActivityProfile::LocalIpc => self.local_ipc_interval_ms,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeartbeatAction {
    None,
    SendProbe,
    /// A transport ACK/keepalive already demonstrated liveness, so Link stays quiet.
    SuppressedByTransport,
    StateChanged(LivenessState),
}

#[derive(Debug)]
pub struct HeartbeatController {
    policy: HeartbeatPolicy,
    last_liveness_unix_ms: u64,
    last_transport_ack_unix_ms: Option<u64>,
    next_probe_unix_ms: u64,
    state: LivenessState,
    paused: bool,
}

impl HeartbeatController {
    pub fn new(policy: HeartbeatPolicy, now_unix_ms: u64) -> Result<Self, &'static str> {
        if !policy.is_valid() {
            return Err("heartbeat intervals must be positive and ordered");
        }
        Ok(Self {
            policy,
            last_liveness_unix_ms: now_unix_ms,
            last_transport_ack_unix_ms: None,
            next_probe_unix_ms: now_unix_ms.saturating_add(policy.idle_interval_ms),
            state: LivenessState::Healthy,
            paused: false,
        })
    }

    pub fn pause(&mut self) {
        self.paused = true;
    }

    pub fn resume(&mut self, now_unix_ms: u64, profile: ConnectionActivityProfile) {
        self.paused = false;
        self.next_probe_unix_ms = now_unix_ms.saturating_add(self.policy.interval(profile));
    }

    pub fn observe_transport_ack(&mut self, now_unix_ms: u64) {
        self.last_transport_ack_unix_ms = Some(now_unix_ms);
        self.observe_liveness(now_unix_ms);
    }

    pub fn observe_probe_ack(&mut self, now_unix_ms: u64) {
        self.observe_liveness(now_unix_ms);
    }

    pub fn observe_latency(
        &mut self,
        now_unix_ms: u64,
        round_trip_millis: u32,
        elevated_at_millis: u32,
    ) -> HeartbeatAction {
        self.last_liveness_unix_ms = now_unix_ms;
        let next = if round_trip_millis >= elevated_at_millis {
            LivenessState::LatencyElevated
        } else {
            LivenessState::Healthy
        };
        if next == self.state {
            HeartbeatAction::None
        } else {
            self.state = next;
            HeartbeatAction::StateChanged(next)
        }
    }

    pub fn observe_peer_close(&mut self) -> HeartbeatAction {
        self.state = LivenessState::PeerClosed;
        HeartbeatAction::StateChanged(self.state)
    }

    pub fn tick(
        &mut self,
        now_unix_ms: u64,
        profile: ConnectionActivityProfile,
    ) -> HeartbeatAction {
        if self.paused || self.state == LivenessState::PeerClosed {
            return HeartbeatAction::None;
        }
        let silence = now_unix_ms.saturating_sub(self.last_liveness_unix_ms);
        let next_state = if silence >= self.policy.dead_after_ms {
            LivenessState::Dead
        } else if silence >= self.policy.unreachable_after_ms {
            LivenessState::TemporarilyUnreachable
        } else {
            LivenessState::Healthy
        };
        if next_state != self.state {
            self.state = next_state;
            return HeartbeatAction::StateChanged(next_state);
        }
        if now_unix_ms < self.next_probe_unix_ms {
            return HeartbeatAction::None;
        }
        let interval = self.policy.interval(profile);
        self.next_probe_unix_ms = now_unix_ms.saturating_add(interval);
        if self
            .last_transport_ack_unix_ms
            .is_some_and(|ack| now_unix_ms.saturating_sub(ack) <= interval)
        {
            HeartbeatAction::SuppressedByTransport
        } else {
            HeartbeatAction::SendProbe
        }
    }

    pub fn state(&self) -> LivenessState {
        self.state
    }

    fn observe_liveness(&mut self, now_unix_ms: u64) {
        self.last_liveness_unix_ms = now_unix_ms;
        self.state = LivenessState::Healthy;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConnectionQuality {
    pub round_trip_millis: Option<u32>,
    pub jitter_millis: Option<u32>,
    pub loss_per_million: Option<u32>,
    pub retransmit_per_million: Option<u32>,
    pub send_queue_pressure_per_million: u32,
    pub transmit_bytes_per_second: u64,
    pub receive_bytes_per_second: u64,
    pub consecutive_failures: u16,
    pub transport: Option<TransportKind>,
    pub liveness: LivenessState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualityObservation {
    pub round_trip_millis: Option<u32>,
    pub sent_packets: u32,
    pub lost_packets: u32,
    pub retransmitted_packets: u32,
    pub transmitted_bytes: u64,
    pub received_bytes: u64,
    pub elapsed_ms: u64,
    pub send_queue_depth: usize,
    pub send_queue_capacity: usize,
    pub consecutive_failures: u16,
    pub liveness: LivenessState,
}

#[derive(Debug)]
pub struct QualityAccumulator {
    transport: TransportKind,
    rtt_ewma: Option<u32>,
    jitter_ewma: Option<u32>,
    total_sent_packets: u64,
    total_lost_packets: u64,
    total_retransmitted_packets: u64,
}

impl QualityAccumulator {
    pub const fn new(transport: TransportKind) -> Self {
        Self {
            transport,
            rtt_ewma: None,
            jitter_ewma: None,
            total_sent_packets: 0,
            total_lost_packets: 0,
            total_retransmitted_packets: 0,
        }
    }

    pub fn observe(&mut self, sample: QualityObservation) -> ConnectionQuality {
        if let Some(rtt) = sample.round_trip_millis {
            let previous = self.rtt_ewma.unwrap_or(rtt);
            let deviation = previous.abs_diff(rtt);
            self.rtt_ewma = Some(ewma(previous, rtt));
            self.jitter_ewma = Some(ewma(self.jitter_ewma.unwrap_or(deviation), deviation));
        }
        self.total_sent_packets = self
            .total_sent_packets
            .saturating_add(u64::from(sample.sent_packets));
        self.total_lost_packets = self
            .total_lost_packets
            .saturating_add(u64::from(sample.lost_packets));
        self.total_retransmitted_packets = self
            .total_retransmitted_packets
            .saturating_add(u64::from(sample.retransmitted_packets));
        ConnectionQuality {
            round_trip_millis: self.rtt_ewma,
            jitter_millis: self.jitter_ewma,
            loss_per_million: ratio_per_million(self.total_lost_packets, self.total_sent_packets),
            retransmit_per_million: ratio_per_million(
                self.total_retransmitted_packets,
                self.total_sent_packets,
            ),
            send_queue_pressure_per_million: queue_pressure(
                sample.send_queue_depth,
                sample.send_queue_capacity,
            ),
            transmit_bytes_per_second: rate(sample.transmitted_bytes, sample.elapsed_ms),
            receive_bytes_per_second: rate(sample.received_bytes, sample.elapsed_ms),
            consecutive_failures: sample.consecutive_failures,
            transport: Some(self.transport),
            liveness: sample.liveness,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualityChangeThreshold {
    pub round_trip_millis: u32,
    pub jitter_millis: u32,
    pub loss_per_million: u32,
    pub retransmit_per_million: u32,
    pub queue_pressure_per_million: u32,
    pub throughput_bytes_per_second: u64,
}

impl Default for QualityChangeThreshold {
    fn default() -> Self {
        Self {
            round_trip_millis: 25,
            jitter_millis: 10,
            loss_per_million: 10_000,
            retransmit_per_million: 10_000,
            queue_pressure_per_million: 100_000,
            throughput_bytes_per_second: 64 * 1024,
        }
    }
}

#[derive(Debug)]
pub struct QualityChangeDetector {
    threshold: QualityChangeThreshold,
    last_emitted: Option<ConnectionQuality>,
}

impl QualityChangeDetector {
    pub const fn new(threshold: QualityChangeThreshold) -> Self {
        Self {
            threshold,
            last_emitted: None,
        }
    }

    pub fn consider(&mut self, value: ConnectionQuality) -> Option<ConnectionQuality> {
        let significant = self.last_emitted.is_none_or(|previous| {
            option_diff(previous.round_trip_millis, value.round_trip_millis)
                >= self.threshold.round_trip_millis
                || option_diff(previous.jitter_millis, value.jitter_millis)
                    >= self.threshold.jitter_millis
                || option_diff(previous.loss_per_million, value.loss_per_million)
                    >= self.threshold.loss_per_million
                || option_diff(
                    previous.retransmit_per_million,
                    value.retransmit_per_million,
                ) >= self.threshold.retransmit_per_million
                || previous
                    .send_queue_pressure_per_million
                    .abs_diff(value.send_queue_pressure_per_million)
                    >= self.threshold.queue_pressure_per_million
                || previous
                    .transmit_bytes_per_second
                    .abs_diff(value.transmit_bytes_per_second)
                    >= self.threshold.throughput_bytes_per_second
                || previous
                    .receive_bytes_per_second
                    .abs_diff(value.receive_bytes_per_second)
                    >= self.threshold.throughput_bytes_per_second
                || previous.liveness != value.liveness
                || previous.transport != value.transport
        });
        significant.then(|| {
            self.last_emitted = Some(value);
            value
        })
    }
}

const fn ewma(previous: u32, sample: u32) -> u32 {
    previous.saturating_mul(7).saturating_add(sample) / 8
}

fn ratio_per_million(numerator: u64, denominator: u64) -> Option<u32> {
    (denominator > 0).then(|| {
        u32::try_from(
            numerator
                .saturating_mul(1_000_000)
                .saturating_div(denominator)
                .min(u64::from(u32::MAX)),
        )
        .unwrap_or(u32::MAX)
    })
}

fn queue_pressure(depth: usize, capacity: usize) -> u32 {
    if capacity == 0 {
        return 0;
    }
    u32::try_from((depth.saturating_mul(1_000_000) / capacity).min(1_000_000)).unwrap_or(1_000_000)
}

fn rate(bytes: u64, elapsed_ms: u64) -> u64 {
    if elapsed_ms == 0 {
        return 0;
    }
    bytes.saturating_mul(1_000).saturating_div(elapsed_ms)
}

fn option_diff(left: Option<u32>, right: Option<u32>) -> u32 {
    match (left, right) {
        (Some(left), Some(right)) => left.abs_diff(right),
        (None, None) => 0,
        _ => u32::MAX,
    }
}
