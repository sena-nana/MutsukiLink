use crate::{
    LimitKind, LinkError, ProtocolChannelId, ProtocolStableId, ProtocolVersion, SessionId,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const CONTROL_CHANNEL_ID: ChannelId = ChannelId(0);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChannelId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChannelGeneration(pub u32);

impl ChannelGeneration {
    pub const INITIAL: Self = Self(1);
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChannelKey {
    pub protocol_id: ProtocolStableId,
    pub version: ProtocolVersion,
    pub protocol_channel_id: ProtocolChannelId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelMode {
    RequestResponse,
    Event,
    Stream,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelConfig {
    pub key: ChannelKey,
    pub id: ChannelId,
    pub generation: ChannelGeneration,
    pub mode: ChannelMode,
    /// Scheduling hint for data channels. Values are mapped to eight bounded
    /// weighted-fair bands: `0` is the lowest weight and `255` the highest.
    /// Control traffic remains on its independently reserved queue.
    pub priority_hint: u8,
    pub capacity: usize,
    pub max_frame_bytes: usize,
    pub max_stream_bytes: Option<u64>,
    pub discardable: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EnvelopeFlags {
    pub end_of_stream: bool,
    pub cancelled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    pub session_id: SessionId,
    pub channel_id: ChannelId,
    pub generation: ChannelGeneration,
    pub sequence: u64,
    pub nesting_depth: u16,
    pub flags: EnvelopeFlags,
    /// Opaque payload; the negotiated protocol owner chooses its serializer.
    pub payload: Vec<u8>,
}

pub type DataEnvelope = Envelope;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundFrame {
    Control(Vec<u8>),
    Data(Envelope),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueAdmission {
    Enqueued,
    DroppedDiscardable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultiplexerLimits {
    pub max_frame_bytes: usize,
    pub max_nesting_depth: u16,
    pub max_channels: usize,
    pub control_queue_capacity: usize,
    pub max_total_pending_frames: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultiplexerStorageSnapshot {
    pub channel_count: usize,
    pub pending_frames: usize,
    pub control_queue_slots: usize,
    pub ready_queue_slots: usize,
    pub data_queue_slots: usize,
}

impl Default for MultiplexerLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 1024 * 1024,
            max_nesting_depth: 32,
            max_channels: 64,
            control_queue_capacity: 32,
            max_total_pending_frames: 512,
        }
    }
}

#[derive(Debug)]
struct ChannelState {
    config: ChannelConfig,
    queue: VecDeque<Envelope>,
    cancelled: bool,
    stream_bytes: u64,
    virtual_finish: u128,
}

#[derive(Debug)]
pub struct Multiplexer {
    session_id: SessionId,
    limits: MultiplexerLimits,
    channels: BTreeMap<ChannelId, ChannelState>,
    keys: BTreeMap<ChannelKey, Vec<ChannelId>>,
    retired_channels: BTreeSet<ChannelId>,
    control: VecDeque<Vec<u8>>,
    ready: VecDeque<ChannelId>,
    virtual_time: u128,
    total_pending: usize,
    allowed_protocols: Option<BTreeSet<(ProtocolStableId, ProtocolVersion)>>,
}

impl Multiplexer {
    pub fn new(session_id: SessionId, limits: MultiplexerLimits) -> Result<Self, LinkError> {
        if limits.max_frame_bytes == 0
            || limits.max_channels == 0
            || limits.control_queue_capacity == 0
            || limits.max_total_pending_frames == 0
        {
            return Err(LinkError::InvalidInput(
                "multiplexer limits must be positive",
            ));
        }
        Ok(Self {
            session_id,
            limits,
            channels: BTreeMap::new(),
            keys: BTreeMap::new(),
            retired_channels: BTreeSet::new(),
            control: VecDeque::new(),
            ready: VecDeque::new(),
            virtual_time: 0,
            total_pending: 0,
            allowed_protocols: None,
        })
    }

    pub fn restricted(
        session_id: SessionId,
        limits: MultiplexerLimits,
        protocols: impl IntoIterator<Item = (ProtocolStableId, ProtocolVersion)>,
    ) -> Result<Self, LinkError> {
        let mut multiplexer = Self::new(session_id, limits)?;
        multiplexer.allowed_protocols = Some(protocols.into_iter().collect());
        Ok(multiplexer)
    }

    pub fn open_channel(&mut self, config: ChannelConfig) -> Result<(), LinkError> {
        if config.id == CONTROL_CHANNEL_ID {
            return Err(LinkError::InvalidInput(
                "channel zero is reserved for control",
            ));
        }
        if config.generation.0 == 0 || config.capacity == 0 || config.max_frame_bytes == 0 {
            return Err(LinkError::InvalidInput(
                "channel generation and limits must be positive",
            ));
        }
        if config.discardable && config.mode != ChannelMode::Event {
            return Err(LinkError::InvalidInput(
                "only event channels may be discardable",
            ));
        }
        if (config.mode == ChannelMode::Stream) != config.max_stream_bytes.is_some() {
            return Err(LinkError::InvalidInput(
                "stream byte limits must match channel mode",
            ));
        }
        if self
            .allowed_protocols
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&(config.key.protocol_id, config.key.version)))
        {
            return Err(LinkError::NamespaceConflict);
        }
        if self
            .channels
            .len()
            .saturating_add(self.retired_channels.len())
            >= self.limits.max_channels
        {
            return Err(LinkError::LimitExceeded {
                kind: LimitKind::Channels,
                limit: self.limits.max_channels,
            });
        }
        if self.retired_channels.contains(&config.id) {
            return Err(LinkError::ClosedChannel(config.id.0));
        }
        if self.channels.contains_key(&config.id) {
            return Err(LinkError::NamespaceConflict);
        }
        self.keys.entry(config.key).or_default().push(config.id);
        self.channels.insert(
            config.id,
            ChannelState {
                config,
                queue: VecDeque::new(),
                cancelled: false,
                stream_bytes: 0,
                virtual_finish: self.virtual_time,
            },
        );
        Ok(())
    }

    pub fn enqueue_control(&mut self, payload: Vec<u8>) -> Result<(), LinkError> {
        self.validate_payload(&payload, 0)?;
        if self.control.len() >= self.limits.control_queue_capacity {
            return Err(LinkError::Backpressure {
                channel: CONTROL_CHANNEL_ID.0,
                capacity: self.limits.control_queue_capacity,
            });
        }
        // The control queue has its own bound and reserved capacity. Saturated
        // data channels therefore cannot prevent close, drain, or heartbeat.
        self.control.push_back(payload);
        self.total_pending += 1;
        Ok(())
    }

    pub fn enqueue(&mut self, envelope: Envelope) -> Result<(), LinkError> {
        self.validate_envelope_identity(&envelope)?;
        if self.total_pending >= self.limits.max_total_pending_frames {
            return Err(LinkError::LimitExceeded {
                kind: LimitKind::PendingFrames,
                limit: self.limits.max_total_pending_frames,
            });
        }
        let channel_id = envelope.channel_id;
        let state = self
            .channels
            .get_mut(&channel_id)
            .ok_or(LinkError::UnknownChannel(channel_id.0))?;
        if state.config.generation != envelope.generation {
            return Err(LinkError::ChannelGenerationMismatch {
                channel: channel_id.0,
            });
        }
        if envelope.payload.len() > state.config.max_frame_bytes {
            return Err(LinkError::LimitExceeded {
                kind: LimitKind::FrameBytes,
                limit: state.config.max_frame_bytes,
            });
        }
        if state.cancelled {
            return Err(LinkError::ChannelCancelled(channel_id.0));
        }
        if state.queue.len() >= state.config.capacity {
            return Err(LinkError::Backpressure {
                channel: channel_id.0,
                capacity: state.config.capacity,
            });
        }
        if let Some(max_stream_bytes) = state.config.max_stream_bytes {
            let frame_bytes =
                u64::try_from(envelope.payload.len()).map_err(|_| LinkError::LimitExceeded {
                    kind: LimitKind::StreamBytes,
                    limit: usize::MAX,
                })?;
            let next_stream_bytes = state.stream_bytes.saturating_add(frame_bytes);
            if next_stream_bytes > max_stream_bytes {
                return Err(LinkError::LimitExceeded {
                    kind: LimitKind::StreamBytes,
                    limit: usize::try_from(max_stream_bytes).unwrap_or(usize::MAX),
                });
            }
            state.stream_bytes = next_stream_bytes;
        }
        if state.queue.is_empty() {
            state.virtual_finish = state.virtual_finish.max(self.virtual_time);
            self.ready.push_back(channel_id);
        }
        state.queue.push_back(envelope);
        self.total_pending += 1;
        Ok(())
    }

    /// Enqueues a discardable event/telemetry frame. Under queue pressure it is
    /// dropped instead of blocking control or reliable application traffic.
    pub fn enqueue_discardable(&mut self, envelope: Envelope) -> Result<QueueAdmission, LinkError> {
        self.validate_envelope_identity(&envelope)?;
        let channel_id = envelope.channel_id;
        let state = self
            .channels
            .get_mut(&channel_id)
            .ok_or(LinkError::UnknownChannel(channel_id.0))?;
        if state.config.generation != envelope.generation {
            return Err(LinkError::ChannelGenerationMismatch {
                channel: channel_id.0,
            });
        }
        if envelope.payload.len() > state.config.max_frame_bytes {
            return Err(LinkError::LimitExceeded {
                kind: LimitKind::FrameBytes,
                limit: state.config.max_frame_bytes,
            });
        }
        if state.config.mode != ChannelMode::Event || !state.config.discardable {
            return Err(LinkError::InvalidInput(
                "only event channels may discard frames under pressure",
            ));
        }
        if state.cancelled {
            return Err(LinkError::ChannelCancelled(channel_id.0));
        }
        if self.total_pending >= self.limits.max_total_pending_frames
            || state.queue.len() >= state.config.capacity
        {
            return Ok(QueueAdmission::DroppedDiscardable);
        }
        if state.queue.is_empty() {
            state.virtual_finish = state.virtual_finish.max(self.virtual_time);
            self.ready.push_back(channel_id);
        }
        state.queue.push_back(envelope);
        self.total_pending += 1;
        Ok(QueueAdmission::Enqueued)
    }

    pub fn next_outbound(&mut self) -> Option<OutboundFrame> {
        if let Some(control) = self.control.pop_front() {
            self.total_pending -= 1;
            return Some(OutboundFrame::Control(control));
        }
        loop {
            let selected = self
                .ready
                .iter()
                .enumerate()
                .filter_map(|(index, channel_id)| {
                    let state = self.channels.get(channel_id)?;
                    state.queue.front().map(|_| (index, state.virtual_finish))
                })
                .min_by_key(|(index, virtual_finish)| (*virtual_finish, *index));
            let Some((index, _)) = selected else {
                self.ready.clear();
                return None;
            };
            let Some(channel_id) = self.ready.remove(index) else {
                continue;
            };
            let Some(state) = self.channels.get_mut(&channel_id) else {
                continue;
            };
            let Some(envelope) = state.queue.pop_front() else {
                continue;
            };
            let start = state.virtual_finish.max(self.virtual_time);
            self.virtual_time = start;
            state.virtual_finish = start.saturating_add(scheduling_cost(
                envelope.payload.len(),
                state.config.priority_hint,
            ));
            if !state.queue.is_empty() {
                self.ready.push_back(channel_id);
            }
            self.total_pending -= 1;
            return Some(OutboundFrame::Data(envelope));
        }
    }

    pub fn cancel_channel(&mut self, id: ChannelId) -> Result<usize, LinkError> {
        let state = self
            .channels
            .get_mut(&id)
            .ok_or(LinkError::UnknownChannel(id.0))?;
        state.cancelled = true;
        let discarded = state.queue.len();
        state.queue.clear();
        self.ready.retain(|ready| *ready != id);
        self.total_pending -= discarded;
        Ok(discarded)
    }

    pub fn close_channel(&mut self, id: ChannelId) -> Result<usize, LinkError> {
        let state = self
            .channels
            .remove(&id)
            .ok_or_else(|| self.closed_or_unknown(id))?;
        let discarded = state.queue.len();
        self.ready.retain(|ready| *ready != id);
        self.total_pending = self.total_pending.saturating_sub(discarded);
        if let Some(ids) = self.keys.get_mut(&state.config.key) {
            ids.retain(|channel_id| *channel_id != id);
            if ids.is_empty() {
                self.keys.remove(&state.config.key);
            }
        }
        self.retired_channels.insert(id);
        Ok(discarded)
    }

    pub fn pending_frames(&self) -> usize {
        self.total_pending
    }

    /// Reports retained queue storage without walking or cloning queued payloads.
    /// This is intended for bounded-resource telemetry and release benchmarks.
    pub fn storage_snapshot(&self) -> MultiplexerStorageSnapshot {
        MultiplexerStorageSnapshot {
            channel_count: self.channels.len(),
            pending_frames: self.total_pending,
            control_queue_slots: self.control.capacity(),
            ready_queue_slots: self.ready.capacity(),
            data_queue_slots: self
                .channels
                .values()
                .map(|state| state.queue.capacity())
                .sum(),
        }
    }

    pub fn discard_all(&mut self) -> usize {
        let discarded = self.total_pending;
        self.control.clear();
        self.ready.clear();
        for state in self.channels.values_mut() {
            state.queue.clear();
        }
        self.total_pending = 0;
        discarded
    }

    pub fn channels_for(
        &self,
        protocol_id: ProtocolStableId,
        version: ProtocolVersion,
        protocol_channel_id: ProtocolChannelId,
    ) -> impl Iterator<Item = ChannelId> + '_ {
        self.keys
            .get(&ChannelKey {
                protocol_id,
                version,
                protocol_channel_id,
            })
            .into_iter()
            .flatten()
            .copied()
    }

    fn validate_payload(&self, payload: &[u8], nesting_depth: u16) -> Result<(), LinkError> {
        if payload.len() > self.limits.max_frame_bytes {
            return Err(LinkError::LimitExceeded {
                kind: LimitKind::FrameBytes,
                limit: self.limits.max_frame_bytes,
            });
        }
        if nesting_depth > self.limits.max_nesting_depth {
            return Err(LinkError::LimitExceeded {
                kind: LimitKind::NestingDepth,
                limit: usize::from(self.limits.max_nesting_depth),
            });
        }
        Ok(())
    }

    fn validate_envelope_identity(&self, envelope: &Envelope) -> Result<(), LinkError> {
        if envelope.session_id != self.session_id {
            return Err(LinkError::SessionMismatch);
        }
        if envelope.channel_id == CONTROL_CHANNEL_ID {
            return Err(LinkError::InvalidInput(
                "channel zero cannot carry a data envelope",
            ));
        }
        if self.retired_channels.contains(&envelope.channel_id) {
            return Err(LinkError::ClosedChannel(envelope.channel_id.0));
        }
        self.validate_payload(&envelope.payload, envelope.nesting_depth)
    }

    fn closed_or_unknown(&self, id: ChannelId) -> LinkError {
        if self.retired_channels.contains(&id) {
            LinkError::ClosedChannel(id.0)
        } else {
            LinkError::UnknownChannel(id.0)
        }
    }
}

const PRIORITY_BANDS: u8 = 8;

fn scheduling_cost(payload_len: usize, priority_hint: u8) -> u128 {
    let bytes = u128::try_from(payload_len.max(1)).expect("usize always fits into u128");
    let band_width = u8::MAX.div_ceil(PRIORITY_BANDS);
    let weight = u128::from(priority_hint / band_width + 1);
    bytes
        .saturating_mul(u128::from(PRIORITY_BANDS))
        .div_ceil(weight)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_id() -> SessionId {
        SessionId::from_bytes([1; 16])
    }

    fn channel(id: u32, namespace: &str, capacity: usize) -> ChannelConfig {
        ChannelConfig {
            key: ChannelKey {
                protocol_id: ProtocolStableId::derive("test", namespace),
                version: ProtocolVersion::new(1, 0),
                protocol_channel_id: ProtocolChannelId(
                    u16::try_from(id).expect("test channel fits u16"),
                ),
            },
            id: ChannelId(id),
            generation: ChannelGeneration::INITIAL,
            mode: ChannelMode::Stream,
            priority_hint: 0,
            capacity,
            max_frame_bytes: 1024,
            max_stream_bytes: Some(64 * 1024),
            discardable: false,
        }
    }

    fn prioritized_channel(
        id: u32,
        namespace: &str,
        capacity: usize,
        priority_hint: u8,
    ) -> ChannelConfig {
        ChannelConfig {
            priority_hint,
            ..channel(id, namespace, capacity)
        }
    }

    fn envelope(config: &ChannelConfig, payload: &[u8]) -> Envelope {
        Envelope {
            session_id: session_id(),
            channel_id: config.id,
            generation: config.generation,
            sequence: 1,
            nesting_depth: 0,
            flags: EnvelopeFlags::default(),
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn slow_data_channel_does_not_block_control_or_other_namespace() {
        let mut mux = Multiplexer::new(session_id(), MultiplexerLimits::default()).unwrap();
        let slow = channel(1, "mutsuki.files", 1);
        let control_plane = channel(2, "mutsuki.distributed", 2);
        mux.open_channel(slow.clone()).unwrap();
        mux.open_channel(control_plane.clone()).unwrap();
        mux.enqueue(envelope(&slow, b"large")).unwrap();
        assert!(matches!(
            mux.enqueue(envelope(&slow, b"blocked")),
            Err(LinkError::Backpressure { channel: 1, .. })
        ));
        mux.enqueue(envelope(&control_plane, b"health")).unwrap();
        mux.enqueue_control(b"drain".to_vec()).unwrap();

        assert_eq!(
            mux.next_outbound(),
            Some(OutboundFrame::Control(b"drain".to_vec()))
        );
        assert!(
            matches!(mux.next_outbound(), Some(OutboundFrame::Data(value)) if value.payload == b"large")
        );
        assert!(
            matches!(mux.next_outbound(), Some(OutboundFrame::Data(value)) if value.payload == b"health")
        );
    }

    #[test]
    fn typed_protocol_key_is_available_outside_the_data_hot_path() {
        let mut mux = Multiplexer::new(session_id(), MultiplexerLimits::default()).unwrap();
        let lilia = channel(1, "mutsuki.lilia", 2);
        let distributed = channel(2, "mutsuki.distributed", 2);
        mux.open_channel(lilia.clone()).unwrap();
        mux.open_channel(distributed.clone()).unwrap();
        assert_eq!(
            mux.channels_for(
                lilia.key.protocol_id,
                ProtocolVersion::new(1, 0),
                lilia.key.protocol_channel_id,
            )
            .collect::<Vec<_>>(),
            vec![ChannelId(1)]
        );
        assert_eq!(
            mux.channels_for(
                distributed.key.protocol_id,
                ProtocolVersion::new(1, 0),
                distributed.key.protocol_channel_id,
            )
            .collect::<Vec<_>>(),
            vec![ChannelId(2)]
        );
    }

    #[test]
    fn priority_hint_changes_data_share_without_starving_low_priority() {
        let mut mux = Multiplexer::new(session_id(), MultiplexerLimits::default()).unwrap();
        let low = prioritized_channel(1, "example.low", 64, 0);
        let high = prioritized_channel(2, "example.high", 64, u8::MAX);
        mux.open_channel(low.clone()).unwrap();
        mux.open_channel(high.clone()).unwrap();
        for sequence in 0..64 {
            let mut low_frame = envelope(&low, &[1; 64]);
            low_frame.sequence = sequence;
            mux.enqueue(low_frame).unwrap();
            let mut high_frame = envelope(&high, &[2; 64]);
            high_frame.sequence = sequence;
            mux.enqueue(high_frame).unwrap();
        }

        let mut low_count = 0;
        let mut high_count = 0;
        for _ in 0..18 {
            match mux.next_outbound().unwrap() {
                OutboundFrame::Data(frame) if frame.channel_id == low.id => low_count += 1,
                OutboundFrame::Data(frame) if frame.channel_id == high.id => high_count += 1,
                frame => panic!("unexpected frame: {frame:?}"),
            }
        }
        assert_eq!(low_count, 2);
        assert_eq!(high_count, 16);
    }

    #[test]
    fn weighted_fair_scheduler_accounts_for_payload_bytes() {
        let mut mux = Multiplexer::new(session_id(), MultiplexerLimits::default()).unwrap();
        let low = prioritized_channel(1, "example.low", 8, 0);
        let high = prioritized_channel(2, "example.high", 8, u8::MAX);
        mux.open_channel(low.clone()).unwrap();
        mux.open_channel(high.clone()).unwrap();
        for sequence in 0..8 {
            let mut low_frame = envelope(&low, &[1; 64]);
            low_frame.sequence = sequence;
            mux.enqueue(low_frame).unwrap();
            let mut high_frame = envelope(&high, &[2; 512]);
            high_frame.sequence = sequence;
            mux.enqueue(high_frame).unwrap();
        }

        let channels = (0..8)
            .map(|_| match mux.next_outbound().unwrap() {
                OutboundFrame::Data(frame) => frame.channel_id,
                OutboundFrame::Control(frame) => panic!("unexpected control frame: {frame:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            channels,
            vec![
                low.id, high.id, low.id, high.id, low.id, high.id, low.id, high.id,
            ]
        );
    }

    #[test]
    fn stale_session_generation_unknown_and_closed_channels_fail_fast() {
        let mut mux = Multiplexer::new(session_id(), MultiplexerLimits::default()).unwrap();
        let config = channel(1, "example.data", 2);
        mux.open_channel(config.clone()).unwrap();

        let mut stale_session = envelope(&config, b"stale");
        stale_session.session_id = SessionId::from_bytes([2; 16]);
        assert_eq!(
            mux.enqueue(stale_session).unwrap_err(),
            LinkError::SessionMismatch
        );

        let mut stale_generation = envelope(&config, b"stale");
        stale_generation.generation = ChannelGeneration(u32::MAX);
        assert_eq!(
            mux.enqueue(stale_generation).unwrap_err(),
            LinkError::ChannelGenerationMismatch { channel: 1 }
        );

        let mut unknown = envelope(&config, b"unknown");
        unknown.channel_id = ChannelId(99);
        assert_eq!(
            mux.enqueue(unknown).unwrap_err(),
            LinkError::UnknownChannel(99)
        );

        mux.close_channel(config.id).unwrap();
        assert_eq!(
            mux.enqueue(envelope(&config, b"late")).unwrap_err(),
            LinkError::ClosedChannel(1)
        );
        assert_eq!(
            mux.open_channel(config).unwrap_err(),
            LinkError::ClosedChannel(1)
        );
    }

    #[test]
    fn channel_table_frame_limit_overrides_larger_connection_limit() {
        let mut mux = Multiplexer::new(session_id(), MultiplexerLimits::default()).unwrap();
        let mut config = channel(1, "example.small", 1);
        config.max_frame_bytes = 4;
        mux.open_channel(config.clone()).unwrap();
        assert!(matches!(
            mux.enqueue(envelope(&config, b"12345")),
            Err(LinkError::LimitExceeded {
                kind: LimitKind::FrameBytes,
                limit: 4,
            })
        ));
    }

    #[test]
    fn stream_byte_limit_is_frozen_in_channel_state() {
        let mut mux = Multiplexer::new(session_id(), MultiplexerLimits::default()).unwrap();
        let mut config = channel(1, "example.stream", 2);
        config.max_stream_bytes = Some(4);
        mux.open_channel(config.clone()).unwrap();
        mux.enqueue(envelope(&config, b"123")).unwrap();
        assert!(matches!(
            mux.enqueue(envelope(&config, b"45")),
            Err(LinkError::LimitExceeded {
                kind: LimitKind::StreamBytes,
                limit: 4,
            })
        ));
    }

    #[test]
    fn channel_churn_is_bounded_by_lifetime_ids_not_only_active_ids() {
        let mut mux = Multiplexer::new(
            session_id(),
            MultiplexerLimits {
                max_channels: 2,
                ..MultiplexerLimits::default()
            },
        )
        .unwrap();
        let first = channel(1, "example.first", 1);
        let second = channel(2, "example.second", 1);
        mux.open_channel(first.clone()).unwrap();
        mux.close_channel(first.id).unwrap();
        mux.open_channel(second.clone()).unwrap();
        mux.close_channel(second.id).unwrap();
        assert!(matches!(
            mux.open_channel(channel(3, "example.third", 1)),
            Err(LinkError::LimitExceeded {
                kind: LimitKind::Channels,
                limit: 2,
            })
        ));
    }
}
