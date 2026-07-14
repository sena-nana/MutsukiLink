use crate::{LimitKind, LinkError, ProtocolVersion, SessionId};
use std::collections::{BTreeMap, VecDeque};

pub const CONTROL_CHANNEL_ID: ChannelId = ChannelId(0);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChannelId(pub u32);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChannelKey {
    pub namespace: String,
    pub version: ProtocolVersion,
    pub id: ChannelId,
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
    pub mode: ChannelMode,
    pub priority_hint: u8,
    pub capacity: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EnvelopeFlags {
    pub end_of_stream: bool,
    pub cancelled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    pub session_id: SessionId,
    pub channel: ChannelKey,
    pub sequence: u64,
    pub nesting_depth: u16,
    pub flags: EnvelopeFlags,
    /// Opaque payload; the namespace owner chooses its serializer.
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundFrame {
    Control(Vec<u8>),
    Data(Envelope),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultiplexerLimits {
    pub max_frame_bytes: usize,
    pub max_nesting_depth: u16,
    pub max_channels: usize,
    pub control_queue_capacity: usize,
    pub max_total_pending_frames: usize,
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
}

#[derive(Debug)]
pub struct Multiplexer {
    limits: MultiplexerLimits,
    channels: BTreeMap<ChannelId, ChannelState>,
    keys: BTreeMap<(String, ProtocolVersion), Vec<ChannelId>>,
    control: VecDeque<Vec<u8>>,
    ready: VecDeque<ChannelId>,
    total_pending: usize,
}

impl Multiplexer {
    pub fn new(limits: MultiplexerLimits) -> Result<Self, LinkError> {
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
            limits,
            channels: BTreeMap::new(),
            keys: BTreeMap::new(),
            control: VecDeque::new(),
            ready: VecDeque::new(),
            total_pending: 0,
        })
    }

    pub fn open_channel(&mut self, config: ChannelConfig) -> Result<(), LinkError> {
        if config.key.id == CONTROL_CHANNEL_ID {
            return Err(LinkError::InvalidInput(
                "channel zero is reserved for control",
            ));
        }
        if config.key.namespace.is_empty() || config.capacity == 0 {
            return Err(LinkError::InvalidInput(
                "channel namespace and capacity must be non-empty",
            ));
        }
        if self.channels.len() >= self.limits.max_channels {
            return Err(LinkError::LimitExceeded {
                kind: LimitKind::Channels,
                limit: self.limits.max_channels,
            });
        }
        if self.channels.contains_key(&config.key.id) {
            return Err(LinkError::NamespaceConflict);
        }
        self.keys
            .entry((config.key.namespace.clone(), config.key.version))
            .or_default()
            .push(config.key.id);
        self.channels.insert(
            config.key.id,
            ChannelState {
                config,
                queue: VecDeque::new(),
                cancelled: false,
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
        self.validate_payload(&envelope.payload, envelope.nesting_depth)?;
        if self.total_pending >= self.limits.max_total_pending_frames {
            return Err(LinkError::LimitExceeded {
                kind: LimitKind::PendingFrames,
                limit: self.limits.max_total_pending_frames,
            });
        }
        let channel_id = envelope.channel.id;
        let state = self
            .channels
            .get_mut(&channel_id)
            .ok_or(LinkError::UnknownChannel(channel_id.0))?;
        if state.config.key != envelope.channel {
            return Err(LinkError::NamespaceConflict);
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
        if state.queue.is_empty() {
            self.ready.push_back(channel_id);
        }
        state.queue.push_back(envelope);
        self.total_pending += 1;
        Ok(())
    }

    pub fn next_outbound(&mut self) -> Option<OutboundFrame> {
        if let Some(control) = self.control.pop_front() {
            self.total_pending -= 1;
            return Some(OutboundFrame::Control(control));
        }
        while let Some(channel_id) = self.ready.pop_front() {
            let Some(state) = self.channels.get_mut(&channel_id) else {
                continue;
            };
            let Some(envelope) = state.queue.pop_front() else {
                continue;
            };
            if !state.queue.is_empty() {
                self.ready.push_back(channel_id);
            }
            self.total_pending -= 1;
            return Some(OutboundFrame::Data(envelope));
        }
        None
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

    pub fn pending_frames(&self) -> usize {
        self.total_pending
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
        namespace: &str,
        version: ProtocolVersion,
    ) -> impl Iterator<Item = ChannelId> + '_ {
        self.keys
            .get(&(namespace.to_owned(), version))
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel(id: u32, namespace: &str, capacity: usize) -> ChannelConfig {
        ChannelConfig {
            key: ChannelKey {
                namespace: namespace.to_owned(),
                version: ProtocolVersion::new(1, 0),
                id: ChannelId(id),
            },
            mode: ChannelMode::Stream,
            priority_hint: 0,
            capacity,
        }
    }

    fn envelope(config: &ChannelConfig, payload: &[u8]) -> Envelope {
        Envelope {
            session_id: SessionId::from_bytes([1; 16]),
            channel: config.key.clone(),
            sequence: 1,
            nesting_depth: 0,
            flags: EnvelopeFlags::default(),
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn slow_data_channel_does_not_block_control_or_other_namespace() {
        let mut mux = Multiplexer::new(MultiplexerLimits::default()).unwrap();
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
    fn namespace_and_version_are_part_of_channel_identity() {
        let mut mux = Multiplexer::new(MultiplexerLimits::default()).unwrap();
        let lilia = channel(1, "mutsuki.lilia", 2);
        let distributed = channel(2, "mutsuki.distributed", 2);
        mux.open_channel(lilia).unwrap();
        mux.open_channel(distributed).unwrap();
        assert_eq!(
            mux.channels_for("mutsuki.lilia", ProtocolVersion::new(1, 0))
                .collect::<Vec<_>>(),
            vec![ChannelId(1)]
        );
        assert_eq!(
            mux.channels_for("mutsuki.distributed", ProtocolVersion::new(1, 0))
                .collect::<Vec<_>>(),
            vec![ChannelId(2)]
        );
    }
}
