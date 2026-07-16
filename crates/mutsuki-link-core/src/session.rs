use crate::{
    ConnectionQuality, ControlModeGuard, DataIdentityMode, DataModeGuard, LimitKind,
    LinkControlError, LinkControlOpcode, LinkError, MAX_SESSION_CHANNEL_MAPPINGS, Multiplexer,
    MultiplexerLimits, MultiplexerStorageSnapshot, NegotiatedSession, OutboundFrame, PeerId,
    ProtocolSelection, QueueAdmission, SessionChannelBinding, SessionChannelMap, SessionContinuity,
    SessionId, ValidatedChannel,
};
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    Connecting,
    Handshaking,
    Established,
    Draining,
    Closed,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CloseReason {
    Graceful,
    LocalAbort,
    RemoteClosed,
    Timeout,
    AuthenticationFailed,
    ProtocolViolation,
    TransportFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInfo {
    pub session_id: SessionId,
    pub peer_id: PeerId,
    pub protocols: Vec<ProtocolSelection>,
    pub continuity: SessionContinuity,
    pub quality: ConnectionQuality,
    pub close_reason: Option<CloseReason>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionEvent {
    StateChanged(SessionState),
    ContinuityChanged(SessionContinuity),
    QualityChanged(ConnectionQuality),
    Closed(CloseReason),
    EventsDropped(u64),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EventSubscriberId(u64);

#[derive(Debug)]
struct Subscriber {
    queue: VecDeque<SessionEvent>,
    capacity: usize,
    dropped: u64,
}

#[derive(Debug)]
pub struct SessionEventBus {
    max_subscribers: usize,
    next_id: u64,
    subscribers: BTreeMap<EventSubscriberId, Subscriber>,
}

impl SessionEventBus {
    pub fn new(max_subscribers: usize) -> Result<Self, LinkError> {
        if max_subscribers == 0 {
            return Err(LinkError::InvalidInput(
                "event subscriber limit must be positive",
            ));
        }
        Ok(Self {
            max_subscribers,
            next_id: 1,
            subscribers: BTreeMap::new(),
        })
    }

    pub fn subscribe(&mut self, capacity: usize) -> Result<EventSubscriberId, LinkError> {
        if capacity == 0 {
            return Err(LinkError::InvalidInput(
                "event queue capacity must be positive",
            ));
        }
        if self.subscribers.len() >= self.max_subscribers {
            return Err(LinkError::LimitExceeded {
                kind: LimitKind::EventSubscribers,
                limit: self.max_subscribers,
            });
        }
        let id = EventSubscriberId(self.next_id);
        self.next_id = self.next_id.checked_add(1).ok_or(LinkError::Closed)?;
        self.subscribers.insert(
            id,
            Subscriber {
                queue: VecDeque::new(),
                capacity,
                dropped: 0,
            },
        );
        Ok(id)
    }

    pub fn publish(&mut self, event: SessionEvent) {
        for subscriber in self.subscribers.values_mut() {
            if subscriber.queue.len() == subscriber.capacity {
                subscriber.queue.pop_front();
                subscriber.dropped = subscriber.dropped.saturating_add(1);
            }
            subscriber.queue.push_back(event.clone());
        }
    }

    pub fn next(&mut self, id: EventSubscriberId) -> Option<SessionEvent> {
        let subscriber = self.subscribers.get_mut(&id)?;
        if subscriber.dropped > 0 {
            let dropped = subscriber.dropped;
            subscriber.dropped = 0;
            return Some(SessionEvent::EventsDropped(dropped));
        }
        subscriber.queue.pop_front()
    }

    pub fn unsubscribe(&mut self, id: EventSubscriberId) -> bool {
        self.subscribers.remove(&id).is_some()
    }
}

#[derive(Debug)]
pub struct Session {
    state: SessionState,
    info: SessionInfo,
    events: SessionEventBus,
    multiplexer: Multiplexer,
    control_mode: ControlModeGuard,
    data_mode: DataModeGuard,
    channel_mappings: SessionChannelMap,
}

impl Session {
    pub fn established(
        negotiated: NegotiatedSession,
        mux_limits: MultiplexerLimits,
        max_event_subscribers: usize,
    ) -> Result<Self, LinkError> {
        let control_mode = negotiated.control_mode_guard();
        let data_mode = DataModeGuard::new(DataIdentityMode::negotiate(
            control_mode.mode(),
            negotiated.link_capabilities,
        ));
        let allowed_protocols = negotiated
            .protocols
            .iter()
            .map(|protocol| (protocol.stable_id, protocol.version))
            .collect::<Vec<_>>();
        Ok(Self {
            state: SessionState::Established,
            info: SessionInfo {
                session_id: negotiated.session_id,
                peer_id: negotiated.remote.peer_id,
                protocols: negotiated.protocols,
                continuity: SessionContinuity::default(),
                quality: ConnectionQuality::default(),
                close_reason: None,
            },
            events: SessionEventBus::new(max_event_subscribers)?,
            multiplexer: Multiplexer::restricted(
                negotiated.session_id,
                mux_limits,
                allowed_protocols,
            )?,
            control_mode,
            data_mode,
            channel_mappings: SessionChannelMap::new(MAX_SESSION_CHANNEL_MAPPINGS).map_err(
                |_| LinkError::InvalidInput("session channel mapping limits are invalid"),
            )?,
        })
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn info(&self) -> &SessionInfo {
        &self.info
    }

    pub fn events(&mut self) -> &mut SessionEventBus {
        &mut self.events
    }

    pub fn data_plane(&mut self) -> SessionDataPlane<'_> {
        SessionDataPlane {
            state: self.state,
            multiplexer: &mut self.multiplexer,
        }
    }

    pub const fn control_mode(&self) -> ControlModeGuard {
        self.control_mode
    }

    pub const fn data_mode(&self) -> DataModeGuard {
        self.data_mode
    }

    pub fn open_validated_channel(
        &mut self,
        validated: &ValidatedChannel,
    ) -> Result<SessionChannelBinding, SessionChannelOpenError> {
        if !matches!(
            self.state,
            SessionState::Established | SessionState::Draining
        ) {
            return Err(SessionChannelOpenError::Control(
                LinkControlError::session_not_active(LinkControlOpcode::OpenChannel),
            ));
        }
        self.control_mode
            .validate_typed()
            .map_err(SessionChannelOpenError::Control)?;
        self.data_mode
            .validate_compact()
            .map_err(SessionChannelOpenError::DataMode)?;
        let accepted = validated.accepted_mapping();
        if !self.validated_channel_matches_session(validated) {
            return Err(SessionChannelOpenError::Control(LinkControlError {
                domain: crate::ErrorDomain::Security,
                code: crate::ErrorCode(2),
                operation: Some(LinkControlOpcode::OpenChannel),
                retryability: crate::Retryability::Never,
                public_message: "channel descriptor is not bound to this negotiated session",
            }));
        }
        self.channel_mappings
            .validate_bind(accepted)
            .map_err(SessionChannelOpenError::Control)?;
        self.multiplexer
            .open_channel(validated.config.clone())
            .map_err(SessionChannelOpenError::Multiplexer)?;
        Ok(self.channel_mappings.bind_validated(accepted))
    }

    /// Compatibility boundary for an owner-provided legacy full-key codec.
    /// The descriptor is still registry-validated, but no compact mapping is
    /// installed and the compact wire codec remains disabled for this Session.
    pub fn open_legacy_validated_channel(
        &mut self,
        validated: &ValidatedChannel,
    ) -> Result<(), SessionChannelOpenError> {
        if !matches!(
            self.state,
            SessionState::Established | SessionState::Draining
        ) {
            return Err(SessionChannelOpenError::Control(
                LinkControlError::session_not_active(LinkControlOpcode::OpenChannel),
            ));
        }
        self.data_mode
            .validate_legacy()
            .map_err(SessionChannelOpenError::DataMode)?;
        if !self.validated_channel_matches_session(validated) {
            return Err(SessionChannelOpenError::Control(LinkControlError {
                domain: crate::ErrorDomain::Security,
                code: crate::ErrorCode(2),
                operation: Some(LinkControlOpcode::OpenChannel),
                retryability: crate::Retryability::Never,
                public_message: "legacy channel descriptor is not bound to this session",
            }));
        }
        self.multiplexer
            .open_channel(validated.config.clone())
            .map_err(SessionChannelOpenError::Multiplexer)
    }

    pub fn close_channel(&mut self, channel_id: crate::ChannelId) -> Result<usize, LinkError> {
        let discarded = self.multiplexer.close_channel(channel_id)?;
        self.channel_mappings.unbind(channel_id);
        Ok(discarded)
    }

    fn validated_channel_matches_session(&self, validated: &ValidatedChannel) -> bool {
        validated.config.key.protocol_id == validated.protocol_id
            && validated.config.key.protocol_channel_id == validated.protocol_channel_id
            && validated.config.generation == crate::ChannelGeneration::INITIAL
            && validated.config.max_frame_bytes == validated.max_frame_bytes
            && validated.config.max_stream_bytes == validated.max_stream_bytes
            && validated.config.discardable == validated.discardable
            && self.info.protocols.iter().any(|protocol| {
                protocol.stable_id == validated.protocol_id
                    && protocol.version == validated.config.key.version
                    && protocol.schema == validated.schema
                    && protocol.capabilities == validated.capabilities
            })
    }

    pub fn channel_mappings(&self) -> &SessionChannelMap {
        &self.channel_mappings
    }

    pub fn update_quality(&mut self, quality: ConnectionQuality) -> Result<(), LinkError> {
        self.ensure_active()?;
        self.info.quality = quality;
        self.events.publish(SessionEvent::QualityChanged(quality));
        Ok(())
    }

    pub fn report_continuity(&mut self, continuity: SessionContinuity) -> Result<(), LinkError> {
        self.ensure_active()?;
        self.info.continuity = continuity;
        self.events
            .publish(SessionEvent::ContinuityChanged(continuity));
        Ok(())
    }

    pub fn begin_drain(&mut self) -> Result<(), LinkError> {
        if self.state != SessionState::Established {
            return Err(LinkError::InvalidState(
                "only an established session can begin draining",
            ));
        }
        self.state = SessionState::Draining;
        self.events
            .publish(SessionEvent::StateChanged(SessionState::Draining));
        Ok(())
    }

    pub fn finish_drain(&mut self) -> Result<(), LinkError> {
        if self.state != SessionState::Draining || self.multiplexer.pending_frames() != 0 {
            return Err(LinkError::InvalidState(
                "drain can finish only after all queued frames are sent",
            ));
        }
        self.close(CloseReason::Graceful, SessionState::Closed);
        Ok(())
    }

    pub fn abort(&mut self) {
        if matches!(self.state, SessionState::Closed | SessionState::Failed) {
            return;
        }
        self.multiplexer.discard_all();
        self.close(CloseReason::LocalAbort, SessionState::Closed);
    }

    pub fn fail(&mut self, reason: CloseReason) {
        if matches!(self.state, SessionState::Closed | SessionState::Failed) {
            return;
        }
        self.multiplexer.discard_all();
        self.close(reason, SessionState::Failed);
    }

    fn close(&mut self, reason: CloseReason, state: SessionState) {
        self.state = state;
        self.info.close_reason = Some(reason.clone());
        self.events.publish(SessionEvent::StateChanged(state));
        self.events.publish(SessionEvent::Closed(reason));
    }

    fn ensure_active(&self) -> Result<(), LinkError> {
        if matches!(
            self.state,
            SessionState::Established | SessionState::Draining
        ) {
            Ok(())
        } else {
            Err(LinkError::Closed)
        }
    }
}

#[derive(Debug)]
pub enum SessionChannelOpenError {
    Control(LinkControlError),
    DataMode(crate::DataCodecError),
    Multiplexer(LinkError),
}

impl std::fmt::Display for SessionChannelOpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Control(error) => error.fmt(formatter),
            Self::DataMode(error) => error.fmt(formatter),
            Self::Multiplexer(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SessionChannelOpenError {}

pub struct SessionDataPlane<'a> {
    state: SessionState,
    multiplexer: &'a mut Multiplexer,
}

impl SessionDataPlane<'_> {
    pub fn enqueue(&mut self, envelope: crate::Envelope) -> Result<(), LinkError> {
        self.ensure_active()?;
        self.multiplexer.enqueue(envelope)
    }

    pub fn enqueue_discardable(
        &mut self,
        envelope: crate::Envelope,
    ) -> Result<QueueAdmission, LinkError> {
        self.ensure_active()?;
        self.multiplexer.enqueue_discardable(envelope)
    }

    pub fn enqueue_control(&mut self, payload: Vec<u8>) -> Result<(), LinkError> {
        self.ensure_active()?;
        self.multiplexer.enqueue_control(payload)
    }

    pub fn next_outbound(&mut self) -> Option<OutboundFrame> {
        self.multiplexer.next_outbound()
    }

    pub fn cancel_channel(&mut self, channel_id: crate::ChannelId) -> Result<usize, LinkError> {
        self.ensure_active()?;
        self.multiplexer.cancel_channel(channel_id)
    }

    pub fn pending_frames(&self) -> usize {
        self.multiplexer.pending_frames()
    }

    pub fn storage_snapshot(&self) -> MultiplexerStorageSnapshot {
        self.multiplexer.storage_snapshot()
    }

    fn ensure_active(&self) -> Result<(), LinkError> {
        if matches!(
            self.state,
            SessionState::Established | SessionState::Draining
        ) {
            Ok(())
        } else {
            Err(LinkError::Closed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthPath, ConnectionId, EndpointId, Identity, LinkCapabilities, ProtocolCapabilitySet,
        ProtocolDebugIdentity, ProtocolVersion, SchemaRef,
    };

    fn negotiated() -> NegotiatedSession {
        NegotiatedSession {
            session_id: SessionId::from_bytes([3; 16]),
            local: Identity {
                peer_id: PeerId::from_bytes([1; 32]),
                endpoint_id: EndpointId::from_bytes([1; 16]),
                connection_id: ConnectionId::from_bytes([1; 16]),
            },
            remote: Identity {
                peer_id: PeerId::from_bytes([2; 32]),
                endpoint_id: EndpointId::from_bytes([2; 16]),
                connection_id: ConnectionId::from_bytes([2; 16]),
            },
            link_version: ProtocolVersion::new(1, 0),
            link_capabilities: LinkCapabilities::TYPED_CONTROL
                | LinkCapabilities::COMPACT_CHANNEL_ID,
            protocols: vec![{
                let identity = ProtocolDebugIdentity::new("local", "test");
                let stable_id = identity.stable_id();
                ProtocolSelection {
                    stable_id,
                    version: ProtocolVersion::new(1, 0),
                    schema: SchemaRef::for_contract("local", "test", 1, b"test"),
                    capabilities: ProtocolCapabilitySet::empty(stable_id),
                }
            }],
            auth_path: AuthPath::FirstPairing,
        }
    }

    fn validated(selection: &ProtocolSelection, channel_id: u32) -> ValidatedChannel {
        let protocol_id = selection.stable_id;
        ValidatedChannel {
            config: crate::ChannelConfig {
                key: crate::ChannelKey {
                    protocol_id,
                    version: selection.version,
                    protocol_channel_id: crate::ProtocolChannelId(1),
                },
                id: crate::ChannelId(channel_id),
                generation: crate::ChannelGeneration::INITIAL,
                mode: crate::ChannelMode::Event,
                priority_hint: 10,
                capacity: 2,
                max_frame_bytes: 1024,
                max_stream_bytes: None,
                discardable: true,
            },
            protocol_id,
            protocol_channel_id: crate::ProtocolChannelId(1),
            schema: selection.schema,
            capabilities: selection.capabilities.clone(),
            debug_name: Some("event".to_owned()),
            max_frame_bytes: 1024,
            max_stream_bytes: None,
            discardable: true,
        }
    }

    #[test]
    fn slow_event_subscriber_never_blocks_publisher() {
        let mut bus = SessionEventBus::new(1).unwrap();
        let subscriber = bus.subscribe(1).unwrap();
        for failures in 1..=100 {
            bus.publish(SessionEvent::QualityChanged(ConnectionQuality {
                consecutive_failures: failures,
                ..ConnectionQuality::default()
            }));
        }
        assert_eq!(bus.next(subscriber), Some(SessionEvent::EventsDropped(99)));
        assert!(matches!(
            bus.next(subscriber),
            Some(SessionEvent::QualityChanged(ConnectionQuality {
                consecutive_failures: 100,
                ..
            }))
        ));
    }

    #[test]
    fn drain_and_abort_have_distinct_reasons() {
        let mut drained =
            Session::established(negotiated(), MultiplexerLimits::default(), 2).unwrap();
        drained.begin_drain().unwrap();
        drained.finish_drain().unwrap();
        assert_eq!(drained.state(), SessionState::Closed);
        assert_eq!(drained.info().close_reason, Some(CloseReason::Graceful));

        let mut aborted =
            Session::established(negotiated(), MultiplexerLimits::default(), 2).unwrap();
        aborted.abort();
        assert_eq!(aborted.info().close_reason, Some(CloseReason::LocalAbort));
        assert_eq!(
            aborted
                .data_plane()
                .enqueue(crate::Envelope {
                    session_id: SessionId::from_bytes([3; 16]),
                    channel_id: crate::ChannelId(1),
                    generation: crate::ChannelGeneration::INITIAL,
                    sequence: 1,
                    nesting_depth: 0,
                    flags: crate::EnvelopeFlags::default(),
                    payload: vec![],
                })
                .unwrap_err(),
            LinkError::Closed
        );
    }

    #[test]
    fn session_rejects_channels_outside_negotiated_protocols() {
        let mut session =
            Session::established(negotiated(), MultiplexerLimits::default(), 1).unwrap();
        let protocol_id = crate::ProtocolStableId::derive("sensitive", "unadvertised");
        let schema = crate::SchemaRef::for_contract("sensitive", "unadvertised", 1, b"test");
        let config = crate::ChannelConfig {
            key: crate::ChannelKey {
                protocol_id,
                version: ProtocolVersion::new(1, 0),
                protocol_channel_id: crate::ProtocolChannelId(1),
            },
            id: crate::ChannelId(1),
            generation: crate::ChannelGeneration::INITIAL,
            mode: crate::ChannelMode::Event,
            priority_hint: 0,
            capacity: 1,
            max_frame_bytes: 1024,
            max_stream_bytes: None,
            discardable: false,
        };
        let error = session
            .open_validated_channel(&ValidatedChannel {
                config,
                protocol_id,
                protocol_channel_id: crate::ProtocolChannelId(1),
                schema,
                capabilities: crate::ProtocolCapabilitySet::empty(protocol_id),
                debug_name: None,
                max_frame_bytes: 1024,
                max_stream_bytes: None,
                discardable: false,
            })
            .unwrap_err();
        assert!(matches!(error, SessionChannelOpenError::Control(_)));
    }

    #[test]
    fn authenticated_session_owns_typed_channel_mapping() {
        let negotiated = negotiated();
        let selection = negotiated.protocols[0].clone();
        let protocol_id = selection.stable_id;
        let mut session =
            Session::established(negotiated, MultiplexerLimits::default(), 1).unwrap();
        let validated = validated(&selection, 7);
        let binding = session.open_validated_channel(&validated).unwrap();
        assert_eq!(binding.generation, crate::ChannelGeneration::INITIAL);
        assert_eq!(
            session
                .channel_mappings()
                .session_channel(protocol_id, crate::ProtocolChannelId(1)),
            Some(crate::ChannelId(7))
        );
        session.close_channel(crate::ChannelId(7)).unwrap();
        let error = session.open_validated_channel(&validated).unwrap_err();
        assert!(matches!(error, SessionChannelOpenError::Control(_)));
    }

    #[test]
    fn legacy_session_uses_explicit_adapter_and_never_installs_compact_mapping() {
        let mut negotiated = negotiated();
        negotiated.link_capabilities = LinkCapabilities::default();
        let selection = negotiated.protocols[0].clone();
        let validated = validated(&selection, 5);
        let mut session =
            Session::established(negotiated, MultiplexerLimits::default(), 1).unwrap();
        assert_eq!(
            session.data_mode().mode(),
            DataIdentityMode::LegacyFullChannelKey
        );
        session.open_legacy_validated_channel(&validated).unwrap();
        assert!(session.channel_mappings().is_empty());
        let error = session.open_validated_channel(&validated).unwrap_err();
        assert!(matches!(error, SessionChannelOpenError::Control(_)));
    }

    #[test]
    fn new_session_starts_empty_and_rejects_previous_session_frame() {
        let previous_session_id = negotiated().session_id;
        let mut next = negotiated();
        next.session_id = SessionId::from_bytes([4; 16]);
        let mut session = Session::established(next, MultiplexerLimits::default(), 1).unwrap();
        assert!(session.channel_mappings().is_empty());
        let error = session
            .data_plane()
            .enqueue(crate::Envelope {
                session_id: previous_session_id,
                channel_id: crate::ChannelId(7),
                generation: crate::ChannelGeneration::INITIAL,
                sequence: 1,
                nesting_depth: 0,
                flags: crate::EnvelopeFlags::default(),
                payload: vec![1],
            })
            .unwrap_err();
        assert_eq!(error, LinkError::SessionMismatch);
    }
}
