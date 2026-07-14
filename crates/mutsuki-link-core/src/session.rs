use crate::{
    ConnectionQuality, LimitKind, LinkError, Multiplexer, MultiplexerLimits, NegotiatedSession,
    PeerId, ProtocolSelection, SessionContinuity, SessionId,
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
}

impl Session {
    pub fn established(
        negotiated: NegotiatedSession,
        mux_limits: MultiplexerLimits,
        max_event_subscribers: usize,
    ) -> Result<Self, LinkError> {
        let allowed_protocols = negotiated
            .protocols
            .iter()
            .map(|protocol| (protocol.namespace.clone(), protocol.version))
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
            multiplexer: Multiplexer::restricted(mux_limits, allowed_protocols)?,
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

    pub fn multiplexer(&mut self) -> &mut Multiplexer {
        &mut self.multiplexer
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthPath, ConnectionId, EndpointId, Identity, ProtocolVersion};

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
            protocols: vec![ProtocolSelection {
                namespace: "test".to_owned(),
                version: ProtocolVersion::new(1, 0),
            }],
            auth_path: AuthPath::FirstPairing,
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
    }

    #[test]
    fn session_rejects_channels_outside_negotiated_protocols() {
        let mut session =
            Session::established(negotiated(), MultiplexerLimits::default(), 1).unwrap();
        let error = session
            .multiplexer()
            .open_channel(crate::ChannelConfig {
                key: crate::ChannelKey {
                    namespace: "sensitive.unadvertised".to_owned(),
                    version: ProtocolVersion::new(1, 0),
                    id: crate::ChannelId(1),
                },
                mode: crate::ChannelMode::Event,
                priority_hint: 0,
                capacity: 1,
            })
            .unwrap_err();
        assert_eq!(error, LinkError::NamespaceConflict);
    }
}
