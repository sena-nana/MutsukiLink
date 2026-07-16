//! Low-latency `NanaTracking` Protocol application binding for `MutsukiLink`.
//!
//! `MutsukiLink` remains payload-agnostic. This independent adapter owns NTP session negotiation,
//! compact-frame transport, absolute-result fragmentation, freshness checks, and receiver reports.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::too_many_lines
)]

mod auth;
mod control;
mod fragment;
mod reliable;

pub use auth::{
    NtpAuthorization, NtpPermission, NtpPermissionGrant, NtpPermissions, NtpRole,
    authorize_ntp_session, authorize_trusted_ntp_session,
};
pub use control::{ControlMessage, ProtocolHello, SessionCommand, SessionProposal};

use control::ControlMessage as Message;
use fragment::{FragmentSend, Reassembler, ReassemblyOutcome, send_fragmented};
use mutsuki_link_core::{
    Connection, PeerId, ProtocolId, RealtimeDatagram, RealtimeFlowId, RealtimePriority,
    SendOutcome, SessionId as LinkSessionId, TransportError, TransportErrorKind,
};
use nana_tracking_protocol::{
    ActiveLayout, CanonicalCodec, CompactFrameCodec, CompactFrameError, CompactFrameInput,
    CompactFrameRef, CompactSample, CompactStreamError, CompactStreamGuard, CompactStreamPolicy,
    ContractError, HandshakeError, HandshakeLimits, LayoutError, LayoutNegotiator, LayoutProposal,
    NanaTrackingDescriptor, NanaTrackingResult, ProducerClockEstimate, ResultStreamGuard,
    SessionId, StreamError, ValueEncoding, WireDecode,
};
use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

pub const CONTROL_PROTOCOL: &str = "nana.tracking.remote.v2";
pub const COMPACT_RIG_FLOW: RealtimeFlowId = RealtimeFlowId(0x4e10);
pub const CORE_RESULT_FLOW: RealtimeFlowId = RealtimeFlowId(0x4e11);
pub const GEOMETRY_FLOW: RealtimeFlowId = RealtimeFlowId(0x4e12);
pub const RESULT_FRAGMENT_HEADER_LEN: usize = fragment::HEADER_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackingTransportMode {
    ReliableLatestOnly,
    Datagram,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundNtpSession {
    pub peer_id: PeerId,
    pub link_session_id: LinkSessionId,
    pub ntp_session_id: SessionId,
    pub generation: u32,
    pub layout_id: u32,
    pub layout_hash: [u8; 32],
    pub expected_frame_len: u32,
    pub value_encoding: ValueEncoding,
    pub target_fps: u16,
    pub transport_mode: TrackingTransportMode,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrackingTelemetry {
    pub reliable_pending: usize,
    pub queue_replacements: u64,
    pub rate_limited: u64,
    pub malformed_frames: u64,
    pub fuse_tripped: bool,
    pub steady_buffer_growths: u64,
    pub replay_dropped: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeometryTopology {
    pub schema_revision: u32,
    pub topology_hash: [u8; 32],
    pub landmark_count: u32,
}

impl Default for GeometryTopology {
    fn default() -> Self {
        Self {
            schema_revision: 1,
            topology_hash: [0; 32],
            landmark_count: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceiverReport {
    pub received: u64,
    pub dropped: u64,
    pub stale: u64,
    pub jitter_ns: u64,
    pub result_age_ns: u64,
    pub clock_uncertainty_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingConfig {
    pub result_deadline: Duration,
    pub max_result_age: Duration,
    pub max_reassembly_bytes: usize,
    pub max_fragments: usize,
    pub max_control_bytes: usize,
    pub max_pending_control: usize,
    pub max_tracking_frame_bytes: usize,
    pub max_target_fps: u16,
    pub max_burst_fps: u16,
    pub max_reconfigure_per_minute: u16,
    pub max_receive_frames_per_poll: usize,
    pub max_protocol_violations: u16,
    /// `None` disables automatic dense-geometry snapshots. An explicit request still sends one.
    pub geometry_cadence: Option<u64>,
    pub compact_policy: CompactStreamPolicy,
}

impl Default for BindingConfig {
    fn default() -> Self {
        Self {
            result_deadline: Duration::from_millis(50),
            max_result_age: Duration::from_millis(100),
            max_reassembly_bytes: 8 * 1024 * 1024,
            max_fragments: 8_192,
            max_control_bytes: 64 * 1024,
            max_pending_control: 16,
            max_tracking_frame_bytes: 8 * 1024 * 1024,
            max_target_fps: 120,
            max_burst_fps: 240,
            max_reconfigure_per_minute: 6,
            max_receive_frames_per_poll: 32,
            max_protocol_violations: 8,
            geometry_cadence: Some(15),
            compact_policy: CompactStreamPolicy {
                max_frame_age_ns: 100_000_000,
                max_future_skew_ns: 2_000_000,
                max_clock_uncertainty_ns: 50_000_000,
                max_sequence_gap: u64::MAX,
                max_capture_jump_ns: 5_000_000_000,
            },
        }
    }
}

impl BindingConfig {
    pub fn validate(self) -> Result<Self, BindingError> {
        if self.result_deadline.is_zero()
            || self.max_result_age.is_zero()
            || self.max_reassembly_bytes == 0
            || self.max_reassembly_bytes > u32::MAX as usize
            || self.max_fragments == 0
            || self.max_fragments > usize::from(u16::MAX)
            || self.max_control_bytes == 0
            || self.max_pending_control == 0
            || self.max_tracking_frame_bytes == 0
            || self.max_tracking_frame_bytes > u32::MAX as usize
            || self.max_target_fps == 0
            || self.max_burst_fps < self.max_target_fps
            || self.max_reconfigure_per_minute == 0
            || self.max_receive_frames_per_poll == 0
            || self.max_protocol_violations == 0
            || self.geometry_cadence == Some(0)
        {
            return Err(BindingError::InvalidConfig);
        }
        Ok(self)
    }

    fn max_result_age_ns(self) -> u64 {
        u64::try_from(self.max_result_age.as_nanos()).unwrap_or(u64::MAX)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindingError {
    Transport(TransportError),
    Codec(nana_tracking_protocol::CodecError),
    Contract(ContractError),
    Layout(LayoutError),
    Handshake(HandshakeError),
    Compact(CompactFrameError),
    CompactStream(CompactStreamError),
    Stream(StreamError),
    InvalidConfig,
    InvalidControl,
    InvalidFragment,
    InvalidState,
    IncompatibleVersion,
    ControlLimit,
    PayloadLimit,
    DatagramsUnsupported,
    Unauthorized,
    SessionBindingMismatch,
    LayoutMismatch,
    RateLimited,
    ChannelFused,
    PeerRevoked,
    ReplayOrDuplicate,
    StaleResult,
}

impl fmt::Display for BindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "transport error: {error}"),
            Self::Codec(error) => write!(formatter, "NTP codec error: {error}"),
            Self::Contract(error) => write!(formatter, "NTP contract error: {error}"),
            Self::Layout(error) => write!(formatter, "NTP layout error: {error}"),
            Self::Handshake(error) => write!(formatter, "NTP layout handshake error: {error}"),
            Self::Compact(error) => write!(formatter, "NTP compact-frame error: {error}"),
            Self::CompactStream(error) => write!(formatter, "NTP compact stream error: {error}"),
            Self::Stream(error) => write!(formatter, "NTP result stream error: {error}"),
            Self::InvalidConfig => formatter.write_str("NTP Link configuration is invalid"),
            Self::InvalidControl => formatter.write_str("NTP Link control message is invalid"),
            Self::InvalidFragment => formatter.write_str("NTP Link result fragment is invalid"),
            Self::InvalidState => {
                formatter.write_str("NTP Link session state does not allow this operation")
            }
            Self::IncompatibleVersion => {
                formatter.write_str("NTP Link protocol version is incompatible")
            }
            Self::ControlLimit => formatter.write_str("NTP Link control budget is exceeded"),
            Self::PayloadLimit => formatter.write_str("NTP Link payload budget is exceeded"),
            Self::DatagramsUnsupported => {
                formatter.write_str("realtime Datagram transport is unavailable")
            }
            Self::Unauthorized => formatter.write_str("NTP Link permission is not granted"),
            Self::SessionBindingMismatch => {
                formatter.write_str("NTP Link session binding does not match")
            }
            Self::LayoutMismatch => formatter.write_str("NTP Link frame layout does not match"),
            Self::RateLimited => formatter.write_str("NTP Link rate limit is exceeded"),
            Self::ChannelFused => formatter.write_str("NTP Link frame channel is fused"),
            Self::PeerRevoked => formatter.write_str("NTP Link peer trust is revoked"),
            Self::ReplayOrDuplicate => {
                formatter.write_str("NTP Link frame is replayed or duplicated")
            }
            Self::StaleResult => formatter.write_str("NTP result exceeded the freshness deadline"),
        }
    }
}

impl std::error::Error for BindingError {}

macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for BindingError {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}

from_error!(TransportError, Transport);
from_error!(nana_tracking_protocol::CodecError, Codec);
from_error!(ContractError, Contract);
from_error!(LayoutError, Layout);
from_error!(HandshakeError, Handshake);
from_error!(CompactFrameError, Compact);
from_error!(CompactStreamError, CompactStream);
from_error!(StreamError, Stream);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FragmentBatchOutcome {
    pub fragments: usize,
    pub enqueued: usize,
    pub replaced: usize,
    pub expired: usize,
    pub congested: usize,
}

impl FragmentBatchOutcome {
    #[must_use]
    pub const fn delivered_to_transport(self) -> bool {
        self.fragments > 0 && self.expired == 0 && self.congested == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishOutcome {
    pub compact: SendOutcome,
    pub core: FragmentBatchOutcome,
    pub geometry: Option<FragmentBatchOutcome>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublisherEvent {
    HelloAccepted,
    LayoutAccepted,
    SessionReady,
    PlaybackChanged(SessionCommand),
    ReceiverReport(ReceiverReport),
    GeometryRequested,
    RemoteError(u16),
    RemoteClosed(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriberEvent {
    HelloAccepted,
    ProposalAccepted,
    SessionReady,
    ClockSynchronized,
    RemoteError(u16),
    RemoteClosed(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveOutcome {
    Idle,
    Progress,
}

#[derive(Clone, Debug)]
struct SessionDefinition {
    descriptor: NanaTrackingDescriptor,
    session_id: SessionId,
    generation: u32,
    layout: ActiveLayout,
    topology: GeometryTopology,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlaybackState {
    Stopped,
    Paused,
    Running,
}

pub struct Publisher<C: Connection> {
    connection: C,
    authorization: NtpAuthorization,
    transport_mode: TrackingTransportMode,
    config: BindingConfig,
    remote_hello: bool,
    pending: Option<SessionDefinition>,
    pending_accepted: bool,
    active: Option<SessionDefinition>,
    playback: PlaybackState,
    outbox: VecDeque<Vec<u8>>,
    compact_samples: Vec<CompactSample>,
    compact_bytes: Vec<u8>,
    fragment_scratch: Vec<u8>,
    reliable: reliable::ReliableLatestSender,
    reconfigure_times: VecDeque<Instant>,
    frame_window_started: Instant,
    frame_window_count: u16,
    sustained_window_started: Instant,
    sustained_frame_count: u32,
    rate_limited: u64,
    last_published_sequence: Option<u64>,
    geometry_requested: bool,
    last_report: Option<ReceiverReport>,
}

impl<C: Connection> Publisher<C> {
    pub fn new(
        connection: C,
        authorization: NtpAuthorization,
        config: BindingConfig,
    ) -> Result<Self, BindingError> {
        let config = config.validate()?;
        validate_connection_authorization(&connection, &authorization, NtpRole::Publisher)?;
        let transport_mode = if connection.max_datagram_payload().is_some() {
            TrackingTransportMode::Datagram
        } else {
            TrackingTransportMode::ReliableLatestOnly
        };
        if !connection.metadata().reliable {
            return Err(BindingError::InvalidState);
        }
        Ok(Self {
            connection,
            authorization,
            transport_mode,
            config,
            remote_hello: false,
            pending: None,
            pending_accepted: false,
            active: None,
            playback: PlaybackState::Stopped,
            outbox: VecDeque::with_capacity(config.max_pending_control),
            compact_samples: Vec::new(),
            compact_bytes: Vec::new(),
            fragment_scratch: Vec::new(),
            reliable: reliable::ReliableLatestSender::default(),
            reconfigure_times: VecDeque::new(),
            frame_window_started: Instant::now(),
            frame_window_count: 0,
            sustained_window_started: Instant::now(),
            sustained_frame_count: 0,
            rate_limited: 0,
            last_published_sequence: None,
            geometry_requested: false,
            last_report: None,
        })
    }

    pub fn into_inner(self) -> C {
        self.connection
    }

    pub fn connection(&self) -> &C {
        &self.connection
    }

    pub fn descriptor(&self) -> Option<&NanaTrackingDescriptor> {
        self.active.as_ref().map(|session| &session.descriptor)
    }

    pub fn topology(&self) -> Option<GeometryTopology> {
        self.active.as_ref().map(|session| session.topology)
    }

    pub fn last_receiver_report(&self) -> Option<ReceiverReport> {
        self.last_report
    }

    pub const fn transport_mode(&self) -> TrackingTransportMode {
        self.transport_mode
    }

    pub fn bound_session(&self) -> Option<BoundNtpSession> {
        self.active
            .as_ref()
            .map(|active| bound_session(&self.authorization, active, self.transport_mode))
    }

    pub fn telemetry(&self) -> TrackingTelemetry {
        TrackingTelemetry {
            reliable_pending: self.reliable.pending(),
            queue_replacements: self.reliable.replacements(),
            rate_limited: self.rate_limited,
            steady_buffer_growths: self.reliable.buffer_growths(),
            ..TrackingTelemetry::default()
        }
    }

    pub fn try_send_hello(&mut self) -> Result<(), BindingError> {
        queue_control(
            &mut self.outbox,
            Message::Hello(ProtocolHello::new(self.authorization.link_session_id())),
            self.config,
        )?;
        flush_control(&mut self.connection, &mut self.outbox)
    }

    pub fn publish_descriptor(
        &mut self,
        descriptor: NanaTrackingDescriptor,
        session_id: SessionId,
        generation: u32,
        layout_id: u32,
        layout: LayoutProposal,
        topology: GeometryTopology,
    ) -> Result<(), BindingError> {
        if !self.remote_hello || self.pending.is_some() {
            return Err(BindingError::InvalidState);
        }
        if self.active.as_ref().is_some_and(|active| {
            active.session_id == session_id && generation <= active.generation
        }) {
            return Err(BindingError::InvalidState);
        }
        if layout.target_fps == 0 || layout.target_fps > self.config.max_target_fps {
            return Err(BindingError::RateLimited);
        }
        if self.active.is_some() {
            self.note_reconfigure(Instant::now())?;
        }
        let active_layout = ActiveLayout::negotiate(
            layout_id,
            layout.clone(),
            &descriptor,
            nana_tracking_protocol::LayoutLimits::default(),
        )?;
        queue_control(
            &mut self.outbox,
            Message::SessionProposal(SessionProposal {
                descriptor: descriptor.clone(),
                session_id,
                generation,
                layout_id,
                layout,
                topology,
            }),
            self.config,
        )?;
        self.pending = Some(SessionDefinition {
            descriptor,
            session_id,
            generation,
            layout: active_layout,
            topology,
        });
        self.pending_accepted = false;
        flush_control(&mut self.connection, &mut self.outbox)
    }

    pub fn poll_control(
        &mut self,
        producer_now_ns: u64,
    ) -> Result<Option<PublisherEvent>, BindingError> {
        flush_control(&mut self.connection, &mut self.outbox)?;
        if self.transport_mode == TrackingTransportMode::ReliableLatestOnly {
            self.reliable.flush(&mut self.connection)?;
        }
        let Some(message) = receive_control(&mut self.connection, self.config)? else {
            return Ok(None);
        };
        let event = match message {
            Message::Hello(hello) => {
                validate_hello(hello, self.authorization.link_session_id())?;
                self.remote_hello = true;
                PublisherEvent::HelloAccepted
            }
            Message::LayoutAccepted(accept) => {
                if self.pending_accepted {
                    return Err(BindingError::InvalidState);
                }
                let pending = self.pending.as_ref().ok_or(BindingError::InvalidState)?;
                if accept.confirmation() != pending.layout.confirmation()
                    || usize::from(accept.parameter_count) != pending.layout.signals().len()
                    || usize::try_from(accept.expected_payload_len).ok()
                        != Some(pending.layout.frame_len())
                {
                    return Err(BindingError::InvalidControl);
                }
                queue_control(
                    &mut self.outbox,
                    Message::LayoutConfirmed(accept.confirmation()),
                    self.config,
                )?;
                self.pending_accepted = true;
                PublisherEvent::LayoutAccepted
            }
            Message::SessionReady {
                session_id,
                generation,
                layout_id,
            } => {
                let pending = self.pending.as_ref().ok_or(BindingError::InvalidState)?;
                if !self.pending_accepted
                    || pending.session_id != session_id
                    || pending.generation != generation
                    || pending.layout.layout_id() != layout_id
                {
                    return Err(BindingError::InvalidControl);
                }
                let pending = self.pending.take().ok_or(BindingError::InvalidState)?;
                self.pending_accepted = false;
                self.compact_samples = vec![
                    CompactSample::unavailable(
                        0.0,
                        nana_tracking_protocol::SignalState::TrackingLost
                    );
                    pending.layout.signals().len()
                ];
                self.compact_bytes.resize(pending.layout.frame_len(), 0);
                self.active = Some(pending);
                self.last_published_sequence = None;
                self.playback = PlaybackState::Paused;
                PublisherEvent::SessionReady
            }
            Message::Command(command) => {
                if self.active.is_none() {
                    return Err(BindingError::InvalidState);
                }
                self.playback = match command {
                    SessionCommand::Start | SessionCommand::Resume => PlaybackState::Running,
                    SessionCommand::Pause => PlaybackState::Paused,
                    SessionCommand::Stop => PlaybackState::Stopped,
                };
                PublisherEvent::PlaybackChanged(command)
            }
            Message::Ping { receiver_send_ns } => {
                queue_control(
                    &mut self.outbox,
                    Message::Pong {
                        receiver_send_ns,
                        producer_send_ns: producer_now_ns,
                    },
                    self.config,
                )?;
                flush_control(&mut self.connection, &mut self.outbox)?;
                return Ok(None);
            }
            Message::ReceiverReport(report) => {
                self.last_report = Some(report);
                PublisherEvent::ReceiverReport(report)
            }
            Message::GeometryRequest => {
                self.geometry_requested = true;
                PublisherEvent::GeometryRequested
            }
            Message::Error { code, .. } => PublisherEvent::RemoteError(code),
            Message::Close { code, .. } => PublisherEvent::RemoteClosed(code),
            _ => return Err(BindingError::InvalidControl),
        };
        flush_control(&mut self.connection, &mut self.outbox)?;
        Ok(Some(event))
    }

    pub fn try_send_latest(
        &mut self,
        result: &NanaTrackingResult,
    ) -> Result<PublishOutcome, BindingError> {
        if self.playback != PlaybackState::Running {
            return Err(BindingError::InvalidState);
        }
        let target_fps = self
            .active
            .as_ref()
            .ok_or(BindingError::InvalidState)?
            .layout
            .proposal()
            .target_fps;
        self.note_frame(Instant::now(), target_fps)?;
        let active = self.active.as_ref().ok_or(BindingError::InvalidState)?;
        if result.session_id != active.session_id || result.generation != active.generation {
            return Err(BindingError::InvalidState);
        }
        if self
            .last_published_sequence
            .is_some_and(|sequence| result.sequence <= sequence)
        {
            return Err(BindingError::ReplayOrDuplicate);
        }
        active.descriptor.validate_result(result)?;

        for (target, signal) in self.compact_samples.iter_mut().zip(active.layout.signals()) {
            let sample = result.rig.get(*signal).ok_or(BindingError::InvalidState)?;
            *target = CompactSample {
                value: sample.value,
                confidence: sample.confidence,
                state: sample.state,
            };
        }
        CompactFrameCodec::encode_into(
            &active.layout,
            &CompactFrameInput {
                session_id: result.session_id,
                generation: result.generation,
                sequence: result.sequence,
                capture_timestamp_ns: result.capture_timestamp_ns,
                produced_timestamp_ns: result.produced_timestamp_ns,
                samples: &self.compact_samples,
            },
            &mut self.compact_bytes,
        )?;
        let deadline = Instant::now() + self.config.result_deadline;
        let core_wire = if result.geometry.face_landmarks.is_empty() {
            CanonicalCodec::encode(result)?
        } else {
            let mut core = result.clone();
            core.geometry.face_landmarks.clear();
            CanonicalCodec::encode(&core)?
        };
        let cadence_due = self
            .config
            .geometry_cadence
            .is_some_and(|cadence| result.sequence % cadence == 0);
        let send_geometry = self.geometry_requested || cadence_due;
        let geometry_wire = if send_geometry {
            self.geometry_requested = false;
            Some(CanonicalCodec::encode(result)?)
        } else {
            None
        };

        if self.transport_mode == TrackingTransportMode::ReliableLatestOnly {
            self.reliable.flush(&mut self.connection)?;
            let compact = self.reliable.enqueue(
                COMPACT_RIG_FLOW,
                result.generation,
                result.sequence,
                RealtimePriority::Critical,
                &self.compact_bytes,
                self.config.max_tracking_frame_bytes,
            )?;
            let core = single_frame_batch(self.reliable.enqueue(
                CORE_RESULT_FLOW,
                result.generation,
                result.sequence,
                RealtimePriority::High,
                &core_wire,
                self.config.max_tracking_frame_bytes,
            )?);
            let geometry = geometry_wire
                .as_deref()
                .map(|wire| {
                    self.reliable
                        .enqueue(
                            GEOMETRY_FLOW,
                            result.generation,
                            result.sequence,
                            RealtimePriority::Disposable,
                            wire,
                            self.config.max_tracking_frame_bytes,
                        )
                        .map(single_frame_batch)
                })
                .transpose()?;
            self.reliable.flush(&mut self.connection)?;
            self.last_published_sequence = Some(result.sequence);
            return Ok(PublishOutcome {
                compact,
                core,
                geometry,
            });
        }

        let max_payload = self
            .connection
            .max_datagram_payload()
            .ok_or(BindingError::DatagramsUnsupported)?;
        if self.compact_bytes.len() > max_payload {
            return Err(BindingError::PayloadLimit);
        }
        let compact = self.connection.try_send_latest(RealtimeDatagram {
            flow: COMPACT_RIG_FLOW,
            generation: result.generation,
            sequence: result.sequence,
            deadline,
            priority: RealtimePriority::Critical,
            payload: &self.compact_bytes,
        })?;
        let core = send_fragmented(
            &mut self.connection,
            FragmentSend {
                flow: CORE_RESULT_FLOW,
                generation: result.generation,
                sequence: result.sequence,
                deadline,
                priority: RealtimePriority::High,
                payload: &core_wire,
                config: self.config,
            },
            &mut self.fragment_scratch,
        )?;
        let geometry = geometry_wire
            .as_deref()
            .map(|wire| {
                send_fragmented(
                    &mut self.connection,
                    FragmentSend {
                        flow: GEOMETRY_FLOW,
                        generation: result.generation,
                        sequence: result.sequence,
                        deadline,
                        priority: RealtimePriority::Disposable,
                        payload: wire,
                        config: self.config,
                    },
                    &mut self.fragment_scratch,
                )
            })
            .transpose()?;
        self.last_published_sequence = Some(result.sequence);
        Ok(PublishOutcome {
            compact,
            core,
            geometry,
        })
    }

    pub fn reset_for_reconnect(
        &mut self,
        connection: C,
        authorization: NtpAuthorization,
    ) -> Result<(), BindingError> {
        validate_connection_authorization(&connection, &authorization, NtpRole::Publisher)?;
        if authorization.link_session_id() == self.authorization.link_session_id() {
            return Err(BindingError::SessionBindingMismatch);
        }
        self.connection = connection;
        self.authorization = authorization;
        self.transport_mode = if self.connection.max_datagram_payload().is_some() {
            TrackingTransportMode::Datagram
        } else {
            TrackingTransportMode::ReliableLatestOnly
        };
        self.remote_hello = false;
        self.pending = None;
        self.pending_accepted = false;
        self.active = None;
        self.playback = PlaybackState::Stopped;
        self.outbox.clear();
        self.reliable.clear();
        self.reconfigure_times.clear();
        self.frame_window_started = Instant::now();
        self.frame_window_count = 0;
        self.sustained_window_started = Instant::now();
        self.sustained_frame_count = 0;
        self.rate_limited = 0;
        self.last_published_sequence = None;
        self.geometry_requested = false;
        self.last_report = None;
        Ok(())
    }

    fn note_reconfigure(&mut self, now: Instant) -> Result<(), BindingError> {
        let cutoff = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
        while self
            .reconfigure_times
            .front()
            .is_some_and(|timestamp| *timestamp <= cutoff)
        {
            self.reconfigure_times.pop_front();
        }
        if self.reconfigure_times.len() >= usize::from(self.config.max_reconfigure_per_minute) {
            self.rate_limited = self.rate_limited.saturating_add(1);
            return Err(BindingError::RateLimited);
        }
        self.reconfigure_times.push_back(now);
        Ok(())
    }

    fn note_frame(&mut self, now: Instant, target_fps: u16) -> Result<(), BindingError> {
        if now.duration_since(self.frame_window_started) >= Duration::from_secs(1) {
            self.frame_window_started = now;
            self.frame_window_count = 0;
        }
        if self.frame_window_count >= self.config.max_burst_fps {
            self.rate_limited = self.rate_limited.saturating_add(1);
            return Err(BindingError::RateLimited);
        }
        if now.duration_since(self.sustained_window_started) >= Duration::from_secs(10) {
            self.sustained_window_started = now;
            self.sustained_frame_count = 0;
        }
        let sustained_limit = u32::from(target_fps).saturating_mul(10);
        if self.sustained_frame_count >= sustained_limit {
            self.rate_limited = self.rate_limited.saturating_add(1);
            return Err(BindingError::RateLimited);
        }
        self.frame_window_count = self.frame_window_count.saturating_add(1);
        self.sustained_frame_count = self.sustained_frame_count.saturating_add(1);
        Ok(())
    }
}

struct SubscriberSession {
    descriptor: NanaTrackingDescriptor,
    session_id: SessionId,
    generation: u32,
    layout: ActiveLayout,
    topology: GeometryTopology,
    compact_guard: CompactStreamGuard,
    result_guard: ResultStreamGuard,
}

struct PendingSubscriberSession {
    proposal: SessionProposal,
}

#[derive(Clone, Debug)]
struct GeometryCache {
    session_id: SessionId,
    generation: u32,
    sequence: u64,
    landmarks: Vec<nana_tracking_protocol::FaceLandmark>,
}

pub struct Subscriber<C: Connection> {
    connection: C,
    authorization: NtpAuthorization,
    transport_mode: TrackingTransportMode,
    config: BindingConfig,
    remote_hello: bool,
    negotiator: LayoutNegotiator,
    pending: Option<PendingSubscriberSession>,
    active: Option<SubscriberSession>,
    outbox: VecDeque<Vec<u8>>,
    core_reassembly: Reassembler,
    geometry_reassembly: Reassembler,
    reliable: reliable::ReliableLatestReceiver,
    geometry_cache: Option<GeometryCache>,
    report: ReceiverReport,
    previous_age_ns: Option<u64>,
    clock: ClockSynchronizer,
    reconfigure_times: VecDeque<Instant>,
    receive_window_started: Instant,
    receive_window_count: u16,
    sustained_receive_window_started: Instant,
    sustained_receive_count: u32,
    rate_limited: u64,
    protocol_violations: u16,
    malformed_frames: u64,
    fused: bool,
}

impl<C: Connection> Subscriber<C> {
    pub fn new(
        connection: C,
        authorization: NtpAuthorization,
        config: BindingConfig,
    ) -> Result<Self, BindingError> {
        let config = config.validate()?;
        validate_connection_authorization(&connection, &authorization, NtpRole::Subscriber)?;
        let transport_mode = if connection.max_datagram_payload().is_some() {
            TrackingTransportMode::Datagram
        } else {
            TrackingTransportMode::ReliableLatestOnly
        };
        if !connection.metadata().reliable {
            return Err(BindingError::InvalidState);
        }
        Ok(Self {
            connection,
            authorization,
            transport_mode,
            config,
            remote_hello: false,
            negotiator: LayoutNegotiator::new(HandshakeLimits::default())?,
            pending: None,
            active: None,
            outbox: VecDeque::with_capacity(config.max_pending_control),
            core_reassembly: Reassembler::new(),
            geometry_reassembly: Reassembler::new(),
            reliable: reliable::ReliableLatestReceiver::default(),
            geometry_cache: None,
            report: ReceiverReport::default(),
            previous_age_ns: None,
            clock: ClockSynchronizer::default(),
            reconfigure_times: VecDeque::new(),
            receive_window_started: Instant::now(),
            receive_window_count: 0,
            sustained_receive_window_started: Instant::now(),
            sustained_receive_count: 0,
            rate_limited: 0,
            protocol_violations: 0,
            malformed_frames: 0,
            fused: false,
        })
    }

    pub fn into_inner(self) -> C {
        self.connection
    }

    pub fn connection(&self) -> &C {
        &self.connection
    }

    pub fn descriptor(&self) -> Option<&NanaTrackingDescriptor> {
        self.active.as_ref().map(|session| &session.descriptor)
    }

    pub fn topology(&self) -> Option<GeometryTopology> {
        self.active.as_ref().map(|session| session.topology)
    }

    pub fn receiver_report(&self) -> ReceiverReport {
        self.report
    }

    pub const fn transport_mode(&self) -> TrackingTransportMode {
        self.transport_mode
    }

    pub fn bound_session(&self) -> Option<BoundNtpSession> {
        self.active.as_ref().map(|active| BoundNtpSession {
            peer_id: self.authorization.peer_id(),
            link_session_id: self.authorization.link_session_id(),
            ntp_session_id: active.session_id,
            generation: active.generation,
            layout_id: active.layout.layout_id(),
            layout_hash: active.layout.confirmation().layout_hash,
            expected_frame_len: u32::try_from(active.layout.frame_len())
                .expect("validated NTP frame length fits u32"),
            value_encoding: active.layout.proposal().value_encoding,
            target_fps: active.layout.proposal().target_fps,
            transport_mode: self.transport_mode,
        })
    }

    pub fn telemetry(&self) -> TrackingTelemetry {
        TrackingTelemetry {
            queue_replacements: self.reliable.replacements(),
            rate_limited: self.rate_limited,
            malformed_frames: self.malformed_frames,
            fuse_tripped: self.fused,
            replay_dropped: self.reliable.stale_discarded(),
            ..TrackingTelemetry::default()
        }
    }

    pub fn try_send_hello(&mut self) -> Result<(), BindingError> {
        queue_control(
            &mut self.outbox,
            Message::Hello(ProtocolHello::new(self.authorization.link_session_id())),
            self.config,
        )?;
        flush_control(&mut self.connection, &mut self.outbox)
    }

    pub fn try_send_command(&mut self, command: SessionCommand) -> Result<(), BindingError> {
        if self.active.is_none() {
            return Err(BindingError::InvalidState);
        }
        queue_control(&mut self.outbox, Message::Command(command), self.config)?;
        flush_control(&mut self.connection, &mut self.outbox)
    }

    pub fn try_request_geometry(&mut self) -> Result<(), BindingError> {
        if self.active.is_none() {
            return Err(BindingError::InvalidState);
        }
        queue_control(&mut self.outbox, Message::GeometryRequest, self.config)?;
        flush_control(&mut self.connection, &mut self.outbox)
    }

    pub fn try_send_ping(&mut self, receiver_now_ns: u64) -> Result<(), BindingError> {
        self.clock.note_ping(receiver_now_ns);
        queue_control(
            &mut self.outbox,
            Message::Ping {
                receiver_send_ns: receiver_now_ns,
            },
            self.config,
        )?;
        flush_control(&mut self.connection, &mut self.outbox)
    }

    pub fn try_send_receiver_report(&mut self) -> Result<(), BindingError> {
        queue_control(
            &mut self.outbox,
            Message::ReceiverReport(self.report),
            self.config,
        )?;
        flush_control(&mut self.connection, &mut self.outbox)
    }

    pub fn producer_clock(&self, receiver_now_ns: u64) -> Option<ProducerClockEstimate> {
        self.clock.estimate(receiver_now_ns)
    }

    pub fn poll_control(
        &mut self,
        receiver_now_ns: u64,
    ) -> Result<Option<SubscriberEvent>, BindingError> {
        flush_control(&mut self.connection, &mut self.outbox)?;
        let Some(message) = receive_control(&mut self.connection, self.config)? else {
            return Ok(None);
        };
        let event = match message {
            Message::Hello(hello) => {
                validate_hello(hello, self.authorization.link_session_id())?;
                self.remote_hello = true;
                SubscriberEvent::HelloAccepted
            }
            Message::SessionProposal(proposal) => {
                if !self.remote_hello || self.pending.is_some() {
                    return Err(BindingError::InvalidState);
                }
                if self.active.is_some() {
                    self.note_reconfigure(Instant::now())?;
                }
                if self.active.as_ref().is_some_and(|active| {
                    active.session_id == proposal.session_id
                        && proposal.generation <= active.generation
                }) {
                    return Err(BindingError::InvalidState);
                }
                let accept = self.negotiator.receive_proposal(
                    proposal.layout_id,
                    proposal.layout.clone(),
                    &proposal.descriptor,
                    receiver_now_ns,
                )?;
                queue_control(
                    &mut self.outbox,
                    Message::LayoutAccepted(accept),
                    self.config,
                )?;
                self.pending = Some(PendingSubscriberSession { proposal });
                SubscriberEvent::ProposalAccepted
            }
            Message::LayoutConfirmed(confirm) => {
                let pending = self.pending.take().ok_or(BindingError::InvalidState)?;
                let layout = self.negotiator.confirm(confirm)?;
                let compact_guard = CompactStreamGuard::confirmed(
                    pending.proposal.session_id,
                    pending.proposal.generation,
                    layout.clone(),
                    confirm,
                    self.config.compact_policy,
                )?;
                let result_guard = ResultStreamGuard::new(
                    pending.proposal.session_id,
                    pending.proposal.generation,
                );
                self.active = Some(SubscriberSession {
                    descriptor: pending.proposal.descriptor,
                    session_id: pending.proposal.session_id,
                    generation: pending.proposal.generation,
                    layout: layout.clone(),
                    topology: pending.proposal.topology,
                    compact_guard,
                    result_guard,
                });
                self.core_reassembly.clear();
                self.geometry_reassembly.clear();
                self.geometry_cache = None;
                self.previous_age_ns = None;
                queue_control(
                    &mut self.outbox,
                    Message::SessionReady {
                        session_id: pending.proposal.session_id,
                        generation: pending.proposal.generation,
                        layout_id: pending.proposal.layout_id,
                    },
                    self.config,
                )?;
                SubscriberEvent::SessionReady
            }
            Message::Pong {
                receiver_send_ns,
                producer_send_ns,
            } => {
                self.clock
                    .note_pong(receiver_send_ns, producer_send_ns, receiver_now_ns)?;
                self.report.clock_uncertainty_ns = self.clock.uncertainty_ns().unwrap_or(0);
                SubscriberEvent::ClockSynchronized
            }
            Message::Error { code, .. } => SubscriberEvent::RemoteError(code),
            Message::Close { code, .. } => SubscriberEvent::RemoteClosed(code),
            _ => return Err(BindingError::InvalidControl),
        };
        flush_control(&mut self.connection, &mut self.outbox)?;
        Ok(Some(event))
    }

    pub fn poll_realtime<F>(
        &mut self,
        clock: ProducerClockEstimate,
        on_compact: F,
    ) -> Result<(ReceiveOutcome, Option<NanaTrackingResult>), BindingError>
    where
        F: FnMut(CompactFrameRef<'_>),
    {
        if self.fused {
            return Err(BindingError::ChannelFused);
        }
        let result = self.poll_realtime_inner(clock, on_compact);
        if result.as_ref().is_err_and(is_protocol_violation) {
            self.protocol_violations = self.protocol_violations.saturating_add(1);
            self.malformed_frames = self.malformed_frames.saturating_add(1);
            if self.protocol_violations >= self.config.max_protocol_violations {
                self.fused = true;
            }
        }
        result
    }

    fn poll_realtime_inner<F>(
        &mut self,
        clock: ProducerClockEstimate,
        mut on_compact: F,
    ) -> Result<(ReceiveOutcome, Option<NanaTrackingResult>), BindingError>
    where
        F: FnMut(CompactFrameRef<'_>),
    {
        let message = if self.transport_mode == TrackingTransportMode::Datagram {
            match self.connection.try_receive_realtime() {
                Ok(message) => message,
                Err(error) if error.kind == TransportErrorKind::WouldBlock => None,
                Err(error) => return Err(error.into()),
            }
        } else {
            self.reliable.poll(
                &mut self.connection,
                self.config.max_tracking_frame_bytes,
                self.config.max_receive_frames_per_poll,
            )?
        };
        let Some(message) = message else {
            return Ok((ReceiveOutcome::Idle, None));
        };
        if message.flow == COMPACT_RIG_FLOW {
            let target_fps = self
                .active
                .as_ref()
                .ok_or(BindingError::InvalidState)?
                .layout
                .proposal()
                .target_fps;
            self.note_received_frame(Instant::now(), target_fps)?;
        }
        if message.payload.len() > self.config.max_tracking_frame_bytes {
            self.report.dropped = self.report.dropped.saturating_add(1);
            return Err(BindingError::PayloadLimit);
        }
        let active_generation = self
            .active
            .as_ref()
            .ok_or(BindingError::InvalidState)?
            .generation;
        if message.generation != active_generation {
            self.report.dropped = self.report.dropped.saturating_add(1);
            return Ok((ReceiveOutcome::Progress, None));
        }

        match message.flow {
            COMPACT_RIG_FLOW => {
                let expected_frame_len = self
                    .active
                    .as_ref()
                    .ok_or(BindingError::InvalidState)?
                    .layout
                    .frame_len();
                if message.payload.len() != expected_frame_len {
                    self.report.dropped = self.report.dropped.saturating_add(1);
                    return Err(BindingError::LayoutMismatch);
                }
                let age = {
                    let active = self.active.as_mut().ok_or(BindingError::InvalidState)?;
                    let frame = active.compact_guard.accept(&message.payload, clock)?;
                    if frame.sequence != message.sequence || frame.generation != message.generation
                    {
                        return Err(BindingError::InvalidFragment);
                    }
                    let age = clock.now_ns().saturating_sub(frame.capture_timestamp_ns);
                    on_compact(frame);
                    age
                };
                self.note_age(age);
                Ok((ReceiveOutcome::Progress, None))
            }
            CORE_RESULT_FLOW => {
                let (generation, sequence, payload) =
                    if self.transport_mode == TrackingTransportMode::ReliableLatestOnly {
                        (message.generation, message.sequence, message.payload)
                    } else {
                        let outcome = self.core_reassembly.push(
                            message.generation,
                            message.sequence,
                            &message.payload,
                            self.config,
                        )?;
                        self.note_reassembly_replacement(&outcome);
                        let ReassemblyOutcome::Complete {
                            generation,
                            sequence,
                            payload,
                            ..
                        } = outcome
                        else {
                            return Ok((ReceiveOutcome::Progress, None));
                        };
                        (generation, sequence, payload)
                    };
                let mut result = NanaTrackingResult::decode_wire(&payload)?;
                if result.generation != generation || result.sequence != sequence {
                    return Err(BindingError::InvalidFragment);
                }
                if let Some(cache) = &self.geometry_cache {
                    if cache.session_id == result.session_id
                        && cache.generation == result.generation
                        && cache.sequence <= result.sequence
                    {
                        result.geometry.face_landmarks.clone_from(&cache.landmarks);
                    }
                }
                let age = clock.now_ns().saturating_sub(result.capture_timestamp_ns);
                if age
                    > self
                        .config
                        .max_result_age_ns()
                        .saturating_add(clock.uncertainty_ns())
                {
                    self.report.stale = self.report.stale.saturating_add(1);
                    self.note_age(age);
                    return Ok((ReceiveOutcome::Progress, None));
                }
                let accepted = {
                    let active = self.active.as_mut().ok_or(BindingError::InvalidState)?;
                    active.descriptor.validate_result(&result)?;
                    active.result_guard.accept(&result)?
                };
                self.report.received = self.report.received.saturating_add(1);
                self.report.dropped = self
                    .report
                    .dropped
                    .saturating_add(accepted.missing_sequences);
                self.note_age(age);
                Ok((ReceiveOutcome::Progress, Some(result)))
            }
            GEOMETRY_FLOW => {
                let complete = if self.transport_mode == TrackingTransportMode::ReliableLatestOnly {
                    Some((message.generation, message.sequence, message.payload))
                } else {
                    let outcome = self.geometry_reassembly.push(
                        message.generation,
                        message.sequence,
                        &message.payload,
                        self.config,
                    )?;
                    self.note_reassembly_replacement(&outcome);
                    match outcome {
                        ReassemblyOutcome::Complete {
                            generation,
                            sequence,
                            payload,
                            ..
                        } => Some((generation, sequence, payload)),
                        ReassemblyOutcome::Pending { .. } | ReassemblyOutcome::IgnoredOld => None,
                    }
                };
                if let Some((generation, sequence, payload)) = complete {
                    let result = NanaTrackingResult::decode_wire(&payload)?;
                    let active = self.active.as_ref().ok_or(BindingError::InvalidState)?;
                    if result.session_id != active.session_id
                        || result.generation != generation
                        || result.sequence != sequence
                    {
                        return Err(BindingError::InvalidFragment);
                    }
                    active.descriptor.validate_result(&result)?;
                    self.geometry_cache = Some(GeometryCache {
                        session_id: result.session_id,
                        generation,
                        sequence,
                        landmarks: result.geometry.face_landmarks,
                    });
                }
                Ok((ReceiveOutcome::Progress, None))
            }
            _ => Ok((ReceiveOutcome::Progress, None)),
        }
    }

    pub fn reset_for_reconnect(
        &mut self,
        connection: C,
        authorization: NtpAuthorization,
    ) -> Result<(), BindingError> {
        validate_connection_authorization(&connection, &authorization, NtpRole::Subscriber)?;
        if authorization.link_session_id() == self.authorization.link_session_id() {
            return Err(BindingError::SessionBindingMismatch);
        }
        self.connection = connection;
        self.authorization = authorization;
        self.transport_mode = if self.connection.max_datagram_payload().is_some() {
            TrackingTransportMode::Datagram
        } else {
            TrackingTransportMode::ReliableLatestOnly
        };
        self.remote_hello = false;
        self.negotiator = LayoutNegotiator::new(HandshakeLimits::default())?;
        self.pending = None;
        self.active = None;
        self.outbox.clear();
        self.core_reassembly.clear();
        self.geometry_reassembly.clear();
        self.reliable.clear();
        self.geometry_cache = None;
        self.report = ReceiverReport::default();
        self.previous_age_ns = None;
        self.clock = ClockSynchronizer::default();
        self.reconfigure_times.clear();
        self.receive_window_started = Instant::now();
        self.receive_window_count = 0;
        self.sustained_receive_window_started = Instant::now();
        self.sustained_receive_count = 0;
        self.rate_limited = 0;
        self.protocol_violations = 0;
        self.malformed_frames = 0;
        self.fused = false;
        Ok(())
    }

    fn note_reconfigure(&mut self, now: Instant) -> Result<(), BindingError> {
        let cutoff = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
        while self
            .reconfigure_times
            .front()
            .is_some_and(|timestamp| *timestamp <= cutoff)
        {
            self.reconfigure_times.pop_front();
        }
        if self.reconfigure_times.len() >= usize::from(self.config.max_reconfigure_per_minute) {
            self.rate_limited = self.rate_limited.saturating_add(1);
            return Err(BindingError::RateLimited);
        }
        self.reconfigure_times.push_back(now);
        Ok(())
    }

    fn note_received_frame(&mut self, now: Instant, target_fps: u16) -> Result<(), BindingError> {
        if now.duration_since(self.receive_window_started) >= Duration::from_secs(1) {
            self.receive_window_started = now;
            self.receive_window_count = 0;
        }
        if self.receive_window_count >= self.config.max_burst_fps {
            self.rate_limited = self.rate_limited.saturating_add(1);
            self.report.dropped = self.report.dropped.saturating_add(1);
            return Err(BindingError::RateLimited);
        }
        if now.duration_since(self.sustained_receive_window_started) >= Duration::from_secs(10) {
            self.sustained_receive_window_started = now;
            self.sustained_receive_count = 0;
        }
        let sustained_limit = u32::from(target_fps).saturating_mul(10);
        if self.sustained_receive_count >= sustained_limit {
            self.rate_limited = self.rate_limited.saturating_add(1);
            self.report.dropped = self.report.dropped.saturating_add(1);
            return Err(BindingError::RateLimited);
        }
        self.receive_window_count = self.receive_window_count.saturating_add(1);
        self.sustained_receive_count = self.sustained_receive_count.saturating_add(1);
        Ok(())
    }

    fn note_reassembly_replacement(&mut self, outcome: &ReassemblyOutcome) {
        let replaced = match outcome {
            ReassemblyOutcome::Pending {
                replaced_incomplete,
            }
            | ReassemblyOutcome::Complete {
                replaced_incomplete,
                ..
            } => *replaced_incomplete,
            ReassemblyOutcome::IgnoredOld => true,
        };
        if replaced {
            self.report.dropped = self.report.dropped.saturating_add(1);
        }
    }

    fn note_age(&mut self, age_ns: u64) {
        if let Some(previous) = self.previous_age_ns {
            let sample = age_ns.abs_diff(previous);
            self.report.jitter_ns = if self.report.jitter_ns == 0 {
                sample
            } else {
                self.report
                    .jitter_ns
                    .saturating_mul(7)
                    .saturating_add(sample)
                    / 8
            };
        }
        self.previous_age_ns = Some(age_ns);
        self.report.result_age_ns = age_ns;
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ClockSynchronizer {
    pending_ping: Option<u64>,
    offset: Option<i128>,
    uncertainty: Option<u64>,
}

impl ClockSynchronizer {
    pub fn note_ping(&mut self, receiver_send_ns: u64) {
        self.pending_ping = Some(receiver_send_ns);
    }

    pub fn note_pong(
        &mut self,
        receiver_send_ns: u64,
        producer_send_ns: u64,
        receiver_receive_ns: u64,
    ) -> Result<(), BindingError> {
        if self.pending_ping != Some(receiver_send_ns) || receiver_receive_ns < receiver_send_ns {
            return Err(BindingError::InvalidControl);
        }
        let uncertainty_ns = receiver_receive_ns.saturating_sub(receiver_send_ns) / 2;
        let producer_at_receive = producer_send_ns.saturating_add(uncertainty_ns);
        self.offset =
            Some(i128::from(producer_at_receive).saturating_sub(i128::from(receiver_receive_ns)));
        self.uncertainty = Some(uncertainty_ns);
        self.pending_ping = None;
        Ok(())
    }

    #[must_use]
    pub fn estimate(&self, receiver_now_ns: u64) -> Option<ProducerClockEstimate> {
        let mapped = i128::from(receiver_now_ns).saturating_add(self.offset?);
        let now_ns = if mapped <= 0 {
            0
        } else {
            u64::try_from(mapped).unwrap_or(u64::MAX)
        };
        Some(ProducerClockEstimate::synchronized(
            now_ns,
            self.uncertainty?,
        ))
    }

    #[must_use]
    pub const fn uncertainty_ns(&self) -> Option<u64> {
        self.uncertainty
    }
}

fn protocol() -> ProtocolId {
    ProtocolId::new(CONTROL_PROTOCOL).expect("static NTP control protocol is valid")
}

fn queue_control(
    outbox: &mut VecDeque<Vec<u8>>,
    message: Message,
    config: BindingConfig,
) -> Result<(), BindingError> {
    if outbox.len() >= config.max_pending_control {
        return Err(BindingError::ControlLimit);
    }
    let encoded = message.encode()?;
    if encoded.len() > config.max_control_bytes {
        return Err(BindingError::ControlLimit);
    }
    outbox.push_back(encoded);
    Ok(())
}

fn flush_control<C: Connection>(
    connection: &mut C,
    outbox: &mut VecDeque<Vec<u8>>,
) -> Result<(), BindingError> {
    while let Some(message) = outbox.front() {
        let result = connection
            .open_control_stream(protocol())?
            .try_send(message);
        match result {
            Ok(()) => {
                outbox.pop_front();
            }
            Err(error) if error.kind == TransportErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn receive_control<C: Connection>(
    connection: &mut C,
    config: BindingConfig,
) -> Result<Option<Message>, BindingError> {
    match connection.open_control_stream(protocol())?.try_receive() {
        Ok(Some(bytes)) if bytes.len() <= config.max_control_bytes => {
            Ok(Some(Message::decode(&bytes)?))
        }
        Ok(Some(_)) => Err(BindingError::ControlLimit),
        Ok(None) => Ok(None),
        Err(error) if error.kind == TransportErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn validate_hello(
    hello: ProtocolHello,
    expected_link_session_id: LinkSessionId,
) -> Result<(), BindingError> {
    if hello.minimum_version > 2 || hello.maximum_version < 2 {
        Err(BindingError::IncompatibleVersion)
    } else if hello.link_session_id != expected_link_session_id {
        Err(BindingError::SessionBindingMismatch)
    } else {
        Ok(())
    }
}

fn validate_connection_authorization<C: Connection>(
    connection: &C,
    authorization: &NtpAuthorization,
    expected_role: NtpRole,
) -> Result<(), BindingError> {
    if authorization.role() != expected_role {
        return Err(BindingError::Unauthorized);
    }
    if connection
        .metadata()
        .peer_hint
        .is_some_and(|peer| peer != authorization.peer_id())
    {
        return Err(BindingError::SessionBindingMismatch);
    }
    Ok(())
}

fn is_protocol_violation(error: &BindingError) -> bool {
    matches!(
        error,
        BindingError::Codec(_)
            | BindingError::Contract(_)
            | BindingError::Compact(_)
            | BindingError::CompactStream(_)
            | BindingError::Stream(_)
            | BindingError::InvalidFragment
            | BindingError::LayoutMismatch
            | BindingError::PayloadLimit
    )
}

fn bound_session(
    authorization: &NtpAuthorization,
    active: &SessionDefinition,
    transport_mode: TrackingTransportMode,
) -> BoundNtpSession {
    BoundNtpSession {
        peer_id: authorization.peer_id(),
        link_session_id: authorization.link_session_id(),
        ntp_session_id: active.session_id,
        generation: active.generation,
        layout_id: active.layout.layout_id(),
        layout_hash: active.layout.confirmation().layout_hash,
        expected_frame_len: u32::try_from(active.layout.frame_len())
            .expect("validated NTP frame length fits u32"),
        value_encoding: active.layout.proposal().value_encoding,
        target_fps: active.layout.proposal().target_fps,
        transport_mode,
    }
}

fn single_frame_batch(outcome: SendOutcome) -> FragmentBatchOutcome {
    FragmentBatchOutcome {
        fragments: 1,
        enqueued: usize::from(matches!(outcome, SendOutcome::Enqueued)),
        replaced: usize::from(matches!(outcome, SendOutcome::ReplacedOlder)),
        expired: usize::from(matches!(outcome, SendOutcome::DroppedExpired)),
        congested: usize::from(matches!(
            outcome,
            SendOutcome::DroppedCongested | SendOutcome::Unsupported
        )),
    }
}
