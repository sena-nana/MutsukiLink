use crate::{ChannelKey, PeerId, SessionId};
use core::fmt;
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestReplay {
    /// Default for unacknowledged requests: Link never sends it again.
    Never,
    /// The namespace owner explicitly declared the request safe to repeat.
    Idempotent,
    /// Link reports it to the owner, which decides whether to create a new request.
    ApplicationDecides,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelCursor {
    pub channel: ChannelKey,
    /// Opaque sequence/cursor understood only by the namespace owner.
    pub cursor: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeOffer {
    pub token: Vec<u8>,
    pub peer_id: PeerId,
    pub previous_session_id: SessionId,
    pub expires_at_unix_ms: u64,
    pub channel_cursors: Vec<ChannelCursor>,
}

pub trait ResumeTokenVerifier {
    /// Verifies authenticity and binding. Implementations should use a MAC or
    /// signature and reject tokens created for another endpoint or protocol set.
    fn verify(&self, offer: &ResumeOffer) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeLimits {
    pub max_token_bytes: usize,
    pub max_channels: usize,
    pub max_cursor_bytes: usize,
    pub max_pending_requests: usize,
}

impl Default for ResumeLimits {
    fn default() -> Self {
        Self {
            max_token_bytes: 512,
            max_channels: 64,
            max_cursor_bytes: 256,
            max_pending_requests: 128,
        }
    }
}

impl ResumeLimits {
    pub const fn is_valid(self) -> bool {
        self.max_token_bytes > 0
            && self.max_channels > 0
            && self.max_cursor_bytes > 0
            && self.max_pending_requests > 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NewSessionReason {
    NoResumeRequested,
    TokenRejected,
    TokenExpired,
    PeerMismatch,
    LimitsExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionContinuity {
    NewSession { reason: NewSessionReason },
    Resumed { previous_session_id: SessionId },
}

impl Default for SessionContinuity {
    fn default() -> Self {
        Self::NewSession {
            reason: NewSessionReason::NoResumeRequested,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResumeErrorKind {
    InvalidLimits,
    TokenTooLarge,
    TooManyChannels,
    CursorTooLarge,
    TooManyPendingRequests,
    DuplicateRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeError {
    pub kind: ResumeErrorKind,
    pub public_message: &'static str,
}

impl fmt::Display for ResumeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.public_message)
    }
}

impl std::error::Error for ResumeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingRequest {
    id: u64,
    replay: RequestReplay,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReplayPlan {
    /// Only requests explicitly declared idempotent appear here.
    pub automatically_retry: Vec<u64>,
    /// The owner receives these IDs and must make a new explicit decision.
    pub application_decision: Vec<u64>,
    /// Non-idempotent/default requests are failed without retransmission.
    pub fail_without_retry: Vec<u64>,
}

#[derive(Debug)]
pub struct ResumeCoordinator {
    limits: ResumeLimits,
    pending: VecDeque<PendingRequest>,
}

impl ResumeCoordinator {
    pub fn new(limits: ResumeLimits) -> Result<Self, ResumeError> {
        if !limits.is_valid() {
            return Err(error(ResumeErrorKind::InvalidLimits));
        }
        Ok(Self {
            limits,
            pending: VecDeque::new(),
        })
    }

    pub fn validate_offer(
        &self,
        offer: &ResumeOffer,
        expected_peer: PeerId,
        now_unix_ms: u64,
        verifier: &impl ResumeTokenVerifier,
    ) -> SessionContinuity {
        if offer.peer_id != expected_peer {
            return new_session(NewSessionReason::PeerMismatch);
        }
        if now_unix_ms >= offer.expires_at_unix_ms {
            return new_session(NewSessionReason::TokenExpired);
        }
        if offer.token.is_empty()
            || offer.token.len() > self.limits.max_token_bytes
            || offer.channel_cursors.len() > self.limits.max_channels
            || offer
                .channel_cursors
                .iter()
                .any(|cursor| cursor.cursor.len() > self.limits.max_cursor_bytes)
        {
            return new_session(NewSessionReason::LimitsExceeded);
        }
        if !verifier.verify(offer) {
            return new_session(NewSessionReason::TokenRejected);
        }
        SessionContinuity::Resumed {
            previous_session_id: offer.previous_session_id,
        }
    }

    pub fn record_unacknowledged(
        &mut self,
        request_id: u64,
        replay: RequestReplay,
    ) -> Result<(), ResumeError> {
        if self.pending.iter().any(|request| request.id == request_id) {
            return Err(error(ResumeErrorKind::DuplicateRequest));
        }
        if self.pending.len() >= self.limits.max_pending_requests {
            return Err(error(ResumeErrorKind::TooManyPendingRequests));
        }
        self.pending.push_back(PendingRequest {
            id: request_id,
            replay,
        });
        Ok(())
    }

    pub fn acknowledge(&mut self, request_id: u64) -> bool {
        let Some(index) = self
            .pending
            .iter()
            .position(|request| request.id == request_id)
        else {
            return false;
        };
        self.pending.remove(index);
        true
    }

    pub fn plan_after_reconnect(&mut self, continuity: SessionContinuity) -> ReplayPlan {
        let mut plan = ReplayPlan::default();
        while let Some(request) = self.pending.pop_front() {
            match (continuity, request.replay) {
                (SessionContinuity::Resumed { .. }, RequestReplay::Idempotent) => {
                    plan.automatically_retry.push(request.id);
                }
                (_, RequestReplay::ApplicationDecides) => {
                    plan.application_decision.push(request.id);
                }
                _ => plan.fail_without_retry.push(request.id),
            }
        }
        plan
    }

    pub fn pending_requests(&self) -> usize {
        self.pending.len()
    }
}

const fn new_session(reason: NewSessionReason) -> SessionContinuity {
    SessionContinuity::NewSession { reason }
}

const fn error(kind: ResumeErrorKind) -> ResumeError {
    let public_message = match kind {
        ResumeErrorKind::InvalidLimits => "resume limits must be positive",
        ResumeErrorKind::TokenTooLarge => "resume token exceeds configured limit",
        ResumeErrorKind::TooManyChannels => "resume channel count exceeds configured limit",
        ResumeErrorKind::CursorTooLarge => "resume cursor exceeds configured limit",
        ResumeErrorKind::TooManyPendingRequests => "pending request count exceeds configured limit",
        ResumeErrorKind::DuplicateRequest => "request is already awaiting acknowledgement",
    };
    ResumeError {
        kind,
        public_message,
    }
}
