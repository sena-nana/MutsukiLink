use crate::{KeyState, LinkPermission, TrustRecord};
use mutsuki_link_core::{PeerId, ProtocolVersion};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, VecDeque};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PairingId([u8; 16]);

impl PairingId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LongTermIdentity {
    pub peer_id: PeerId,
    pub public_key: Vec<u8>,
    pub display_name: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingMethod {
    ShortCode,
    QrCode,
    BilateralConfirmation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingOffer {
    pub pairing_id: PairingId,
    pub initiator: LongTermIdentity,
    pub protocol_version: ProtocolVersion,
    pub challenge: [u8; 32],
    pub method: PairingMethod,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingResponse {
    pub pairing_id: PairingId,
    pub responder: LongTermIdentity,
    pub transcript_hash: [u8; 32],
    pub short_code: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingConfirmation {
    pub pairing_id: PairingId,
    pub signer_peer_id: PeerId,
    pub transcript_hash: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingTerminationReason {
    Rejected,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingTermination {
    pub pairing_id: PairingId,
    pub reason: PairingTerminationReason,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingPresentation {
    pub peer_name: String,
    pub peer_fingerprint: [u8; 32],
    pub short_code: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingRole {
    Initiator,
    Responder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingState {
    AwaitingResponse,
    AwaitingUserConfirmation,
    AwaitingPeerConfirmation,
    Paired,
    Rejected,
    TimedOut,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PairingEvent {
    StateChanged(PairingState),
    Present(PairingPresentation),
    Completed(PeerId),
    EventsDropped(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingErrorKind {
    InvalidInput,
    InvalidState,
    DuplicatePairing,
    TimedOut,
    Cancelled,
    Rejected,
    CodeMismatch,
    TranscriptMismatch,
    IdentityProofRejected,
    ReplayDetected,
    RateLimited,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingError {
    pub kind: PairingErrorKind,
    pub public_message: &'static str,
}

impl PairingError {
    const fn new(kind: PairingErrorKind, public_message: &'static str) -> Self {
        Self {
            kind,
            public_message,
        }
    }
}

impl fmt::Display for PairingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.public_message)
    }
}

impl std::error::Error for PairingError {}

/// The identity owner supplies a real signature backend. Pairing core only
/// defines what transcript is signed and verified.
pub trait PairingCrypto {
    fn sign_transcript(&self, transcript_hash: &[u8; 32]) -> Result<Vec<u8>, PairingError>;
    fn verify_transcript(
        &self,
        public_key: &[u8],
        transcript_hash: &[u8; 32],
        signature: &[u8],
    ) -> bool;
}

#[derive(Debug)]
pub struct ReplayGuard {
    capacity: usize,
    order: VecDeque<[u8; 32]>,
    challenges: BTreeSet<[u8; 32]>,
}

impl ReplayGuard {
    pub fn new(capacity: usize) -> Result<Self, PairingError> {
        if capacity == 0 {
            return Err(PairingError::new(
                PairingErrorKind::InvalidInput,
                "replay guard capacity must be positive",
            ));
        }
        Ok(Self {
            capacity,
            order: VecDeque::new(),
            challenges: BTreeSet::new(),
        })
    }

    pub fn reserve(&mut self, challenge: &[u8; 32]) -> Result<[u8; 32], PairingError> {
        let hash: [u8; 32] = Sha256::digest(challenge).into();
        if !self.challenges.insert(hash) {
            return Err(PairingError::new(
                PairingErrorKind::ReplayDetected,
                "pairing challenge was already used",
            ));
        }
        self.order.push_back(hash);
        if self.order.len() > self.capacity {
            if let Some(expired) = self.order.pop_front() {
                self.challenges.remove(&expired);
            }
        }
        Ok(hash)
    }
}

#[derive(Debug)]
pub struct PairingSession {
    role: PairingRole,
    state: PairingState,
    local: LongTermIdentity,
    remote: Option<LongTermIdentity>,
    pairing_id: PairingId,
    protocol_version: ProtocolVersion,
    challenge: [u8; 32],
    method: PairingMethod,
    expires_at_unix_ms: u64,
    transcript_hash: Option<[u8; 32]>,
    short_code: Option<String>,
    local_confirmed: bool,
    remote_confirmed: bool,
    events: VecDeque<PairingEvent>,
    event_capacity: usize,
    dropped_events: u64,
}

impl PairingSession {
    pub fn initiator(
        local: LongTermIdentity,
        pairing_id: PairingId,
        protocol_version: ProtocolVersion,
        challenge: [u8; 32],
        method: PairingMethod,
        expires_at_unix_ms: u64,
        already_trusted: bool,
        event_capacity: usize,
    ) -> Result<Self, PairingError> {
        validate_identity(&local)?;
        validate_new(already_trusted, expires_at_unix_ms, event_capacity)?;
        Ok(Self {
            role: PairingRole::Initiator,
            state: PairingState::AwaitingResponse,
            local,
            remote: None,
            pairing_id,
            protocol_version,
            challenge,
            method,
            expires_at_unix_ms,
            transcript_hash: None,
            short_code: None,
            local_confirmed: false,
            remote_confirmed: false,
            events: VecDeque::new(),
            event_capacity,
            dropped_events: 0,
        })
    }

    pub fn responder(
        local: LongTermIdentity,
        offer: PairingOffer,
        now_unix_ms: u64,
        already_trusted: bool,
        event_capacity: usize,
    ) -> Result<(Self, PairingResponse), PairingError> {
        validate_identity(&local)?;
        validate_identity(&offer.initiator)?;
        validate_new(already_trusted, offer.expires_at_unix_ms, event_capacity)?;
        if now_unix_ms >= offer.expires_at_unix_ms {
            return Err(PairingError::new(
                PairingErrorKind::TimedOut,
                "pairing offer expired",
            ));
        }
        let transcript_hash = transcript_hash(
            &offer.initiator,
            &local,
            offer.protocol_version,
            &offer.challenge,
            offer.method,
        );
        let short_code = short_code(&transcript_hash);
        let response = PairingResponse {
            pairing_id: offer.pairing_id,
            responder: local.clone(),
            transcript_hash,
            short_code: short_code.clone(),
        };
        let presentation = presentation(&offer.initiator, &short_code);
        let mut session = Self {
            role: PairingRole::Responder,
            state: PairingState::AwaitingUserConfirmation,
            local,
            remote: Some(offer.initiator),
            pairing_id: offer.pairing_id,
            protocol_version: offer.protocol_version,
            challenge: offer.challenge,
            method: offer.method,
            expires_at_unix_ms: offer.expires_at_unix_ms,
            transcript_hash: Some(transcript_hash),
            short_code: Some(short_code),
            local_confirmed: false,
            remote_confirmed: false,
            events: VecDeque::new(),
            event_capacity,
            dropped_events: 0,
        };
        session.emit(PairingEvent::Present(presentation));
        Ok((session, response))
    }

    pub fn role(&self) -> PairingRole {
        self.role
    }

    pub fn state(&self) -> PairingState {
        self.state
    }

    pub fn offer(&self) -> Result<PairingOffer, PairingError> {
        if self.role != PairingRole::Initiator || self.state != PairingState::AwaitingResponse {
            return Err(invalid_state());
        }
        Ok(PairingOffer {
            pairing_id: self.pairing_id,
            initiator: self.local.clone(),
            protocol_version: self.protocol_version,
            challenge: self.challenge,
            method: self.method,
            expires_at_unix_ms: self.expires_at_unix_ms,
        })
    }

    pub fn receive_response(
        &mut self,
        response: PairingResponse,
        now_unix_ms: u64,
    ) -> Result<(), PairingError> {
        self.check_time(now_unix_ms)?;
        if self.role != PairingRole::Initiator
            || self.state != PairingState::AwaitingResponse
            || response.pairing_id != self.pairing_id
        {
            return Err(self.fail(
                PairingErrorKind::InvalidState,
                "pairing response is not expected",
            ));
        }
        validate_identity(&response.responder)?;
        let expected = transcript_hash(
            &self.local,
            &response.responder,
            self.protocol_version,
            &self.challenge,
            self.method,
        );
        if response.transcript_hash != expected || response.short_code != short_code(&expected) {
            return Err(self.fail(
                PairingErrorKind::TranscriptMismatch,
                "pairing transcript does not match",
            ));
        }
        self.remote = Some(response.responder);
        self.transcript_hash = Some(expected);
        self.short_code = Some(response.short_code);
        self.set_state(PairingState::AwaitingUserConfirmation);
        self.emit(PairingEvent::Present(self.presentation()?));
        Ok(())
    }

    pub fn presentation(&self) -> Result<PairingPresentation, PairingError> {
        let remote = self.remote.as_ref().ok_or_else(invalid_state)?;
        let code = self.short_code.as_ref().ok_or_else(invalid_state)?;
        Ok(presentation(remote, code))
    }

    pub fn confirm(
        &mut self,
        displayed_code: &str,
        crypto: &impl PairingCrypto,
        now_unix_ms: u64,
    ) -> Result<PairingConfirmation, PairingError> {
        self.check_time(now_unix_ms)?;
        if self.state != PairingState::AwaitingUserConfirmation {
            return Err(invalid_state());
        }
        if self.short_code.as_deref() != Some(displayed_code) {
            return Err(self.fail(
                PairingErrorKind::CodeMismatch,
                "pairing short code does not match",
            ));
        }
        let transcript_hash = self.transcript_hash.ok_or_else(invalid_state)?;
        let signature = crypto.sign_transcript(&transcript_hash)?;
        self.local_confirmed = true;
        if self.remote_confirmed {
            self.complete();
        } else {
            self.set_state(PairingState::AwaitingPeerConfirmation);
        }
        Ok(PairingConfirmation {
            pairing_id: self.pairing_id,
            signer_peer_id: self.local.peer_id,
            transcript_hash,
            signature,
        })
    }

    pub fn receive_confirmation(
        &mut self,
        confirmation: PairingConfirmation,
        crypto: &impl PairingCrypto,
        now_unix_ms: u64,
    ) -> Result<(), PairingError> {
        self.check_time(now_unix_ms)?;
        if !matches!(
            self.state,
            PairingState::AwaitingUserConfirmation | PairingState::AwaitingPeerConfirmation
        ) {
            return Err(invalid_state());
        }
        let remote = self.remote.as_ref().ok_or_else(invalid_state)?;
        let transcript_hash = self.transcript_hash.ok_or_else(invalid_state)?;
        if confirmation.pairing_id != self.pairing_id
            || confirmation.signer_peer_id != remote.peer_id
            || confirmation.transcript_hash != transcript_hash
        {
            return Err(self.fail(
                PairingErrorKind::TranscriptMismatch,
                "pairing confirmation does not match transcript",
            ));
        }
        if !crypto.verify_transcript(
            &remote.public_key,
            &transcript_hash,
            &confirmation.signature,
        ) {
            return Err(self.fail(
                PairingErrorKind::IdentityProofRejected,
                "pairing identity proof was rejected",
            ));
        }
        self.remote_confirmed = true;
        if self.local_confirmed {
            self.complete();
        }
        Ok(())
    }

    pub fn reject(&mut self) -> Result<PairingTermination, PairingError> {
        self.ensure_nonterminal()?;
        self.set_state(PairingState::Rejected);
        Ok(PairingTermination {
            pairing_id: self.pairing_id,
            reason: PairingTerminationReason::Rejected,
        })
    }

    pub fn cancel(&mut self) -> Result<PairingTermination, PairingError> {
        self.ensure_nonterminal()?;
        self.set_state(PairingState::Cancelled);
        Ok(PairingTermination {
            pairing_id: self.pairing_id,
            reason: PairingTerminationReason::Cancelled,
        })
    }

    pub fn receive_termination(
        &mut self,
        termination: PairingTermination,
    ) -> Result<(), PairingError> {
        self.ensure_nonterminal()?;
        if termination.pairing_id != self.pairing_id {
            return Err(self.fail(
                PairingErrorKind::TranscriptMismatch,
                "pairing termination does not match session",
            ));
        }
        self.set_state(match termination.reason {
            PairingTerminationReason::Rejected => PairingState::Rejected,
            PairingTerminationReason::Cancelled => PairingState::Cancelled,
        });
        Ok(())
    }

    pub fn tick(&mut self, now_unix_ms: u64) -> Result<(), PairingError> {
        self.check_time(now_unix_ms)
    }

    pub fn trust_record(
        &self,
        alias: String,
        permissions: BTreeSet<LinkPermission>,
        now_unix_ms: u64,
    ) -> Result<TrustRecord, PairingError> {
        if self.state != PairingState::Paired || alias.is_empty() {
            return Err(invalid_state());
        }
        let remote = self.remote.as_ref().ok_or_else(invalid_state)?;
        Ok(TrustRecord {
            peer_id: remote.peer_id,
            public_key: remote.public_key.clone(),
            alias,
            first_paired_at_unix_ms: now_unix_ms,
            permissions,
            key_state: KeyState::Active,
            last_pairing_challenge_hash: Sha256::digest(self.challenge).into(),
            previous_key_fingerprints: Vec::new(),
        })
    }

    pub fn drain_events(&mut self) -> Vec<PairingEvent> {
        let mut events = Vec::new();
        if self.dropped_events > 0 {
            events.push(PairingEvent::EventsDropped(self.dropped_events));
            self.dropped_events = 0;
        }
        events.extend(self.events.drain(..));
        events
    }

    fn check_time(&mut self, now_unix_ms: u64) -> Result<(), PairingError> {
        if now_unix_ms >= self.expires_at_unix_ms {
            if !is_terminal(self.state) {
                self.set_state(PairingState::TimedOut);
            }
            return Err(PairingError::new(
                PairingErrorKind::TimedOut,
                "pairing session timed out",
            ));
        }
        Ok(())
    }

    fn ensure_nonterminal(&self) -> Result<(), PairingError> {
        if is_terminal(self.state) {
            Err(invalid_state())
        } else {
            Ok(())
        }
    }

    fn complete(&mut self) {
        self.set_state(PairingState::Paired);
        if let Some(remote) = &self.remote {
            self.emit(PairingEvent::Completed(remote.peer_id));
        }
    }

    fn set_state(&mut self, state: PairingState) {
        self.state = state;
        self.emit(PairingEvent::StateChanged(state));
    }

    fn emit(&mut self, event: PairingEvent) {
        if self.events.len() == self.event_capacity {
            self.events.pop_front();
            self.dropped_events = self.dropped_events.saturating_add(1);
        }
        self.events.push_back(event);
    }

    fn fail(&mut self, kind: PairingErrorKind, message: &'static str) -> PairingError {
        self.set_state(PairingState::Failed);
        PairingError::new(kind, message)
    }
}

fn validate_identity(identity: &LongTermIdentity) -> Result<(), PairingError> {
    if identity.public_key.len() < 16 || identity.display_name.is_empty() {
        return Err(PairingError::new(
            PairingErrorKind::InvalidInput,
            "long-term identity is invalid",
        ));
    }
    Ok(())
}

fn validate_new(
    already_trusted: bool,
    expires_at_unix_ms: u64,
    event_capacity: usize,
) -> Result<(), PairingError> {
    if already_trusted {
        return Err(PairingError::new(
            PairingErrorKind::DuplicatePairing,
            "peer is already paired",
        ));
    }
    if expires_at_unix_ms == 0 || event_capacity == 0 {
        return Err(PairingError::new(
            PairingErrorKind::InvalidInput,
            "pairing limits are invalid",
        ));
    }
    Ok(())
}

fn transcript_hash(
    initiator: &LongTermIdentity,
    responder: &LongTermIdentity,
    version: ProtocolVersion,
    challenge: &[u8; 32],
    method: PairingMethod,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"mutsuki-link-pairing-v1");
    hash.update(initiator.peer_id.as_bytes());
    update_sized(&mut hash, &initiator.public_key);
    hash.update(responder.peer_id.as_bytes());
    update_sized(&mut hash, &responder.public_key);
    hash.update(version.major.to_be_bytes());
    hash.update(version.minor.to_be_bytes());
    hash.update(challenge);
    hash.update([match method {
        PairingMethod::ShortCode => 1,
        PairingMethod::QrCode => 2,
        PairingMethod::BilateralConfirmation => 3,
    }]);
    hash.finalize().into()
}

fn update_sized(hash: &mut Sha256, value: &[u8]) {
    hash.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(value);
}

fn short_code(transcript_hash: &[u8; 32]) -> String {
    let value =
        u32::from_be_bytes(transcript_hash[..4].try_into().expect("four bytes")) % 1_000_000;
    format!("{value:06}")
}

fn presentation(identity: &LongTermIdentity, short_code: &str) -> PairingPresentation {
    PairingPresentation {
        peer_name: identity.display_name.clone(),
        peer_fingerprint: Sha256::digest(&identity.public_key).into(),
        short_code: short_code.to_owned(),
    }
}

fn is_terminal(state: PairingState) -> bool {
    matches!(
        state,
        PairingState::Paired
            | PairingState::Rejected
            | PairingState::TimedOut
            | PairingState::Cancelled
            | PairingState::Failed
    )
}

fn invalid_state() -> PairingError {
    PairingError::new(
        PairingErrorKind::InvalidState,
        "pairing command is invalid in the current state",
    )
}
