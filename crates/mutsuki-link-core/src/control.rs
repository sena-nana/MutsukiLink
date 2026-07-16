use crate::{
    AuthPath, ChannelGeneration, ChannelId, Identity, ProtocolOffer, ProtocolSelection,
    ProtocolVersion, SessionId, VersionRange,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const PROTOCOL_ID_DOMAIN: &[u8] = b"mutsuki-link.protocol-stable-id.v1\0";
const SCHEMA_ID_DOMAIN: &[u8] = b"mutsuki-link.schema-id.v1\0";
pub const MAX_PROTOCOL_CAPABILITY_WORDS: usize = 8;
pub const MAX_CONTROL_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_CONTROL_PROTOCOLS: usize = 32;
pub const MAX_CONTROL_DEBUG_COMPONENT_BYTES: usize = 128;
pub const MAX_SESSION_CHANNEL_MAPPINGS: usize = 128;
pub const TYPED_CONTROL_WIRE_VERSION: u16 = 1;
const CONTROL_MAGIC: [u8; 4] = *b"MLCT";
const CONTROL_HEADER_BYTES: usize = 39;
const CONTROL_PAYLOAD_LENGTH_OFFSET: usize = CONTROL_HEADER_BYTES - 4;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolStableId([u8; 16]);

impl ProtocolStableId {
    pub fn derive(authority: &str, name: &str) -> Self {
        Self(derive_128(PROTOCOL_ID_DOMAIN, authority, name))
    }

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn wire_namespace(self) -> String {
        let mut output = String::with_capacity(39);
        output.push_str("stable.");
        for byte in self.0 {
            use std::fmt::Write;
            write!(output, "{byte:02x}").expect("writing to string");
        }
        output
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolChannelId(pub u16);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolDebugIdentity {
    pub authority: String,
    pub name: String,
}

impl ProtocolDebugIdentity {
    pub fn new(authority: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            authority: authority.into(),
            name: name.into(),
        }
    }

    pub fn stable_id(&self) -> ProtocolStableId {
        ProtocolStableId::derive(&self.authority, &self.name)
    }

    pub fn is_canonical(&self) -> bool {
        !self.authority.is_empty()
            && self.authority.split('.').all(canonical_identity_component)
            && canonical_identity_component(&self.name)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchemaId([u8; 16]);

impl SchemaId {
    pub fn derive(authority: &str, name: &str) -> Self {
        Self(derive_128(SCHEMA_ID_DOMAIN, authority, name))
    }

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchemaRevision(pub u32);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchemaFingerprint([u8; 32]);

impl SchemaFingerprint {
    pub fn digest(contract: &[u8]) -> Self {
        Self(Sha256::digest(contract).into())
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchemaRef {
    pub id: SchemaId,
    pub revision: SchemaRevision,
    pub fingerprint: SchemaFingerprint,
}

impl SchemaRef {
    pub fn for_contract(authority: &str, name: &str, revision: u32, contract: &[u8]) -> Self {
        Self {
            id: SchemaId::derive(authority, name),
            revision: SchemaRevision(revision),
            fingerprint: SchemaFingerprint::digest(contract),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinkCapabilities(u64);

impl LinkCapabilities {
    pub const COMPACT_CHANNEL_ID: Self = Self(1 << 0);
    pub const DATAGRAMS: Self = Self(1 << 1);
    pub const SESSION_RESUME: Self = Self(1 << 2);
    pub const MANAGEMENT_CHANNEL: Self = Self(1 << 3);
    pub const ORDERED_RESPONSE_MULTIPLEX: Self = Self(1 << 4);
    /// Both peers understand the typed control envelope introduced in wire v1.
    pub const TYPED_CONTROL: Self = Self(1 << 5);

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn contains(self, capability: Self) -> bool {
        self.0 & capability.0 == capability.0
    }

    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlIdentityMode {
    /// Compatibility mode for peers that predate typed-control capability.
    LegacyStringV1,
    TypedV1,
}

impl ControlIdentityMode {
    pub const fn negotiate(capabilities: LinkCapabilities) -> Self {
        if capabilities.contains(LinkCapabilities::TYPED_CONTROL) {
            Self::TypedV1
        } else {
            Self::LegacyStringV1
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlModeGuard {
    mode: ControlIdentityMode,
}

impl ControlModeGuard {
    pub const fn new(mode: ControlIdentityMode) -> Self {
        Self { mode }
    }

    pub const fn mode(self) -> ControlIdentityMode {
        self.mode
    }

    pub fn validate_typed(&self) -> Result<(), LinkControlError> {
        if self.mode == ControlIdentityMode::TypedV1 {
            Ok(())
        } else {
            Err(LinkControlError::mode_mismatch())
        }
    }

    pub fn validate_legacy(&self) -> Result<(), LinkControlError> {
        if self.mode == ControlIdentityMode::LegacyStringV1 {
            Ok(())
        } else {
            Err(LinkControlError::mode_mismatch())
        }
    }
}

impl std::ops::BitOr for LinkCapabilities {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolCapabilitySet {
    pub protocol_id: ProtocolStableId,
    pub words: Vec<u64>,
}

impl ProtocolCapabilitySet {
    pub fn empty(protocol_id: ProtocolStableId) -> Self {
        Self {
            protocol_id,
            words: Vec::new(),
        }
    }

    pub fn is_bounded(&self) -> bool {
        self.words.len() <= MAX_PROTOCOL_CAPABILITY_WORDS
    }

    pub fn intersect(&self, other: &Self) -> Option<Self> {
        (self.protocol_id == other.protocol_id).then(|| Self {
            protocol_id: self.protocol_id,
            words: self
                .words
                .iter()
                .zip(&other.words)
                .map(|(left, right)| left & right)
                .collect(),
        })
    }

    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.protocol_id == other.protocol_id
            && self.words.iter().enumerate().all(|(index, word)| {
                let other_word = other.words.get(index).copied().unwrap_or(0);
                word & !other_word == 0
            })
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkControlOpcode {
    Hello = 0x0001,
    ProtocolOffer = 0x0002,
    ProtocolSelect = 0x0003,
    OpenChannel = 0x0010,
    ChannelAccepted = 0x0011,
    CloseChannel = 0x0012,
    Ping = 0x0020,
    Pong = 0x0021,
    BeginDrain = 0x0022,
    CloseSession = 0x0023,
    Error = 0x00ff,
}

impl TryFrom<u16> for LinkControlOpcode {
    type Error = LinkControlError;

    fn try_from(value: u16) -> Result<Self, LinkControlError> {
        match value {
            0x0001 => Ok(Self::Hello),
            0x0002 => Ok(Self::ProtocolOffer),
            0x0003 => Ok(Self::ProtocolSelect),
            0x0010 => Ok(Self::OpenChannel),
            0x0011 => Ok(Self::ChannelAccepted),
            0x0012 => Ok(Self::CloseChannel),
            0x0020 => Ok(Self::Ping),
            0x0021 => Ok(Self::Pong),
            0x0022 => Ok(Self::BeginDrain),
            0x0023 => Ok(Self::CloseSession),
            0x00ff => Ok(Self::Error),
            _ => Err(LinkControlError::unknown_opcode()),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlFlags(u16);

impl ControlFlags {
    pub const RESPONSE: Self = Self(1 << 0);
    const KNOWN_BITS: u16 = Self::RESPONSE.0;

    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::KNOWN_BITS == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenChannel {
    pub protocol_id: ProtocolStableId,
    pub protocol_channel_id: ProtocolChannelId,
    pub requested_session_channel_id: ChannelId,
    pub capacity: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptChannel {
    pub protocol_id: ProtocolStableId,
    pub protocol_channel_id: ProtocolChannelId,
    pub session_channel_id: ChannelId,
}

/// Authenticated, session-local mapping consumed by the compact data envelope.
/// Both indexes are maintained together so neither a protocol channel nor a
/// session channel can be silently rebound by a repeated remote control frame.
#[derive(Clone, Debug)]
pub struct SessionChannelMap {
    maximum: usize,
    by_protocol: BTreeMap<(ProtocolStableId, ProtocolChannelId), SessionChannelBinding>,
    by_session: BTreeMap<ChannelId, (ProtocolStableId, ProtocolChannelId, ChannelGeneration)>,
    retired: BTreeSet<ChannelId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionChannelBinding {
    pub channel_id: ChannelId,
    pub generation: ChannelGeneration,
}

impl SessionChannelMap {
    pub fn new(maximum: usize) -> Result<Self, LinkControlError> {
        if maximum == 0 || maximum > MAX_SESSION_CHANNEL_MAPPINGS {
            return Err(LinkControlError::limit_exceeded());
        }
        Ok(Self {
            maximum,
            by_protocol: BTreeMap::new(),
            by_session: BTreeMap::new(),
            retired: BTreeSet::new(),
        })
    }

    pub fn bind(
        &mut self,
        accepted: AcceptChannel,
    ) -> Result<SessionChannelBinding, LinkControlError> {
        self.validate_bind(accepted)?;
        Ok(self.bind_validated(accepted))
    }

    pub(crate) fn bind_validated(&mut self, accepted: AcceptChannel) -> SessionChannelBinding {
        let binding = SessionChannelBinding {
            channel_id: accepted.session_channel_id,
            generation: ChannelGeneration::INITIAL,
        };
        let protocol_key = (accepted.protocol_id, accepted.protocol_channel_id);
        self.by_protocol.insert(protocol_key, binding);
        self.by_session.insert(
            accepted.session_channel_id,
            (
                accepted.protocol_id,
                accepted.protocol_channel_id,
                binding.generation,
            ),
        );
        binding
    }

    pub(crate) fn validate_bind(&self, accepted: AcceptChannel) -> Result<(), LinkControlError> {
        if accepted.protocol_channel_id.0 == 0 || accepted.session_channel_id.0 == 0 {
            return Err(LinkControlError::invalid_channel_mapping());
        }
        let protocol_key = (accepted.protocol_id, accepted.protocol_channel_id);
        if self.by_protocol.contains_key(&protocol_key)
            || self.by_session.contains_key(&accepted.session_channel_id)
            || self.retired.contains(&accepted.session_channel_id)
        {
            return Err(LinkControlError::duplicate_channel_mapping());
        }
        if self.by_protocol.len().saturating_add(self.retired.len()) >= self.maximum {
            return Err(LinkControlError::channel_mapping_limit());
        }
        Ok(())
    }

    pub fn session_channel(
        &self,
        protocol_id: ProtocolStableId,
        protocol_channel_id: ProtocolChannelId,
    ) -> Option<ChannelId> {
        self.by_protocol
            .get(&(protocol_id, protocol_channel_id))
            .map(|binding| binding.channel_id)
    }

    pub fn binding(
        &self,
        protocol_id: ProtocolStableId,
        protocol_channel_id: ProtocolChannelId,
    ) -> Option<SessionChannelBinding> {
        self.by_protocol
            .get(&(protocol_id, protocol_channel_id))
            .copied()
    }

    pub fn protocol_channel(
        &self,
        session_channel_id: ChannelId,
    ) -> Option<(ProtocolStableId, ProtocolChannelId)> {
        self.by_session
            .get(&session_channel_id)
            .map(|(protocol_id, protocol_channel_id, _)| (*protocol_id, *protocol_channel_id))
    }

    pub fn session_binding(
        &self,
        session_channel_id: ChannelId,
    ) -> Option<(ProtocolStableId, ProtocolChannelId, ChannelGeneration)> {
        self.by_session.get(&session_channel_id).copied()
    }

    pub fn unbind(
        &mut self,
        session_channel_id: ChannelId,
    ) -> Option<(ProtocolStableId, ProtocolChannelId)> {
        let (protocol_id, protocol_channel_id, _) = self.by_session.remove(&session_channel_id)?;
        let protocol_key = (protocol_id, protocol_channel_id);
        self.by_protocol.remove(&protocol_key);
        self.retired.insert(session_channel_id);
        Some(protocol_key)
    }

    pub fn len(&self) -> usize {
        self.by_protocol.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_protocol.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelloControl {
    pub identity: Identity,
    pub link_versions: VersionRange,
    pub link_capabilities: LinkCapabilities,
    pub requested_auth: AuthPath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseChannel {
    pub session_channel_id: ChannelId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ping {
    pub nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pong {
    pub nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BeginDrain {
    pub deadline_millis: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseSession {
    pub reason_code: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlPayload {
    Hello(HelloControl),
    OfferProtocols(Vec<ProtocolOffer>),
    SelectProtocols(Vec<ProtocolSelection>),
    OpenChannel(OpenChannel),
    AcceptChannel(AcceptChannel),
    CloseChannel(CloseChannel),
    Ping(Ping),
    Pong(Pong),
    BeginDrain(BeginDrain),
    CloseSession(CloseSession),
    Error(LinkControlError),
}

impl ControlPayload {
    pub const fn opcode(&self) -> LinkControlOpcode {
        match self {
            Self::Hello(_) => LinkControlOpcode::Hello,
            Self::OfferProtocols(_) => LinkControlOpcode::ProtocolOffer,
            Self::SelectProtocols(_) => LinkControlOpcode::ProtocolSelect,
            Self::OpenChannel(_) => LinkControlOpcode::OpenChannel,
            Self::AcceptChannel(_) => LinkControlOpcode::ChannelAccepted,
            Self::CloseChannel(_) => LinkControlOpcode::CloseChannel,
            Self::Ping(_) => LinkControlOpcode::Ping,
            Self::Pong(_) => LinkControlOpcode::Pong,
            Self::BeginDrain(_) => LinkControlOpcode::BeginDrain,
            Self::CloseSession(_) => LinkControlOpcode::CloseSession,
            Self::Error(_) => LinkControlOpcode::Error,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlEnvelope {
    pub wire_version: u16,
    pub opcode: LinkControlOpcode,
    pub request_id: RequestId,
    pub session_id: Option<SessionId>,
    pub flags: ControlFlags,
    pub payload: ControlPayload,
}

impl ControlEnvelope {
    pub fn typed(
        request_id: RequestId,
        session_id: Option<SessionId>,
        flags: ControlFlags,
        payload: ControlPayload,
    ) -> Self {
        Self {
            wire_version: TYPED_CONTROL_WIRE_VERSION,
            opcode: payload.opcode(),
            request_id,
            session_id,
            flags,
            payload,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorDomain {
    Control,
    Protocol,
    Channel,
    Security,
    Resource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorCode(pub u16);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Retryability {
    Never,
    RetryAfterBackoff,
    Reconnect,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkControlError {
    pub domain: ErrorDomain,
    pub code: ErrorCode,
    pub operation: Option<LinkControlOpcode>,
    pub retryability: Retryability,
    pub public_message: &'static str,
}

impl LinkControlError {
    const fn unknown_opcode() -> Self {
        Self {
            domain: ErrorDomain::Control,
            code: ErrorCode(1),
            operation: None,
            retryability: Retryability::Never,
            public_message: "unknown Link control opcode",
        }
    }

    const fn malformed(code: u16, message: &'static str) -> Self {
        Self {
            domain: ErrorDomain::Control,
            code: ErrorCode(code),
            operation: None,
            retryability: Retryability::Never,
            public_message: message,
        }
    }

    const fn mode_mismatch() -> Self {
        Self::malformed(2, "control identity mode does not match negotiated session")
    }

    const fn unsupported_version() -> Self {
        Self::malformed(3, "unsupported typed control wire version")
    }

    const fn truncated() -> Self {
        Self::malformed(4, "truncated typed control frame")
    }

    const fn limit_exceeded() -> Self {
        Self::malformed(5, "typed control frame exceeds a resource limit")
    }

    const fn invalid_payload() -> Self {
        Self::malformed(6, "invalid typed control payload")
    }

    const fn opcode_mismatch() -> Self {
        Self::malformed(7, "typed control opcode does not match payload")
    }

    const fn trailing_bytes() -> Self {
        Self::malformed(8, "typed control frame contains trailing bytes")
    }

    const fn invalid_channel_mapping() -> Self {
        Self {
            domain: ErrorDomain::Channel,
            code: ErrorCode(1),
            operation: Some(LinkControlOpcode::ChannelAccepted),
            retryability: Retryability::Never,
            public_message: "session channel mapping is invalid",
        }
    }

    const fn duplicate_channel_mapping() -> Self {
        Self {
            domain: ErrorDomain::Channel,
            code: ErrorCode(2),
            operation: Some(LinkControlOpcode::ChannelAccepted),
            retryability: Retryability::Never,
            public_message: "session channel mapping conflicts with an existing binding",
        }
    }

    const fn channel_mapping_limit() -> Self {
        Self {
            domain: ErrorDomain::Resource,
            code: ErrorCode(1),
            operation: Some(LinkControlOpcode::ChannelAccepted),
            retryability: Retryability::Never,
            public_message: "session channel mapping limit exceeded",
        }
    }

    pub(crate) const fn session_not_active(operation: LinkControlOpcode) -> Self {
        Self {
            domain: ErrorDomain::Control,
            code: ErrorCode(9),
            operation: Some(operation),
            retryability: Retryability::Reconnect,
            public_message: "control operation requires an active session",
        }
    }
}

pub fn encode_control_envelope(
    guard: &ControlModeGuard,
    envelope: &ControlEnvelope,
) -> Result<Vec<u8>, LinkControlError> {
    guard.validate_typed()?;
    if envelope.wire_version != TYPED_CONTROL_WIRE_VERSION {
        return Err(LinkControlError::unsupported_version());
    }
    if envelope.opcode != envelope.payload.opcode() {
        return Err(LinkControlError::opcode_mismatch());
    }

    let mut wire = Vec::with_capacity(CONTROL_HEADER_BYTES + 256);
    wire.extend_from_slice(&CONTROL_MAGIC);
    wire.extend_from_slice(&envelope.wire_version.to_be_bytes());
    wire.extend_from_slice(&(envelope.opcode as u16).to_be_bytes());
    wire.extend_from_slice(&envelope.flags.bits().to_be_bytes());
    wire.extend_from_slice(&envelope.request_id.0.to_be_bytes());
    if let Some(session_id) = envelope.session_id {
        wire.push(1);
        wire.extend_from_slice(session_id.as_bytes());
    } else {
        wire.push(0);
        wire.extend_from_slice(&[0; 16]);
    }
    wire.extend_from_slice(&0_u32.to_be_bytes());

    let mut writer = Writer { bytes: wire };
    encode_payload(&mut writer, &envelope.payload)?;
    let payload_len = writer.bytes.len().saturating_sub(CONTROL_HEADER_BYTES);
    if payload_len > MAX_CONTROL_PAYLOAD_BYTES {
        return Err(LinkControlError::limit_exceeded());
    }
    let payload_len = u32::try_from(payload_len).map_err(|_| LinkControlError::limit_exceeded())?;
    writer.bytes[CONTROL_PAYLOAD_LENGTH_OFFSET..CONTROL_HEADER_BYTES]
        .copy_from_slice(&payload_len.to_be_bytes());
    Ok(writer.bytes)
}

pub fn decode_control_envelope(
    guard: &ControlModeGuard,
    wire: &[u8],
) -> Result<ControlEnvelope, LinkControlError> {
    guard.validate_typed()?;
    if wire.len() < CONTROL_HEADER_BYTES {
        return Err(LinkControlError::truncated());
    }
    let mut reader = Reader::new(wire);
    if reader.take_array::<4>()? != CONTROL_MAGIC {
        return Err(LinkControlError::invalid_payload());
    }
    let wire_version = reader.u16()?;
    if wire_version != TYPED_CONTROL_WIRE_VERSION {
        return Err(LinkControlError::unsupported_version());
    }
    let opcode = LinkControlOpcode::try_from(reader.u16()?)?;
    let flags =
        ControlFlags::from_bits(reader.u16()?).ok_or_else(LinkControlError::invalid_payload)?;
    let request_id = RequestId(reader.u64()?);
    let session_present = reader.u8()?;
    let session_bytes = reader.take_array::<16>()?;
    let session_id = match session_present {
        0 if session_bytes == [0; 16] => None,
        1 => Some(SessionId::from_bytes(session_bytes)),
        _ => return Err(LinkControlError::invalid_payload()),
    };
    let payload_len =
        usize::try_from(reader.u32()?).map_err(|_| LinkControlError::limit_exceeded())?;
    if payload_len > MAX_CONTROL_PAYLOAD_BYTES {
        return Err(LinkControlError::limit_exceeded());
    }
    if reader.remaining() < payload_len {
        return Err(LinkControlError::truncated());
    }
    if reader.remaining() != payload_len {
        return Err(LinkControlError::trailing_bytes());
    }
    let mut payload_reader = Reader::new(reader.take(payload_len)?);
    let payload = decode_payload(opcode, &mut payload_reader)?;
    if payload_reader.remaining() != 0 {
        return Err(LinkControlError::trailing_bytes());
    }
    Ok(ControlEnvelope {
        wire_version,
        opcode,
        request_id,
        session_id,
        flags,
        payload,
    })
}

fn encode_payload(writer: &mut Writer, payload: &ControlPayload) -> Result<(), LinkControlError> {
    match payload {
        ControlPayload::Hello(hello) => {
            if !hello.link_versions.is_valid() {
                return Err(LinkControlError::invalid_payload());
            }
            writer.bytes(hello.identity.peer_id.as_bytes());
            writer.bytes(hello.identity.endpoint_id.as_bytes());
            writer.bytes(hello.identity.connection_id.as_bytes());
            writer.version_range(hello.link_versions);
            writer.u64(hello.link_capabilities.bits());
            writer.u8(match hello.requested_auth {
                AuthPath::FirstPairing => 0,
                AuthPath::TrustedReconnect => 1,
            });
        }
        ControlPayload::OfferProtocols(offers) => {
            writer.count(offers.len(), MAX_CONTROL_PROTOCOLS)?;
            let mut stable_ids = BTreeSet::new();
            for offer in offers {
                if !stable_ids.insert(offer.stable_id)
                    || !offer.versions.is_valid()
                    || offer.schema.revision.0 == 0
                    || offer.capabilities.protocol_id != offer.stable_id
                    || offer.debug_identity.as_ref().is_some_and(|identity| {
                        !identity.is_canonical() || identity.stable_id() != offer.stable_id
                    })
                {
                    return Err(LinkControlError::invalid_payload());
                }
                writer.protocol_id(offer.stable_id);
                writer.debug_identity(offer.debug_identity.as_ref())?;
                writer.version_range(offer.versions);
                writer.schema(offer.schema);
                writer.capabilities(&offer.capabilities)?;
            }
        }
        ControlPayload::SelectProtocols(selections) => {
            writer.count(selections.len(), MAX_CONTROL_PROTOCOLS)?;
            let mut stable_ids = BTreeSet::new();
            for selection in selections {
                if !stable_ids.insert(selection.stable_id)
                    || selection.schema.revision.0 == 0
                    || selection.capabilities.protocol_id != selection.stable_id
                {
                    return Err(LinkControlError::invalid_payload());
                }
                writer.protocol_id(selection.stable_id);
                writer.version(selection.version);
                writer.schema(selection.schema);
                writer.capabilities(&selection.capabilities)?;
            }
        }
        ControlPayload::OpenChannel(open) => {
            if open.protocol_channel_id.0 == 0
                || open.requested_session_channel_id.0 == 0
                || open.capacity == 0
            {
                return Err(LinkControlError::invalid_payload());
            }
            writer.protocol_id(open.protocol_id);
            writer.u16(open.protocol_channel_id.0);
            writer.u32(open.requested_session_channel_id.0);
            writer.u32(open.capacity);
        }
        ControlPayload::AcceptChannel(accepted) => {
            if accepted.protocol_channel_id.0 == 0 || accepted.session_channel_id.0 == 0 {
                return Err(LinkControlError::invalid_payload());
            }
            writer.protocol_id(accepted.protocol_id);
            writer.u16(accepted.protocol_channel_id.0);
            writer.u32(accepted.session_channel_id.0);
        }
        ControlPayload::CloseChannel(close) => {
            if close.session_channel_id.0 == 0 {
                return Err(LinkControlError::invalid_payload());
            }
            writer.u32(close.session_channel_id.0);
        }
        ControlPayload::Ping(ping) => writer.u64(ping.nonce),
        ControlPayload::Pong(pong) => writer.u64(pong.nonce),
        ControlPayload::BeginDrain(drain) => writer.u32(drain.deadline_millis),
        ControlPayload::CloseSession(close) => writer.u16(close.reason_code),
        ControlPayload::Error(error) => {
            writer.u8(error_domain_to_wire(error.domain));
            writer.u16(error.code.0);
            writer.u16(error.operation.map_or(u16::MAX, |opcode| opcode as u16));
            writer.u8(retryability_to_wire(error.retryability));
        }
    }
    Ok(())
}

fn decode_payload(
    opcode: LinkControlOpcode,
    reader: &mut Reader<'_>,
) -> Result<ControlPayload, LinkControlError> {
    Ok(match opcode {
        LinkControlOpcode::Hello => ControlPayload::Hello(HelloControl {
            identity: Identity {
                peer_id: crate::PeerId::from_bytes(reader.take_array()?),
                endpoint_id: crate::EndpointId::from_bytes(reader.take_array()?),
                connection_id: crate::ConnectionId::from_bytes(reader.take_array()?),
            },
            link_versions: reader.version_range()?,
            link_capabilities: LinkCapabilities::from_bits(reader.u64()?),
            requested_auth: match reader.u8()? {
                0 => AuthPath::FirstPairing,
                1 => AuthPath::TrustedReconnect,
                _ => return Err(LinkControlError::invalid_payload()),
            },
        }),
        LinkControlOpcode::ProtocolOffer => {
            let count = reader.bounded_count(MAX_CONTROL_PROTOCOLS)?;
            let mut offers = Vec::with_capacity(count);
            let mut stable_ids = BTreeSet::new();
            for _ in 0..count {
                let stable_id = reader.protocol_id()?;
                let debug_identity = reader.debug_identity()?;
                let versions = reader.version_range()?;
                let schema = reader.schema()?;
                let capabilities = reader.capabilities()?;
                if !stable_ids.insert(stable_id)
                    || capabilities.protocol_id != stable_id
                    || debug_identity.as_ref().is_some_and(|identity| {
                        !identity.is_canonical() || identity.stable_id() != stable_id
                    })
                {
                    return Err(LinkControlError::invalid_payload());
                }
                offers.push(ProtocolOffer {
                    stable_id,
                    debug_identity,
                    versions,
                    schema,
                    capabilities,
                });
            }
            ControlPayload::OfferProtocols(offers)
        }
        LinkControlOpcode::ProtocolSelect => {
            let count = reader.bounded_count(MAX_CONTROL_PROTOCOLS)?;
            let mut selections = Vec::with_capacity(count);
            let mut stable_ids = BTreeSet::new();
            for _ in 0..count {
                let stable_id = reader.protocol_id()?;
                let version = reader.version()?;
                let schema = reader.schema()?;
                let capabilities = reader.capabilities()?;
                if !stable_ids.insert(stable_id) || capabilities.protocol_id != stable_id {
                    return Err(LinkControlError::invalid_payload());
                }
                selections.push(ProtocolSelection {
                    stable_id,
                    version,
                    schema,
                    capabilities,
                });
            }
            ControlPayload::SelectProtocols(selections)
        }
        LinkControlOpcode::OpenChannel => {
            let open = OpenChannel {
                protocol_id: reader.protocol_id()?,
                protocol_channel_id: ProtocolChannelId(reader.u16()?),
                requested_session_channel_id: ChannelId(reader.u32()?),
                capacity: reader.u32()?,
            };
            if open.protocol_channel_id.0 == 0
                || open.requested_session_channel_id.0 == 0
                || open.capacity == 0
            {
                return Err(LinkControlError::invalid_payload());
            }
            ControlPayload::OpenChannel(open)
        }
        LinkControlOpcode::ChannelAccepted => {
            let accepted = AcceptChannel {
                protocol_id: reader.protocol_id()?,
                protocol_channel_id: ProtocolChannelId(reader.u16()?),
                session_channel_id: ChannelId(reader.u32()?),
            };
            if accepted.protocol_channel_id.0 == 0 || accepted.session_channel_id.0 == 0 {
                return Err(LinkControlError::invalid_payload());
            }
            ControlPayload::AcceptChannel(accepted)
        }
        LinkControlOpcode::CloseChannel => {
            let close = CloseChannel {
                session_channel_id: ChannelId(reader.u32()?),
            };
            if close.session_channel_id.0 == 0 {
                return Err(LinkControlError::invalid_payload());
            }
            ControlPayload::CloseChannel(close)
        }
        LinkControlOpcode::Ping => ControlPayload::Ping(Ping {
            nonce: reader.u64()?,
        }),
        LinkControlOpcode::Pong => ControlPayload::Pong(Pong {
            nonce: reader.u64()?,
        }),
        LinkControlOpcode::BeginDrain => ControlPayload::BeginDrain(BeginDrain {
            deadline_millis: reader.u32()?,
        }),
        LinkControlOpcode::CloseSession => ControlPayload::CloseSession(CloseSession {
            reason_code: reader.u16()?,
        }),
        LinkControlOpcode::Error => {
            let domain = error_domain_from_wire(reader.u8()?)?;
            let code = ErrorCode(reader.u16()?);
            let operation = match reader.u16()? {
                u16::MAX => None,
                value => Some(LinkControlOpcode::try_from(value)?),
            };
            let retryability = retryability_from_wire(reader.u8()?)?;
            ControlPayload::Error(LinkControlError {
                domain,
                code,
                operation,
                retryability,
                public_message: "remote returned a structured control error",
            })
        }
    })
}

fn error_domain_to_wire(domain: ErrorDomain) -> u8 {
    match domain {
        ErrorDomain::Control => 0,
        ErrorDomain::Protocol => 1,
        ErrorDomain::Channel => 2,
        ErrorDomain::Security => 3,
        ErrorDomain::Resource => 4,
    }
}

fn error_domain_from_wire(value: u8) -> Result<ErrorDomain, LinkControlError> {
    match value {
        0 => Ok(ErrorDomain::Control),
        1 => Ok(ErrorDomain::Protocol),
        2 => Ok(ErrorDomain::Channel),
        3 => Ok(ErrorDomain::Security),
        4 => Ok(ErrorDomain::Resource),
        _ => Err(LinkControlError::invalid_payload()),
    }
}

fn retryability_to_wire(retryability: Retryability) -> u8 {
    match retryability {
        Retryability::Never => 0,
        Retryability::RetryAfterBackoff => 1,
        Retryability::Reconnect => 2,
    }
}

fn retryability_from_wire(value: u8) -> Result<Retryability, LinkControlError> {
    match value {
        0 => Ok(Retryability::Never),
        1 => Ok(Retryability::RetryAfterBackoff),
        2 => Ok(Retryability::Reconnect),
        _ => Err(LinkControlError::invalid_payload()),
    }
}

struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn count(&mut self, value: usize, maximum: usize) -> Result<(), LinkControlError> {
        if value > maximum || value > usize::from(u8::MAX) {
            return Err(LinkControlError::limit_exceeded());
        }
        self.u8(u8::try_from(value).map_err(|_| LinkControlError::limit_exceeded())?);
        Ok(())
    }

    fn version(&mut self, version: ProtocolVersion) {
        self.u16(version.major);
        self.u16(version.minor);
    }

    fn version_range(&mut self, versions: VersionRange) {
        self.version(versions.minimum);
        self.version(versions.maximum);
    }

    fn protocol_id(&mut self, id: ProtocolStableId) {
        self.bytes(id.as_bytes());
    }

    fn schema(&mut self, schema: SchemaRef) {
        self.bytes(schema.id.as_bytes());
        self.u32(schema.revision.0);
        self.bytes(schema.fingerprint.as_bytes());
    }

    fn capabilities(
        &mut self,
        capabilities: &ProtocolCapabilitySet,
    ) -> Result<(), LinkControlError> {
        self.protocol_id(capabilities.protocol_id);
        self.count(capabilities.words.len(), MAX_PROTOCOL_CAPABILITY_WORDS)?;
        for word in &capabilities.words {
            self.u64(*word);
        }
        Ok(())
    }

    fn debug_identity(
        &mut self,
        identity: Option<&ProtocolDebugIdentity>,
    ) -> Result<(), LinkControlError> {
        match identity {
            Some(identity) => {
                if !identity.is_canonical() {
                    return Err(LinkControlError::invalid_payload());
                }
                self.u8(1);
                self.string(&identity.authority)?;
                self.string(&identity.name)?;
            }
            None => self.u8(0),
        }
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<(), LinkControlError> {
        if value.is_empty() || value.len() > MAX_CONTROL_DEBUG_COMPONENT_BYTES {
            return Err(LinkControlError::limit_exceeded());
        }
        let len = u16::try_from(value.len()).map_err(|_| LinkControlError::limit_exceeded())?;
        self.u16(len);
        self.bytes(value.as_bytes());
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], LinkControlError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(LinkControlError::limit_exceeded)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(LinkControlError::truncated)?;
        self.position = end;
        Ok(value)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], LinkControlError> {
        self.take(N)?
            .try_into()
            .map_err(|_| LinkControlError::truncated())
    }

    fn u8(&mut self) -> Result<u8, LinkControlError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, LinkControlError> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    fn u32(&mut self) -> Result<u32, LinkControlError> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    fn u64(&mut self) -> Result<u64, LinkControlError> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn bounded_count(&mut self, maximum: usize) -> Result<usize, LinkControlError> {
        let count = usize::from(self.u8()?);
        if count > maximum {
            return Err(LinkControlError::limit_exceeded());
        }
        Ok(count)
    }

    fn version(&mut self) -> Result<ProtocolVersion, LinkControlError> {
        Ok(ProtocolVersion::new(self.u16()?, self.u16()?))
    }

    fn version_range(&mut self) -> Result<VersionRange, LinkControlError> {
        let versions = VersionRange::new(self.version()?, self.version()?);
        if !versions.is_valid() {
            return Err(LinkControlError::invalid_payload());
        }
        Ok(versions)
    }

    fn protocol_id(&mut self) -> Result<ProtocolStableId, LinkControlError> {
        Ok(ProtocolStableId::from_bytes(self.take_array()?))
    }

    fn schema(&mut self) -> Result<SchemaRef, LinkControlError> {
        let schema = SchemaRef {
            id: SchemaId::from_bytes(self.take_array()?),
            revision: SchemaRevision(self.u32()?),
            fingerprint: SchemaFingerprint::from_bytes(self.take_array()?),
        };
        if schema.revision.0 == 0 {
            return Err(LinkControlError::invalid_payload());
        }
        Ok(schema)
    }

    fn capabilities(&mut self) -> Result<ProtocolCapabilitySet, LinkControlError> {
        let protocol_id = self.protocol_id()?;
        let count = self.bounded_count(MAX_PROTOCOL_CAPABILITY_WORDS)?;
        let mut words = Vec::with_capacity(count);
        for _ in 0..count {
            words.push(self.u64()?);
        }
        Ok(ProtocolCapabilitySet { protocol_id, words })
    }

    fn debug_identity(&mut self) -> Result<Option<ProtocolDebugIdentity>, LinkControlError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(ProtocolDebugIdentity::new(
                self.string()?,
                self.string()?,
            ))),
            _ => Err(LinkControlError::invalid_payload()),
        }
    }

    fn string(&mut self) -> Result<String, LinkControlError> {
        let len = usize::from(self.u16()?);
        if len == 0 || len > MAX_CONTROL_DEBUG_COMPONENT_BYTES {
            return Err(LinkControlError::limit_exceeded());
        }
        let value = std::str::from_utf8(self.take(len)?)
            .map_err(|_| LinkControlError::invalid_payload())?;
        Ok(value.to_owned())
    }
}

impl std::fmt::Display for LinkControlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.public_message)
    }
}

impl std::error::Error for LinkControlError {}

fn derive_128(domain: &[u8], authority: &str, name: &str) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update(authority.as_bytes())
        .chain_update([0])
        .chain_update(name.as_bytes())
        .finalize();
    digest[..16].try_into().expect("SHA-256 prefix is fixed")
}

fn canonical_identity_component(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed_guard() -> ControlModeGuard {
        ControlModeGuard::new(ControlIdentityMode::TypedV1)
    }

    fn open_envelope() -> ControlEnvelope {
        ControlEnvelope::typed(
            RequestId(0x0102_0304_0506_0708),
            Some(SessionId::from_bytes([0xaa; 16])),
            ControlFlags::default(),
            ControlPayload::OpenChannel(OpenChannel {
                protocol_id: ProtocolStableId::from_bytes([
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ]),
                protocol_channel_id: ProtocolChannelId(42),
                requested_session_channel_id: ChannelId(0x0102_0304),
                capacity: 64,
            }),
        )
    }

    #[test]
    fn stable_ids_are_domain_separated_and_deterministic() {
        let protocol = ProtocolStableId::derive("example.org", "tracking");
        assert_eq!(
            protocol,
            ProtocolStableId::derive("example.org", "tracking")
        );
        assert_ne!(
            protocol.as_bytes(),
            SchemaId::derive("example.org", "tracking").as_bytes()
        );
    }

    #[test]
    fn capability_intersection_is_bounded_and_protocol_scoped() {
        let id = ProtocolStableId::derive("example.org", "tracking");
        let left = ProtocolCapabilitySet {
            protocol_id: id,
            words: vec![0b1011, 0b0101],
        };
        let right = ProtocolCapabilitySet {
            protocol_id: id,
            words: vec![0b0110],
        };
        assert_eq!(left.intersect(&right).unwrap().words, vec![0b0010]);
        assert!(left.is_bounded());
    }

    #[test]
    fn open_channel_codec_matches_golden_wire_vector() {
        let encoded = encode_control_envelope(&typed_guard(), &open_envelope()).unwrap();
        let hex = encoded.iter().fold(
            String::with_capacity(encoded.len() * 2),
            |mut output, byte| {
                use std::fmt::Write;
                write!(output, "{byte:02x}").expect("writing golden vector to string");
                output
            },
        );
        assert_eq!(
            hex,
            concat!(
                "4d4c4354000100100000010203040506070801",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000001a",
                "000102030405060708090a0b0c0d0e0f002a0102030400000040"
            )
        );
        assert_eq!(
            decode_control_envelope(&typed_guard(), &encoded).unwrap(),
            open_envelope()
        );
    }

    #[test]
    fn every_control_payload_has_an_explicit_round_trip() {
        let protocol_id = ProtocolStableId::derive("example.org", "tracking");
        let schema = SchemaRef::for_contract("example.org", "tracking", 1, b"contract-v1");
        let capabilities = ProtocolCapabilitySet {
            protocol_id,
            words: vec![0x55aa, 7],
        };
        let offer = ProtocolOffer {
            stable_id: protocol_id,
            debug_identity: Some(ProtocolDebugIdentity::new("example.org", "tracking")),
            versions: VersionRange::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 2)),
            schema,
            capabilities: capabilities.clone(),
        };
        let selection = ProtocolSelection {
            stable_id: protocol_id,
            version: ProtocolVersion::new(1, 2),
            schema,
            capabilities,
        };
        let payloads = vec![
            ControlPayload::Hello(HelloControl {
                identity: Identity {
                    peer_id: crate::PeerId::from_bytes([1; 32]),
                    endpoint_id: crate::EndpointId::from_bytes([2; 16]),
                    connection_id: crate::ConnectionId::from_bytes([3; 16]),
                },
                link_versions: VersionRange::new(
                    ProtocolVersion::new(1, 0),
                    ProtocolVersion::new(1, 1),
                ),
                link_capabilities: LinkCapabilities::TYPED_CONTROL
                    | LinkCapabilities::COMPACT_CHANNEL_ID,
                requested_auth: AuthPath::TrustedReconnect,
            }),
            ControlPayload::OfferProtocols(vec![offer]),
            ControlPayload::SelectProtocols(vec![selection]),
            open_envelope().payload,
            ControlPayload::AcceptChannel(AcceptChannel {
                protocol_id,
                protocol_channel_id: ProtocolChannelId(4),
                session_channel_id: ChannelId(9),
            }),
            ControlPayload::CloseChannel(CloseChannel {
                session_channel_id: ChannelId(9),
            }),
            ControlPayload::Ping(Ping { nonce: 123 }),
            ControlPayload::Pong(Pong { nonce: 123 }),
            ControlPayload::BeginDrain(BeginDrain {
                deadline_millis: 500,
            }),
            ControlPayload::CloseSession(CloseSession { reason_code: 8 }),
        ];

        for payload in payloads {
            let envelope = ControlEnvelope::typed(
                RequestId(7),
                Some(SessionId::from_bytes([9; 16])),
                ControlFlags::RESPONSE,
                payload,
            );
            let encoded = encode_control_envelope(&typed_guard(), &envelope).unwrap();
            assert_eq!(
                decode_control_envelope(&typed_guard(), &encoded).unwrap(),
                envelope
            );
        }
    }

    #[test]
    fn structured_error_round_trip_preserves_machine_fields() {
        let envelope = ControlEnvelope::typed(
            RequestId(10),
            None,
            ControlFlags::RESPONSE,
            ControlPayload::Error(LinkControlError {
                domain: ErrorDomain::Channel,
                code: ErrorCode(27),
                operation: Some(LinkControlOpcode::OpenChannel),
                retryability: Retryability::Reconnect,
                public_message: "local diagnostic only",
            }),
        );
        let decoded = decode_control_envelope(
            &typed_guard(),
            &encode_control_envelope(&typed_guard(), &envelope).unwrap(),
        )
        .unwrap();
        let ControlPayload::Error(error) = decoded.payload else {
            panic!("expected structured error")
        };
        assert_eq!(error.domain, ErrorDomain::Channel);
        assert_eq!(error.code, ErrorCode(27));
        assert_eq!(error.operation, Some(LinkControlOpcode::OpenChannel));
        assert_eq!(error.retryability, Retryability::Reconnect);
        assert_ne!(error.public_message, "local diagnostic only");
    }

    #[test]
    fn parser_rejects_every_truncation_unknown_opcode_and_trailing_data() {
        let encoded = encode_control_envelope(&typed_guard(), &open_envelope()).unwrap();
        for end in 0..encoded.len() {
            assert!(decode_control_envelope(&typed_guard(), &encoded[..end]).is_err());
        }

        let mut unknown_opcode = encoded.clone();
        unknown_opcode[6..8].copy_from_slice(&0x7777_u16.to_be_bytes());
        let error = decode_control_envelope(&typed_guard(), &unknown_opcode).unwrap_err();
        assert_eq!(error.code, ErrorCode(1));

        let mut trailing = encoded;
        trailing.push(0);
        let error = decode_control_envelope(&typed_guard(), &trailing).unwrap_err();
        assert_eq!(error.code, ErrorCode(8));
    }

    #[test]
    fn bounded_control_fuzz_corpus_never_panics_or_allocates_from_untrusted_lengths() {
        let guard = typed_guard();
        let valid = encode_control_envelope(&guard, &open_envelope()).unwrap();
        for offset in 0..valid.len() {
            let mut mutated = valid.clone();
            mutated[offset] ^= 0xa5;
            let _result = decode_control_envelope(&guard, &mutated);
        }
        for len in 0..512_usize {
            let corpus = (0..len)
                .map(|index| {
                    u8::try_from((index.wrapping_mul(31) ^ len) & 0xff)
                        .expect("fuzz byte is masked")
                })
                .collect::<Vec<_>>();
            let _result = decode_control_envelope(&guard, &corpus);
        }
    }

    #[test]
    fn typed_and_legacy_modes_cannot_mix_within_a_session() {
        let legacy = ControlModeGuard::new(ControlIdentityMode::LegacyStringV1);
        assert_eq!(
            encode_control_envelope(&legacy, &open_envelope())
                .unwrap_err()
                .code,
            ErrorCode(2)
        );
        assert!(legacy.validate_legacy().is_ok());
        assert!(typed_guard().validate_legacy().is_err());
        assert_eq!(
            ControlIdentityMode::negotiate(LinkCapabilities::TYPED_CONTROL),
            ControlIdentityMode::TypedV1
        );
        assert_eq!(
            ControlIdentityMode::negotiate(LinkCapabilities::default()),
            ControlIdentityMode::LegacyStringV1
        );
    }

    #[test]
    fn codec_enforces_protocol_capability_and_debug_string_bounds() {
        let protocol_id = ProtocolStableId::derive("example.org", "tracking");
        let schema = SchemaRef::for_contract("example.org", "tracking", 1, b"contract-v1");
        let oversized = ProtocolOffer {
            stable_id: protocol_id,
            debug_identity: None,
            versions: VersionRange::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 0)),
            schema,
            capabilities: ProtocolCapabilitySet {
                protocol_id,
                words: vec![0; MAX_PROTOCOL_CAPABILITY_WORDS + 1],
            },
        };
        let envelope = ControlEnvelope::typed(
            RequestId(1),
            None,
            ControlFlags::default(),
            ControlPayload::OfferProtocols(vec![oversized]),
        );
        assert_eq!(
            encode_control_envelope(&typed_guard(), &envelope)
                .unwrap_err()
                .code,
            ErrorCode(5)
        );
    }

    #[test]
    fn session_channel_mapping_is_bijective_and_never_overwritten() {
        let protocol_id = ProtocolStableId::derive("example.org", "tracking");
        let accepted = AcceptChannel {
            protocol_id,
            protocol_channel_id: ProtocolChannelId(3),
            session_channel_id: ChannelId(17),
        };
        let mut mappings = SessionChannelMap::new(2).unwrap();
        mappings.bind(accepted).unwrap();
        assert_eq!(
            mappings.session_channel(protocol_id, ProtocolChannelId(3)),
            Some(ChannelId(17))
        );
        assert_eq!(
            mappings.protocol_channel(ChannelId(17)),
            Some((protocol_id, ProtocolChannelId(3)))
        );
        assert_eq!(
            mappings.session_binding(ChannelId(17)),
            Some((
                protocol_id,
                ProtocolChannelId(3),
                ChannelGeneration::INITIAL,
            ))
        );

        assert_eq!(mappings.bind(accepted).unwrap_err().code, ErrorCode(2));
        assert_eq!(
            mappings
                .bind(AcceptChannel {
                    protocol_id,
                    protocol_channel_id: ProtocolChannelId(4),
                    session_channel_id: ChannelId(17),
                })
                .unwrap_err()
                .code,
            ErrorCode(2)
        );
        assert_eq!(
            mappings.unbind(ChannelId(17)),
            Some((protocol_id, ProtocolChannelId(3)))
        );
        assert!(mappings.is_empty());
        assert_eq!(
            mappings
                .bind(AcceptChannel {
                    protocol_id,
                    protocol_channel_id: ProtocolChannelId(5),
                    session_channel_id: ChannelId(17),
                })
                .unwrap_err()
                .code,
            ErrorCode(2)
        );
        mappings
            .bind(AcceptChannel {
                protocol_id,
                protocol_channel_id: ProtocolChannelId(6),
                session_channel_id: ChannelId(18),
            })
            .unwrap();
        mappings.unbind(ChannelId(18));
        let error = mappings
            .bind(AcceptChannel {
                protocol_id,
                protocol_channel_id: ProtocolChannelId(7),
                session_channel_id: ChannelId(19),
            })
            .unwrap_err();
        assert_eq!(error.domain, ErrorDomain::Resource);
        assert_eq!(error.code, ErrorCode(1));
    }
}
