use crate::{
    ChannelConfig, ChannelId, ChannelKey, ChannelMode, ProtocolOffer, ProtocolSelection,
    ProtocolVersion, VersionRange,
};
use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

const MAX_PROTOCOL_ID_BYTES: usize = 128;
const MAX_CHANNEL_NAME_BYTES: usize = 64;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolId(String);

impl ProtocolId {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolRegistryError> {
        let value = value.into();
        if value.len() > MAX_PROTOCOL_ID_BYTES || !valid_protocol_id(&value) {
            return Err(error(ProtocolRegistryErrorKind::InvalidProtocolId));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProtocolId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolChannel {
    pub name: String,
    pub mode: ChannelMode,
    /// Lower values are more important. Link records but does not interpret product priority.
    pub priority: u8,
    pub max_frame_bytes: usize,
    pub max_stream_bytes: Option<u64>,
    pub max_in_flight_frames: usize,
    /// Only event channels may opt into overload dropping.
    pub discardable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolDescriptor {
    pub id: ProtocolId,
    pub versions: VersionRange,
    pub channels: Vec<ProtocolChannel>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolRegistryLimits {
    pub max_protocols: usize,
    pub max_channels_per_protocol: usize,
    pub max_total_channels: usize,
    pub max_protocol_id_bytes: usize,
    pub max_channel_name_bytes: usize,
}

impl Default for ProtocolRegistryLimits {
    fn default() -> Self {
        Self {
            max_protocols: 16,
            max_channels_per_protocol: 32,
            max_total_channels: 128,
            max_protocol_id_bytes: MAX_PROTOCOL_ID_BYTES,
            max_channel_name_bytes: MAX_CHANNEL_NAME_BYTES,
        }
    }
}

impl ProtocolRegistryLimits {
    pub const fn is_valid(self) -> bool {
        self.max_protocols > 0
            && self.max_channels_per_protocol > 0
            && self.max_total_channels > 0
            && self.max_protocol_id_bytes > 0
            && self.max_protocol_id_bytes <= MAX_PROTOCOL_ID_BYTES
            && self.max_channel_name_bytes > 0
            && self.max_channel_name_bytes <= MAX_CHANNEL_NAME_BYTES
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolRegistryErrorKind {
    InvalidLimits,
    InvalidProtocolId,
    InvalidVersionRange,
    InvalidChannel,
    DuplicateProtocol,
    DuplicateChannel,
    RegistryLimitExceeded,
    UnknownProtocol,
    ProtocolNotNegotiated,
    VersionNotSupported,
    ChannelNotDefined,
    ChannelCapacityExceeded,
    FrameLimitExceeded,
    StreamLimitExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolRegistryError {
    pub kind: ProtocolRegistryErrorKind,
    pub public_message: &'static str,
}

impl fmt::Display for ProtocolRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.public_message)
    }
}

impl std::error::Error for ProtocolRegistryError {}

#[derive(Debug)]
pub struct ProtocolRegistry {
    limits: ProtocolRegistryLimits,
    descriptors: BTreeMap<ProtocolId, ProtocolDescriptor>,
    total_channels: usize,
}

impl ProtocolRegistry {
    pub fn new(limits: ProtocolRegistryLimits) -> Result<Self, ProtocolRegistryError> {
        if !limits.is_valid() {
            return Err(error(ProtocolRegistryErrorKind::InvalidLimits));
        }
        Ok(Self {
            limits,
            descriptors: BTreeMap::new(),
            total_channels: 0,
        })
    }

    pub fn register(
        &mut self,
        descriptor: ProtocolDescriptor,
    ) -> Result<(), ProtocolRegistryError> {
        self.validate_descriptor(&descriptor)?;
        if self.descriptors.contains_key(&descriptor.id) {
            return Err(error(ProtocolRegistryErrorKind::DuplicateProtocol));
        }
        if self.descriptors.len() >= self.limits.max_protocols
            || self
                .total_channels
                .saturating_add(descriptor.channels.len())
                > self.limits.max_total_channels
        {
            return Err(error(ProtocolRegistryErrorKind::RegistryLimitExceeded));
        }
        self.total_channels = self
            .total_channels
            .saturating_add(descriptor.channels.len());
        self.descriptors.insert(descriptor.id.clone(), descriptor);
        Ok(())
    }

    pub fn freeze(self) -> FrozenProtocolRegistry {
        FrozenProtocolRegistry {
            descriptors: self.descriptors,
            max_remote_offers: self.limits.max_protocols,
        }
    }

    fn validate_descriptor(
        &self,
        descriptor: &ProtocolDescriptor,
    ) -> Result<(), ProtocolRegistryError> {
        if descriptor.id.as_str().len() > self.limits.max_protocol_id_bytes {
            return Err(error(ProtocolRegistryErrorKind::InvalidProtocolId));
        }
        if !descriptor.versions.is_valid() {
            return Err(error(ProtocolRegistryErrorKind::InvalidVersionRange));
        }
        if descriptor.channels.is_empty()
            || descriptor.channels.len() > self.limits.max_channels_per_protocol
        {
            return Err(error(ProtocolRegistryErrorKind::RegistryLimitExceeded));
        }
        let mut channel_names = BTreeSet::new();
        for channel in &descriptor.channels {
            if channel.name.len() > self.limits.max_channel_name_bytes
                || !valid_component(&channel.name)
                || channel.max_frame_bytes == 0
                || channel.max_in_flight_frames == 0
                || channel.max_stream_bytes == Some(0)
                || ((channel.mode == ChannelMode::Stream) != channel.max_stream_bytes.is_some())
                || (channel.mode != ChannelMode::Event && channel.discardable)
            {
                return Err(error(ProtocolRegistryErrorKind::InvalidChannel));
            }
            if !channel_names.insert(channel.name.as_str()) {
                return Err(error(ProtocolRegistryErrorKind::DuplicateChannel));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct FrozenProtocolRegistry {
    descriptors: BTreeMap<ProtocolId, ProtocolDescriptor>,
    max_remote_offers: usize,
}

impl FrozenProtocolRegistry {
    pub fn offers(&self) -> Vec<ProtocolOffer> {
        self.descriptors
            .values()
            .map(|descriptor| ProtocolOffer {
                namespace: descriptor.id.to_string(),
                versions: descriptor.versions,
            })
            .collect()
    }

    /// Computes independent intersections. An incompatible protocol is omitted
    /// without invalidating other shared protocol namespaces.
    pub fn negotiate(
        &self,
        remote: &[ProtocolOffer],
    ) -> Result<Vec<ProtocolSelection>, ProtocolRegistryError> {
        if remote.len() > self.max_remote_offers {
            return Err(error(ProtocolRegistryErrorKind::RegistryLimitExceeded));
        }
        Ok(self
            .descriptors
            .values()
            .filter_map(|descriptor| {
                remote
                    .iter()
                    .filter(|offer| offer.namespace == descriptor.id.as_str())
                    .find_map(|offer| descriptor.versions.negotiate(offer.versions))
                    .map(|version| ProtocolSelection {
                        namespace: descriptor.id.to_string(),
                        version,
                    })
            })
            .collect())
    }

    pub fn activate(
        &self,
        negotiated: &[ProtocolSelection],
    ) -> Result<ActiveProtocolSet, ProtocolRegistryError> {
        if negotiated.len() > self.descriptors.len() {
            return Err(error(ProtocolRegistryErrorKind::RegistryLimitExceeded));
        }
        let mut active = BTreeMap::new();
        for selection in negotiated {
            let id = ProtocolId::new(selection.namespace.clone())?;
            let descriptor = self
                .descriptors
                .get(&id)
                .ok_or_else(|| error(ProtocolRegistryErrorKind::UnknownProtocol))?;
            if descriptor
                .versions
                .negotiate(VersionRange::new(selection.version, selection.version))
                .is_none()
            {
                return Err(error(ProtocolRegistryErrorKind::VersionNotSupported));
            }
            active.insert(
                id,
                ActiveProtocol {
                    version: selection.version,
                    channels: descriptor
                        .channels
                        .iter()
                        .map(|channel| (channel.name.clone(), channel.clone()))
                        .collect(),
                },
            );
        }
        Ok(ActiveProtocolSet { active })
    }
}

#[derive(Clone, Debug)]
struct ActiveProtocol {
    version: ProtocolVersion,
    channels: BTreeMap<String, ProtocolChannel>,
}

#[derive(Clone, Debug)]
pub struct ActiveProtocolSet {
    active: BTreeMap<ProtocolId, ActiveProtocol>,
}

impl ActiveProtocolSet {
    pub fn contains(&self, protocol: &ProtocolId) -> bool {
        self.active.contains_key(protocol)
    }

    pub fn len(&self) -> usize {
        self.active.len()
    }

    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }

    pub fn open_channel(
        &self,
        request: ChannelOpenRequest,
    ) -> Result<ValidatedChannel, ProtocolRegistryError> {
        let protocol = self
            .active
            .get(&request.protocol)
            .ok_or_else(|| error(ProtocolRegistryErrorKind::ProtocolNotNegotiated))?;
        let channel = protocol
            .channels
            .get(&request.channel_name)
            .ok_or_else(|| error(ProtocolRegistryErrorKind::ChannelNotDefined))?;
        if request.capacity == 0 || request.capacity > channel.max_in_flight_frames {
            return Err(error(ProtocolRegistryErrorKind::ChannelCapacityExceeded));
        }
        Ok(ValidatedChannel {
            config: ChannelConfig {
                key: ChannelKey {
                    namespace: request.protocol.to_string(),
                    version: protocol.version,
                    id: request.channel_id,
                },
                mode: channel.mode,
                priority_hint: channel.priority,
                capacity: request.capacity,
            },
            channel_name: request.channel_name,
            max_frame_bytes: channel.max_frame_bytes,
            max_stream_bytes: channel.max_stream_bytes,
            discardable: channel.discardable,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelOpenRequest {
    pub protocol: ProtocolId,
    pub channel_name: String,
    pub channel_id: ChannelId,
    pub capacity: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedChannel {
    pub config: ChannelConfig,
    pub channel_name: String,
    pub max_frame_bytes: usize,
    pub max_stream_bytes: Option<u64>,
    pub discardable: bool,
}

impl ValidatedChannel {
    pub fn validate_payload(
        &self,
        frame_bytes: usize,
        stream_bytes: Option<u64>,
    ) -> Result<(), ProtocolRegistryError> {
        if frame_bytes > self.max_frame_bytes {
            return Err(error(ProtocolRegistryErrorKind::FrameLimitExceeded));
        }
        if let Some(stream_bytes) = stream_bytes {
            let Some(maximum) = self.max_stream_bytes else {
                return Err(error(ProtocolRegistryErrorKind::StreamLimitExceeded));
            };
            if stream_bytes > maximum {
                return Err(error(ProtocolRegistryErrorKind::StreamLimitExceeded));
            }
        }
        Ok(())
    }
}

fn valid_protocol_id(value: &str) -> bool {
    value.contains('.')
        && value.len() <= MAX_PROTOCOL_ID_BYTES
        && value.split('.').all(valid_component)
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

const fn error(kind: ProtocolRegistryErrorKind) -> ProtocolRegistryError {
    let public_message = match kind {
        ProtocolRegistryErrorKind::InvalidLimits => "protocol registry limits must be positive",
        ProtocolRegistryErrorKind::InvalidProtocolId => "protocol id is not a valid namespace",
        ProtocolRegistryErrorKind::InvalidVersionRange => "protocol version range is invalid",
        ProtocolRegistryErrorKind::InvalidChannel => "protocol channel definition is invalid",
        ProtocolRegistryErrorKind::DuplicateProtocol => "protocol id is already registered",
        ProtocolRegistryErrorKind::DuplicateChannel => "protocol channel is already defined",
        ProtocolRegistryErrorKind::RegistryLimitExceeded => "protocol registry limit exceeded",
        ProtocolRegistryErrorKind::UnknownProtocol => "protocol is not registered",
        ProtocolRegistryErrorKind::ProtocolNotNegotiated => "protocol was not negotiated",
        ProtocolRegistryErrorKind::VersionNotSupported => "protocol version is not supported",
        ProtocolRegistryErrorKind::ChannelNotDefined => "protocol channel is not defined",
        ProtocolRegistryErrorKind::ChannelCapacityExceeded => {
            "channel capacity exceeds protocol limit"
        }
        ProtocolRegistryErrorKind::FrameLimitExceeded => "frame exceeds protocol limit",
        ProtocolRegistryErrorKind::StreamLimitExceeded => "stream exceeds protocol limit",
    };
    ProtocolRegistryError {
        kind,
        public_message,
    }
}
