use crate::{
    CONTROL_CHANNEL_ID, ChannelGeneration, ChannelId, ControlIdentityMode, Envelope, EnvelopeFlags,
    LinkCapabilities, SessionId,
};

pub const COMPACT_DATA_WIRE_VERSION: u16 = 1;
pub const COMPACT_DATA_HEADER_BYTES: usize = 47;
const DATA_MAGIC: [u8; 4] = *b"MLDT";
const DATA_FRAME_KIND: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataIdentityMode {
    LegacyFullChannelKey,
    CompactV1,
}

impl DataIdentityMode {
    pub const fn negotiate(
        control_mode: ControlIdentityMode,
        capabilities: LinkCapabilities,
    ) -> Self {
        if matches!(control_mode, ControlIdentityMode::TypedV1)
            && capabilities.contains(LinkCapabilities::COMPACT_CHANNEL_ID)
        {
            Self::CompactV1
        } else {
            Self::LegacyFullChannelKey
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataModeGuard {
    mode: DataIdentityMode,
}

impl DataModeGuard {
    pub const fn new(mode: DataIdentityMode) -> Self {
        Self { mode }
    }

    pub const fn mode(self) -> DataIdentityMode {
        self.mode
    }

    pub fn validate_compact(self) -> Result<(), DataCodecError> {
        if self.mode == DataIdentityMode::CompactV1 {
            Ok(())
        } else {
            Err(error(DataCodecErrorKind::ModeMismatch))
        }
    }

    pub fn validate_legacy(self) -> Result<(), DataCodecError> {
        if self.mode == DataIdentityMode::LegacyFullChannelKey {
            Ok(())
        } else {
            Err(error(DataCodecErrorKind::ModeMismatch))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataCodecLimits {
    pub max_payload_bytes: usize,
    pub max_nesting_depth: u16,
}

impl Default for DataCodecLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: 1024 * 1024,
            max_nesting_depth: 32,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataCodecErrorKind {
    ModeMismatch,
    UnsupportedVersion,
    UnknownFrameKind,
    InvalidHeader,
    InvalidFlags,
    InvalidChannel,
    LimitExceeded,
    Truncated,
    TrailingBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataCodecError {
    pub kind: DataCodecErrorKind,
    pub public_message: &'static str,
}

impl std::fmt::Display for DataCodecError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.public_message)
    }
}

impl std::error::Error for DataCodecError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BorrowedDataEnvelope<'a> {
    pub session_id: SessionId,
    pub channel_id: ChannelId,
    pub generation: ChannelGeneration,
    pub sequence: u64,
    pub nesting_depth: u16,
    pub flags: EnvelopeFlags,
    pub payload: &'a [u8],
}

impl BorrowedDataEnvelope<'_> {
    pub fn into_owned(self) -> Envelope {
        Envelope {
            session_id: self.session_id,
            channel_id: self.channel_id,
            generation: self.generation,
            sequence: self.sequence,
            nesting_depth: self.nesting_depth,
            flags: self.flags,
            payload: self.payload.to_vec(),
        }
    }
}

pub fn encode_data_envelope(
    guard: DataModeGuard,
    envelope: &Envelope,
    limits: DataCodecLimits,
) -> Result<Vec<u8>, DataCodecError> {
    let mut output = Vec::with_capacity(COMPACT_DATA_HEADER_BYTES + envelope.payload.len());
    encode_data_envelope_into(guard, envelope, limits, &mut output)?;
    Ok(output)
}

/// Encodes into caller-owned storage. After one adequate reserve, repeated
/// calls do not grow the buffer and therefore need no per-frame allocation.
pub fn encode_data_envelope_into(
    guard: DataModeGuard,
    envelope: &Envelope,
    limits: DataCodecLimits,
    output: &mut Vec<u8>,
) -> Result<(), DataCodecError> {
    guard.validate_compact()?;
    validate_limits(envelope, limits)?;
    let payload_len = u32::try_from(envelope.payload.len())
        .map_err(|_| error(DataCodecErrorKind::LimitExceeded))?;
    output.clear();
    output.reserve(COMPACT_DATA_HEADER_BYTES + envelope.payload.len());
    output.extend_from_slice(&DATA_MAGIC);
    output.extend_from_slice(&COMPACT_DATA_WIRE_VERSION.to_be_bytes());
    output.push(DATA_FRAME_KIND);
    output.extend_from_slice(envelope.session_id.as_bytes());
    output.extend_from_slice(&envelope.channel_id.0.to_be_bytes());
    output.extend_from_slice(&envelope.generation.0.to_be_bytes());
    output.extend_from_slice(&envelope.sequence.to_be_bytes());
    output.extend_from_slice(&envelope.nesting_depth.to_be_bytes());
    output.extend_from_slice(&flags_to_bits(envelope.flags).to_be_bytes());
    output.extend_from_slice(&payload_len.to_be_bytes());
    output.extend_from_slice(&envelope.payload);
    Ok(())
}

/// Decodes a compact frame without allocating or copying its payload.
pub fn decode_data_envelope(
    guard: DataModeGuard,
    wire: &[u8],
    limits: DataCodecLimits,
) -> Result<BorrowedDataEnvelope<'_>, DataCodecError> {
    guard.validate_compact()?;
    if wire.len() < COMPACT_DATA_HEADER_BYTES {
        return Err(error(DataCodecErrorKind::Truncated));
    }
    if wire[..4] != DATA_MAGIC {
        return Err(error(DataCodecErrorKind::InvalidHeader));
    }
    let version = u16::from_be_bytes([wire[4], wire[5]]);
    if version != COMPACT_DATA_WIRE_VERSION {
        return Err(error(DataCodecErrorKind::UnsupportedVersion));
    }
    if wire[6] != DATA_FRAME_KIND {
        return Err(error(DataCodecErrorKind::UnknownFrameKind));
    }
    let session_id = SessionId::from_bytes(array_at(wire, 7)?);
    let channel_id = ChannelId(u32::from_be_bytes(array_at(wire, 23)?));
    let generation = ChannelGeneration(u32::from_be_bytes(array_at(wire, 27)?));
    if channel_id == CONTROL_CHANNEL_ID || generation.0 == 0 {
        return Err(error(DataCodecErrorKind::InvalidChannel));
    }
    let sequence = u64::from_be_bytes(array_at(wire, 31)?);
    let nesting_depth = u16::from_be_bytes(array_at(wire, 39)?);
    if nesting_depth > limits.max_nesting_depth {
        return Err(error(DataCodecErrorKind::LimitExceeded));
    }
    let flags = flags_from_bits(u16::from_be_bytes(array_at(wire, 41)?))?;
    let payload_len = usize::try_from(u32::from_be_bytes(array_at(wire, 43)?))
        .map_err(|_| error(DataCodecErrorKind::LimitExceeded))?;
    if payload_len > limits.max_payload_bytes {
        return Err(error(DataCodecErrorKind::LimitExceeded));
    }
    let expected = COMPACT_DATA_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or_else(|| error(DataCodecErrorKind::LimitExceeded))?;
    if wire.len() < expected {
        return Err(error(DataCodecErrorKind::Truncated));
    }
    if wire.len() != expected {
        return Err(error(DataCodecErrorKind::TrailingBytes));
    }
    Ok(BorrowedDataEnvelope {
        session_id,
        channel_id,
        generation,
        sequence,
        nesting_depth,
        flags,
        payload: &wire[COMPACT_DATA_HEADER_BYTES..],
    })
}

fn validate_limits(envelope: &Envelope, limits: DataCodecLimits) -> Result<(), DataCodecError> {
    if envelope.channel_id == CONTROL_CHANNEL_ID || envelope.generation.0 == 0 {
        return Err(error(DataCodecErrorKind::InvalidChannel));
    }
    if envelope.payload.len() > limits.max_payload_bytes
        || envelope.nesting_depth > limits.max_nesting_depth
    {
        return Err(error(DataCodecErrorKind::LimitExceeded));
    }
    Ok(())
}

fn flags_to_bits(flags: EnvelopeFlags) -> u16 {
    u16::from(flags.end_of_stream) | (u16::from(flags.cancelled) << 1)
}

fn flags_from_bits(bits: u16) -> Result<EnvelopeFlags, DataCodecError> {
    if bits & !0b11 != 0 {
        return Err(error(DataCodecErrorKind::InvalidFlags));
    }
    Ok(EnvelopeFlags {
        end_of_stream: bits & 1 != 0,
        cancelled: bits & 2 != 0,
    })
}

fn array_at<const N: usize>(wire: &[u8], offset: usize) -> Result<[u8; N], DataCodecError> {
    wire.get(offset..offset.saturating_add(N))
        .ok_or_else(|| error(DataCodecErrorKind::Truncated))?
        .try_into()
        .map_err(|_| error(DataCodecErrorKind::Truncated))
}

const fn error(kind: DataCodecErrorKind) -> DataCodecError {
    let public_message = match kind {
        DataCodecErrorKind::ModeMismatch => "data identity mode does not match negotiated session",
        DataCodecErrorKind::UnsupportedVersion => "unsupported compact data wire version",
        DataCodecErrorKind::UnknownFrameKind => "unknown Link frame kind",
        DataCodecErrorKind::InvalidHeader => "invalid compact data header",
        DataCodecErrorKind::InvalidFlags => "invalid compact data flags",
        DataCodecErrorKind::InvalidChannel => "compact data channel identity is invalid",
        DataCodecErrorKind::LimitExceeded => "compact data frame exceeds a resource limit",
        DataCodecErrorKind::Truncated => "truncated compact data frame",
        DataCodecErrorKind::TrailingBytes => "compact data frame contains trailing bytes",
    };
    DataCodecError {
        kind,
        public_message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> DataModeGuard {
        DataModeGuard::new(DataIdentityMode::CompactV1)
    }

    fn frame() -> Envelope {
        Envelope {
            session_id: SessionId::from_bytes([0xaa; 16]),
            channel_id: ChannelId(0x0102_0304),
            generation: ChannelGeneration(0x0506_0708),
            sequence: 0x1112_1314_1516_1718,
            nesting_depth: 2,
            flags: EnvelopeFlags {
                end_of_stream: true,
                cancelled: false,
            },
            payload: vec![0xde, 0xad, 0xbe, 0xef],
        }
    }

    #[test]
    fn compact_data_codec_matches_golden_vector() {
        let encoded = encode_data_envelope(guard(), &frame(), DataCodecLimits::default()).unwrap();
        let hex = encoded.iter().fold(
            String::with_capacity(encoded.len() * 2),
            |mut output, byte| {
                use std::fmt::Write;
                write!(output, "{byte:02x}").expect("writing golden vector");
                output
            },
        );
        assert_eq!(
            hex,
            concat!(
                "4d4c4454000101aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "010203040506070811121314151617180002000100000004deadbeef"
            )
        );
        let decoded = decode_data_envelope(guard(), &encoded, DataCodecLimits::default()).unwrap();
        assert_eq!(decoded.into_owned(), frame());
    }

    #[test]
    fn decoder_rejects_every_truncation_and_bounded_mutation_corpus() {
        let encoded = encode_data_envelope(guard(), &frame(), DataCodecLimits::default()).unwrap();
        for end in 0..encoded.len() {
            assert!(
                decode_data_envelope(guard(), &encoded[..end], DataCodecLimits::default()).is_err()
            );
        }
        for offset in 0..encoded.len() {
            let mut mutated = encoded.clone();
            mutated[offset] ^= 0x5a;
            let _result = decode_data_envelope(guard(), &mutated, DataCodecLimits::default());
        }
        for len in 0..512_usize {
            let corpus = (0..len)
                .map(|index| {
                    u8::try_from((index.wrapping_mul(17) ^ len) & 0xff)
                        .expect("fuzz byte is masked")
                })
                .collect::<Vec<_>>();
            let _result = decode_data_envelope(guard(), &corpus, DataCodecLimits::default());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_data_envelope(guard(), &trailing, DataCodecLimits::default())
                .unwrap_err()
                .kind,
            DataCodecErrorKind::TrailingBytes
        );
    }

    #[test]
    fn data_mode_requires_both_typed_control_and_compact_capability() {
        assert_eq!(
            DataIdentityMode::negotiate(
                ControlIdentityMode::TypedV1,
                LinkCapabilities::COMPACT_CHANNEL_ID,
            ),
            DataIdentityMode::CompactV1
        );
        assert_eq!(
            DataIdentityMode::negotiate(
                ControlIdentityMode::LegacyStringV1,
                LinkCapabilities::COMPACT_CHANNEL_ID,
            ),
            DataIdentityMode::LegacyFullChannelKey
        );
        assert!(
            DataModeGuard::new(DataIdentityMode::LegacyFullChannelKey)
                .validate_compact()
                .is_err()
        );
        assert!(guard().validate_legacy().is_err());
    }

    #[test]
    fn caller_owned_buffer_is_reused_after_warmup() {
        let frame = frame();
        let mut output = Vec::new();
        encode_data_envelope_into(guard(), &frame, DataCodecLimits::default(), &mut output)
            .unwrap();
        let capacity = output.capacity();
        for _ in 0..1_000 {
            encode_data_envelope_into(guard(), &frame, DataCodecLimits::default(), &mut output)
                .unwrap();
            assert_eq!(output.capacity(), capacity);
        }
    }
}
