use nana_tracking_protocol::{
    CanonicalCodec, LayoutAccept, LayoutConfirm, LayoutProposal, MAX_LAYOUT_SIGNALS,
    NanaTrackingDescriptor, QualityEncoding, SessionId, SignalId, TrackingProfile, ValueEncoding,
    WireDecode,
};

use crate::{BindingError, GeometryTopology, ReceiverReport};

const MAGIC: [u8; 4] = *b"NTLC";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 10;
const MAX_REASON_BYTES: usize = 256;
const MAX_CONTROL_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolHello {
    pub minimum_version: u16,
    pub maximum_version: u16,
}

impl Default for ProtocolHello {
    fn default() -> Self {
        Self {
            minimum_version: 1,
            maximum_version: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SessionCommand {
    Start = 1,
    Stop = 2,
    Pause = 3,
    Resume = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionProposal {
    pub descriptor: NanaTrackingDescriptor,
    pub session_id: SessionId,
    pub generation: u32,
    pub layout_id: u32,
    pub layout: LayoutProposal,
    pub topology: GeometryTopology,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlMessage {
    Hello(ProtocolHello),
    SessionProposal(SessionProposal),
    LayoutAccepted(LayoutAccept),
    LayoutConfirmed(LayoutConfirm),
    SessionReady {
        session_id: SessionId,
        generation: u32,
        layout_id: u32,
    },
    Command(SessionCommand),
    ReceiverReport(ReceiverReport),
    Ping {
        receiver_send_ns: u64,
    },
    Pong {
        receiver_send_ns: u64,
        producer_send_ns: u64,
    },
    GeometryRequest,
    Error {
        code: u16,
        reason: String,
    },
    Close {
        code: u16,
        reason: String,
    },
}

impl ControlMessage {
    pub(crate) fn encode(self) -> Result<Vec<u8>, BindingError> {
        let mut writer = Writer::new(kind(&self));
        match self {
            Self::Hello(hello) => {
                writer.u16(hello.minimum_version);
                writer.u16(hello.maximum_version);
            }
            Self::SessionProposal(proposal) => {
                writer.bytes(&proposal.session_id.0);
                writer.u32(proposal.generation);
                writer.u32(proposal.layout_id);
                let descriptor = CanonicalCodec::encode(&proposal.descriptor)?;
                writer.sized_bytes(&descriptor)?;
                writer.u8(proposal.layout.profile as u8);
                writer.u16(proposal.layout.base_layout_version);
                writer.u8(proposal.layout.value_encoding as u8);
                writer.u8(proposal.layout.quality_encoding as u8);
                writer.u16(proposal.layout.target_fps);
                let extra_count = u16::try_from(proposal.layout.extra_signals.len())
                    .map_err(|_| BindingError::ControlLimit)?;
                writer.u16(extra_count);
                for signal in &proposal.layout.extra_signals {
                    writer.u16(signal.get());
                }
                writer.u32(proposal.topology.schema_revision);
                writer.bytes(&proposal.topology.topology_hash);
                writer.u32(proposal.topology.landmark_count);
            }
            Self::LayoutAccepted(accept) => {
                writer.u32(accept.layout_id);
                writer.bytes(&accept.layout_hash);
                writer.u16(accept.parameter_count);
                writer.u32(accept.expected_payload_len);
            }
            Self::LayoutConfirmed(confirm) => {
                writer.u32(confirm.layout_id);
                writer.bytes(&confirm.layout_hash);
            }
            Self::SessionReady {
                session_id,
                generation,
                layout_id,
            } => {
                writer.bytes(&session_id.0);
                writer.u32(generation);
                writer.u32(layout_id);
            }
            Self::Command(command) => writer.u8(command as u8),
            Self::ReceiverReport(report) => {
                writer.u64(report.received);
                writer.u64(report.dropped);
                writer.u64(report.stale);
                writer.u64(report.jitter_ns);
                writer.u64(report.result_age_ns);
                writer.u64(report.clock_uncertainty_ns);
            }
            Self::Ping { receiver_send_ns } => writer.u64(receiver_send_ns),
            Self::Pong {
                receiver_send_ns,
                producer_send_ns,
            } => {
                writer.u64(receiver_send_ns);
                writer.u64(producer_send_ns);
            }
            Self::GeometryRequest => {}
            Self::Error { code, reason } | Self::Close { code, reason } => {
                writer.u16(code);
                writer.string(&reason)?;
            }
        }
        writer.finish()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BindingError> {
        let (kind, mut reader) = Reader::framed(bytes)?;
        let message = match kind {
            1 => Self::Hello(ProtocolHello {
                minimum_version: reader.u16()?,
                maximum_version: reader.u16()?,
            }),
            2 => {
                let session_id = SessionId(reader.array()?);
                let generation = reader.u32()?;
                let layout_id = reader.u32()?;
                let descriptor = NanaTrackingDescriptor::decode_wire(reader.sized_bytes()?)?;
                let profile = match reader.u8()? {
                    0 => TrackingProfile::Partial,
                    1 => TrackingProfile::Basic,
                    2 => TrackingProfile::Spatial,
                    3 => TrackingProfile::Full,
                    _ => return Err(BindingError::InvalidControl),
                };
                let base_layout_version = reader.u16()?;
                let value_encoding = match reader.u8()? {
                    1 => ValueEncoding::I16Normalized,
                    _ => return Err(BindingError::InvalidControl),
                };
                let quality_encoding = match reader.u8()? {
                    0 => QualityEncoding::None,
                    1 => QualityEncoding::StateAndConfidenceU8,
                    _ => return Err(BindingError::InvalidControl),
                };
                let target_fps = reader.u16()?;
                let extra_count = usize::from(reader.u16()?);
                if extra_count > MAX_LAYOUT_SIGNALS {
                    return Err(BindingError::InvalidControl);
                }
                let mut extra_signals = Vec::with_capacity(extra_count);
                for _ in 0..extra_count {
                    extra_signals
                        .push(SignalId::new(reader.u16()?).ok_or(BindingError::InvalidControl)?);
                }
                let topology = GeometryTopology {
                    schema_revision: reader.u32()?,
                    topology_hash: reader.array()?,
                    landmark_count: reader.u32()?,
                };
                Self::SessionProposal(SessionProposal {
                    layout: LayoutProposal {
                        revisions: descriptor.revisions,
                        profile,
                        base_layout_version,
                        extra_signals,
                        value_encoding,
                        quality_encoding,
                        target_fps,
                    },
                    descriptor,
                    session_id,
                    generation,
                    layout_id,
                    topology,
                })
            }
            3 => Self::LayoutAccepted(LayoutAccept {
                layout_id: reader.u32()?,
                layout_hash: reader.array()?,
                parameter_count: reader.u16()?,
                expected_payload_len: reader.u32()?,
            }),
            4 => Self::LayoutConfirmed(LayoutConfirm {
                layout_id: reader.u32()?,
                layout_hash: reader.array()?,
            }),
            5 => Self::SessionReady {
                session_id: SessionId(reader.array()?),
                generation: reader.u32()?,
                layout_id: reader.u32()?,
            },
            6 => Self::Command(match reader.u8()? {
                1 => SessionCommand::Start,
                2 => SessionCommand::Stop,
                3 => SessionCommand::Pause,
                4 => SessionCommand::Resume,
                _ => return Err(BindingError::InvalidControl),
            }),
            7 => Self::ReceiverReport(ReceiverReport {
                received: reader.u64()?,
                dropped: reader.u64()?,
                stale: reader.u64()?,
                jitter_ns: reader.u64()?,
                result_age_ns: reader.u64()?,
                clock_uncertainty_ns: reader.u64()?,
            }),
            8 => Self::Ping {
                receiver_send_ns: reader.u64()?,
            },
            9 => Self::Pong {
                receiver_send_ns: reader.u64()?,
                producer_send_ns: reader.u64()?,
            },
            10 => Self::GeometryRequest,
            11 | 12 => {
                let code = reader.u16()?;
                let reason = reader.string()?;
                if kind == 11 {
                    Self::Error { code, reason }
                } else {
                    Self::Close { code, reason }
                }
            }
            _ => return Err(BindingError::InvalidControl),
        };
        reader.finish()?;
        Ok(message)
    }
}

const fn kind(message: &ControlMessage) -> u8 {
    match message {
        ControlMessage::Hello(_) => 1,
        ControlMessage::SessionProposal(_) => 2,
        ControlMessage::LayoutAccepted(_) => 3,
        ControlMessage::LayoutConfirmed(_) => 4,
        ControlMessage::SessionReady { .. } => 5,
        ControlMessage::Command(_) => 6,
        ControlMessage::ReceiverReport(_) => 7,
        ControlMessage::Ping { .. } => 8,
        ControlMessage::Pong { .. } => 9,
        ControlMessage::GeometryRequest => 10,
        ControlMessage::Error { .. } => 11,
        ControlMessage::Close { .. } => 12,
    }
}

struct Writer(Vec<u8>);

impl Writer {
    fn new(kind: u8) -> Self {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(&MAGIC);
        bytes.push(VERSION);
        bytes.push(kind);
        bytes.extend_from_slice(&[0; 4]);
        Self(bytes)
    }

    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }

    fn sized_bytes(&mut self, value: &[u8]) -> Result<(), BindingError> {
        self.u32(u32::try_from(value.len()).map_err(|_| BindingError::ControlLimit)?);
        self.bytes(value);
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<(), BindingError> {
        if value.len() > MAX_REASON_BYTES {
            return Err(BindingError::ControlLimit);
        }
        self.u16(u16::try_from(value.len()).map_err(|_| BindingError::ControlLimit)?);
        self.bytes(value.as_bytes());
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u8>, BindingError> {
        let payload_len = self
            .0
            .len()
            .checked_sub(HEADER_LEN)
            .and_then(|length| u32::try_from(length).ok())
            .ok_or(BindingError::ControlLimit)?;
        self.0[6..10].copy_from_slice(&payload_len.to_be_bytes());
        Ok(self.0)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn framed(bytes: &'a [u8]) -> Result<(u8, Self), BindingError> {
        if bytes.len() < HEADER_LEN
            || bytes.len() > MAX_CONTROL_BYTES
            || bytes[..4] != MAGIC
            || bytes[4] != VERSION
        {
            return Err(BindingError::InvalidControl);
        }
        let payload_len = usize::try_from(u32::from_be_bytes(
            bytes[6..10]
                .try_into()
                .map_err(|_| BindingError::InvalidControl)?,
        ))
        .map_err(|_| BindingError::InvalidControl)?;
        if payload_len != bytes.len() - HEADER_LEN {
            return Err(BindingError::InvalidControl);
        }
        Ok((
            bytes[5],
            Self {
                bytes: &bytes[HEADER_LEN..],
                offset: 0,
            },
        ))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BindingError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(BindingError::InvalidControl)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BindingError::InvalidControl)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], BindingError> {
        self.take(N)?
            .try_into()
            .map_err(|_| BindingError::InvalidControl)
    }

    fn u8(&mut self) -> Result<u8, BindingError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, BindingError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, BindingError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, BindingError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn sized_bytes(&mut self) -> Result<&'a [u8], BindingError> {
        let length = usize::try_from(self.u32()?).map_err(|_| BindingError::InvalidControl)?;
        self.take(length)
    }

    fn string(&mut self) -> Result<String, BindingError> {
        let length = usize::from(self.u16()?);
        if length > MAX_REASON_BYTES {
            return Err(BindingError::ControlLimit);
        }
        String::from_utf8(self.take(length)?.to_vec()).map_err(|_| BindingError::InvalidControl)
    }

    fn finish(self) -> Result<(), BindingError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(BindingError::InvalidControl)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nana_tracking_protocol::{
        ContractRevisions, SignalBitSet, StructureFeatures, TrackingFeatures,
    };

    #[test]
    fn control_messages_round_trip_without_diagnostic_json() {
        let descriptor = NanaTrackingDescriptor::from_capabilities(
            SignalBitSet::stable_through(76),
            StructureFeatures::FULL_REQUIRED,
            TrackingFeatures::WRIST_POSE,
        );
        let proposal = ControlMessage::SessionProposal(SessionProposal {
            descriptor,
            session_id: SessionId([3; 16]),
            generation: 4,
            layout_id: 7,
            layout: LayoutProposal {
                revisions: ContractRevisions::NTP_V1,
                profile: TrackingProfile::Full,
                base_layout_version: 1,
                extra_signals: Vec::new(),
                value_encoding: ValueEncoding::I16Normalized,
                quality_encoding: QualityEncoding::StateAndConfidenceU8,
                target_fps: 120,
            },
            topology: GeometryTopology {
                schema_revision: 2,
                topology_hash: [5; 32],
                landmark_count: 68,
            },
        });
        let encoded = proposal.clone().encode().unwrap();
        assert_eq!(ControlMessage::decode(&encoded).unwrap(), proposal);
    }
}
