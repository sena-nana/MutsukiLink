#![allow(clippy::missing_errors_doc)]

use mutsuki_link::{
    ChannelGeneration, ChannelId, DataCodecLimits, DataIdentityMode, DataModeGuard, Envelope,
    EnvelopeFlags, SessionId, decode_data_envelope, encode_data_envelope_into,
};
use serde::Serialize;
use std::error::Error;
use std::fs;
use std::time::Instant;

const ITERATIONS: u128 = 250_000;
const MIN_ROUNDTRIPS_PER_SECOND: u128 = 1_000_000;
const COMPACT_HEADER_BYTES: usize = 47;
const LEGACY_FIXED_FIELDS_BYTES: usize = 43;

#[derive(Serialize)]
struct LegacyIdentitySample {
    identity_length: usize,
    modeled_minimum_header_bytes: usize,
    compact_header_savings_bytes: isize,
}

#[derive(Serialize)]
struct CodecSample {
    payload_bytes: usize,
    encoded_bytes: usize,
    roundtrips_per_second: u128,
    equivalent_60_fps_streams: u128,
    equivalent_120_fps_streams: u128,
    steady_encode_buffer_growth_events: usize,
    borrowed_decode_payload_copies: usize,
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    smoke_only: bool,
    claim_boundary: &'static str,
    operating_system: &'static str,
    architecture: &'static str,
    compact_header_bytes: usize,
    legacy_reference_model: &'static str,
    legacy_identity_matrix: Vec<LegacyIdentitySample>,
    codec_matrix: Vec<CodecSample>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let guard = DataModeGuard::new(DataIdentityMode::CompactV1);
    let limits = DataCodecLimits::default();
    let mut codec_matrix = Vec::new();
    for payload_bytes in [64, 256, 1024] {
        let mut frame = Envelope {
            session_id: SessionId::from_bytes([1; 16]),
            channel_id: ChannelId(7),
            generation: ChannelGeneration::INITIAL,
            sequence: 0,
            nesting_depth: 0,
            flags: EnvelopeFlags::default(),
            payload: vec![0x5a; payload_bytes],
        };
        let mut encoded = Vec::new();
        encode_data_envelope_into(guard, &frame, limits, &mut encoded)?;
        let warmed_capacity = encoded.capacity();
        let mut growth_events = 0;
        let started = Instant::now();
        for sequence in 0..ITERATIONS {
            frame.sequence = u64::try_from(sequence)?;
            encode_data_envelope_into(guard, &frame, limits, &mut encoded)?;
            if encoded.capacity() != warmed_capacity {
                growth_events += 1;
            }
            let decoded = std::hint::black_box(decode_data_envelope(guard, &encoded, limits)?);
            if decoded.sequence != frame.sequence || decoded.payload.len() != payload_bytes {
                return Err("compact data codec roundtrip mismatch".into());
            }
        }
        let elapsed_nanos = started.elapsed().as_nanos().max(1);
        let roundtrips_per_second = ITERATIONS.saturating_mul(1_000_000_000) / elapsed_nanos;
        if roundtrips_per_second < MIN_ROUNDTRIPS_PER_SECOND || growth_events != 0 {
            return Err("compact data codec performance budget exceeded".into());
        }
        codec_matrix.push(CodecSample {
            payload_bytes,
            encoded_bytes: encoded.len(),
            roundtrips_per_second,
            equivalent_60_fps_streams: roundtrips_per_second / 60,
            equivalent_120_fps_streams: roundtrips_per_second / 120,
            steady_encode_buffer_growth_events: growth_events,
            borrowed_decode_payload_copies: 0,
        });
    }

    let legacy_identity_matrix = [8, 32, 128]
        .into_iter()
        .map(
            |identity_bytes| -> Result<LegacyIdentitySample, Box<dyn Error>> {
                let legacy_header = LEGACY_FIXED_FIELDS_BYTES + identity_bytes;
                Ok(LegacyIdentitySample {
                    identity_length: identity_bytes,
                    modeled_minimum_header_bytes: legacy_header,
                    compact_header_savings_bytes: isize::try_from(legacy_header)?
                        - isize::try_from(COMPACT_HEADER_BYTES)?,
                })
            },
        )
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;

    let report = Report {
        schema: "mutsuki-link-compact-data-baseline/1.0.0",
        smoke_only: true,
        claim_boundary: "Synthetic local codec smoke only; not LAN, Wi-Fi, NanaTracking quality, or production latency",
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        compact_header_bytes: COMPACT_HEADER_BYTES,
        legacy_reference_model: "Minimum old field set with 2-byte identity length; excludes serializer framing and allocator overhead",
        legacy_identity_matrix,
        codec_matrix,
    };
    let json = serde_json::to_string_pretty(&report)?;
    if let Ok(path) = std::env::var("MUTSUKI_LINK_COMPACT_OUTPUT") {
        fs::write(path, json.as_bytes())?;
    }
    println!("{json}");
    Ok(())
}
