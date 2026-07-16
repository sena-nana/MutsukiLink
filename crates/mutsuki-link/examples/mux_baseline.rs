#![allow(clippy::cast_precision_loss, clippy::missing_errors_doc)]

use mutsuki_link::{
    ChannelConfig, ChannelGeneration, ChannelId, ChannelKey, ChannelMode, Envelope, EnvelopeFlags,
    Multiplexer, MultiplexerLimits, OutboundFrame, ProtocolChannelId, ProtocolStableId,
    ProtocolVersion, SessionId,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::time::Instant;

const PAYLOAD_SIZES: [usize; 4] = [1024, 16 * 1024, 64 * 1024, 1024 * 1024];
const CHANNEL_COUNTS: [usize; 3] = [1, 16, 64];
const SAMPLES: usize = 7;
const RELATIVE_REGRESSION_FACTOR: u128 = 2;
const SCHEDULER_JITTER_FLOOR_NS: u128 = 5_000;

#[derive(Debug, Deserialize, Serialize)]
struct MatrixEntry {
    channels: usize,
    payload_bytes: usize,
    cycles_per_sample: usize,
    p50_ns_per_frame: u128,
    p95_ns_per_frame: u128,
    p99_ns_per_frame: u128,
    frames_per_second: u128,
    steady_queue_slot_growth: isize,
}

#[derive(Debug, Deserialize, Serialize)]
struct ControlLatency {
    p50: u128,
    p95: u128,
    p99: u128,
}

#[derive(Debug, Deserialize, Serialize)]
struct Report {
    schema: String,
    smoke_only: bool,
    claim_boundary: String,
    operating_system: String,
    architecture: String,
    logical_cpus: usize,
    fixed_multiplexer_bytes: usize,
    priority_bands: usize,
    control_under_saturated_data: ControlLatency,
    matrix: Vec<MatrixEntry>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let report = Report {
        schema: "mutsuki-link-mux-baseline/1.0.0".to_owned(),
        smoke_only: true,
        claim_boundary: "Local in-memory scheduler benchmark only; not LAN, Wi-Fi, or production transport performance".to_owned(),
        operating_system: std::env::consts::OS.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        logical_cpus: std::thread::available_parallelism()?.get(),
        fixed_multiplexer_bytes: std::mem::size_of::<Multiplexer>(),
        priority_bands: 8,
        control_under_saturated_data: benchmark_control()?,
        matrix: benchmark_matrix()?,
    };
    if let Ok(path) = std::env::var("MUTSUKI_LINK_BASELINE") {
        compare_baseline(&report, &serde_json::from_slice(&fs::read(path)?)?)?;
    }
    let json = serde_json::to_string_pretty(&report)?;
    if let Ok(path) = std::env::var("MUTSUKI_LINK_OUTPUT") {
        fs::write(path, json.as_bytes())?;
    }
    println!("{json}");
    Ok(())
}

fn benchmark_matrix() -> Result<Vec<MatrixEntry>, Box<dyn Error>> {
    let mut entries = Vec::with_capacity(PAYLOAD_SIZES.len() * CHANNEL_COUNTS.len());
    for channels in CHANNEL_COUNTS {
        for payload_bytes in PAYLOAD_SIZES {
            entries.push(benchmark_scenario(channels, payload_bytes)?);
        }
    }
    Ok(entries)
}

fn benchmark_scenario(
    channels: usize,
    payload_bytes: usize,
) -> Result<MatrixEntry, Box<dyn Error>> {
    let (mut mux, mut frames) = populated_mux(channels, payload_bytes)?;
    cycle(&mut mux, &mut frames)?;
    cycle(&mut mux, &mut frames)?;
    let before = mux.storage_snapshot();
    let bytes_per_cycle = channels.saturating_mul(payload_bytes).max(1);
    let cycles = (64 * 1024 * 1024 / bytes_per_cycle).clamp(4, 4096);
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        for _ in 0..cycles {
            cycle(&mut mux, &mut frames)?;
        }
        let frames_processed = cycles.saturating_mul(channels).max(1);
        samples.push(started.elapsed().as_nanos() / frames_processed as u128);
    }
    let after = mux.storage_snapshot();
    let before_slots = before
        .control_queue_slots
        .saturating_add(before.ready_queue_slots)
        .saturating_add(before.data_queue_slots);
    let after_slots = after
        .control_queue_slots
        .saturating_add(after.ready_queue_slots)
        .saturating_add(after.data_queue_slots);
    let growth = isize::try_from(after_slots)? - isize::try_from(before_slots)?;
    if growth != 0 || mux.pending_frames() != 0 || frames.len() != channels {
        return Err("steady-state scheduler storage changed".into());
    }
    samples.sort_unstable();
    let p50 = percentile(&samples, 50);
    Ok(MatrixEntry {
        channels,
        payload_bytes,
        cycles_per_sample: cycles,
        p50_ns_per_frame: p50,
        p95_ns_per_frame: percentile(&samples, 95),
        p99_ns_per_frame: percentile(&samples, 99),
        frames_per_second: 1_000_000_000_u128 / p50.max(1),
        steady_queue_slot_growth: growth,
    })
}

fn benchmark_control() -> Result<ControlLatency, Box<dyn Error>> {
    let (mut mux, frames) = populated_mux(64, 1024)?;
    for frame in frames {
        mux.enqueue(frame)?;
    }
    let mut control = Vec::with_capacity(32);
    control.extend_from_slice(b"release-control");
    mux.enqueue_control(control)?;
    let OutboundFrame::Control(mut control) = mux.next_outbound().ok_or("missing control")? else {
        return Err("data bypassed reserved control queue".into());
    };
    let mut samples = Vec::with_capacity(10_000);
    for _ in 0..10_000 {
        let started = Instant::now();
        mux.enqueue_control(control)?;
        let OutboundFrame::Control(returned) = mux.next_outbound().ok_or("missing control")? else {
            return Err("data bypassed reserved control queue".into());
        };
        samples.push(started.elapsed().as_nanos());
        control = returned;
    }
    samples.sort_unstable();
    Ok(ControlLatency {
        p50: percentile(&samples, 50),
        p95: percentile(&samples, 95),
        p99: percentile(&samples, 99),
    })
}

fn populated_mux(
    channels: usize,
    payload_bytes: usize,
) -> Result<(Multiplexer, Vec<Envelope>), Box<dyn Error>> {
    let session_id = SessionId::from_bytes([1; 16]);
    let mut mux = Multiplexer::new(
        session_id,
        MultiplexerLimits {
            max_frame_bytes: 1024 * 1024,
            max_nesting_depth: 1,
            max_channels: 64,
            control_queue_capacity: 8,
            max_total_pending_frames: 72,
        },
    )?;
    let mut frames = Vec::with_capacity(channels);
    for index in 0..channels {
        let id = ChannelId(u32::try_from(index + 1)?);
        let key = ChannelKey {
            protocol_id: ProtocolStableId::derive("benchmark", "mux"),
            version: ProtocolVersion::new(1, 0),
            protocol_channel_id: ProtocolChannelId(u16::try_from(index + 1)?),
        };
        mux.open_channel(ChannelConfig {
            key,
            id,
            generation: ChannelGeneration::INITIAL,
            mode: ChannelMode::Stream,
            priority_hint: u8::try_from((index % 8) * 32)?,
            capacity: 1,
            max_frame_bytes: 1024 * 1024,
            max_stream_bytes: Some(u64::MAX),
            discardable: false,
        })?;
        frames.push(Envelope {
            session_id,
            channel_id: id,
            generation: ChannelGeneration::INITIAL,
            sequence: 0,
            nesting_depth: 0,
            flags: EnvelopeFlags::default(),
            payload: vec![7; payload_bytes],
        });
    }
    Ok((mux, frames))
}

fn cycle(mux: &mut Multiplexer, frames: &mut Vec<Envelope>) -> Result<(), Box<dyn Error>> {
    for frame in frames.drain(..) {
        mux.enqueue(frame)?;
    }
    while let Some(frame) = mux.next_outbound() {
        let OutboundFrame::Data(mut envelope) = frame else {
            return Err("unexpected control frame".into());
        };
        envelope.sequence = envelope.sequence.wrapping_add(1);
        frames.push(envelope);
    }
    Ok(())
}

fn compare_baseline(current: &Report, baseline: &Report) -> Result<(), Box<dyn Error>> {
    if current.schema != baseline.schema {
        return Err("baseline schema mismatch".into());
    }
    for entry in &current.matrix {
        let reference = baseline
            .matrix
            .iter()
            .find(|candidate| {
                candidate.channels == entry.channels
                    && candidate.payload_bytes == entry.payload_bytes
            })
            .ok_or("baseline matrix entry missing")?;
        let latency_limit = reference
            .p99_ns_per_frame
            .saturating_mul(RELATIVE_REGRESSION_FACTOR)
            .max(SCHEDULER_JITTER_FLOOR_NS);
        if entry.p99_ns_per_frame > latency_limit {
            return Err(format!(
                "mux latency regression for {} channels / {} bytes: {}ns > {}ns",
                entry.channels, entry.payload_bytes, entry.p99_ns_per_frame, latency_limit
            )
            .into());
        }
        if entry
            .frames_per_second
            .saturating_mul(RELATIVE_REGRESSION_FACTOR)
            < reference.frames_per_second
        {
            return Err(format!(
                "mux throughput regression for {} channels / {} bytes",
                entry.channels, entry.payload_bytes
            )
            .into());
        }
        if entry.steady_queue_slot_growth != 0 {
            return Err("mux steady-state queue storage grew".into());
        }
    }
    let control_limit = baseline
        .control_under_saturated_data
        .p99
        .saturating_mul(RELATIVE_REGRESSION_FACTOR)
        .max(SCHEDULER_JITTER_FLOOR_NS);
    if current.control_under_saturated_data.p99 > control_limit {
        return Err("control-under-data latency regression".into());
    }
    if current.fixed_multiplexer_bytes > baseline.fixed_multiplexer_bytes.saturating_mul(2) {
        return Err("fixed multiplexer size regressed by at least 2x".into());
    }
    Ok(())
}

fn percentile(samples: &[u128], value: usize) -> u128 {
    let index = samples
        .len()
        .saturating_mul(value)
        .div_ceil(100)
        .saturating_sub(1);
    samples[index.min(samples.len().saturating_sub(1))]
}
