use std::error::Error;
use std::time::{Duration, Instant};

use mutsuki_link::{
    CancellationToken, Connection, EndpointId, ExponentialBackoff, MemoryTransportConfig,
    RealtimeDatagram, RealtimeFlowId, RealtimePriority, RealtimeQueueConfig, RealtimeSendQueue,
    ReconnectAction, ReconnectController, ReconnectFailure, ReconnectPolicy, RequestReplay,
    ResumeCoordinator, ResumeLimits, RetryLimit, SendOutcome, SessionContinuity, SessionId,
    TransportErrorKind, memory_transport_pair,
};
use serde::Serialize;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<std::alloc::System> = &INSTRUMENTED_SYSTEM;

#[derive(Serialize)]
struct RawCase {
    case_id: &'static str,
    latency_ns: u128,
    allocations: usize,
    allocated_bytes: usize,
    counters: serde_json::Value,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cases = vec![
        bounded_control_priority()?,
        realtime_latest_only()?,
        reconnect_policy()?,
        reconnect_fault()?,
    ];
    let report = serde_json::json!({
        "schema": "mutsuki.link.performance.raw/v1",
        "boundary": "in-memory Link state machines and bounded queues; not a network latency claim",
        "cases": cases,
        "rss_bytes": current_rss_bytes(),
    });
    let json = serde_json::to_string_pretty(&report)?;
    if let Ok(path) = std::env::var("MUTSUKI_LINK_OUTPUT") {
        std::fs::write(path, &json)?;
    }
    println!("{json}");
    Ok(())
}

fn bounded_control_priority() -> Result<RawCase, Box<dyn Error>> {
    let config = MemoryTransportConfig {
        queue_capacity: 8,
        max_message_bytes: 64 * 1024,
        datagram_capacity: 2,
    };
    let (mut sender, mut receiver) = memory_transport_pair(
        EndpointId::from_bytes([1; 16]),
        EndpointId::from_bytes([2; 16]),
        config,
    );
    for _ in 0..config.queue_capacity {
        sender.try_send(&vec![0x5a; config.max_message_bytes])?;
    }
    let blocked = sender.try_send(b"overflow").unwrap_err();
    let allocation = Region::new(GLOBAL);
    let started = Instant::now();
    sender.try_send_control(b"control")?;
    let received = receiver
        .try_receive_control()?
        .ok_or("missing control frame")?;
    let latency_ns = started.elapsed().as_nanos();
    let allocation = allocation.change();
    if received != b"control" || blocked.kind != TransportErrorKind::WouldBlock {
        return Err("bounded control priority invariant failed".into());
    }
    Ok(RawCase {
        case_id: "link.backpressure.saturated-control",
        latency_ns,
        allocations: allocation.allocations + allocation.reallocations,
        allocated_bytes: allocation
            .bytes_allocated
            .saturating_add_signed(allocation.bytes_reallocated),
        counters: serde_json::json!({
            "data_queue_capacity": config.queue_capacity,
            "data_frames_queued": config.queue_capacity,
            "control_frames_delivered": 1,
            "would_block": 1,
        }),
    })
}

fn realtime_latest_only() -> Result<RawCase, Box<dyn Error>> {
    let mut queue = RealtimeSendQueue::new(
        RealtimeQueueConfig {
            max_flows: 2,
            max_datagrams_per_group: 2,
            max_group_bytes: 4096,
        },
        1200,
    )?;
    let now = Instant::now();
    let deadline = now + Duration::from_secs(1);
    let allocation = Region::new(GLOBAL);
    let started = Instant::now();
    let first = queue.enqueue(datagram(1, 1, deadline), now)?;
    let replacement = queue.enqueue(datagram(1, 2, deadline), now)?;
    let expired = queue.enqueue(datagram(2, 1, now), now)?;
    queue.enqueue(datagram(2, 1, deadline), now)?;
    let dropped = queue.drop_disposable_for_congestion();
    queue.reset_for_reconnect();
    let latency_ns = started.elapsed().as_nanos();
    let allocation = allocation.change();
    let telemetry = queue.telemetry();
    if first != SendOutcome::Enqueued
        || replacement != SendOutcome::ReplacedOlder
        || expired != SendOutcome::DroppedExpired
        || dropped != 2
        || telemetry.pending != 0
        || telemetry.reconnect_count != 1
    {
        return Err("latest-only queue invariant failed".into());
    }
    Ok(RawCase {
        case_id: "link.datagram.latest-only-backpressure",
        latency_ns,
        allocations: allocation.allocations + allocation.reallocations,
        allocated_bytes: allocation
            .bytes_allocated
            .saturating_add_signed(allocation.bytes_reallocated),
        counters: serde_json::json!({
            "replaced": telemetry.replaced,
            "expired": telemetry.expired,
            "congestion_dropped": telemetry.congestion_dropped,
            "pending_after_reset": telemetry.pending,
            "reconnect_count": telemetry.reconnect_count,
            "queue_max_flows": 2,
        }),
    })
}

fn reconnect_policy() -> Result<RawCase, Box<dyn Error>> {
    let mut controller = ReconnectController::new(
        ReconnectPolicy::ExponentialBackoff(ExponentialBackoff {
            initial_delay_ms: 10,
            maximum_delay_ms: 1_000,
            multiplier_per_thousand: 2_000,
            jitter_per_thousand: 100,
            limit: RetryLimit {
                max_attempts: 56,
                max_elapsed_ms: 60_000,
            },
        }),
        CancellationToken::default(),
    )?;
    let allocation = Region::new(GLOBAL);
    let started = Instant::now();
    let mut attempts = 0_u64;
    let mut stops = 0_u64;
    for index in 0..10_000_u64 {
        match controller.after_failure(
            ReconnectFailure::TemporarilyUnreachable,
            index.saturating_mul(10),
            500,
        ) {
            ReconnectAction::AttemptAt { .. } => attempts += 1,
            ReconnectAction::Stop(_) => {
                stops += 1;
                controller.reset();
            }
            ReconnectAction::AwaitApplication => {}
        }
    }
    let latency_ns = started.elapsed().as_nanos();
    let allocation = allocation.change();
    if attempts == 0 || stops == 0 {
        return Err("reconnect budget was not exercised".into());
    }
    Ok(RawCase {
        case_id: "link.reconnect.policy",
        latency_ns,
        allocations: allocation.allocations + allocation.reallocations,
        allocated_bytes: allocation
            .bytes_allocated
            .saturating_add_signed(allocation.bytes_reallocated),
        counters: serde_json::json!({
            "evaluations": 10_000,
            "attempts": attempts,
            "budget_stops": stops,
            "max_attempts_per_storm": 56,
        }),
    })
}

fn reconnect_fault() -> Result<RawCase, Box<dyn Error>> {
    let config = MemoryTransportConfig::default();
    let (mut client, mut peer) = memory_transport_pair(
        EndpointId::from_bytes([1; 16]),
        EndpointId::from_bytes([2; 16]),
        config,
    );
    let allocation = Region::new(GLOBAL);
    let started = Instant::now();
    peer.abort();
    let peer_loss = client.try_send_control(b"pending").unwrap_err();

    let (mut reconnected, mut replacement_peer) = memory_transport_pair(
        EndpointId::from_bytes([1; 16]),
        EndpointId::from_bytes([2; 16]),
        config,
    );
    reconnected.try_send_control(b"reconnected")?;
    let delivered = replacement_peer
        .try_receive_control()?
        .ok_or("reconnected control frame missing")?;

    let mut resume = ResumeCoordinator::new(ResumeLimits::default())?;
    resume.record_unacknowledged(1, RequestReplay::Idempotent)?;
    resume.record_unacknowledged(2, RequestReplay::Never)?;
    resume.record_unacknowledged(3, RequestReplay::ApplicationDecides)?;
    let replay = resume.plan_after_reconnect(SessionContinuity::Resumed {
        previous_session_id: SessionId::from_bytes([3; 16]),
    });
    let latency_ns = started.elapsed().as_nanos();
    let allocation = allocation.change();
    if peer_loss.kind != TransportErrorKind::Aborted
        || delivered != b"reconnected"
        || replay.automatically_retry != [1]
        || replay.fail_without_retry != [2]
        || replay.application_decision != [3]
        || resume.pending_requests() != 0
    {
        return Err("abrupt peer loss or reconnect replay invariant failed".into());
    }
    Ok(RawCase {
        case_id: "link.reconnect.fault",
        latency_ns,
        allocations: allocation.allocations + allocation.reallocations,
        allocated_bytes: allocation
            .bytes_allocated
            .saturating_add_signed(allocation.bytes_reallocated),
        counters: serde_json::json!({
            "abrupt_peer_loss": 1,
            "reconnect_success": 1,
            "automatically_retried": replay.automatically_retry.len(),
            "failed_without_retry": replay.fail_without_retry.len(),
            "application_decision": replay.application_decision.len(),
            "pending_after_plan": resume.pending_requests(),
        }),
    })
}

fn datagram(flow: u16, sequence: u64, deadline: Instant) -> RealtimeDatagram<'static> {
    RealtimeDatagram {
        flow: RealtimeFlowId(flow),
        generation: 1,
        sequence,
        deadline,
        priority: RealtimePriority::Disposable,
        payload: b"realtime",
    }
}

fn current_rss_bytes() -> u64 {
    if cfg!(windows) {
        return std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("(Get-Process -Id {}).WorkingSet64", std::process::id()),
            ])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0);
    }
    std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(0)
        * 1024
}
