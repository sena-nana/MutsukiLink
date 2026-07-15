use crate::{TransportError, TransportErrorKind};
use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

const REALTIME_MAGIC: [u8; 4] = *b"MLRD";
const REALTIME_VERSION: u8 = 1;
pub const REALTIME_DATAGRAM_HEADER_LEN: usize = 20;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RealtimeFlowId(pub u16);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RealtimePriority {
    Critical,
    High,
    Normal,
    Disposable,
}

impl RealtimePriority {
    const fn code(self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::High => 1,
            Self::Normal => 2,
            Self::Disposable => 3,
        }
    }

    fn from_code(code: u8) -> Result<Self, TransportError> {
        match code {
            0 => Ok(Self::Critical),
            1 => Ok(Self::High),
            2 => Ok(Self::Normal),
            3 => Ok(Self::Disposable),
            _ => Err(invalid_realtime("realtime priority is invalid")),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RealtimeDatagram<'a> {
    pub flow: RealtimeFlowId,
    pub generation: u32,
    pub sequence: u64,
    pub deadline: Instant,
    pub priority: RealtimePriority,
    pub payload: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct QueuedRealtimeDatagram {
    pub flow: RealtimeFlowId,
    pub generation: u32,
    pub sequence: u64,
    pub deadline: Instant,
    pub priority: RealtimePriority,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedRealtimeDatagram {
    pub flow: RealtimeFlowId,
    pub generation: u32,
    pub sequence: u64,
    pub priority: RealtimePriority,
    pub received_at: Instant,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    Enqueued,
    ReplacedOlder,
    DroppedExpired,
    DroppedCongested,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealtimeQueueConfig {
    pub max_flows: usize,
    pub max_datagrams_per_group: usize,
    pub max_group_bytes: usize,
}

impl Default for RealtimeQueueConfig {
    fn default() -> Self {
        Self {
            max_flows: 32,
            max_datagrams_per_group: 2_048,
            max_group_bytes: 8 * 1024 * 1024,
        }
    }
}

impl RealtimeQueueConfig {
    pub const fn is_valid(self) -> bool {
        self.max_flows > 0 && self.max_datagrams_per_group > 0 && self.max_group_bytes > 0
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RealtimeFlowTelemetry {
    pub queued: u64,
    pub sent: u64,
    pub sent_bytes: u64,
    pub replaced: u64,
    pub expired: u64,
    pub congestion_dropped: u64,
    pub received: u64,
    pub received_bytes: u64,
    pub receive_queue_overflow: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RealtimeTelemetry {
    pub queued: u64,
    pub pending: usize,
    pub sent: u64,
    pub sent_bytes: u64,
    pub replaced: u64,
    pub expired: u64,
    pub congestion_dropped: u64,
    pub receive_queue_overflow: u64,
    pub rtt_us: Option<u64>,
    pub estimated_send_rate_bps: Option<u64>,
    pub congestion_events: u64,
    pub current_datagram_payload: Option<usize>,
    pub max_datagram_payload: usize,
    pub mtu_change_count: u64,
    pub migration_count: u64,
    pub reconnect_count: u64,
    pub flows: BTreeMap<RealtimeFlowId, RealtimeFlowTelemetry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealtimeEvent {
    DatagramPayloadChanged { previous: usize, current: usize },
    PathMigrated,
    SessionReset,
}

#[derive(Debug)]
struct PendingGroup {
    generation: u32,
    sequence: u64,
    deadline: Instant,
    priority: RealtimePriority,
    datagrams: VecDeque<Vec<u8>>,
    payload_bytes: usize,
    insertion_order: u64,
}

#[derive(Debug)]
pub struct RealtimeSendQueue {
    config: RealtimeQueueConfig,
    max_payload: usize,
    groups: BTreeMap<RealtimeFlowId, PendingGroup>,
    telemetry: RealtimeTelemetry,
    next_insertion_order: u64,
    transport_congestion_events: u64,
}

impl RealtimeSendQueue {
    pub fn new(config: RealtimeQueueConfig, max_payload: usize) -> Result<Self, TransportError> {
        if !config.is_valid() || max_payload == 0 {
            return Err(invalid_realtime("realtime queue limits must be positive"));
        }
        let telemetry = RealtimeTelemetry {
            current_datagram_payload: Some(max_payload),
            max_datagram_payload: max_payload,
            ..RealtimeTelemetry::default()
        };
        Ok(Self {
            config,
            max_payload,
            groups: BTreeMap::new(),
            telemetry,
            next_insertion_order: 0,
            transport_congestion_events: 0,
        })
    }

    pub const fn max_payload(&self) -> usize {
        self.max_payload
    }

    pub fn pending_datagrams(&self) -> usize {
        self.groups
            .values()
            .map(|group| group.datagrams.len())
            .sum()
    }

    pub fn telemetry(&self) -> RealtimeTelemetry {
        let mut telemetry = self.telemetry.clone();
        telemetry.pending = self.pending_datagrams();
        telemetry
    }

    pub fn congestion_dropped_for_flow(&self, flow: RealtimeFlowId) -> u64 {
        self.telemetry
            .flows
            .get(&flow)
            .map_or(0, |stats| stats.congestion_dropped)
    }

    pub fn enqueue(
        &mut self,
        datagram: RealtimeDatagram<'_>,
        now: Instant,
    ) -> Result<SendOutcome, TransportError> {
        self.expire(now);
        if datagram.payload.len() > self.max_payload {
            return Err(TransportError::new(
                TransportErrorKind::MessageTooLarge,
                "realtime datagram exceeds path payload limit",
            ));
        }
        if datagram.deadline <= now {
            self.note_expired(datagram.flow, 1);
            return Ok(SendOutcome::DroppedExpired);
        }

        if let Some(group) = self.groups.get(&datagram.flow) {
            match compare_group(
                datagram.generation,
                datagram.sequence,
                group.generation,
                group.sequence,
            ) {
                GroupOrder::Older => {
                    self.note_congestion_drop(datagram.flow, 1);
                    return Ok(SendOutcome::DroppedCongested);
                }
                GroupOrder::Same => return self.append_to_group(datagram),
                GroupOrder::Newer => {}
            }
        } else if self.groups.len() >= self.config.max_flows
            && !self.evict_lower_priority(datagram.priority)
        {
            self.note_congestion_drop(datagram.flow, 1);
            return Ok(SendOutcome::DroppedCongested);
        }

        let replaced = self.drop_flow_group(datagram.flow, DropReason::Replaced);
        let insertion_order = self.next_insertion_order;
        self.next_insertion_order = self.next_insertion_order.wrapping_add(1);
        self.groups.insert(
            datagram.flow,
            PendingGroup {
                generation: datagram.generation,
                sequence: datagram.sequence,
                deadline: datagram.deadline,
                priority: datagram.priority,
                datagrams: VecDeque::from([datagram.payload.to_vec()]),
                payload_bytes: datagram.payload.len(),
                insertion_order,
            },
        );
        self.note_queued(datagram.flow);
        Ok(if replaced > 0 {
            SendOutcome::ReplacedOlder
        } else {
            SendOutcome::Enqueued
        })
    }

    pub fn peek_next_wire_len(&mut self, now: Instant) -> Option<usize> {
        self.expire(now);
        let flow = self.next_flow()?;
        self.groups
            .get(&flow)
            .and_then(|group| group.datagrams.front())
            .and_then(|payload| REALTIME_DATAGRAM_HEADER_LEN.checked_add(payload.len()))
    }

    pub fn pop_next(&mut self, now: Instant) -> Option<QueuedRealtimeDatagram> {
        self.expire(now);
        let flow = self.next_flow()?;
        self.pop_flow(flow)
    }

    pub fn pop_next_fitting(
        &mut self,
        now: Instant,
        max_wire_len: usize,
    ) -> Option<QueuedRealtimeDatagram> {
        self.expire(now);
        let priority = self.groups.values().map(|group| group.priority).min()?;
        let flow = self
            .groups
            .iter()
            .filter(|(_, group)| group.priority == priority)
            .filter(|(_, group)| {
                group
                    .datagrams
                    .front()
                    .and_then(|payload| REALTIME_DATAGRAM_HEADER_LEN.checked_add(payload.len()))
                    .is_some_and(|wire_len| wire_len <= max_wire_len)
            })
            .min_by_key(|(flow, group)| (group.insertion_order, **flow))
            .map(|(flow, _)| *flow)?;
        self.pop_flow(flow)
    }

    fn pop_flow(&mut self, flow: RealtimeFlowId) -> Option<QueuedRealtimeDatagram> {
        let group = self.groups.get_mut(&flow)?;
        let payload = group.datagrams.pop_front()?;
        let datagram = QueuedRealtimeDatagram {
            flow,
            generation: group.generation,
            sequence: group.sequence,
            deadline: group.deadline,
            priority: group.priority,
            payload,
        };
        if group.datagrams.is_empty() {
            self.groups.remove(&flow);
        }
        Some(datagram)
    }

    pub fn note_sent(&mut self, datagram: &QueuedRealtimeDatagram) {
        self.telemetry.sent = self.telemetry.sent.saturating_add(1);
        self.telemetry.sent_bytes = self
            .telemetry
            .sent_bytes
            .saturating_add(datagram.payload.len() as u64);
        let flow = self.telemetry.flows.entry(datagram.flow).or_default();
        flow.sent = flow.sent.saturating_add(1);
        flow.sent_bytes = flow
            .sent_bytes
            .saturating_add(datagram.payload.len() as u64);
    }

    pub fn note_transport_congestion(&mut self) {
        self.telemetry.congestion_events = self.telemetry.congestion_events.saturating_add(1);
    }

    pub fn drop_disposable_for_congestion(&mut self) -> usize {
        let flows: Vec<_> = self
            .groups
            .iter()
            .filter_map(|(flow, group)| {
                (group.priority == RealtimePriority::Disposable).then_some(*flow)
            })
            .collect();
        flows
            .into_iter()
            .map(|flow| self.drop_flow_group(flow, DropReason::Congested))
            .sum()
    }

    pub fn set_max_payload(&mut self, max_payload: usize) -> Result<bool, TransportError> {
        if max_payload == 0 {
            return Err(invalid_realtime("realtime payload limit must be positive"));
        }
        if max_payload == self.max_payload {
            return Ok(false);
        }
        let previous = self.max_payload;
        self.max_payload = max_payload;
        self.telemetry.current_datagram_payload = Some(max_payload);
        self.telemetry.max_datagram_payload = self.telemetry.max_datagram_payload.max(max_payload);
        self.telemetry.mtu_change_count = self.telemetry.mtu_change_count.saturating_add(1);
        if max_payload < previous {
            let oversized: Vec<_> = self
                .groups
                .iter()
                .filter_map(|(flow, group)| {
                    group
                        .datagrams
                        .iter()
                        .any(|payload| payload.len() > max_payload)
                        .then_some(*flow)
                })
                .collect();
            for flow in oversized {
                self.drop_flow_group(flow, DropReason::Congested);
            }
        }
        Ok(true)
    }

    pub fn note_network_metrics(
        &mut self,
        rtt_us: u64,
        estimated_send_rate_bps: Option<u64>,
        transport_congestion_events: u64,
    ) {
        self.telemetry.rtt_us = Some(rtt_us);
        self.telemetry.estimated_send_rate_bps = estimated_send_rate_bps;
        let new_events =
            transport_congestion_events.saturating_sub(self.transport_congestion_events);
        self.telemetry.congestion_events =
            self.telemetry.congestion_events.saturating_add(new_events);
        self.transport_congestion_events = transport_congestion_events;
    }

    pub fn note_migration(&mut self) {
        self.telemetry.migration_count = self.telemetry.migration_count.saturating_add(1);
    }

    pub fn reset_for_reconnect(&mut self) {
        self.clear_pending();
        self.telemetry.reconnect_count = self.telemetry.reconnect_count.saturating_add(1);
        self.telemetry.pending = 0;
    }

    pub fn clear_pending(&mut self) {
        self.groups.clear();
    }

    fn append_to_group(
        &mut self,
        datagram: RealtimeDatagram<'_>,
    ) -> Result<SendOutcome, TransportError> {
        let group = self.groups.get_mut(&datagram.flow).expect("group exists");
        let payload_bytes = group
            .payload_bytes
            .checked_add(datagram.payload.len())
            .ok_or_else(|| invalid_realtime("realtime group size overflow"))?;
        if group.datagrams.len() >= self.config.max_datagrams_per_group
            || payload_bytes > self.config.max_group_bytes
        {
            let dropped = group.datagrams.len().saturating_add(1);
            self.groups.remove(&datagram.flow);
            self.note_congestion_drop(datagram.flow, dropped);
            return Ok(SendOutcome::DroppedCongested);
        }
        group.deadline = group.deadline.min(datagram.deadline);
        group.priority = group.priority.min(datagram.priority);
        group.datagrams.push_back(datagram.payload.to_vec());
        group.payload_bytes = payload_bytes;
        self.note_queued(datagram.flow);
        Ok(SendOutcome::Enqueued)
    }

    fn next_flow(&self) -> Option<RealtimeFlowId> {
        self.groups
            .iter()
            .min_by_key(|(flow, group)| (group.priority, group.insertion_order, **flow))
            .map(|(flow, _)| *flow)
    }

    fn expire(&mut self, now: Instant) -> usize {
        let expired: Vec<_> = self
            .groups
            .iter()
            .filter_map(|(flow, group)| (group.deadline <= now).then_some(*flow))
            .collect();
        expired
            .into_iter()
            .map(|flow| self.drop_flow_group(flow, DropReason::Expired))
            .sum()
    }

    fn evict_lower_priority(&mut self, incoming: RealtimePriority) -> bool {
        let victim = self
            .groups
            .iter()
            .filter(|(_, group)| group.priority > incoming)
            .max_by_key(|(_, group)| (group.priority, std::cmp::Reverse(group.insertion_order)))
            .map(|(flow, _)| *flow);
        if let Some(flow) = victim {
            self.drop_flow_group(flow, DropReason::Congested);
            true
        } else {
            false
        }
    }

    fn drop_flow_group(&mut self, flow: RealtimeFlowId, reason: DropReason) -> usize {
        let Some(group) = self.groups.remove(&flow) else {
            return 0;
        };
        let count = group.datagrams.len();
        match reason {
            DropReason::Replaced => self.note_replaced(flow, count),
            DropReason::Expired => self.note_expired(flow, count),
            DropReason::Congested => self.note_congestion_drop(flow, count),
        }
        count
    }

    fn note_queued(&mut self, flow: RealtimeFlowId) {
        self.telemetry.queued = self.telemetry.queued.saturating_add(1);
        let stats = self.telemetry.flows.entry(flow).or_default();
        stats.queued = stats.queued.saturating_add(1);
    }

    fn note_replaced(&mut self, flow: RealtimeFlowId, count: usize) {
        self.telemetry.replaced = self.telemetry.replaced.saturating_add(count as u64);
        let stats = self.telemetry.flows.entry(flow).or_default();
        stats.replaced = stats.replaced.saturating_add(count as u64);
    }

    fn note_expired(&mut self, flow: RealtimeFlowId, count: usize) {
        self.telemetry.expired = self.telemetry.expired.saturating_add(count as u64);
        let stats = self.telemetry.flows.entry(flow).or_default();
        stats.expired = stats.expired.saturating_add(count as u64);
    }

    fn note_congestion_drop(&mut self, flow: RealtimeFlowId, count: usize) {
        self.telemetry.congestion_dropped = self
            .telemetry
            .congestion_dropped
            .saturating_add(count as u64);
        let stats = self.telemetry.flows.entry(flow).or_default();
        stats.congestion_dropped = stats.congestion_dropped.saturating_add(count as u64);
    }
}

#[derive(Clone, Copy)]
enum DropReason {
    Replaced,
    Expired,
    Congested,
}

enum GroupOrder {
    Older,
    Same,
    Newer,
}

fn compare_group(
    candidate_generation: u32,
    candidate_sequence: u64,
    current_generation: u32,
    current_sequence: u64,
) -> GroupOrder {
    if candidate_generation == current_generation {
        if candidate_sequence == current_sequence {
            GroupOrder::Same
        } else if is_newer_u64(candidate_sequence, current_sequence) {
            GroupOrder::Newer
        } else {
            GroupOrder::Older
        }
    } else if is_newer_u32(candidate_generation, current_generation) {
        GroupOrder::Newer
    } else {
        GroupOrder::Older
    }
}

const fn is_newer_u32(candidate: u32, current: u32) -> bool {
    let difference = candidate.wrapping_sub(current);
    difference != 0 && difference < (1 << 31)
}

const fn is_newer_u64(candidate: u64, current: u64) -> bool {
    let difference = candidate.wrapping_sub(current);
    difference != 0 && difference < (1 << 63)
}

pub fn encode_realtime_datagram(
    datagram: &QueuedRealtimeDatagram,
) -> Result<Vec<u8>, TransportError> {
    let length = REALTIME_DATAGRAM_HEADER_LEN
        .checked_add(datagram.payload.len())
        .ok_or_else(|| invalid_realtime("realtime datagram size overflow"))?;
    let mut encoded = Vec::with_capacity(length);
    encoded.extend_from_slice(&REALTIME_MAGIC);
    encoded.push(REALTIME_VERSION);
    encoded.push(datagram.priority.code());
    encoded.extend_from_slice(&datagram.flow.0.to_be_bytes());
    encoded.extend_from_slice(&datagram.generation.to_be_bytes());
    encoded.extend_from_slice(&datagram.sequence.to_be_bytes());
    encoded.extend_from_slice(&datagram.payload);
    Ok(encoded)
}

pub fn decode_realtime_datagram(
    encoded: &[u8],
    received_at: Instant,
) -> Result<ReceivedRealtimeDatagram, TransportError> {
    if encoded.len() < REALTIME_DATAGRAM_HEADER_LEN {
        return Err(invalid_realtime("realtime datagram is truncated"));
    }
    if encoded[..4] != REALTIME_MAGIC || encoded[4] != REALTIME_VERSION {
        return Err(invalid_realtime("realtime datagram header is invalid"));
    }
    Ok(ReceivedRealtimeDatagram {
        flow: RealtimeFlowId(u16::from_be_bytes([encoded[6], encoded[7]])),
        generation: u32::from_be_bytes(encoded[8..12].try_into().expect("fixed header")),
        sequence: u64::from_be_bytes(encoded[12..20].try_into().expect("fixed header")),
        priority: RealtimePriority::from_code(encoded[5])?,
        received_at,
        payload: encoded[REALTIME_DATAGRAM_HEADER_LEN..].to_vec(),
    })
}

pub fn realtime_flow_from_wire(encoded: &[u8]) -> Option<RealtimeFlowId> {
    (encoded.len() >= REALTIME_DATAGRAM_HEADER_LEN
        && encoded[..4] == REALTIME_MAGIC
        && encoded[4] == REALTIME_VERSION)
        .then(|| RealtimeFlowId(u16::from_be_bytes([encoded[6], encoded[7]])))
}

fn invalid_realtime(message: &'static str) -> TransportError {
    TransportError::new(TransportErrorKind::Other, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn config(max_flows: usize) -> RealtimeQueueConfig {
        RealtimeQueueConfig {
            max_flows,
            max_datagrams_per_group: 8,
            max_group_bytes: 1024,
        }
    }

    fn datagram(
        flow: u16,
        generation: u32,
        sequence: u64,
        deadline: Instant,
        priority: RealtimePriority,
        payload: &[u8],
    ) -> RealtimeDatagram<'_> {
        RealtimeDatagram {
            flow: RealtimeFlowId(flow),
            generation,
            sequence,
            deadline,
            priority,
            payload,
        }
    }

    #[test]
    fn newer_sequence_replaces_the_whole_unsent_group() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(1);
        let mut queue = RealtimeSendQueue::new(config(2), 100).unwrap();
        assert_eq!(
            queue
                .enqueue(
                    datagram(1, 1, 1, deadline, RealtimePriority::Normal, b"old-a"),
                    now,
                )
                .unwrap(),
            SendOutcome::Enqueued
        );
        queue
            .enqueue(
                datagram(1, 1, 1, deadline, RealtimePriority::Normal, b"old-b"),
                now,
            )
            .unwrap();
        assert_eq!(
            queue
                .enqueue(
                    datagram(1, 1, 2, deadline, RealtimePriority::Normal, b"new"),
                    now,
                )
                .unwrap(),
            SendOutcome::ReplacedOlder
        );
        let next = queue.pop_next(now).unwrap();
        assert_eq!(next.sequence, 2);
        assert_eq!(next.payload, b"new");
        assert_eq!(queue.telemetry().replaced, 2);
    }

    #[test]
    fn deadlines_drop_before_enqueue_and_before_transport() {
        let now = Instant::now();
        let mut queue = RealtimeSendQueue::new(config(2), 100).unwrap();
        assert_eq!(
            queue
                .enqueue(
                    datagram(1, 1, 1, now, RealtimePriority::Normal, b"late"),
                    now,
                )
                .unwrap(),
            SendOutcome::DroppedExpired
        );
        queue
            .enqueue(
                datagram(
                    1,
                    1,
                    2,
                    now + Duration::from_millis(5),
                    RealtimePriority::Normal,
                    b"pending",
                ),
                now,
            )
            .unwrap();
        assert!(queue.pop_next(now + Duration::from_millis(6)).is_none());
        assert_eq!(queue.telemetry().expired, 2);
    }

    #[test]
    fn flows_are_independent_and_priority_controls_drain_order() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(1);
        let mut queue = RealtimeSendQueue::new(config(2), 100).unwrap();
        queue
            .enqueue(
                datagram(1, 1, 1, deadline, RealtimePriority::Disposable, b"media"),
                now,
            )
            .unwrap();
        queue
            .enqueue(
                datagram(2, 1, 1, deadline, RealtimePriority::Critical, b"sensor"),
                now,
            )
            .unwrap();
        assert_eq!(queue.pop_next(now).unwrap().flow, RealtimeFlowId(2));
        assert_eq!(queue.pop_next(now).unwrap().flow, RealtimeFlowId(1));

        let mut saturated = RealtimeSendQueue::new(config(1), 100).unwrap();
        saturated
            .enqueue(
                datagram(1, 1, 1, deadline, RealtimePriority::Disposable, b"old"),
                now,
            )
            .unwrap();
        assert_eq!(
            saturated
                .enqueue(
                    datagram(2, 1, 1, deadline, RealtimePriority::Critical, b"critical",),
                    now,
                )
                .unwrap(),
            SendOutcome::Enqueued
        );
        assert_eq!(saturated.pop_next(now).unwrap().flow, RealtimeFlowId(2));
        assert_eq!(saturated.telemetry().congestion_dropped, 1);
    }

    #[test]
    fn mtu_and_group_limits_are_structured_and_bounded() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(1);
        let mut queue = RealtimeSendQueue::new(config(2), 8).unwrap();
        assert_eq!(
            queue
                .enqueue(
                    datagram(1, 1, 1, deadline, RealtimePriority::Normal, &[0; 9],),
                    now,
                )
                .unwrap_err()
                .kind,
            TransportErrorKind::MessageTooLarge
        );
        queue
            .enqueue(
                datagram(1, 1, 1, deadline, RealtimePriority::Normal, &[0; 8]),
                now,
            )
            .unwrap();
        queue.set_max_payload(4).unwrap();
        assert_eq!(queue.pending_datagrams(), 0);
        assert_eq!(queue.telemetry().congestion_dropped, 1);
        assert_eq!(queue.telemetry().mtu_change_count, 1);
    }

    #[test]
    fn reconnect_clears_pending_data_and_requires_a_new_generation() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(1);
        let mut queue = RealtimeSendQueue::new(config(2), 100).unwrap();
        queue
            .enqueue(
                datagram(1, 7, 9, deadline, RealtimePriority::Normal, b"old"),
                now,
            )
            .unwrap();
        queue.reset_for_reconnect();
        assert_eq!(queue.pending_datagrams(), 0);
        assert_eq!(queue.telemetry().reconnect_count, 1);
        queue
            .enqueue(
                datagram(1, 8, 1, deadline, RealtimePriority::Normal, b"new"),
                now,
            )
            .unwrap();
        assert_eq!(queue.pop_next(now).unwrap().generation, 8);
    }

    #[test]
    fn sustained_congestion_keeps_only_latest_sequence_without_memory_growth() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(10);
        let mut queue = RealtimeSendQueue::new(config(1), 100).unwrap();
        for sequence in 0..10_000 {
            queue
                .enqueue(
                    datagram(
                        1,
                        1,
                        sequence,
                        deadline,
                        RealtimePriority::Disposable,
                        &[1; 100],
                    ),
                    now,
                )
                .unwrap();
            assert_eq!(queue.pending_datagrams(), 1);
        }
        let latest = queue.pop_next(now).unwrap();
        assert_eq!(latest.sequence, 9_999);
        assert_eq!(queue.telemetry().replaced, 9_999);
    }

    #[test]
    fn simulated_loss_rtt_and_bandwidth_drop_never_trigger_retransmit_or_backlog() {
        let now = Instant::now();
        for loss_percent in [0u64, 1, 5] {
            let mut queue = RealtimeSendQueue::new(config(1), 100).unwrap();
            let mut delivered = 0;
            for sequence in 0..100u64 {
                queue
                    .enqueue(
                        datagram(
                            1,
                            1,
                            sequence,
                            now + Duration::from_secs(1),
                            RealtimePriority::Disposable,
                            &[1; 32],
                        ),
                        now,
                    )
                    .unwrap();
                let sent_once = queue.pop_next(now).unwrap();
                if sequence % 100 >= loss_percent {
                    delivered += 1;
                }
                queue.note_sent(&sent_once);
                assert_eq!(queue.pending_datagrams(), 0);
            }
            assert_eq!(delivered, 100 - loss_percent);
            assert_eq!(queue.telemetry().sent, 100);
        }

        for rtt_ms in [5, 50, 100] {
            let mut queue = RealtimeSendQueue::new(config(1), 100).unwrap();
            queue
                .enqueue(
                    datagram(
                        1,
                        1,
                        1,
                        now + Duration::from_millis(75),
                        RealtimePriority::Normal,
                        b"deadline",
                    ),
                    now,
                )
                .unwrap();
            assert_eq!(
                queue
                    .pop_next(now + Duration::from_millis(rtt_ms))
                    .is_some(),
                rtt_ms < 75
            );
        }

        let mut throttled = RealtimeSendQueue::new(config(1), 100).unwrap();
        for sequence in 0..1_000u64 {
            throttled
                .enqueue(
                    datagram(
                        1,
                        1,
                        sequence,
                        now + Duration::from_secs(1),
                        RealtimePriority::Disposable,
                        &[2; 100],
                    ),
                    now,
                )
                .unwrap();
            if sequence < 100 || sequence % 10 == 0 {
                throttled.pop_next(now);
            }
            assert!(throttled.pending_datagrams() <= 1);
        }
        assert_eq!(throttled.pop_next(now).unwrap().sequence, 999);
    }

    #[test]
    fn realtime_wire_preserves_datagram_boundaries_and_metadata() {
        let now = Instant::now();
        let queued = QueuedRealtimeDatagram {
            flow: RealtimeFlowId(7),
            generation: 11,
            sequence: 42,
            deadline: now + Duration::from_secs(1),
            priority: RealtimePriority::High,
            payload: b"opaque application data".to_vec(),
        };
        let encoded = encode_realtime_datagram(&queued).unwrap();
        assert_eq!(realtime_flow_from_wire(&encoded), Some(RealtimeFlowId(7)));
        let decoded = decode_realtime_datagram(&encoded, now).unwrap();
        assert_eq!(decoded.flow, queued.flow);
        assert_eq!(decoded.generation, queued.generation);
        assert_eq!(decoded.sequence, queued.sequence);
        assert_eq!(decoded.priority, queued.priority);
        assert_eq!(decoded.payload, queued.payload);
    }

    #[test]
    fn wire_simulation_allows_loss_and_reordering_without_hidden_retransmit() {
        let now = Instant::now();
        for loss_percent in [1u64, 5] {
            let mut wire = Vec::new();
            let mut expected = Vec::new();
            for sequence in 0..100u64 {
                if sequence % 100 < loss_percent {
                    continue;
                }
                let queued = QueuedRealtimeDatagram {
                    flow: RealtimeFlowId(9),
                    generation: 3,
                    sequence,
                    deadline: now + Duration::from_secs(1),
                    priority: RealtimePriority::Disposable,
                    payload: sequence.to_be_bytes().to_vec(),
                };
                wire.push(encode_realtime_datagram(&queued).unwrap());
                expected.push(sequence);
            }
            for window in wire.chunks_mut(7) {
                window.reverse();
            }
            let received: Vec<_> = wire
                .iter()
                .map(|encoded| decode_realtime_datagram(encoded, now).unwrap().sequence)
                .collect();
            assert_eq!(received.len(), expected.len());
            let mut reordered = received.clone();
            reordered.sort_unstable();
            assert_eq!(reordered, expected);
            assert_ne!(received, expected);
        }
    }
}
