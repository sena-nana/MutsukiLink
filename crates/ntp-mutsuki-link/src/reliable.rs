use mutsuki_link_core::{
    Connection, RealtimeFlowId, RealtimePriority, ReceivedRealtimeDatagram, SendOutcome,
    TransportErrorKind,
};
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::time::Instant;

use crate::BindingError;

const MAGIC: [u8; 4] = *b"NTLF";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 23;

#[derive(Clone, Debug)]
struct PendingFrame {
    pending: bool,
    priority: RealtimePriority,
    wire: Vec<u8>,
}

#[derive(Debug, Default)]
pub(crate) struct ReliableLatestSender {
    pending: BTreeMap<RealtimeFlowId, PendingFrame>,
    replacements: u64,
    buffer_growths: u64,
}

impl ReliableLatestSender {
    pub(crate) fn enqueue(
        &mut self,
        flow: RealtimeFlowId,
        generation: u32,
        sequence: u64,
        priority: RealtimePriority,
        payload: &[u8],
        max_frame_bytes: usize,
    ) -> Result<SendOutcome, BindingError> {
        let wire_len = HEADER_LEN
            .checked_add(payload.len())
            .ok_or(BindingError::PayloadLimit)?;
        if wire_len > max_frame_bytes || payload.len() > u32::MAX as usize {
            return Err(BindingError::PayloadLimit);
        }
        let (frame, replaced) = match self.pending.entry(flow) {
            Entry::Vacant(entry) => (
                entry.insert(PendingFrame {
                    pending: true,
                    priority,
                    wire: Vec::with_capacity(wire_len),
                }),
                false,
            ),
            Entry::Occupied(entry) => {
                let frame = entry.into_mut();
                let replaced = frame.pending;
                (frame, replaced)
            }
        };
        frame.pending = true;
        frame.priority = priority;
        frame.wire.clear();
        let previous_capacity = frame.wire.capacity();
        frame.wire.reserve(wire_len);
        if frame.wire.capacity() > previous_capacity {
            self.buffer_growths = self.buffer_growths.saturating_add(1);
        }
        frame.wire.extend_from_slice(&MAGIC);
        frame.wire.push(VERSION);
        frame.wire.extend_from_slice(&flow.0.to_be_bytes());
        frame.wire.extend_from_slice(&generation.to_be_bytes());
        frame.wire.extend_from_slice(&sequence.to_be_bytes());
        frame.wire.extend_from_slice(
            &u32::try_from(payload.len())
                .map_err(|_| BindingError::PayloadLimit)?
                .to_be_bytes(),
        );
        frame.wire.extend_from_slice(payload);
        if replaced {
            self.replacements = self.replacements.saturating_add(1);
            Ok(SendOutcome::ReplacedOlder)
        } else {
            Ok(SendOutcome::Enqueued)
        }
    }

    pub(crate) fn flush<C: Connection>(&mut self, connection: &mut C) -> Result<(), BindingError> {
        loop {
            let Some(flow) = self
                .pending
                .iter()
                .filter(|(_, frame)| frame.pending)
                .min_by_key(|(_, frame)| frame.priority)
                .map(|(flow, _)| *flow)
            else {
                return Ok(());
            };
            let frame = self.pending.get(&flow).expect("selected frame exists");
            match connection.try_send(&frame.wire) {
                Ok(()) => {
                    self.pending
                        .get_mut(&flow)
                        .expect("selected frame exists")
                        .pending = false;
                }
                Err(error) if error.kind == TransportErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub(crate) fn clear(&mut self) {
        self.pending.clear();
    }

    pub(crate) fn pending(&self) -> usize {
        self.pending.values().filter(|frame| frame.pending).count()
    }

    pub(crate) fn replacements(&self) -> u64 {
        self.replacements
    }

    pub(crate) fn buffer_growths(&self) -> u64 {
        self.buffer_growths
    }
}

#[derive(Debug, Default)]
pub(crate) struct ReliableLatestReceiver {
    pending: BTreeMap<RealtimeFlowId, ReceivedRealtimeDatagram>,
    replacements: u64,
    stale_discarded: u64,
}

impl ReliableLatestReceiver {
    pub(crate) fn poll<C: Connection>(
        &mut self,
        connection: &mut C,
        max_frame_bytes: usize,
        max_drain: usize,
    ) -> Result<Option<ReceivedRealtimeDatagram>, BindingError> {
        for _ in 0..max_drain {
            let wire = match connection.try_receive() {
                Ok(Some(wire)) => wire,
                Ok(None) => break,
                Err(error) if error.kind == TransportErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            };
            let frame = decode(wire, max_frame_bytes)?;
            let replace = self
                .pending
                .get(&frame.flow)
                .is_none_or(|previous| frame.sequence > previous.sequence);
            if replace && self.pending.insert(frame.flow, frame).is_some() {
                self.replacements = self.replacements.saturating_add(1);
            } else if !replace {
                self.stale_discarded = self.stale_discarded.saturating_add(1);
            }
        }
        let flow = self
            .pending
            .iter()
            .min_by_key(|(_, frame)| (frame.priority, frame.sequence))
            .map(|(flow, _)| *flow);
        Ok(flow.and_then(|flow| self.pending.remove(&flow)))
    }

    pub(crate) fn clear(&mut self) {
        self.pending.clear();
    }

    pub(crate) fn replacements(&self) -> u64 {
        self.replacements
    }

    pub(crate) fn stale_discarded(&self) -> u64 {
        self.stale_discarded
    }
}

fn decode(
    mut wire: Vec<u8>,
    max_frame_bytes: usize,
) -> Result<ReceivedRealtimeDatagram, BindingError> {
    if wire.len() < HEADER_LEN
        || wire.len() > max_frame_bytes
        || wire[..4] != MAGIC
        || wire[4] != VERSION
    {
        return Err(BindingError::InvalidFragment);
    }
    let flow = RealtimeFlowId(u16::from_be_bytes([wire[5], wire[6]]));
    let generation = u32::from_be_bytes(
        wire[7..11]
            .try_into()
            .map_err(|_| BindingError::InvalidFragment)?,
    );
    let sequence = u64::from_be_bytes(
        wire[11..19]
            .try_into()
            .map_err(|_| BindingError::InvalidFragment)?,
    );
    let payload_len = usize::try_from(u32::from_be_bytes(
        wire[19..23]
            .try_into()
            .map_err(|_| BindingError::InvalidFragment)?,
    ))
    .map_err(|_| BindingError::InvalidFragment)?;
    if payload_len != wire.len() - HEADER_LEN {
        return Err(BindingError::InvalidFragment);
    }
    let priority = match flow {
        crate::COMPACT_RIG_FLOW => RealtimePriority::Critical,
        crate::CORE_RESULT_FLOW => RealtimePriority::High,
        crate::GEOMETRY_FLOW => RealtimePriority::Disposable,
        _ => return Err(BindingError::InvalidFragment),
    };
    wire.drain(..HEADER_LEN);
    Ok(ReceivedRealtimeDatagram {
        flow,
        generation,
        sequence,
        priority,
        received_at: Instant::now(),
        payload: wire,
    })
}
