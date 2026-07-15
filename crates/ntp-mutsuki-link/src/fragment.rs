use mutsuki_link_core::{
    Connection, RealtimeDatagram, RealtimeFlowId, RealtimePriority, SendOutcome,
};
use std::time::Instant;

use crate::{BindingConfig, BindingError, FragmentBatchOutcome};

const MAGIC: [u8; 4] = *b"NTF1";
const VERSION: u8 = 1;
pub(crate) const HEADER_LEN: usize = 18;

#[derive(Clone, Copy)]
pub(crate) struct FragmentSend<'a> {
    pub(crate) flow: RealtimeFlowId,
    pub(crate) generation: u32,
    pub(crate) sequence: u64,
    pub(crate) deadline: Instant,
    pub(crate) priority: RealtimePriority,
    pub(crate) payload: &'a [u8],
    pub(crate) config: BindingConfig,
}

pub(crate) fn send_fragmented<C: Connection>(
    connection: &mut C,
    request: FragmentSend<'_>,
    scratch: &mut Vec<u8>,
) -> Result<FragmentBatchOutcome, BindingError> {
    let FragmentSend {
        flow,
        generation,
        sequence,
        deadline,
        priority,
        payload,
        config,
    } = request;
    if payload.is_empty() || payload.len() > config.max_reassembly_bytes {
        return Err(BindingError::PayloadLimit);
    }
    let max_payload = connection
        .max_datagram_payload()
        .ok_or(BindingError::DatagramsUnsupported)?;
    let chunk_bytes = max_payload
        .checked_sub(HEADER_LEN)
        .filter(|value| *value > 0)
        .ok_or(BindingError::PayloadLimit)?;
    let fragment_count = payload.len().div_ceil(chunk_bytes);
    if fragment_count > config.max_fragments || fragment_count > usize::from(u16::MAX) {
        return Err(BindingError::PayloadLimit);
    }

    let mut aggregate = FragmentBatchOutcome::default();
    scratch.reserve(max_payload.saturating_sub(scratch.capacity()));
    for (index, chunk) in payload.chunks(chunk_bytes).enumerate() {
        let offset = index
            .checked_mul(chunk_bytes)
            .ok_or(BindingError::PayloadLimit)?;
        scratch.clear();
        scratch.extend_from_slice(&MAGIC);
        scratch.push(VERSION);
        scratch.push(0);
        scratch.extend_from_slice(
            &u16::try_from(index)
                .map_err(|_| BindingError::PayloadLimit)?
                .to_be_bytes(),
        );
        scratch.extend_from_slice(
            &u16::try_from(fragment_count)
                .map_err(|_| BindingError::PayloadLimit)?
                .to_be_bytes(),
        );
        scratch.extend_from_slice(
            &u32::try_from(offset)
                .map_err(|_| BindingError::PayloadLimit)?
                .to_be_bytes(),
        );
        scratch.extend_from_slice(
            &u32::try_from(payload.len())
                .map_err(|_| BindingError::PayloadLimit)?
                .to_be_bytes(),
        );
        scratch.extend_from_slice(chunk);
        let outcome = connection.try_send_latest(RealtimeDatagram {
            flow,
            generation,
            sequence,
            deadline,
            priority,
            payload: scratch,
        })?;
        aggregate.fragments = aggregate.fragments.saturating_add(1);
        match outcome {
            SendOutcome::Enqueued => aggregate.enqueued = aggregate.enqueued.saturating_add(1),
            SendOutcome::ReplacedOlder => {
                aggregate.replaced = aggregate.replaced.saturating_add(1);
            }
            SendOutcome::DroppedExpired => {
                aggregate.expired = aggregate.expired.saturating_add(1);
                break;
            }
            SendOutcome::DroppedCongested => {
                aggregate.congested = aggregate.congested.saturating_add(1);
                break;
            }
            SendOutcome::Unsupported => return Err(BindingError::DatagramsUnsupported),
        }
    }
    Ok(aggregate)
}

#[derive(Debug)]
pub(crate) struct Reassembler {
    state: Option<Reassembly>,
    last_completed: Option<(u32, u64)>,
}

impl Reassembler {
    pub(crate) const fn new() -> Self {
        Self {
            state: None,
            last_completed: None,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.state = None;
        self.last_completed = None;
    }

    pub(crate) fn push(
        &mut self,
        generation: u32,
        sequence: u64,
        payload: &[u8],
        config: BindingConfig,
    ) -> Result<ReassemblyOutcome, BindingError> {
        if self
            .last_completed
            .is_some_and(|(last_generation, last_sequence)| {
                generation < last_generation
                    || (generation == last_generation && sequence <= last_sequence)
            })
        {
            return Ok(ReassemblyOutcome::IgnoredOld);
        }
        let fragment = Fragment::decode(payload, config)?;
        let replace = match &self.state {
            Some(current) if generation < current.generation => {
                return Ok(ReassemblyOutcome::IgnoredOld);
            }
            Some(current) if generation == current.generation && sequence < current.sequence => {
                return Ok(ReassemblyOutcome::IgnoredOld);
            }
            Some(current) if generation == current.generation && sequence == current.sequence => {
                false
            }
            _ => true,
        };
        let replaced_incomplete = replace && self.state.is_some();
        if replace {
            self.state = Some(Reassembly::new(generation, sequence, fragment)?);
        }
        let state = self.state.as_mut().ok_or(BindingError::InvalidFragment)?;
        if state.fragment_count != fragment.count || state.total_len != fragment.total_len {
            return Err(BindingError::InvalidFragment);
        }
        state.insert(fragment)?;
        if !state.complete() {
            return Ok(ReassemblyOutcome::Pending {
                replaced_incomplete,
            });
        }
        let complete = self.state.take().ok_or(BindingError::InvalidFragment)?;
        self.last_completed = Some((complete.generation, complete.sequence));
        Ok(ReassemblyOutcome::Complete {
            generation: complete.generation,
            sequence: complete.sequence,
            payload: complete.finish()?,
            replaced_incomplete,
        })
    }
}

#[derive(Debug)]
pub(crate) enum ReassemblyOutcome {
    Pending {
        replaced_incomplete: bool,
    },
    Complete {
        generation: u32,
        sequence: u64,
        payload: Vec<u8>,
        replaced_incomplete: bool,
    },
    IgnoredOld,
}

#[derive(Clone, Copy)]
struct Fragment<'a> {
    index: usize,
    count: usize,
    offset: usize,
    total_len: usize,
    payload: &'a [u8],
}

impl<'a> Fragment<'a> {
    fn decode(bytes: &'a [u8], config: BindingConfig) -> Result<Self, BindingError> {
        if bytes.len() <= HEADER_LEN || bytes[..4] != MAGIC || bytes[4] != VERSION || bytes[5] != 0
        {
            return Err(BindingError::InvalidFragment);
        }
        let index = usize::from(u16::from_be_bytes(
            bytes[6..8]
                .try_into()
                .map_err(|_| BindingError::InvalidFragment)?,
        ));
        let count = usize::from(u16::from_be_bytes(
            bytes[8..10]
                .try_into()
                .map_err(|_| BindingError::InvalidFragment)?,
        ));
        let offset = usize::try_from(u32::from_be_bytes(
            bytes[10..14]
                .try_into()
                .map_err(|_| BindingError::InvalidFragment)?,
        ))
        .map_err(|_| BindingError::InvalidFragment)?;
        let total_len = usize::try_from(u32::from_be_bytes(
            bytes[14..18]
                .try_into()
                .map_err(|_| BindingError::InvalidFragment)?,
        ))
        .map_err(|_| BindingError::InvalidFragment)?;
        let payload = &bytes[HEADER_LEN..];
        if count == 0
            || count > config.max_fragments
            || index >= count
            || total_len == 0
            || total_len > config.max_reassembly_bytes
            || offset
                .checked_add(payload.len())
                .is_none_or(|end| end > total_len)
        {
            return Err(BindingError::InvalidFragment);
        }
        Ok(Self {
            index,
            count,
            offset,
            total_len,
            payload,
        })
    }
}

#[derive(Debug)]
struct Reassembly {
    generation: u32,
    sequence: u64,
    fragment_count: usize,
    total_len: usize,
    slots: Vec<Option<(usize, usize)>>,
    received: usize,
    bytes: Vec<u8>,
}

impl Reassembly {
    fn new(generation: u32, sequence: u64, first: Fragment<'_>) -> Result<Self, BindingError> {
        let mut state = Self {
            generation,
            sequence,
            fragment_count: first.count,
            total_len: first.total_len,
            slots: vec![None; first.count],
            received: 0,
            bytes: vec![0; first.total_len],
        };
        state.insert(first)?;
        Ok(state)
    }

    fn insert(&mut self, fragment: Fragment<'_>) -> Result<(), BindingError> {
        let slot = self
            .slots
            .get_mut(fragment.index)
            .ok_or(BindingError::InvalidFragment)?;
        let range = (fragment.offset, fragment.payload.len());
        if let Some(existing) = slot {
            if *existing != range
                || self.bytes[fragment.offset..fragment.offset + fragment.payload.len()]
                    != *fragment.payload
            {
                return Err(BindingError::InvalidFragment);
            }
            return Ok(());
        }
        self.bytes[fragment.offset..fragment.offset + fragment.payload.len()]
            .copy_from_slice(fragment.payload);
        *slot = Some(range);
        self.received = self.received.saturating_add(1);
        Ok(())
    }

    const fn complete(&self) -> bool {
        self.received == self.fragment_count
    }

    fn finish(self) -> Result<Vec<u8>, BindingError> {
        let mut ranges = self
            .slots
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(BindingError::InvalidFragment)?;
        ranges.sort_unstable_by_key(|range| range.0);
        let mut cursor = 0usize;
        for (offset, length) in ranges {
            if offset != cursor {
                return Err(BindingError::InvalidFragment);
            }
            cursor = cursor
                .checked_add(length)
                .ok_or(BindingError::InvalidFragment)?;
        }
        if cursor != self.total_len {
            return Err(BindingError::InvalidFragment);
        }
        Ok(self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment(index: u16, count: u16, offset: u32, total: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&[VERSION, 0]);
        bytes.extend_from_slice(&index.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        bytes.extend_from_slice(&offset.to_be_bytes());
        bytes.extend_from_slice(&total.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn out_of_order_fragments_reassemble_and_new_sequence_drops_partial_state() {
        let config = BindingConfig::default();
        let mut reassembler = Reassembler::new();
        assert!(matches!(
            reassembler.push(1, 1, &fragment(1, 2, 3, 6, b"def"), config),
            Ok(ReassemblyOutcome::Pending { .. })
        ));
        let complete = reassembler
            .push(1, 1, &fragment(0, 2, 0, 6, b"abc"), config)
            .unwrap();
        assert!(matches!(
            complete,
            ReassemblyOutcome::Complete { payload, .. } if payload == b"abcdef"
        ));

        reassembler
            .push(1, 2, &fragment(0, 2, 0, 6, b"old"), config)
            .unwrap();
        assert!(matches!(
            reassembler
                .push(1, 3, &fragment(0, 1, 0, 3, b"new"), config)
                .unwrap(),
            ReassemblyOutcome::Complete {
                replaced_incomplete: true,
                payload,
                ..
            } if payload == b"new"
        ));
    }
}
