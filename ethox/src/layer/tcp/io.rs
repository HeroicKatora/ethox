//! Provided implementations for `RecvBuf` and `SendBuf`.
//!
//! This is not quite a compatibility layer with socket APIs but parts of it may be reasonably
//! close to enabling it.
use core::borrow::BorrowMut;
use core::convert::TryFrom;

use crate::wire::TcpSeqNumber;
use crate::storage::assembler::{Assembler, Contig};

use super::{AvailableBytes, ReceivedSegment, RecvBuf, SendBuf};

/// A sender with no data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Empty {
    _private: (),
}

/// A receiver that doesn't store anything.
///
/// Note that this will *not* have the highest throughput for ignoring data on a congested network
/// or with some amount of loss. This does not perform unlimited selective acknowledgement (SACK)
/// of all regions it has received, so that some retransmissions are necessary even though data is
/// ignored.
#[derive(Default)]
pub struct Sink {
    highest: Option<TcpSeqNumber>,
}

/// Sender with fixed data.
pub struct SendOnce<B> {
    data: B,
    consumed: usize,
    at: Option<TcpSeqNumber>,
}

/// A receiver with a single fixed buffer.
pub struct RecvInto<B> {
    /// Buffer of bytes.
    buffer: B,
    /// The highest fully complete sequence number.
    complete: Option<TcpSeqNumber>,
    /// The index corresponding to the highest sequence number.
    mark: usize,
    /// Assembler since we can easily buffer.
    asm: Assembler<[Contig; 4]>,
}

impl Empty {
    pub fn new() -> Self {
        Empty::default()
    }
}

impl Sink {
    pub fn new() -> Self {
        Sink::default()
    }
}

impl<B: AsRef<[u8]>> SendOnce<B> {
    pub fn new(data: B) -> Self {
        SendOnce {
            data,
            consumed: 0,
            at: None,
        }
    }
}

impl<B: BorrowMut<[u8]>> RecvInto<B> {
    pub fn new(buffer: B) -> Self {
        RecvInto {
            buffer,
            complete: None,
            mark: 0,
            asm: Assembler::new([Contig::default(); 4]),
        }
    }

    pub fn get_ref(&self) -> &B {
        &self.buffer
    }

    pub fn get_mut(&mut self) -> &mut B {
        &mut self.buffer
    }

    pub fn received(&self) -> &[u8] {
        &self.buffer.borrow()[..self.mark]
    }
}

impl SendBuf for Empty {
    fn available(&self) -> AvailableBytes {
        AvailableBytes {
            total: 0,
            fin: true,
        }
    }

    fn fill(&mut self, buf: &mut [u8], _: TcpSeqNumber) {
        assert_eq!(buf.len(), 0, "Called empty send buffer to fill data");
    }

    fn ack(&mut self, _: TcpSeqNumber) {
        // Nothing todo, we don't track the number.
    }
}

impl RecvBuf for Sink {
    fn receive(&mut self, _: &[u8], segment: ReceivedSegment) {
        let highest = *self.highest.get_or_insert(segment.begin);

        if segment.contains_in_window(highest) {
            self.highest = Some(segment.sequence_end());
        }
    }

    fn ack(&mut self) -> TcpSeqNumber {
        self.highest.expect("Must not be called before any isn indication")
    }

    fn window(&self) -> usize {
        usize::max_value()
    }
}

impl<B: AsRef<[u8]>> SendBuf for SendOnce<B> {
    fn available(&self) -> AvailableBytes {
        AvailableBytes {
            total: self.data.as_ref().len() - self.consumed,
            fin: true,
        }
    }

    fn fill(&mut self, buf: &mut [u8], begin: TcpSeqNumber) {
        let consumed_at = self.at.expect("Fill must not be called before isn indication");
        let data = &self.data.as_ref()[self.consumed..];

        let start = begin - consumed_at;
        let end = start + buf.len();
        buf.copy_from_slice(&data[start..end])
    }

    fn ack(&mut self, ack: TcpSeqNumber) {
        let previous = *self.at.get_or_insert(ack);
        self.consumed += ack - previous;
        // FIXME: The ack'ed FIN will be one out-of-bounds otherwise. This is ugly.
        self.consumed = self.consumed.min(self.data.as_ref().len());
        self.at = Some(ack);
    }
}

impl<B: BorrowMut<[u8]>> RecvBuf for RecvInto<B> {
    fn receive(&mut self, mut data: &[u8], segment: ReceivedSegment) {
        let begin = self.complete.get_or_insert(segment.begin);
        let buffer = &mut self.buffer.borrow_mut()[self.mark..];

        let relative = if &segment.begin > begin {
            (segment.begin - *begin) as u32
        } else {
            let pre = *begin - segment.begin;
            data = &data[pre..];
            0u32
        };

        let available = u32::try_from(buffer.len())
            .ok().unwrap_or_else(u32::max_value);

        // UNWRAP: Incoming data is bounded by tcp sizes.
        let in_length = u32::try_from(data.len()).unwrap();
        let length = available.min(in_length);

        // Try to add it to the reassembly buffer.
        let new_data = match self.asm.bounded_add(relative, length, available) {
            Err(_) => return,
            // `new` bounded by `available` which is valid `usize`.
            Ok(new) => new as usize,
        };

        // AS: converts back what was `usize` before.
        buffer[relative as usize..(relative+length) as usize]
            .copy_from_slice(&data[..length as usize]);
        self.mark += new_data;

        *begin += usize::from(segment.syn);
        *begin += new_data;
        *begin += usize::from(new_data == segment.data_len && segment.fin);
    }

    fn ack(&mut self) -> TcpSeqNumber {
        self.complete.expect("Must not be called before any isn indication")
    }

    fn window(&self) -> usize {
        self.buffer.borrow()[self.mark..].len()
    }
}
