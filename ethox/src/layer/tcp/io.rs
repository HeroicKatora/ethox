//! Provided implementations for `RecvBuf` and `SendBuf`.
//!
//! This is not quite a compatibility layer with socket APIs but parts of it may be reasonably
//! close to enabling it.
use core::borrow::{Borrow, BorrowMut};
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

/// Sender with buffered data.
pub struct SendFrom<B> {
    /// The buffer of bytes.
    data: B,
    /// Index of the next fully acked byte.
    consumed: usize,
    /// Index of the highest sent byte.
    sent: usize,
    /// Indicate that all data has been put into the buffer.
    fin: bool,
    /// The tcp sequence number corresponding to the `consumed` index.
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

impl<B: Borrow<[u8]>> SendFrom<B> {
    /// Create a buffered sender.
    pub fn new(data: B) -> Self {
        SendFrom {
            data,
            consumed: 0,
            sent: 0,
            fin: false,
            at: None,
        }
    }

    /// A one-shot sender.
    ///
    /// This is equivalent to calling `fin` immediately.
    pub fn once(data: B) -> Self {
        SendFrom {
            data,
            consumed: 0,
            sent: 0,
            fin: true,
            at: None,
        }
    }

    pub fn get_ref(&self) -> &B {
        &self.data
    }

    pub fn get_mut(&mut self) -> &mut B {
        &mut self.data
    }

    /// Indicate that no more data will be added.
    pub fn fin(&mut self) {
        self.fin = true;
    }

    /// Get a reference to the data in the retransmit buffer.
    ///
    /// No mutable variant since you should not change this data. It's of course not compliant with
    /// the tcp specification to modify the data.
    pub fn sending(&self) -> &[u8] {
        &self.data.borrow()[self.consumed..self.sent]
    }

    /// Get a reference to the data that was not yet sent.
    pub fn unsent(&self) -> &[u8] {
        &self.data.borrow()[self.sent..]
    }

    /// Get a mutable reference to the data that was not yet sent.
    pub fn unsent_mut(&mut self) -> &mut [u8]
        where B: BorrowMut<[u8]>
    {
        &mut self.data.borrow_mut()[self.sent..]
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

impl<B: Borrow<[u8]>> SendBuf for SendFrom<B> {
    fn available(&self) -> AvailableBytes {
        AvailableBytes {
            total: self.data.borrow().len() - self.consumed,
            fin: self.fin,
        }
    }

    fn fill(&mut self, buf: &mut [u8], begin: TcpSeqNumber) {
        let consumed_at = self.at.expect("Fill must not be called before isn indication");
        let data = &self.data.borrow()[self.consumed..];

        let start = begin - consumed_at;
        let end = start + buf.len();
        self.sent = self.sent.max(self.consumed + end);
        buf.copy_from_slice(&data[start..end])
    }

    fn ack(&mut self, ack: TcpSeqNumber) {
        let previous = *self.at.get_or_insert(ack);
        self.consumed += ack - previous;
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
