//! Provided implementations for `RecvBuf` and `SendBuf`.
//!
//! This is not quite a compatibility layer with socket APIs but parts of it may be reasonably
//! close to enabling it.
use core::borrow::{Borrow, BorrowMut};
use core::convert::TryFrom;

use crate::alloc::vec::Vec;
use crate::wire::TcpSeqNumber;
use crate::storage::assembler::{Assembler, Contig};

use super::{AvailableBytes, ReceivedSegment, RecvBuf, SendBuf};

/// A sender with no data.
///
/// Use the `Default` trait to instantiate it.
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
///
/// Use the `Default` trait to instantiate it.
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

impl<Buffer: Borrow<[u8]>> SendFrom<Buffer> {
    /// Create a buffered sender.
    pub fn new(data: Buffer) -> Self {
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
    pub fn once(data: Buffer) -> Self {
        SendFrom {
            data,
            consumed: 0,
            sent: 0,
            fin: true,
            at: None,
        }
    }

    /// Get a reference to the data buffer.
    pub fn get_ref(&self) -> &Buffer {
        &self.data
    }

    /// Get a mutable reference to the data buffer.
    ///
    /// This allows one to modify the data but doing so requires some care. It is fine to
    /// re-allocate it and append more data (e.g. extend a contained `Vec`) but shortening should
    /// never cause the length of borrowed bytes to become smaller than [`sent_bytes`]. Otherwise,
    /// the sender may panic the next time it is used.
    ///
    /// It is also okay to remove some bytes from the start of the buffer when combined with
    /// `bump_external`.
    ///
    /// [`sent_bytes`]: #method.sent_bytes
    pub fn get_mut(&mut self) -> &mut Buffer {
        &mut self.data
    }

    /// Indicate that no more data will be added.
    ///
    /// It's not illegal to add more data to the end afterwards but it will be ignored if a segment
    /// with the FIN bit set has already been sent.
    pub fn fin(&mut self) {
        self.fin = true;
    }

    /// Number bytes in the buffer that have been transmitted in a segment.
    ///
    /// This is an index into the byte slice, not the total over the complete connection lifetime.
    /// A modification to the buffer might have already removed some bytes from the start that were
    /// acknowledged.
    ///
    /// This does *not* mean the other side has already acknowledged it or that the transmission
    /// has been successful. For that information, see [`completed_bytes`] instead.
    ///
    /// [`completed_bytes`]: #method.completed_bytes
    pub fn sent_bytes(&self) -> usize {
        self.consumed
    }

    /// Number of bytes already acknowledged by the other TCP.
    ///
    /// This is an index into the byte slice, not the total over the complete connection lifetime.
    /// A modification to the buffer might have already removed some bytes from the start that were
    /// acknowledged.
    pub fn completed_bytes(&self) -> usize {
        self.consumed
    }

    /// Number of bytes in the retransmit region.
    ///
    /// This is simply a helper method asserting that [`sent_bytes`] is larger than
    /// [`completed_bytes`].
    ///
    /// [`sent_bytes`]: #method.sent_bytes
    /// [`completed_bytes`]: #method.completed_bytes
    pub fn retransmit_bytes(&self) -> usize {
        self.sent - self.consumed
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
    ///
    /// Since the remote can not possibly have received this data yet, you may modify the bytes
    /// without violating the externally observed behaviour of the network device.
    pub fn unsent_mut(&mut self) -> &mut [u8]
        where Buffer: BorrowMut<[u8]>
    {
        &mut self.data.borrow_mut()[self.sent..]
    }

    /// Mark sent data as having been removed from the start of the buffer.
    ///
    /// Note: this does not remove the data itself.
    ///
    /// This method will panic if `amount` is larger than [`completed_bytes`].
    ///
    /// [`completed_bytes`]: #method.completed_bytes
    ///
    /// ## Usage
    ///
    /// Call this method after having remove parts of the bytes whose transfer has been completed.
    /// A simplest case is draining the bytes. We will show this with a vector as the backing
    /// buffer allocation.
    ///
    /// ```
    /// # use ethox::layer::tcp::io::SendFrom;
    /// fn remove_completed(sender: &mut SendFrom<Vec<u8>>) {
    ///     let to_remove = sender.completed_bytes();
    ///     sender.get_mut().drain(..to_remove).for_each(drop);
    ///     sender.bump_external(to_remove);
    /// }
    /// ```
    ///
    /// This method has been named [`bump`].
    ///
    /// [`bump`]: #method.bump
    /// ```
    pub fn bump_external(&mut self, amount: usize) {
        self.consumed = self.consumed.checked_sub(amount)
            .expect("Tried bumping send buffer into sent region");
        self.sent -= amount;
    }

    /// Rotate the buffered bytes, replacing acknowledged data with new data.
    ///
    /// Returns the number of bytes read.
    ///
    /// First moves unsent and pending data to the front, then overwrites the free space at the end
    /// with new data and finally bumps the buffer by the bytes we have removed. This will not
    /// modify the total amount of data buffered. It is also less efficient than using a dedicated
    /// `VecDeque`, which avoids moving all bytes, but works for all linear byte buffers.
    pub fn bump_with_read(&mut self, data: &[u8]) -> usize
        where Buffer: BorrowMut<[u8]>
    {
        let front_space = self.completed_bytes();
        let amount = front_space.min(data.len());

        let buffer = self.get_mut().borrow_mut();
        buffer.copy_within(front_space.., front_space - amount);
        let new_space = buffer.len() - amount;
        buffer[new_space..].copy_from_slice(&data[..amount]);

        self.bump_external(amount);
        amount
    }
}

impl SendFrom<Vec<u8>> {
    /// Remove some sent data from the start of the buffer.
    ///
    /// Runtime is linear in the length of the vector.
    pub fn bump_to(&mut self, at: usize) {
        assert!(at <= self.consumed, "Tried removing unsent data.");
        self.bump_external(at);
        self.data.drain(..at).for_each(drop);
    }

    /// Remove all sent data from the start of the buffer.
    ///
    /// Runtime is linear in the length of the vector.
    pub fn bump(&mut self) {
        self.bump_to(self.consumed)
    }
}

impl<Buffer: BorrowMut<[u8]>> RecvInto<Buffer> {
    /// Create a new buffered and assembling receiver.
    pub fn new(buffer: Buffer) -> Self {
        RecvInto {
            buffer,
            complete: None,
            mark: 0,
            asm: Assembler::new([Contig::default(); 4]),
        }
    }

    /// Get a reference to the data buffer.
    pub fn get_ref(&self) -> &Buffer {
        &self.buffer
    }

    /// Get a mutable reference to the data buffer.
    ///
    /// This allows one to modify the data but doing so requires some care to avoid incorrect
    /// segment reassembly. It is fine TODO
    pub fn get_mut(&mut self) -> &mut Buffer {
        &mut self.buffer
    }

    /// Get a reference to the completely received bytes.
    ///
    /// This is most useful for actually processing them and then bumping the buffer to make room
    /// for new data. For a constant size buffer that will reopen the receive window.
    pub fn received(&self) -> &[u8] {
        &self.buffer.borrow()[..self.mark]
    }

    /// Mark bytes as having been fully removed from the underlying buffer.
    ///
    /// Note: this does not remove the data itself.
    ///
    /// Call this after having fully read the start of the received message sequence to free buffer
    /// space. This decreases the start index of the available region for receiving more data and
    /// may increase the indicated window size.
    pub fn bump_external(&mut self, amount: usize) {
        self.mark = self.mark.checked_sub(amount)
            .expect("Tried bumping receive buffer into unreceived region");
    }
}

impl RecvInto<Vec<u8>> {
    /// Remove some sent data from the start of the buffer.
    ///
    /// Runtime is linear in the length of the vector.
    pub fn bump_to(&mut self, at: usize) {
        // First bump_external as bounds check.
        self.bump_external(at);
        self.buffer.drain(..at).for_each(drop);
    }

    /// Remove all received data from the start of the buffer.
    ///
    /// You should have read the data first.
    ///
    /// Runtime is linear in the length of the vector.
    pub fn bump(&mut self) {
        self.bump_to(self.mark)
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
