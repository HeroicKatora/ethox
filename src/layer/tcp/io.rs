//! Provided implementations for `RecvBuf` and `SendBuf`.
//!
//! This is not quite a compatibility layer with socket APIs but parts of it may be reasonably
//! close to enabling it.
use crate::wire::TcpSeqNumber;
use super::{RecvBuf, SendBuf};

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

impl SendBuf for Empty {
    fn available(&self) -> usize {
        0
    }

    fn fill(&mut self, buf: &mut [u8], _: TcpSeqNumber) {
        assert_eq!(buf.len(), 0, "Called empty send buffer to fill data");
    }

    fn ack(&mut self, _: TcpSeqNumber) {
        // Nothing todo, we don't track the number.
    }
}

impl RecvBuf for Sink {
    fn receive(&mut self, buf: &[u8], begin: TcpSeqNumber) {
        let highest = *self.highest.get_or_insert(begin);

        if begin.contains_in_window(highest, buf.len()) {
            self.highest = Some(begin + buf.len());
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
    fn available(&self) -> usize {
        self.data.as_ref().len() - self.consumed
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
        self.at = Some(ack);
    }
}
