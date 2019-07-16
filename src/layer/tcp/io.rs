//! Provided implementations for `RecvBuf` and `SendBuf`.
//!
//! This is not quite a compatibility layer with socket APIs but parts of it may be reasonably
//! close to enabling it.
use crate::wire::TcpSeqNumber;
use super::{RecvBuf, SendBuf};

/// A sender with no data.
pub struct Empty {
    _private: (),
}

/// A receiver that doesn't store anything.
///
/// Note that this will *not* have the highest throughput for ignoring data on a congested network
/// or with some amount of loss. This does not perform unlimited selective acknowledgement (SACK)
/// of all regions it has received, so that some retransmissions are necessary even though data is
/// ignored.
pub struct Sink {
    highest: TcpSeqNumber,
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
        if begin.contains_in_window(self.highest, buf.len()) {
            self.highest = begin + buf.len();
        }
    }

    fn ack(&mut self) -> TcpSeqNumber {
        self.highest
    }

    fn window(&self) -> usize {
        usize::max_value()
    }
}
