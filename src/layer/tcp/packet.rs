use crate::layer::ip;
use crate::wire::{Reframe, Payload, PayloadMut, PayloadResult, payload};
use crate::wire::{TcpPacket, TcpRepr, TcpSeqNumber};

use super::connection::{Endpoint, Operator};
use super::endpoint::FourTuple;

/// An incoming tcp packet.
///
/// Don't worry, you can't really do anything with it yet. Not that you'd want to because
/// connections are always closed or not actually responding.
pub struct In<'a, P: Payload> {
    inner: Kind<'a, P>,
}

pub trait SendBuf {
    /// Check the available data.
    ///
    /// This should be the total of previously sent bytes and unsent bytes.
    fn available(&self) -> usize;

    /// Fill in some retransmited data.
    ///
    /// The tcp connection layer will take care to never call this with a buffer outside the
    /// indicated available data length. Bytes that have already been sent are not supposed to
    /// change afterwards, i.e. the `SendBuf` is also utilized as the retransmit buffer.
    fn fill(&mut self, buf: &mut [u8], begin: TcpSeqNumber);

    /// Notify the buffer that some data can be safely discarded.
    ///
    /// The tcp layer will ensure that no data before the new `begin` is requested again.
    fn ack(&mut self, begin: TcpSeqNumber);
}

pub trait RecvBuf {
    /// Accept some incoming data.
    ///
    /// Report back the new unreceived byte. This allows the receive buffer to choose the strategy
    /// for partially acknowledged data.
    fn receive(&mut self, buf: &[u8], begin: TcpSeqNumber);

    /// Get the highest completed sequence number.
    fn ack(&mut self) -> TcpSeqNumber;

    /// Get the current window size.
    ///
    /// Shrinking the window size without having accepted new data is allowed but strongly
    /// discouraged.
    fn window(&self) -> usize;
}

enum Kind<'a, P: Payload> {
    Open {
        operator: Operator<'a>,
        tcp: TcpPacket<ip::IpPacket<'a, P>>,
    },
    Closed {
        endpoint: &'a mut Endpoint,
        tcp: TcpPacket<ip::IpPacket<'a, P>>,
    },
}

impl<'a, P: PayloadMut> Kind<'a, P> {
    pub fn try_open(
        endpoint: &'a mut Endpoint,
        tcp: TcpPacket<ip::IpPacket<'a, P>>,
    ) -> Self {
        let repr = tcp.repr();

        let connection = FourTuple {
            local: unimplemented!(),
            local_port: repr.dst_port,
            remote: unimplemented!(),
            remote_port: repr.src_port,
        };

        let key = unimplemented!();

        match Operator::new(endpoint, key) {
            Some(operator) => Kind::Open {
                operator,
                tcp,
            },
            None => Kind::Closed {
                endpoint,
                tcp,
            }
        }
    }
}
