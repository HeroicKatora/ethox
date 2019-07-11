use crate::layer::ip;
use crate::wire::{Reframe, Payload, PayloadMut, PayloadResult, payload};
use crate::wire::{TcpPacket, TcpRepr};

use super::connection::{Endpoint, Operator};
use super::endpoint::FourTuple;

/// An incoming tcp packet.
///
/// Don't worry, you can't really do anything with it yet. Not that you'd want to because
/// connections are always closed or not actually responding.
pub struct In<'a, P: Payload> {
    inner: Kind<'a, P>,
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
