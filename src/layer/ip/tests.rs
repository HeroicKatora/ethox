use super::*;
use crate::managed::Slice;
use crate::nic::{external::External, Device};
use crate::layer::eth::{Init, NeighborCache};
use crate::wire::{EthernetAddress, EthernetProtocol, IpAddress, IpProtocol, Payload, PayloadMut};

const MAC_ADDR_SRC: EthernetAddress = EthernetAddress([0, 1, 2, 3, 4, 5]);
const IP_ADDR_SRC: IpAddress = IpAddress::v4(127, 0, 0, 1);
const MAC_ADDR_DST: EthernetAddress = EthernetAddress([5, 4, 3, 2, 1, 0]);
const IP_ADDR_DST: IpAddress = IpAddress::v4(127, 0, 0, 2);

static PAYLOAD_BYTES: [u8; 50] =
    [0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0xff];

fn simple_send<P: PayloadMut>(mut frame: RawPacket<P>) {
    frame.
}

fn simple_recv<P: Payload>(mut frame: Packet<P>) {
    assert_eq!(frame.packet.payload().as_slice(), &PAYLOAD_BYTES[..]);
}
