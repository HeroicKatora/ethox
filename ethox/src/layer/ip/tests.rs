use super::*;
use crate::managed::Slice;
use crate::nic::{external::External, Device};
use crate::layer::{arp, eth, ip};
use crate::wire::{EthernetAddress, InterfaceId, IpAddress, IpCidr, IpSubnet, Ipv4Address, Ipv4Subnet, Ipv6Address, Ipv6Subnet, IpProtocol};
use crate::wire::{ethernet_frame, ipv4_packet, ipv6_packet};
use crate::wire::{Payload, PayloadMut};

static PAYLOAD_BYTES: [u8; 50] =
    [0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0xff];

struct SimpleSend {
    dst_addr: IpAddress,
}

#[test]
fn simple_ipv4() {
    const MAC_ADDR_SRC: EthernetAddress = EthernetAddress([0, 1, 2, 3, 4, 5]);
    const IP_ADDR_SRC: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);
    const MAC_ADDR_DST: EthernetAddress = EthernetAddress([6, 5, 4, 3, 2, 1]);
    const IP_ADDR_DST: Ipv4Address = Ipv4Address::new(10, 0, 0, 2);

    let mut nic = External::new_send(Slice::One(vec![0; 1024]));

    let mut eth = eth::Endpoint::new(MAC_ADDR_SRC);

    let mut neighbors = [arp::Neighbor::default(); 1];
    let neighbors = {
        let mut eth_cache = arp::NeighborCache::new(&mut neighbors[..]);
        eth_cache.fill(IP_ADDR_DST.into(), MAC_ADDR_DST, None).unwrap();
        eth_cache
    };
    let mut ip = [ip::Route::unspecified(); 2];
    let mut ip = ip::Endpoint::new(IpCidr::new(IP_ADDR_SRC.into(), 24),
        // No routes necessary for local link.
        ip::Routes::new(&mut ip[..]),
        neighbors);

    let sent = nic.tx(1, eth.send(ip.send(SimpleSend {
        dst_addr: IP_ADDR_DST.into(),
    })));
    assert_eq!(sent, Ok(1));

    {
        // Retarget the packet to self.
        let buffer = nic.get_mut(0).unwrap();
        let eth = ethernet_frame::new_unchecked_mut(buffer);
        eth.set_dst_addr(MAC_ADDR_SRC);
        eth.set_src_addr(MAC_ADDR_DST);
        let ip = ipv4_packet::new_unchecked_mut(eth.payload_mut_slice());
        ip.set_dst_addr(IP_ADDR_SRC);
        ip.set_src_addr(IP_ADDR_DST);
        ip.fill_checksum();
    }

    // Set the buffer to be received.
    nic.receive_all();

    let recv = nic.rx(1,
        eth.recv(ip.recv_with(simple_recv)));
   assert_eq!(recv, Ok(1)); 
}

#[test]
fn simple_ipv6() {
    const MAC_ADDR_SRC: EthernetAddress = EthernetAddress([0, 1, 2, 3, 4, 5]);
    const IP_ADDR_SRC: Ipv6Address = Ipv6Address::from_link_local_id(InterfaceId::from_generated_ether(MAC_ADDR_SRC));
    const MAC_ADDR_DST: EthernetAddress = EthernetAddress([6, 5, 4, 3, 2, 1]);
    const IP_ADDR_DST: Ipv6Address = Ipv6Address::from_link_local_id(InterfaceId::from_generated_ether(MAC_ADDR_DST));

    let mut nic = External::new_send(Slice::One(vec![0; 1024]));

    let mut eth = eth::Endpoint::new(MAC_ADDR_SRC);

    let mut neighbors = [arp::Neighbor::default(); 1];
    let neighbors = {
        let mut eth_cache = arp::NeighborCache::new(&mut neighbors[..]);
        eth_cache.fill(IP_ADDR_DST.into(), MAC_ADDR_DST, None).unwrap();
        eth_cache
    };
    let mut ip = [ip::Route::unspecified(); 2];
    let mut ip = ip::Endpoint::new(IpCidr::new(IP_ADDR_SRC.into(), 24),
        // No routes necessary for local link.
        ip::Routes::new(&mut ip[..]),
        neighbors);

    let sent = nic.tx(1, eth.send(ip.send(SimpleSend {
        dst_addr: IP_ADDR_DST.into(),
    })));
    assert_eq!(sent, Ok(1));

    {
        // Retarget the packet to self.
        let buffer = nic.get_mut(0).unwrap();
        let eth = ethernet_frame::new_unchecked_mut(buffer);
        eth.set_dst_addr(MAC_ADDR_SRC);
        eth.set_src_addr(MAC_ADDR_DST);
        let ip = ipv6_packet::new_unchecked_mut(eth.payload_mut_slice());
        ip.set_dst_addr(IP_ADDR_SRC);
        ip.set_src_addr(IP_ADDR_DST);
    }

    // Set the buffer to be received.
    nic.receive_all();

    let recv = nic.rx(1,
        eth.recv(ip.recv_with(simple_recv)));
   assert_eq!(recv, Ok(1)); 
}

fn simple_recv<P: Payload>(frame: InPacket<P>) {
    assert_eq!(frame.packet.payload().as_slice(), &PAYLOAD_BYTES[..]);
}

impl<P: PayloadMut> ip::Send<P> for SimpleSend {
    fn send(&mut self, packet: RawPacket<P>) {
        let init = ip::Init {
            source: match self.dst_addr {
                IpAddress::Ipv4(_) => IpSubnet::from(Ipv4Subnet::ANY),
                IpAddress::Ipv6(_) => IpSubnet::from(Ipv6Subnet::ANY),
                _ => unreachable!(),
            }.into(),
            dst_addr: self.dst_addr,
            payload: PAYLOAD_BYTES.len(),
            protocol: IpProtocol::Unknown(0xEF),
        };
        let mut prepared = packet.prepare(init)
            .expect("Found no valid routes");
        prepared
            .payload_mut_slice()
            .copy_from_slice(&PAYLOAD_BYTES[..]);
        prepared.send()
            .expect("Could actuall egress packet");
    }
}
