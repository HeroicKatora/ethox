use crate::managed::Slice;
use crate::nic::{external::External, Device};
use crate::layer::{arp, eth, ip, udp};
use crate::wire::{ethernet, Payload, PayloadMut};
use crate::wire::ip::{v4, Cidr, Subnet};

const MAC_ADDR_SRC: ethernet::Address = ethernet::Address([0, 1, 2, 3, 4, 5]);
const IP_ADDR_SRC: v4::Address = v4::Address::new(127, 0, 0, 1);
const MAC_ADDR_DST: ethernet::Address = ethernet::Address([6, 5, 4, 3, 2, 1]);
const IP_ADDR_DST: v4::Address = v4::Address::new(127, 0, 0, 2);

static PAYLOAD_BYTES: [u8; 50] =
    [0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0xff];

fn simple_send<P: PayloadMut>(frame: udp::RawPacket<P>) {
    let init = udp::Init {
        source: Subnet::from(v4::Subnet::ANY).into(),
        src_port: 80,
        dst_addr: IP_ADDR_DST.into(),
        dst_port: 80,
        payload: PAYLOAD_BYTES.len(),
    };
    let mut prepared = frame.prepare(init)
        .expect("Found no valid routes");
    prepared
        .packet
        .payload_mut()
        .copy_from_slice(&PAYLOAD_BYTES[..]);
    prepared.send()
        .expect("Could actuall egress packet");
}

fn simple_recv<P: Payload>(frame: udp::Packet<P>) {
    assert_eq!(frame.packet.payload().as_slice(), &PAYLOAD_BYTES[..]);
}

#[test]
fn simple() {
    let mut nic = External::new_send(Slice::One(vec![0; 1024]));

    let mut eth = eth::Endpoint::new(MAC_ADDR_SRC);

    let mut neighbors = [arp::Neighbor::default(); 1];
    let neighbors = {
        let mut eth_cache = arp::NeighborCache::new(&mut neighbors[..]);
        eth_cache.fill(IP_ADDR_DST.into(), MAC_ADDR_DST, None).unwrap();
        arp::Endpoint::new(eth_cache)
    };
    let mut ip = [ip::Route::unspecified(); 2];
    let mut ip = ip::Endpoint::new(Cidr::new(IP_ADDR_SRC.into(), 24),
        // No routes necessary for local link.
        ip::Routes::new(&mut ip[..]),
        neighbors);

    let mut udp = udp::Endpoint::new(80);

    let sent = nic.tx(1, eth.send(ip.send(
        udp.send_with(simple_send))));
    assert_eq!(sent, Ok(1));

    {
        // Retarget the packet to self.
        let buffer = nic.get_mut(0).unwrap();
        let eth = ethernet::frame::new_unchecked_mut(buffer);
        eth.set_dst_addr(MAC_ADDR_SRC);
        eth.set_src_addr(MAC_ADDR_DST);
        let ip = v4::packet::new_unchecked_mut(eth.payload_mut_slice());
        ip.set_dst_addr(IP_ADDR_SRC);
        ip.set_src_addr(IP_ADDR_DST);
        ip.fill_checksum();
    }

    // Set the buffer to be received.
    nic.receive_all();

    let recv = nic.rx(1, eth.recv(ip.recv(
        udp.recv_with(simple_recv))));
   assert_eq!(recv, Ok(1)); 
}
