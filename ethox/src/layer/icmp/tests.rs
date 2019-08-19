use crate::managed::Slice;
use crate::nic::{loopback::Loopback, Device};
use crate::layer::{eth, ip, icmp};
use crate::wire::{EthernetAddress, Ipv4Address, IpCidr, PayloadMut};

const MAC_ADDR_HOST: EthernetAddress = EthernetAddress([0, 1, 2, 3, 4, 5]);
const IP_ADDR_HOST: Ipv4Address = Ipv4Address::new(127, 0, 0, 1);
const MAC_ADDR_OTHER: EthernetAddress = EthernetAddress([6, 5, 4, 3, 2, 1]);
const IP_ADDR_OTHER: Ipv4Address = Ipv4Address::new(127, 0, 0, 2);

static PING_BYTES: [u8; 50] =
    [   
        0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xff
    ];

#[test]
fn answer_ping() {
    let mut nic = Loopback::<Vec<u8>>::new(vec![0; 1 << 12].into());

    queue_ping(&mut nic);

    let mut eth = eth::Endpoint::new(MAC_ADDR_HOST);
    
    let mut neighbors = [eth::Neighbor::default(); 1];
    let neighbors = {
        let mut eth_cache = eth::NeighborCache::new(&mut neighbors[..]);
        eth_cache.fill(IP_ADDR_OTHER.into(), MAC_ADDR_OTHER, None).unwrap();
        eth_cache
    };
    let mut ip = [ip::Route::unspecified(); 2];
    let mut ip = ip::Endpoint::new(IpCidr::new(IP_ADDR_HOST.into(), 24),
        // No routes necessary for local link.
        ip::Routes::new(&mut ip[..]),
        neighbors);

    let mut icmp = icmp::Endpoint::new();

    let recv = nic.rx(1, eth.recv(ip.recv(
        icmp.answer())));

   assert_eq!(recv, Ok(1));
}

fn queue_ping(nic: &mut Loopback<Vec<u8>>) {
    fn prepare_ping<P: PayloadMut>(packet: icmp::RawPacket<P>) {
        let init = icmp::Init::EchoRequest {
            source: ip::Source::Exact(IP_ADDR_OTHER.into()),
            dst_addr: IP_ADDR_HOST.into(),
            ident: 0,
            seq_no: 0,
            payload: PING_BYTES.len(),
        };
        let mut packet = packet.prepare(init)
            .expect("Can initialize to the host");
        packet
            .payload_mut_slice()
            .copy_from_slice(&PING_BYTES[..]);
        packet
            .send()
            .expect("Can send the packet");
    }

    let mut eth = eth::Endpoint::new(MAC_ADDR_OTHER);

    let mut neighbors = [eth::Neighbor::default(); 1];
    let neighbors = {
        let mut eth_cache = eth::NeighborCache::new(&mut neighbors[..]);
        eth_cache.fill(IP_ADDR_HOST.into(), MAC_ADDR_HOST, None).unwrap();
        eth_cache
    };
    let mut ip = ip::Endpoint::new(
        IpCidr::new(IP_ADDR_OTHER.into(), 24),
        ip::Routes::new(Slice::empty()),
        neighbors);

    let mut icmp = icmp::Endpoint::new();

    // Queue the ping to be received.
    nic.tx(1, eth.send(ip.send(
        icmp.send_with(prepare_ping)))
    ).expect("Ping can be queued.");
}
