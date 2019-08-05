use crate::managed::Slice;
use crate::nic::{loopback::Loopback, Device};
use crate::layer::{eth, ip, arp};
use crate::wire::{EthernetAddress, Ipv4Address, IpCidr, PayloadMut};

const MAC_ADDR_HOST: EthernetAddress = EthernetAddress([0, 1, 2, 3, 4, 5]);
const IP_ADDR_HOST: Ipv4Address = Ipv4Address::new(127, 0, 0, 1);
const MAC_ADDR_OTHER: EthernetAddress = EthernetAddress([6, 5, 4, 3, 2, 1]);
const IP_ADDR_OTHER: Ipv4Address = Ipv4Address::new(127, 0, 0, 2);

#[test]
fn answer_arp() {
    let mut nic = Loopback::<Vec<u8>>::new(vec![0; 1 << 12].into());

    queue_arp(&mut nic);

    let mut eth = [eth::Neighbor::default(); 1];
    let mut eth = eth::Endpoint::new(MAC_ADDR_HOST, {
        let eth_cache = eth::NeighborCache::new(&mut eth[..]);
        // No ARP cache entries needed.
        eth_cache
    });

    let mut ip = [ip::Route::unspecified(); 2];
    let mut ip = ip::Endpoint::new(IpCidr::new(IP_ADDR_HOST.into(), 24), {
        let ip_routes = ip::Routes::new(&mut ip[..]);
        // No routes necessary for local link.
        ip_routes
    });

    let mut arp = arp::Endpoint::new();

    let recv = nic.rx(1, eth.recv(
        arp.answer(&mut ip)));

    assert_eq!(recv, Ok(1));
}

fn queue_arp(nic: &mut Loopback<Vec<u8>>) {
    fn prepare_arp<P: PayloadMut>(packet: arp::RawPacket<P>) {
        let init = arp::Init::EthernetIpv4Request {
            source_hardware_addr: MAC_ADDR_OTHER,
            source_protocol_addr: IP_ADDR_OTHER.into(),
            target_hardware_addr: Default::default(),
            target_protocol_addr: IP_ADDR_HOST.into(),
        };
        let packet = packet.prepare(init)
            .expect("Can initialize to the host");
        packet
            .send()
            .expect("Can send the packet");
    }

    let mut eth = [eth::Neighbor::default(); 1];
    let mut eth = eth::Endpoint::new(MAC_ADDR_OTHER, {
        let eth_cache = eth::NeighborCache::new(&mut eth[..]);
        // No ARP cache entries needed.
        eth_cache
    });

    let mut ip = ip::Endpoint::new(
        IpCidr::new(IP_ADDR_OTHER.into(), 24),
        ip::Routes::new(Slice::empty()));

    let mut arp = arp::Endpoint::new();

    // Queue the ping to be received.
    nic.tx(1, eth.send(
        arp.send_with(&mut ip, prepare_arp))
    ).expect("ARP can be queued.");
}
