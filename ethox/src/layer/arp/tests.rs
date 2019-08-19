use crate::managed::Slice;
use crate::nic::{external::External, Device};
use crate::layer::{eth, ip, arp};
use crate::wire::{EthernetAddress, Ipv4Address, IpCidr};
use crate::wire::{ethernet_frame, EthernetProtocol, EthernetRepr};
use crate::wire::{arp_packet, ArpOperation, ArpRepr};

const MAC_ADDR_HOST: EthernetAddress = EthernetAddress([0, 1, 2, 3, 4, 5]);
const IP_ADDR_HOST: Ipv4Address = Ipv4Address::new(127, 0, 0, 1);
const MAC_ADDR_OTHER: EthernetAddress = EthernetAddress([6, 5, 4, 3, 2, 1]);
const IP_ADDR_OTHER: Ipv4Address = Ipv4Address::new(127, 0, 0, 2);

#[test]
fn simple_arp() {
    let mut nic = External::new_send(Slice::One(vec![0; 1024]));

    let mut eth = eth::Endpoint::new(MAC_ADDR_HOST);

    // No prior ARP cache entries needed.
    let mut neighbors = [eth::Neighbor::default(); 1];
    let mut routes = [ip::Route::unspecified(); 2];
    let mut ip = ip::Endpoint::new(IpCidr::new(IP_ADDR_HOST.into(), 24),
        // No routes necessary for local link.
        ip::Routes::new(&mut routes[..]),
        eth::NeighborCache::new(Slice::empty()));

    let mut arp = arp::Endpoint::new(eth::NeighborCache::new(&mut neighbors[..]));

    {
        // Initialize the request.
        let buffer = nic.get_mut(0).unwrap();
        buffer.resize(14 + 28, 0u8);
        let eth = ethernet_frame::new_unchecked_mut(buffer);
        EthernetRepr {
            src_addr: MAC_ADDR_OTHER,
            dst_addr: MAC_ADDR_HOST,
            ethertype: EthernetProtocol::Arp,
        }.emit(eth);
        eth.set_dst_addr(MAC_ADDR_HOST);
        eth.set_src_addr(MAC_ADDR_OTHER);
        let arp = arp_packet::new_unchecked_mut(eth.payload_mut_slice());
        ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: MAC_ADDR_OTHER,
            source_protocol_addr: IP_ADDR_OTHER,
            target_hardware_addr: MAC_ADDR_HOST,
            target_protocol_addr: IP_ADDR_HOST,
        }.emit(arp);
    }

    // Set the buffer to be received.
    nic.receive_all();

    let recv = nic.rx(1, eth.recv(arp.answer(&mut ip)));
    assert_eq!(recv, Ok(1));

    let buffer = nic.get_mut(0).unwrap();
    let eth = ethernet_frame::new_unchecked_mut(buffer);
    assert_eq!(eth.dst_addr(), MAC_ADDR_OTHER);
    assert_eq!(eth.src_addr(), MAC_ADDR_HOST);
    assert_eq!(eth.ethertype(), EthernetProtocol::Arp);

    let arp = arp_packet::new_unchecked_mut(eth.payload_mut_slice());
    assert_eq!(arp.operation(), ArpOperation::Reply);
    assert_eq!(arp.source_hardware_addr(), MAC_ADDR_HOST);
    assert_eq!(arp.source_protocol_addr(), IP_ADDR_HOST);
    assert_eq!(arp.target_hardware_addr(), MAC_ADDR_OTHER);
    assert_eq!(arp.target_protocol_addr(), IP_ADDR_OTHER);
}
