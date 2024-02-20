use crate::managed::Slice;
use crate::nic::{external::External, Device};
use crate::layer::{eth, ip as ip_layer, arp as arp_layer};
use crate::wire::{ethernet, ip, arp};

const MAC_ADDR_HOST: ethernet::Address = ethernet::Address([0, 1, 2, 3, 4, 5]);
const IP_ADDR_HOST: ip::v4::Address = ip::v4::Address::new(127, 0, 0, 1);
const MAC_ADDR_OTHER: ethernet::Address = ethernet::Address([6, 5, 4, 3, 2, 1]);
const IP_ADDR_OTHER: ip::v4::Address = ip::v4::Address::new(127, 0, 0, 2);

#[test]
fn simple_arp() {
    let mut nic = External::new_send(Slice::One(vec![0; 1024]));

    let mut eth = eth::Endpoint::new(MAC_ADDR_HOST);

    // No prior ARP cache entries needed.
    let mut neighbors = [arp_layer::Neighbor::default(); 1];
    let mut routes = [ip_layer::Route::unspecified(); 2];
    let arp = arp_layer::Endpoint::new(
        arp_layer::NeighborCache::new(Slice::empty()));
    let mut ip = ip_layer::Endpoint::new(
        ip::Cidr::new(IP_ADDR_HOST.into(), 24),
        // No routes necessary for local link.
        ip_layer::Routes::new(&mut routes[..]),
        arp,
    );

    let mut arp = arp_layer::Endpoint::new(arp_layer::NeighborCache::new(&mut neighbors[..]));

    {
        // Initialize the request.
        let buffer = nic.get_mut(0).unwrap();
        buffer.resize(14 + 28, 0u8);
        let eth = ethernet::frame::new_unchecked_mut(buffer);
        ethernet::Repr {
            src_addr: MAC_ADDR_OTHER,
            dst_addr: MAC_ADDR_HOST,
            ethertype: ethernet::EtherType::Arp,
        }.emit(eth);
        eth.set_dst_addr(MAC_ADDR_HOST);
        eth.set_src_addr(MAC_ADDR_OTHER);
        let arp = arp::packet::new_unchecked_mut(eth.payload_mut_slice());
        arp::Repr::EthernetIpv4 {
            operation: arp::Operation::Request,
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
    let eth = ethernet::frame::new_unchecked_mut(buffer);
    assert_eq!(eth.dst_addr(), MAC_ADDR_OTHER);
    assert_eq!(eth.src_addr(), MAC_ADDR_HOST);
    assert_eq!(eth.ethertype(), ethernet::EtherType::Arp);

    let arp = arp::packet::new_unchecked_mut(eth.payload_mut_slice());
    assert_eq!(arp.operation(), arp::Operation::Reply);
    assert_eq!(arp.source_hardware_addr(), MAC_ADDR_HOST);
    assert_eq!(arp.source_protocol_addr(), IP_ADDR_HOST);
    assert_eq!(arp.target_hardware_addr(), MAC_ADDR_OTHER);
    assert_eq!(arp.target_protocol_addr(), IP_ADDR_OTHER);
}
