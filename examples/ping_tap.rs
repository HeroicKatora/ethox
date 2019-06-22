//! Debugs all packets coming in on a tap.
use structopt::StructOpt;

use ethox::managed::{List, Slice};
use ethox::nic::{Device, TapInterface};
use ethox::layer::{eth, ip, icmp};
use ethox::wire::{Ipv4Cidr, EthernetAddress};

// Only used as `arp` layer replacement.
use ethox::wire::{Ipv4Address, EthernetProtocol, PayloadMut};

fn main() {
    let Config {
        name,
        host,
        hostmac,
        gateway,
        gatemac,
    } = Config::from_args();

    let mut eth = [eth::Neighbor::default(); 1];
    let mut eth = eth::Endpoint::new(hostmac, {
        let mut eth_cache = eth::NeighborCache::new(&mut eth[..]);
        eth_cache.fill(gateway.address().into(), gatemac, None).unwrap();
        eth_cache
    });

    let mut ip = [ip::Route::new_ipv4_gateway(gateway.address()); 1];
    let routes = ip::Routes::import(List::new_full(ip.as_mut().into()));
    let mut ip = ip::Endpoint::new(Slice::One(host.into()), routes);

    let mut icmp = icmp::Endpoint::new();

    let mut interface = TapInterface::new(&name, vec![0; 1 << 14])
        .expect("Couldn't initialize interface");

    // While arp is not done, send one gratuitous announcement.
    // https://tools.ietf.org/html/rfc5944#section-4.6
    interface.tx(1, eth.send(ArpAnnouncement {
        addr: host.address(),
    })).expect("Arp announcement failed");

    eprintln!("Announced ourselves");

    loop {
        // Receive the next packet.
        let result = interface.rx(1, eth.recv(ip.recv(icmp.answer())));

        result.unwrap_or_else(|err| {
            panic!("Error during receive {:?} {:?}", err, interface.last_err());
        });
    }
}

#[derive(StructOpt)]
struct Config {
    name: String,
    host: Ipv4Cidr,
    hostmac: EthernetAddress,
    gateway: Ipv4Cidr,
    gatemac: EthernetAddress,
}

struct ArpAnnouncement {
    addr: Ipv4Address,
}

impl<P: PayloadMut> eth::Send<P> for ArpAnnouncement {
    fn send(&mut self, mut raw: eth::RawPacket<P>) {
        let src_addr = raw.handle.src_addr();
        let mut prepared = raw.prepare(eth::Init {
            src_addr,
            dst_addr: EthernetAddress::BROADCAST,
            ethertype: EthernetProtocol::Arp,
            payload: 28,
        }).unwrap();

        {
            // Send an arp request where sender = target
            let slice = prepared
                .payload_mut_slice();
            slice[0..2].copy_from_slice(&[0, 1]); // HTYPE
            slice[2..4].copy_from_slice(&[0x80, 0]); // PTYPE
            slice[4..6].copy_from_slice(&[6, 4]); // H and P address length
            slice[6..8].copy_from_slice(&[0, 1]); // Operation
            slice[ 8..14].copy_from_slice(src_addr.as_bytes()); // H addr sender
            slice[18..24].copy_from_slice(&[0; 6]); // H addr target
            slice[14..18].copy_from_slice(self.addr.as_bytes()); // P addr sender
            slice[24..28].copy_from_slice(self.addr.as_bytes()); // P addr target
        }

        prepared
            .send()
            .unwrap();
    }
}
