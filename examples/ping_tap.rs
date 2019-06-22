//! Debugs all packets coming in on a tap.
use structopt::StructOpt;

use ethox::managed::{List, Slice};
use ethox::nic::{Device, TapInterface};
use ethox::layer::{eth, ip, icmp};
use ethox::wire::{Ipv4Cidr, EthernetAddress};

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
