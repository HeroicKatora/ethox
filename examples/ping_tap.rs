//! Debugs all packets coming in on a tap.
use std::{env, process};

use ethox::managed::{List, Slice};
use ethox::nic::{Device, TapInterface};
use ethox::layer::{eth, ip, icmp};
use ethox::wire::{Ipv4Cidr, EthernetAddress, pretty_print::Formatter};

fn main() {
    let name = env::args().nth(1)
        .unwrap_or_else(usage_and_exit);
    
    let host: Ipv4Cidr = unimplemented!();
    let hostmac: EthernetAddress = unimplemented!();
    let gateway: Ipv4Cidr = unimplemented!();
    let gatemac: EthernetAddress = unimplemented!();

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
        let result = interface.rx(1, Formatter::default());

        result.unwrap_or_else(|err| {
            panic!("Error during receive {:?} {:?}", err, interface.last_err());
        });
    }
}

fn usage_and_exit<T>() -> T {
    eprintln!("Usage: debug_tap <ifname>");
    process::exit(1);
}
