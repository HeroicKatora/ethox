//! Provides answers to arp requests on a tap interface.
//!
//! # Usage
//!
//! The example will try to open a tap as a network device and then answer all incoming arp
//! requests to its hostaddress. For this purpose it is also configured with one static device that is
//! assumed to provide a gateway if you want to ping it from an address outside its assigned CIDR
//! block.
//!
//! The following steps are necessary to set the example up (likey requires root or sudo):
//!
//! 1. Setup the tap interface, named `tap0` here:
//!
//!   > $ ip tuntap add mode tap name tap0
//! 2. Assign an address on the host system
//!
//!   > $ ip addr add 10.0.0.2/24 dev tap0
//! 3. Bring up the interface on the host
//!
//!   > $ ip link set up dev tap0
//! 4. Chose ip and mac for the example and add them to arp
//!
//!   > $ arp -si tap0 10.0.0.1 ab:ff:ff:ff:ff:ff
//! 4. You no longer require root. Start the arp_tap example.
//! 
//!   > $ cargo run --example arp_tap -- tap0 10.0.0.1/24 ab:ff:ff:ff:ff:ff 10.0.0.2/24 <host_mac>
//! 5. Ping the interface from the host (show unanswered packets). You could also try flood pings
//!    for fun (`-f`).
//! 
//!   > $ ping -OI tap0 10.0.0.1
use std::io::{stdout, Write};
use structopt::StructOpt;

use ethox::managed::{List, Slice};
use ethox::nic::{Device, sys::TapInterface};
use ethox::layer::{arp, eth, ip};
use ethox::wire::{Ipv4Cidr, EthernetAddress, PayloadMut};

fn main() {
    let Config {
        name,
        host,
        hostmac,
        gateway,
        gatemac,
    } = Config::from_args();

    let mut eth = eth::Endpoint::new(hostmac);

    let mut neighbors = [arp::Neighbor::default(); 5];
    let neighbors = {
        let mut eth_cache = arp::NeighborCache::new(&mut neighbors[..]);
        eth_cache.fill(gateway.address().into(), gatemac, None).unwrap();
        eth_cache
    };
    let mut ip = [ip::Route::new_ipv4_gateway(gateway.address()); 1];
    let routes = ip::Routes::import(List::new_full(ip.as_mut().into()));
    let mut ip = ip::Endpoint::new(Slice::One(host.into()), routes, neighbors);

    let mut interface = TapInterface::new(&name, vec![0; 1 << 14])
        .expect("Couldn't initialize interface");

    let out = stdout();
    let mut out = out.lock();

    out.write_all(b"Started arp endpoint\n").unwrap();

    loop {
        // Receive the next packet.
        let result = interface.rx(1, eth.recv(ip.recv_with(drop_packet)));

        if let Ok(1) = result {
            out.write_all(b".").unwrap();
            out.flush().unwrap();
        }

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

/// Drops all packets. Arp should is handled internally.
fn drop_packet<P: PayloadMut>(_: ip::InPacket<P>) { }
