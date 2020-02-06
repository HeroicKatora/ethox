//! Provides answers to pings on a tap interface.
//!
//! # Usage
//!
//! The example will try to open a tap as a network device and then answer all incoming icmpv4
//! pings to its hostaddress. For this purpose it is also configured with one static device that is
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
//! 4. You no longer require root. Start the ping_tap example.
//! 
//!   > $ cargo run --example ping_tap -- tap0 10.0.0.1/24 ab:ff:ff:ff:ff:ff 10.0.0.2/24
//! 5. Ping the interface from the host (show unanswered packets). You could also try flood pings
//!    for fun (`-f`).
//! 
//!   > $ ping -OI tap0 10.0.0.1
use std::io::{stdout, Write};
use structopt::StructOpt;

use ethox::managed::{List, Slice};
use ethox::nic::{Device, sys::TapInterface};
use ethox::layer::{arp, eth, ip, icmp};
use ethox::wire::{ip::v4::Cidr, ethernet::Address};

fn main() {
    let Config {
        name,
        host,
        hostmac,
        gateway,
    } = Config::from_args();

    let mut eth = eth::Endpoint::new(hostmac);

    let mut neighbors = [arp::Neighbor::default(); 1];
    let mut routes = [ip::Route::new_ipv4_gateway(gateway.address()); 1];
    let mut ip = ip::Endpoint::new(Slice::One(host.into()),
        // Prefill the routes
        ip::Routes::import(List::new_full(routes.as_mut().into())), 
        // But do automatic arp
        arp::NeighborCache::new(&mut neighbors[..]));

    let mut icmp = icmp::Endpoint::new();

    let mut interface = TapInterface::new(&name, vec![0; 1 << 14])
        .expect("Couldn't initialize interface");

    let out = stdout();
    let mut out = out.lock();

    out.write_all(b"Started icmpv4 endpoint\n").unwrap();

    loop {
        // Receive the next packet.
        let rx_ok = interface.rx(1, eth.recv(ip.recv(icmp.answer())));
        // Give some chance for outgoing maintenance such as arp.
        let tx_ok = interface.tx(1, eth.send(ip.layer_internal()));

        let result = rx_ok.and_then(|x| tx_ok.map(|y| x + y));

        if let Ok(1) | Ok(2) = result {
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
    host: Cidr,
    hostmac: Address,
    gateway: Cidr,
}
