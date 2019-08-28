//! A tcp client example
//!
//! Connects to a given remote tcp host and sends a single provided message. Any incoming data is
//! silently discarded without having been copied into a buffer (but no FIN sent).
//!
//! Prepend the ethox configuration to the usual iperf options. Call example:
//!
//! * `iperf3 tap0 10.0.0.1/24 ab:ff:ff:ff:ff:ff 10.0.0.2/24 -c 10.0.0.2 5001 -l 10000 -n 2470`
mod config;
// mod iperf;
mod iperf2;

use std::io::{stdout, Write};

use ethox::managed::{List, Slice};
use ethox::nic::{Device, TapInterface};
use ethox::layer::{eth, ip};

fn main() {
    let config = config::Config::from_args();

    let out = stdout();
    let mut out = out.lock();

    let mut interface = TapInterface::new(&config.tap, vec![0; 1 << 14])
        .expect("Couldn't initialize interface");

    let mut eth = eth::Endpoint::new(config.hostmac);

    let mut neighbors = [eth::Neighbor::default(); 1];
    let mut routes = [ip::Route::new_ipv4_gateway(config.gateway.address()); 1];
    let mut ip = ip::Endpoint::new(
        Slice::One(config.host.into()),
        ip::Routes::import(List::new_full(routes.as_mut().into())),
        eth::NeighborCache::new(&mut neighbors[..]));

    let mut iperf = iperf2::Iperf::new(&config.iperf3);

    out.write_all(b"[+] Configured layers, communicating").unwrap();

    let result = loop {
        interface.rx(10, eth.recv(ip.recv(&mut iperf))).unwrap();
        interface.tx(10, eth.send(ip.send(&mut iperf))).unwrap();

        if let Some(result) = iperf.result() {
            break result;
        }
    };

    out.write_all(b"[+] Done").unwrap();
    write!(out, "{:?}", result).unwrap();
}
