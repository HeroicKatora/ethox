//! A tcp client example
//!
//! Connects to a given remote tcp host and sends a single provided message. Any incoming data is
//! silently discarded without having been copied into a buffer (but no FIN sent).
use std::io::{stdout, Write};
use std::net;
use structopt::StructOpt;

use ethox::managed::{List, Map, SlotMap, Slice};
use ethox::nic::{Device, RawSocket, TapInterface};
use ethox::layer::{eth, ip, tcp};
use ethox::wire::{Ipv4Address, Ipv4Cidr, EthernetAddress};

fn main() {
    let Config {
        name,
        host,
        hostmac,
        gateway,
        gatemac,
        server,
        server_port,
        message,
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

    let mut tcp = tcp::Endpoint::new(
        Map::Pairs(List::new(Slice::One(Default::default()))),
        SlotMap::new(Slice::One(Default::default()), Slice::One(Default::default())),
        tcp::IsnGenerator::from_std_hash(),
    );
    let mut tcp_client = tcp::Client::new(
        Ipv4Address::from(server).into(), server_port,
        tcp::io::Sink::new(), tcp::io::SendOnce::new(message));

    let mut interface = RawSocket::new(&name, vec![0; 1 << 14])
        .expect("Couldn't initialize interface");

    let out = stdout();
    let mut out = out.lock();

    out.write_all(b"Started tcp endpoint\n").unwrap();

    loop {
        let rx = interface.rx(10, eth.recv(ip.recv(tcp.recv(&mut tcp_client)))).unwrap();
        let tx = interface.tx(10, eth.send(ip.send(tcp.send(&mut tcp_client)))).unwrap();

        if tcp_client.is_closed() {
            break;
        }
    }
}

#[derive(StructOpt)]
struct Config {
    name: String,
    host: Ipv4Cidr,
    hostmac: EthernetAddress,
    gateway: Ipv4Cidr,
    gatemac: EthernetAddress,
    server: net::Ipv4Addr,
    server_port: u16,
    message: String,
}
