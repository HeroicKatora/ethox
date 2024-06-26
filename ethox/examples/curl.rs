//! A simplified curl.
//!
//! Connects to a given remote tcp/http host and requests the root page, then prints the response
//! without headers. Can handle up to 1MB of response data.
use std::io::{stdout, Write};
use structopt::StructOpt;

use ethox::managed::{List, Map, SlotMap, Slice};
use ethox::nic::{Device, sys::RawSocket, Protocol};
use ethox::layer::{arp, eth, ip, tcp};
use ethox::wire::{ip::v4, ethernet};

fn main() {
    let Config {
        name,
        host,
        hostmac,
        gateway,
        server,
        server_port,
    } = Config::from_args();

    let mut eth = eth::Endpoint::new(hostmac);

    // Buffer space for arp neighbor cache
    let mut neighbors = [arp::Neighbor::default(); 1];
    // Buffer space for routes, we only have a single state one.
    let mut routes = [ip::Route::new_ipv4_gateway(gateway.address()); 1];
    let neighbors = arp::NeighborCache::new(&mut neighbors[..]);
    let mut ip = ip::Endpoint::new(Slice::One(host.into()),
        ip::Routes::import(List::new_full(routes.as_mut().into())),
        arp::Endpoint::new(neighbors));

    let mut tcp = tcp::Endpoint::new(
        Map::Pairs(List::new(Slice::One(Default::default()))),
        SlotMap::new(Slice::One(Default::default()), Slice::One(Default::default())),
        tcp::IsnGenerator::from_std_hash(),
    );

    let message = "GET / HTTP/1.0\r\n\r\n";
    let mut tcp_client = tcp::Client::new(
        v4::Address::from(server).into(), server_port,
        tcp::io::RecvInto::new(vec![0; 1 << 20]),
        tcp::io::SendFrom::once(message.as_bytes()));

    let mut interface = RawSocket::new(&name, vec![0; 1 << 14])
        .expect(&format!("Couldn't initialize interface {}", name));
    *interface.capabilities_mut().tcp_mut() = Protocol::offloaded().into();

    let out = stdout();
    let mut out = out.lock();

    loop {
        let rx = interface.rx(10, eth.recv(ip.recv(tcp.recv(&mut tcp_client)))).unwrap();
        let tx = interface.tx(10, eth.send(ip.send(tcp.send(&mut tcp_client)))).unwrap();

        if tcp_client.is_closed() {
            break;
        }
    }

    let received = tcp_client.recv().received();
    let http = String::from_utf8_lossy(received);
    let header_end = http.find("\r\n\r\n")
        .expect(&format!("Expected http header end in {}", http));
    write!(out, "{}", &http[header_end+4..])
        .unwrap();
}

#[derive(StructOpt)]
struct Config {
    name: String,
    host: v4::Cidr,
    hostmac: ethernet::Address,
    gateway: v4::Cidr,
    server: std::net::Ipv4Addr,
    server_port: u16,
}
