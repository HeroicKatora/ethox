//! A simplified curl.
//!
//! Connects to a given remote tcp/http host and requests the root page, then prints the response
//! without headers. Can handle up to 1MB of response data.
use std::io::{stdout, Write};
use std::net;
use structopt::StructOpt;

use ethox::managed::{List, Map, SlotMap, Slice};
use ethox::nic::{Device, RawSocket, Protocol};
use ethox::layer::{eth, ip, tcp};
use ethox::wire::{Ipv4Address, Ipv4Cidr, EthernetAddress};

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

    let mut neighbors = [eth::Neighbor::default(); 1];
    let mut routes = [ip::Route::new_ipv4_gateway(gateway.address()); 1];
    let mut ip = ip::Endpoint::new(Slice::One(host.into()),
        ip::Routes::import(List::new_full(routes.as_mut().into())),
        eth::NeighborCache::new(&mut neighbors[..]));

    let mut tcp = tcp::Endpoint::new(
        Map::Pairs(List::new(Slice::One(Default::default()))),
        SlotMap::new(Slice::One(Default::default()), Slice::One(Default::default())),
        tcp::IsnGenerator::from_std_hash(),
    );

    let message = "GET / HTTP/1.0\r\n\r\n".to_owned();
    let mut tcp_client = tcp::Client::new(
        Ipv4Address::from(server).into(), server_port,
        tcp::io::RecvInto::new(vec![0; 1 << 20]),
        tcp::io::SendOnce::new(message));

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
    host: Ipv4Cidr,
    hostmac: EthernetAddress,
    gateway: Ipv4Cidr,
    server: net::Ipv4Addr,
    server_port: u16,
}
