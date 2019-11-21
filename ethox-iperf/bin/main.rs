//! A tcp client example
//!
//! Connects to a given remote tcp host and sends a single provided message. Any incoming data is
//! silently discarded without having been copied into a buffer (but no FIN sent).
//!
//! Prepend the ethox configuration to the usual iperf options. Call example assuming a connected
//! veth pair `veth0` and `veth1`.
//!
//! * Client: `iperf3 veth0 10.0.0.1/24 ac:ff:ff:ff:ff:ff 10.0.0.2/24 -c 10.0.0.2 5001 -n 10000 -l 1470 --udp`
//! * Server: `iperf3 veth1 10.0.0.2/24 ac:ff:ff:fe:ff:ff 10.0.0.1/24 -s 5001 --udp`
//!
//! (This uses a locally administered unicast MAC address)
pub use ethox_iperf::{config, iperf2};

use ethox::managed::{List, Slice};
use ethox::nic::RawSocket;
use ethox::layer::{eth, ip};

fn main() {
    let config = config::Config::from_args();

    let mut interface = RawSocket::new(&config.tap, vec![0; 1 << 20])
        .expect("Couldn't initialize interface");
    let mut interface = interface.batched();

    let mut eth = eth::Endpoint::new(config.hostmac);

    let mut neighbors = [eth::Neighbor::default(); 1];
    let mut routes = [ip::Route::new_ipv4_gateway(config.gateway.address()); 1];
    let mut ip = ip::Endpoint::new(
        Slice::One(config.host.into()),
        ip::Routes::import(List::new_full(routes.as_mut().into())),
        eth::NeighborCache::new(&mut neighbors[..]));

    println!("[+] Configured layers, communicating");

    let result = match &config.iperf3 {
        config::Iperf3Config::Client(
            config::IperfClient { kind: config::Transport::Udp, client
        }) => {
            ethox_iperf::client(
                &mut interface,
                10,
                &mut eth,
                &mut ip,
                iperf2::Iperf::new(client),
            )
        },
        config::Iperf3Config::Client(
            config::IperfClient { kind: config::Transport::Tcp, client
        }) => {
            ethox_iperf::client(
                &mut interface,
                10,
                &mut eth,
                &mut ip,
                iperf2::IperfTcp::new(client),
            )
        },
        config::Iperf3Config::Server(
            config::IperfServer { kind: config::Transport::Udp, server }
        ) => {
            ethox_iperf::server(
                &mut interface,
                10,
                &mut eth,
                &mut ip,
                iperf2::Server::new(server),
            )
        }
        _ => unimplemented!("Tcp server is not yet implemented!"),
    };

    println!("[+] Done\n");
    println!("{}", result);
}
