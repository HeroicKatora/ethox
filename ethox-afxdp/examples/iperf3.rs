pub use ethox_iperf::{config, iperf2};

use ethox::layer::{arp, eth, ip};
use ethox::managed::{List, Slice};
use ethox_afxdp::{AfXdp, UmemBuilder, UmemBuilderOptions};

fn main() {
    let config = config::Config::from_args();

    let mut interface: AfXdp = (|| {
        let mut builder = UmemBuilder::new(&UmemBuilderOptions::default())?;

        builder.with_socket(
            &ethox_afxdp::BuilderBindOptions {
                name: config.tap.clone(),
                channel: 0,
                rx_ring_desc_num: 2048,
                tx_ring_desc_num: 2048,
            },
            Default::default(),
        )?;

        builder.build()
    })()
    .expect("Failed to create interface");

    let mut eth = eth::Endpoint::new(config.hostmac);

    let mut neighbors = [arp::Neighbor::default(); 1];
    let mut routes = [ip::Route::new_ipv4_gateway(config.gateway.address()); 1];
    let mut ip = ip::Endpoint::new(
        Slice::One(config.host.into()),
        ip::Routes::import(List::new_full(routes.as_mut().into())),
        arp::NeighborCache::new(&mut neighbors[..]),
    );

    println!("[+] Configured layers, communicating");

    let result = match &config.iperf3 {
        config::Iperf3Config::Client(config::IperfClient {
            kind: config::Transport::Udp,
            client,
        }) => ethox_iperf::client(
            &mut interface,
            10,
            &mut eth,
            &mut ip,
            iperf2::Iperf::new(client),
        ),
        config::Iperf3Config::Client(config::IperfClient {
            kind: config::Transport::Tcp,
            client,
        }) => ethox_iperf::client(
            &mut interface,
            10,
            &mut eth,
            &mut ip,
            iperf2::IperfTcp::new(client),
        ),
        config::Iperf3Config::Server(config::IperfServer {
            kind: config::Transport::Udp,
            server,
        }) => ethox_iperf::server(
            &mut interface,
            10,
            &mut eth,
            &mut ip,
            iperf2::Server::new(server),
        ),
        _ => unimplemented!("Tcp server is not yet implemented!"),
    };

    println!("[+] Done\n");
    println!("{}", result);
}
