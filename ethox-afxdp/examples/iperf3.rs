extern crate alloc;

use alloc::ffi::CString;
use core::num::NonZeroU32;
pub use ethox_iperf::{config, iperf2};

use ethox::layer::{arp, eth, ip};
use ethox::managed::{List, Slice};
use ethox_afxdp::{AfXdp, AfXdpBuilder, DeviceOptions, XdpRxMethod};
use xdpilone::{IfInfo, SocketConfig, UmemConfig};

#[repr(align(4096))]
#[derive(Clone, Copy)]
struct Page([u8; 4096]);

fn main() {
    let config = config::Config::from_args();

    let mut interface: AfXdp = (|| {
        let cstrname = CString::new(config.tap).unwrap();
        let mut ifinfo = Box::new(IfInfo::invalid());
        ifinfo.from_name(&cstrname).unwrap();

        let memory = vec![Page([0; 4096]); 1 << 7].into_boxed_slice();

        let mut builder = AfXdpBuilder::from_boxed_slice(memory, UmemConfig::default())?;

        builder.with_socket(DeviceOptions {
            ifinfo: &*ifinfo,
            config: &SocketConfig {
                rx_size: NonZeroU32::new(32),
                tx_size: NonZeroU32::new(32),
                bind_flags: SocketConfig::XDP_BIND_ZEROCOPY | SocketConfig::XDP_BIND_NEED_WAKEUP,
                ..SocketConfig::default()
            },
            bind: XdpRxMethod::DefaultProgram,
        })?;

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
            32,
            &mut eth,
            &mut ip,
            iperf2::Iperf::new(client),
        ),
        config::Iperf3Config::Client(config::IperfClient {
            kind: config::Transport::Tcp,
            client,
        }) => ethox_iperf::client(
            &mut interface,
            32,
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
