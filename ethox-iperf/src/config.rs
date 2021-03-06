use structopt::StructOpt;
use std::net;

use ethox::wire::{ip::v4::Cidr, ethernet::Address};

#[derive(Clone, StructOpt)]
pub enum Iperf3Config {
    #[structopt(name = "-c")]
    Client(IperfClient),

    #[structopt(name = "-s")]
    Server(IperfServer),
}

#[derive(Clone, StructOpt)]
pub enum Transport {
    #[structopt(name = "--udp")]
    Udp,
    #[structopt(name = "--tcp")]
    Tcp,
}

#[derive(Clone, StructOpt)]
pub struct IperfClient {
    #[structopt(flatten)]
    pub kind: Transport,
    #[structopt(flatten)]
    pub client: Client,
}

#[derive(Clone, StructOpt)]
pub struct IperfServer {
    #[structopt(flatten)]
    pub kind: Transport,
    #[structopt(flatten)]
    pub server: Server,
}

#[derive(Clone, StructOpt)]
pub struct Client {
    pub host: net::Ipv4Addr,
    pub port: u16,
    #[structopt(short = "l")]
    pub buffer_bytes: usize,
    #[structopt(short = "n")]
    pub total_bytes: usize,
}

#[derive(Clone, StructOpt)]
pub struct Server {
    #[structopt(short = "B")]
    pub host: Option<net::Ipv4Addr>,
    pub port: u16,
}

#[derive(Clone, StructOpt)]
pub struct Config {
    pub tap: String,
    pub host: Cidr,
    pub hostmac: Address,
    pub gateway: Cidr,

    #[structopt(subcommand)]
    pub iperf3: Iperf3Config,
}

impl Config {
    pub fn from_args() -> Self {
        StructOpt::from_args()
    }
}
