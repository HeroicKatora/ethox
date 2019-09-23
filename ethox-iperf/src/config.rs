use structopt::StructOpt;
use std::net;

use ethox::wire::{Ipv4Cidr, EthernetAddress};

#[derive(Clone, StructOpt)]
pub enum Iperf3Config {
    #[structopt(name = "-c")]
    Client(IperfClient),
}

#[derive(Clone, StructOpt)]
pub enum ClientKind {
    #[structopt(name = "--udp")]
    Udp,
    #[structopt(name = "--tcp")]
    Tcp,
}

#[derive(Clone, StructOpt)]
pub struct IperfClient {
    #[structopt(flatten)]
    pub kind: ClientKind,
    #[structopt(flatten)]
    pub client: Client,
}

#[derive(Clone, StructOpt)]
pub struct Client {
    pub host: net::Ipv4Addr,
    pub port: u16,
    #[structopt(short = "n")]
    pub bytes: usize,
    #[structopt(short = "l")]
    pub length: usize,
}

#[derive(Clone, StructOpt)]
pub struct Config {
    pub tap: String,
    pub host: Ipv4Cidr,
    pub hostmac: EthernetAddress,
    pub gateway: Ipv4Cidr,

    #[structopt(subcommand)]
    pub iperf3: Iperf3Config,
}

impl Config {
    pub fn from_args() -> Self {
        StructOpt::from_args()
    }
}
