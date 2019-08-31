use structopt::StructOpt;
use std::net;

use ethox::wire::{Ipv4Cidr, EthernetAddress};

#[derive(Clone, StructOpt)]
pub enum Iperf3Config {
    #[structopt(name = "-c")]
    Client {
        host: net::Ipv4Addr,
        port: u16,

        #[structopt(short = "n")]
        bytes: usize,
        #[structopt(short = "l")]
        length: usize,
    },
}

#[derive(StructOpt)]
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
