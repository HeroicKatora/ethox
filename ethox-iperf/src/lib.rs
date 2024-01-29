#![cfg_attr(feature = "bench", feature(test))]
#[cfg(feature = "bench")]
extern crate test;

mod pattern;
mod score;

pub mod config;
#[allow(unused)]
pub mod iperf3;
pub mod iperf2;
pub use score::Score;

use ethox::wire::pretty_print;

pub trait Client<Nic>:
    ethox::layer::ip::Recv<Nic::Payload> +
    ethox::layer::ip::Send<Nic::Payload>
where
    Nic: ethox::nic::Device,
    Nic::Payload: Sized,
{ 
    fn result(&self) -> Option<Score>;

    fn verbose(&self) -> bool {
        true
    }
}

pub fn client<Nic>(
    nic: &mut Nic,
    burst: usize,
    eth: &mut ethox::layer::eth::Endpoint,
    ip: &mut ethox::layer::ip::Endpoint,
    mut client: impl Client<Nic>,
) -> Score
where
    Nic: ethox::nic::Device,
    Nic::Payload: ethox::wire::PayloadMut + Sized,
    Nic::Handle: Sized,
{
    loop {
        let _ = nic.rx(burst, eth.recv(ip.recv(&mut client)));
        let _ = nic.tx(burst, eth.send(ip.send(&mut client)));

        if let Some(result) = client.result() {
            return result;
        }
    }
}

/// Just a clone of `client` for now but should be logically used for server.
pub fn server<Nic>(
    nic: &mut Nic,
    burst: usize,
    eth: &mut ethox::layer::eth::Endpoint,
    ip: &mut ethox::layer::ip::Endpoint,
    mut client: impl Client<Nic>,
) -> Score
where
    Nic: ethox::nic::Device,
    Nic::Payload: ethox::wire::PayloadMut + Sized,
    Nic::Handle: Sized,
{
    // FIXME:
    // * reset after a client instead of terminate
    // * accept more than one client
    loop {
        if client.verbose() {
            let _ = nic.rx(burst, pretty_print::FormatWith {
                formatter: pretty_print::Formatter::default(),
                inner: eth.recv(ip.recv(&mut client))
            });
        } else {
            let _ = nic.rx(burst, eth.recv(ip.recv(&mut client)));
        }

        let _ = nic.tx(burst, eth.send(ip.send(&mut client)));

        if let Some(result) = client.result() {
            return result;
        }
    }
}
