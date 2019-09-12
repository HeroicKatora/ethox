mod score;

pub mod config;
#[allow(unused)]
pub mod iperf3;
pub mod iperf2;
pub use score::Score;

pub trait Client<Nic>:
    ethox::layer::ip::Recv<Nic::Payload> +
    ethox::layer::ip::Send<Nic::Payload>
where
    Nic: ethox::nic::Device,
    Nic::Payload: Sized,
{ 
    fn result(&self) -> Option<Score>;
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
        nic.rx(burst, eth.recv(ip.recv(&mut client))).unwrap();
        nic.tx(burst, eth.send(ip.send(&mut client))).unwrap();

        if let Some(result) = client.result() {
            return result;
        }
    }
}
