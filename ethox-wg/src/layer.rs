use alloc::{string::String, vec::Vec};
use super::{crypto, Peer, This};
use ethox::managed::Slice;
use ethox::layer::{arp, eth, ip, udp};
use ethox::wire::{self, Payload, PayloadMut};
use x25519_dalek::{PublicKey, StaticSecret};

/// Open configuration.
pub struct Config {
    /// Our own interface.
    pub interface: InterfaceConfig,
    /// The peers.
    pub peers: Slice<'static, PeerConfig>,
}

/// Configuration for our interface.
pub struct InterfaceConfig {
    /// Hex encoded private key.
    pub private_key: KeyConfig,
}

/// Configuration of one peer.
pub struct PeerConfig {
    /// Public key of the peer.
    pub public_key: KeyConfig,
    pub allowed_ips: Slice<'static, wire::ip::v4::Cidr>,
}

pub enum KeyConfig {
    Hex(String),
    Data(Vec<u8>),
}

/// The state of the Wireguard module.
pub struct Wireguard {
    this: This,
    /// Fake ethernet data.
    eth: eth::Endpoint<'static>,
    /// Fake ip data.
    ip: ip::Endpoint<'static>,
    peers: Vec<PeerState>,
}

struct PeerState {
    peer: super::Peer,
}

pub struct WithState<'guard, H> {
    inner: &'guard mut Wireguard,
    handler: H,
}

impl Wireguard {
    pub fn new(config: &Config) -> Self {
        let fake_src = wire::ethernet::Address([0; 6]);
        let fake_gw = wire::ip::v4::Address([0; 4]);

        let mut neighbors = arp::NeighborCache::new({
            Slice::One(arp::Neighbor::default())
        });

        let mut routes = ip::Routes::new({
            Slice::One(ip::Route::unspecified())
        });

        neighbors.fill(fake_gw.into(), fake_src, None)
            .expect("The neighbor was still available");
        routes.add_route(ip::Route::new_ipv4_gateway(fake_gw))
            .expect("The route was still available");

        let private_key = config.interface.private_key.to_private();
        let mut system = crypto::System::new();

        let peers = config.peers
            .iter()
            .map(|cpeer| {
                let public = cpeer.public_key.to_public();
                let mut peer = Peer::new(&mut system, public);
                peer.addresses = cpeer.allowed_ips
                    .iter()
                    .map(|cidr| cidr.address().into())
                    .collect::<Vec<_>>()
                    .into();
                peer.into()
            })
            .collect::<Vec<_>>();

        Wireguard {
            this: This::from_key(system, private_key),
            eth: eth::Endpoint::new(fake_src),
            ip: ip::Endpoint::new(
                Slice::One(wire::ip::v4::Cidr::new(fake_gw, 0).into()),
                routes,
                neighbors,
            ),
            peers,
        }
    }

    /// Create an ip tunnel.
    ///
    /// The return value can be used as an `ip` sender or receiver.
    pub fn tunnel<IpHandler>(&mut self, handler: IpHandler) -> WithState<'_, IpHandler> {
        WithState { inner: self, handler }
    }
}

impl From<Peer> for PeerState {
    fn from(peer: Peer) -> Self {
        PeerState {
            peer,
        }
    }
}

impl KeyConfig {
    fn to_public(&self) -> PublicKey {
        PublicKey::from(self.extract())
    }

    fn to_private(&self) -> StaticSecret {
        StaticSecret::from(self.extract())
    }

    fn extract(&self) -> [u8; 32] {
        match self {
            KeyConfig::Hex(st) => {
                let mut data = [0; 32];
                for (i, b) in data.iter_mut().enumerate() {
                    let src = &st[2*i..2*i+2];
                    *b = u8::from_str_radix(src, 16).unwrap();
                }
                data
            },
            KeyConfig::Data(vec) => {
                let mut data = [0; 32];
                data.copy_from_slice(vec);
                data
            },
        }
    }
}

impl<P: PayloadMut, IpHandler> udp::Recv<P> for WithState<'_, IpHandler>
where
    IpHandler: ip::Recv<P>,
{
    fn receive(&mut self, pkg: udp::Packet<P>) {
        let udp::Packet { packet, control } = pkg;
        todo!();
    }
}

impl<P: PayloadMut, IpHandler> udp::Send<P> for WithState<'_, IpHandler>
where
    IpHandler: ip::Send<P>,
{
    fn send(&mut self, pkg: udp::RawPacket<P>) {
        let udp::RawPacket { payload, control } = pkg;
        // Check for outstanding cookie messages to deliver?
        todo!();
        // Check the handler.
    }
}
