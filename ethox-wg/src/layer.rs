use alloc::{string::String, vec::Vec};
use super::{crypto, Peer, This, wire::Packet, wire::Repr, wire::wireguard};
use ethox::managed::Slice;
use ethox::nic::{self, common::{EnqueueFlag, PacketInfo}, Capabilities};
use ethox::layer::{arp, eth, ip, udp};
use ethox::wire::{self, PayloadMut};
use ethox::time::Instant;
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
    /// The subnets dedicated to this peer.
    pub allowed_ips: Slice<'static, wire::ip::v4::Subnet>,
    /// An optional address of the peer.
    pub assumed_at: Option<(wire::ip::v4::Address, u16)>,
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

        let routes: usize = config.peers
            .iter()
            .map(|peer| peer.allowed_ips.len())
            .sum();

        let mut neighbors = arp::NeighborCache::new({
            Slice::One(arp::Neighbor::default())
        });

        let mut routes = ip::Routes::new({
            alloc::vec![ip::Route::unspecified(); routes]
        });

        neighbors.fill(fake_gw.into(), fake_src, None)
            .expect("The neighbor was still available");

        for peer in config.peers.iter() {
            for &subnet in peer.allowed_ips.iter() {
                routes.add_route(ip::Route {
                    net: subnet.into(),
                    next_hop: fake_gw.into(),
                    expires_at: ethox::time::Expiration::Never,
                }).expect("The route was still available");
            }
        }

        let private_key = config.interface.private_key.to_private();
        let mut system = crypto::System::new();

        let peers = config.peers
            .iter()
            .map(|cpeer| {
                let public = cpeer.public_key.to_public();
                let mut peer = Peer::new(&mut system, public);
                peer.addresses = cpeer.allowed_ips
                    .iter()
                    .map(|&cidr| cidr.into())
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

    fn fake_info(ts: Instant) -> PacketInfo {
        // In particular, pretend to do all checksum so that packet generation does not waste those
        // cycles.
        PacketInfo {
            timestamp: ts,
            capabilities: {
                let mut caps = Capabilities::no_support();
                *caps.ipv4_mut() = nic::Protocol::offloaded();
                caps
            },
        }
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

        // Parse packet.
        let packet = match Packet::new_checked(packet) {
            Err(_) => return,
            Ok(packet) => packet,
        };

        // Check if this is meta traffic.
        match packet.repr() {
            // Or if it corresponds to some of our peers.
            Repr::Data { receiver, .. } => {}
            _ => todo!(),
        }

        let ts = control.info().timestamp();
        // Setup a fake nic+eth+ip stack below.
        let mut fake_nic = EnqueueFlag::set_true(Wireguard::fake_info(ts));
        let eth = self.inner.eth.controller(&mut fake_nic);
        let control = self.inner.ip.controller(eth);

        let fake = ip::InPacket::<P> { packet: todo!(), control };
        self.handler.receive(fake);

        // Check the handle for send.
        todo!();
    }
}

impl<P: PayloadMut, IpHandler> udp::Send<P> for WithState<'_, IpHandler>
where
    IpHandler: ip::Send<P>,
{
    fn send(&mut self, pkg: udp::RawPacket<P>) {
        let udp::RawPacket { payload, control } = pkg;

        let ts = control.info().timestamp();
        // Setup a fake nic+eth+ip stack below.
        let mut fake_nic = EnqueueFlag::set_true(Wireguard::fake_info(ts));
        let eth = self.inner.eth.controller(&mut fake_nic);
        let control = self.inner.ip.controller(eth);

        // Check for outstanding cookie messages to deliver?
        let fake = ip::RawPacket { payload, control };
        self.handler.send(fake);

        // Check the handle for send.
        todo!();
    }
}
