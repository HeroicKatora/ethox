use alloc::{string::String, vec::Vec};
use super::{crypto, Peer, This, wire::Packet, wire::Repr, wire::wireguard};
use ethox::managed::Slice;
use ethox::nic::{self, common::{EnqueueFlag, PacketInfo}, Capabilities};
use ethox::layer::{arp, eth, ip, udp};
use ethox::wire::{self, Payload, PayloadMut, PayloadMutExt};
use ethox::time::Instant;
use hashbrown::hash_map::HashMap;
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
    /// Connections for which we have completed the handshake.
    active: HashMap<u32, ConnectionState>,
}

struct PeerState {
    peer: super::Peer,
    handshake: super::PreHandshake,
}

struct ConnectionState {
    /// The peer on the other side.
    peer: usize,
    /// The client state for re-keying etc.
    client: super::Client,
    /// The crypto state.
    crypt: super::CryptConnection,
}

struct Connection<'lt> {
    this: &'lt mut This,
    peer: &'lt mut PeerState,
    state: &'lt mut ConnectionState,
}

pub struct WithState<'guard, H> {
    inner: &'guard mut Wireguard,
    handler: H,
}

impl Wireguard {
    // The destination address we use when pretending to send packets.
    const FAKE_ETH_SRC: wire::ethernet::Address = wire::ethernet::Address([0; 6]);
    // The receiver address we use when pretending to receive packets.
    const FAKE_ETH_DST: wire::ethernet::Address = wire::ethernet::Address([0x8; 6]);
    // An address for routing, pretending to be the next hop for all packets.
    // This is only used internally to resolve to the FAKE_ETH_DST in the arp cache.
    const FAKE_IP_GW: wire::ip::v4::Address = wire::ip::v4::Address([0; 4]);

    pub fn new(config: &Config) -> Self {
        let fake_src = Self::FAKE_ETH_SRC;
        let fake_gw = Self::FAKE_IP_GW;

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
        let mut this = This::from_key(crypto::System::new(), private_key);

        let peers = config.peers
            .iter()
            .map(|cpeer| {
                let public = cpeer.public_key.to_public();
                let mut peer = Peer::new(&mut this.system, public);
                peer.addresses = cpeer.allowed_ips
                    .iter()
                    .map(|&cidr| cidr.into())
                    .collect::<Vec<_>>()
                    .into();
                PeerState::from(peer, &mut this)
            })
            .collect::<Vec<_>>();

        Wireguard {
            this,
            eth: eth::Endpoint::new(fake_src),
            ip: ip::Endpoint::new(
                Slice::One(wire::ip::v4::Cidr::new(fake_gw, 0).into()),
                routes,
                neighbors,
            ),
            peers,
            active: HashMap::default(),
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

    fn connection(&mut self, nr: u32) -> Option<Connection<'_>> {
        let state = self.active.get_mut(&nr)?;
        let peer = &mut self.peers[state.peer];
        let this = &mut self.this;
        Some(Connection {
            this,
            state,
            peer,
        })
    }

    fn handle_response<T: PayloadMut>(
        &mut self,
        response: Packet<T>,
    ) {
        let repr = response.repr();
    }
}

impl PeerState {
    fn from(peer: Peer, this: &mut This) -> Self {
        let handshake = this.prepare_send(&peer);
        PeerState {
            peer,
            handshake,
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

        // Check if it corresponds to some of our peers.
        let con = match packet.repr() {
            // Or if this is meta traffic.
            Repr::Init { sender } => {
                todo!()
            }
            Repr::Response { sender, receiver } => {
                todo!()
            }
            Repr::Cookie { receiver } => {
                todo!()
            }
            Repr::Data { receiver, .. } => {
                match self.inner.connection(receiver) {
                    None => return,
                    Some(connection) => connection,
                }
            }
        };

        // There _is_ a connection for this, let's try to unseal the packet.
        let unsealed = match packet.unseal(con.this, &mut con.state.crypt) {
            // Something was invalid. Maybe nonce reuse, an attack, a packet delayed for too long,
            // etc. We don't care, just drop it. If the inner was a stream it will retry anyways.
            // TODO: might reuse this buffer?
            Err(_) => return,
            Ok(unsealed) => unsealed,
        };

        // Nice. So let's see if our peer 
        // TODO: should we enforce checksums or provide a nob?
        let ip = match wire::ip::v4::Packet::new_checked(&unsealed, wire::Checksum::Manual) {
            Err(_) => return,
            Ok(ip) => ip,
        };

        // Let's see if this is in fact valid to come for the peer.
        let ip_repr = ip.repr();
        let sender = ip_repr.src_addr;
        if {
            let sources = &con.peer.peer.addresses;
            let matches = |subnet: &wire::ip::Subnet| subnet.contains(sender.into());
            !sources.iter().any(matches)
        } {
            // Bad origin for this peer.
            return;
        };

        // By this point, we can discard the Wireguard information.
        // The next handler also expects a fully owned buffer.
        let wg_len = unsealed.payload().len();
        let wg_start = unsealed.payload().as_ptr() as usize;
        let raw = unsealed
            .into_inner() // wg
            .into_inner() // udp
            .into_inner() // ip
            .into_inner(); // eth
        let raw_start = raw.payload().as_ptr() as usize;
        let rel = wg_start - raw_start;
        // We want only a synthetic ethernet header.
        let hdr = wire::ethernet::Repr {
            dst_addr: Wireguard::FAKE_ETH_DST,
            src_addr: Wireguard::FAKE_ETH_SRC,
            ethertype: wire::ethernet::EtherType::Ipv4,
        };
        let want_len = hdr.header_len();

        // This should succeed since we shorten the packet.
        raw.reframe_payload(wire::ReframePayload {
            length: wg_len,
            old_payload: rel..rel+wg_len,
            new_payload: want_len..want_len+wg_len,
        }).unwrap();

        let eth = {
            let frame = wire::ethernet::frame::new_unchecked_mut(raw.payload_mut());
            hdr.emit(frame);
            wire::ethernet::Frame::new_unchecked(raw, hdr)
        };

        // Reassemble the packet using the repr we had before.
        let packet = wire::ip::v4::Packet::new_unchecked(eth, ip_repr);

        let ts = control.info().timestamp();
        // Setup a fake nic+eth+ip stack below.
        let mut fake_nic = EnqueueFlag::set_true(Wireguard::fake_info(ts));
        let eth = self.inner.eth.controller(&mut fake_nic);
        let control = self.inner.ip.controller(eth);

        // Receive our fake packet.
        self.handler.receive(ip::InPacket::<P> {
            packet: ip::IpPacket::V4(packet),
            control,
        });

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
