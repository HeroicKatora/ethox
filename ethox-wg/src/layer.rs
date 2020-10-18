use alloc::{string::String, vec::Vec};
use ethox::managed::Slice;
use ethox::nic::{self, common::{EnqueueFlag, PacketInfo}, Capabilities};
use ethox::layer::{arp, eth, ip, udp};
use ethox::wire::{self, Payload, PayloadMut, PayloadMutExt};
use ethox::time::Instant;
use hashbrown::hash_map::{Entry, HashMap};
use x25519_dalek::{PublicKey, StaticSecret};
use super::{
    crypto,
    Client,
    Peer,
    This,
    wire::Packet,
    wire::Repr,
    wire::wireguard,
};

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
    /// The listen port.
    pub listen_port: Option<u16>,
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
    listen_port: u16,
    /// The peers.
    peers: Vec<PeerState>,
    /// Outstanding handshake requests.
    init_probes: HashMap<u32, SentHandshakeState>,
    /// Connections for which we have completed the handshake.
    /// Keep this in sync with `PeerState::active` of the peer.
    active: HashMap<u32, ConnectionState>,
    /// Prepared handshake to ourselves.
    handshake: super::PreHandshake,
}

struct SentHandshakeState {
    for_peer: usize,
    crypt: super::PostInitHandshake,
}

struct PeerState {
    peer: super::Peer,
    /// The prepared handshake.
    handshake: super::PreHandshake,
    /// An active connection if there is one.
    active: Option<u32>,
    /// The subnets for this peer.
    subnets: Vec<wire::ip::v4::Subnet>,
    /// The known address of the peer, if any.
    reachable_ip: Option<(wire::ip::v4::Address, u16)>,
}

struct ConnectionState {
    /// The peer on the other side.
    peer: usize,
    peer_receiver: u32,
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
        let handshake = this.prepare_recv();

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
                let mut peer_state = PeerState::from(peer, &mut this);
                if let Some(at) = cpeer.assumed_at {
                    peer_state.reachable_ip = Some(at);
                }
                peer_state.subnets.extend(cpeer.allowed_ips.iter().cloned());
                peer_state
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
            listen_port: config.interface.listen_port
                .expect("Automatic listen port not implemented"),
            peers,
            active: HashMap::default(),
            init_probes: HashMap::default(),
            handshake,
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

    fn handle_init<T: PayloadMut>(
        &mut self,
        response: Packet<T>,
        timestamp: Instant,
        from_port: (wire::ip::v4::Address, u16),
    ) {
        // Respond to this?
        let sender = response.init_sender();
        let post_init = match response.consume_init(&mut self.this, &self.handshake) {
            // This was not for us. Silence.
            Err(_) => return,
            Ok(init) => init,
        };

        // Find out who sent this.
        let sender_pub = post_init.initiator_public();
        let sender_idx = match {
            self.peers.iter().position(|state| state.peer.public == sender_pub)
        } {
            // None of our peers.
            None => return,
            Some(sender) => sender,
        };
        let sender = &mut self.peers[sender_idx];

        // Good job, we know that one. Let's make sure we queue to send something back.
        todo!()
    }

    fn handle_response<T: PayloadMut>(
        &mut self,
        response: Packet<T>,
        timestamp: Instant,
    ) {
        let sender = response.response_sender();
        let receiver = response.response_receiver();

        // Recover the partial handshake.
        let handshake = match self.init_probes.entry(receiver) {
            Entry::Occupied(occupied) => occupied,
            Entry::Vacant(_) => return,
        };

        // And try to complete it.
        let mut post_hs = None;
        let this = &mut self.this;
        handshake.replace_entry_with(|_, handshake| {
            match response.consume_response(this, &handshake.crypt) {
                // Wrong packet or some trying to interfere? Drop it and restore previous state.
                Err(_) => Some(handshake),
                Ok(post) => {
                    post_hs = Some((handshake, post));
                    None
                }
            }
        });

        // Insert the completed handshake if any.
        if let Some((handshake, post_hs)) = post_hs {
            let crypt = post_hs.into_initiator();
            // Create, or recover, the connection state for the peer.
            let peer_id = handshake.for_peer;
            let peer = &mut self.peers[peer_id];

            if let Some(active) = peer.active {
                // Expect our internals to be consistent.
                let active = self.active.get_mut(&active).unwrap();
                active.crypt = crypt;
                active.client.last_alive = timestamp;
                active.client.last_rekey_time = timestamp;
                active.client.messages_without_rekey = 0;
            } else {
                // This _should_ be a unique id?
                self.active
                    .entry(sender)
                    .and_modify(|_| panic!("Duplicate incoming connection?"))
                    .or_insert(ConnectionState {
                        peer: peer_id,
                        peer_receiver: sender,
                        client: Client::from_initial_key(timestamp),
                        crypt,
                    });
            };
        }
    }

    fn handle_send<P: PayloadMut>(
        &mut self,
        packet: ip::RawPacket<P>,
    ) {
        let ip::RawPacket { payload, mut control } = packet;
        // Did you actually leave a valid ethernet+ipv4 frame`
        let frame = match wire::ethernet::Frame::new_checked(payload) {
            Ok(frame) => frame,
            Err(_) => return,
        };
        // Ignore the checksum, we trust the sender side.
        let ipv4 = match wire::ip::v4::Packet::new_checked(frame, wire::Checksum::Ignored) {
            Ok(packet) => packet,
            Err(_) => return,
        };

        // Find the destination peer.
        // TODO: can we use a custom next_hop to collect this information via routing?
        let dst = ipv4.repr().dst_addr;

        let peer = 'a: loop {
            for (peer_idx, peer) in self.peers.iter_mut().enumerate() {
                for addr in &peer.subnets {
                    if addr.contains(dst) {
                        break 'a Some((peer_idx, peer));
                    }
                }
            }
            break 'a None;
        };

        let (peer_idx, peer) = match peer {
            // Did you do custom routing?
            None => return,
            Some(tup) => tup,
        };

        let (ip, port) = match peer.reachable_ip {
            // Hm, nope. Maybe we should only have routes to known peers?
            None => return,
            Some(tup) => tup,
        };

        // We need to relocate the ip payload.
        let ipv4_len = ipv4.get_ref().payload().len();
        let ip_addr = ipv4.get_ref().payload().as_ptr() as usize;
        let raw = ipv4.into_inner().into_inner();
        let base_addr = raw.payload().as_ptr() as usize;
        let ip_start = ip_addr - base_addr;

        let wg_len = Repr::len_for_payload(ipv4_len);

        // Query the actual route, we want to preserve the payload without copies.
        let route = match control.route_to(ip.into()) {
            Ok(route) => route,
            // No route, no peer.
            Err(_) => return,
        };

        // We do manual framing etc. to preserve the underlying payload.
        let eth_hdr = wire::ethernet::Repr {
            dst_addr: route.next_mac,
            src_addr: route.src_mac,
            ethertype: wire::ethernet::EtherType::Ipv4,
        };

        let ip_hdr = wire::ip::v4::Repr {
            dst_addr: ip,
            src_addr: match route.src_addr {
                wire::ip::Address::Ipv4(v4) => v4,
                _ => unreachable!("Chose ipv6 source address"),
            },
            hop_limit: u8::max_value(),
            payload_len: wg_len + 8,
            protocol: wire::ip::Protocol::Udp,
        };

        let udp_hdr = wire::udp::Repr {
            dst_port: port,
            src_port: self.listen_port,
            length: 0,
        };

        let udp_chk = wire::udp::Checksum::Manual {
            src_addr: route.src_addr,
            dst_addr: ip.into(),
        };

        let wg_start = eth_hdr.header_len()
            + ip_hdr.buffer_len()
            + 8;
        let payload_start = wg_start+Repr::payload_offset();

        match raw.reframe_payload(wire::ReframePayload {
            length: wg_start + wg_len,
            old_payload: ip_start..ip_start+ipv4_len,
            new_payload: payload_start..payload_start+ipv4_len,
        }) {
            Ok(_) => {},
            Err(_) => return,
        }

        // Start emitting headers.
        let payload = raw.payload_mut();
        eth_hdr.emit(wire::ethernet::frame::new_unchecked_mut(payload));
        let mut eth = wire::ethernet::Frame::new_unchecked(raw, eth_hdr);
        ip_hdr.emit(wire::ip::v4::packet::new_unchecked_mut(eth.payload_mut()), wire::Checksum::Manual);
        let mut ip = wire::ip::v4::Packet::new_unchecked(eth, ip_hdr);
        udp_hdr.emit(wire::udp::packet::new_unchecked_mut(ip.payload_mut()), udp_chk);
        let udp = wire::udp::Packet::new_unchecked(ip, udp_hdr);

        // Huh, reached the Wireguard things..
        todo!()
    }
}

impl PeerState {
    fn from(peer: Peer, this: &mut This) -> Self {
        let handshake = this.prepare_send(&peer);
        PeerState {
            peer,
            handshake,
            active: None,
            subnets: Vec::new(),
            reachable_ip: None,
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
        let from_port = packet.repr().src_port;
        let original_control = control;

        let from_ip = match packet.get_ref().repr().src_addr() {
            wire::ip::Address::Ipv4(addr) => addr,
            // Don't handle any non-ipv4 traffic.
            _ => return,
        };

        // Parse packet contents as Wireguard.
        let packet = match Packet::new_checked(packet) {
            Err(_) => return,
            Ok(packet) => packet,
        };

        let timestamp = original_control.info().timestamp();
        // Check if it corresponds to some of our peers.
        let con = match packet.repr() {
            // Or if this is meta traffic.
            Repr::Init { .. } => {
                let from = (from_ip, from_port);
                return self.inner.handle_init(packet, timestamp, from);
            }
            Repr::Response { .. } => {
                return self.inner.handle_response(packet, timestamp);
            }
            Repr::Cookie { .. } => {
                // FIXME: cookie handling.
                return;
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
            wire::ethernet::Frame::new_unchecked(&mut *raw, hdr)
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
        if fake_nic.was_sent() {
            self.inner.handle_send(ip::RawPacket {
                payload: raw,
                control: original_control.into_ip(),
            });
        }
    }
}

impl<P: PayloadMut, IpHandler> udp::Send<P> for WithState<'_, IpHandler>
where
    IpHandler: ip::Send<P>,
{
    fn send(&mut self, pkg: udp::RawPacket<P>) {
        let udp::RawPacket { payload, control } = pkg;
        let original_control = control;

        let ts = original_control.info().timestamp();
        // Setup a fake nic+eth+ip stack below.
        let mut fake_nic = EnqueueFlag::set_true(Wireguard::fake_info(ts));
        let eth = self.inner.eth.controller(&mut fake_nic);
        let control = self.inner.ip.controller(eth);

        // Check for outstanding cookie messages to deliver?
        let fake = ip::RawPacket { payload, control };
        self.handler.send(fake);

        // Check the handle for send.
        if fake_nic.was_sent() {
            self.inner.handle_send(ip::RawPacket {
                payload,
                control: original_control.into_ip(),
            });
        }
    }
}
