//! A very simple udp iperf protocol.
//!
//! For udp, the client (sender) simply floods the server with packets of client-side specified
//! length and bandwidth. A few bytes of metdata are provided in it, the rest is filled with the
//! repeating pattern `0123456789`. Technically, the implementation would wait for a single ack
//! packet from the server on the reverse path but it is not important for giving results. The
//! server seems to merely time-out after a while.
//!
//! There is no control channel as for iperf3. This may have negative impact on the accuracy of the
//! measurement but greatly simplifies the independent implementation for udp.
use core::{mem, ptr};

use ethox::layer::{ip, tcp, udp, Error};
use ethox::time::{Duration, Instant};
use ethox::wire::{Ipv4Subnet, PayloadMut, TcpSeqNumber};
use ethox::managed::{Map, Partial, SlotMap};

use super::config;

pub struct Iperf {
    connection: Connection,
    udp: udp::Endpoint<'static>,
}

pub struct IperfTcp {
    client: tcp::Client<tcp::io::Sink, PatternBuffer>,
    tcp: tcp::Endpoint<'static>,
    result: Option<TcpResult>,
    first_sent: Option<Instant>,
    last_time: Option<Instant>,
}

/// An iperf2 udp server instance.
///
/// Only supports a single connection to a client, then must be restarted.
pub struct Server {
    connection: ServerConnection,
    udp: udp::Endpoint<'static>,
}

struct Connection {
    /// The init parameters for udp.
    send_init: udp::Init,

    /// The size of each packet.
    packet_size: usize,

    /// Bytes to send. When lower than `packet_size`, we permit a single packet that is too small.
    remaining: usize,

    /// Number of sent packets.
    sent_packets: u32,

    /// Shape traffic to target bandwidth.
    target_rate: Option<SendRate>,

    /// Result we got from the server.
    result: Option<Result>,

    /// Time of the last sent packet.
    last_time: Instant,
}

/// Tracks the state of a unique perf connection to a client.
struct ServerConnection {
    /// Init for sending the ack packet back.
    send_init: udp::Init,

    /// Maximum observed length of packets, assumed to be the length of almost all.
    packet_size: usize,

    /// Number of bytes transferred.
    received_bytes: usize,

    /// The maximally observed packet number.
    max_packet_id: u32,

    /// Number of received packet.
    received_packets: u32,

    /// The server side result.
    result: Option<ServerResult>,

    /// The timestamp of the first packet that was received.
    begin_ts: Instant,

    /// We wait with termination until we sent the result.
    result_sent: bool,
}

struct SendRate {
    /// Bandwidth target.
    bytes_per_sec: usize,

    /// A counter of bytes, wrapping at the packet size.
    ///
    /// This represents partially sent packets at a certain timestamp.
    wrapping_part_bytes: usize,

    /// Time of the last sent packet.
    last_time: Instant,
}

/// A 'TCP-buffer' for the iperf pattern.
///
/// This does not allocate any data, instead filling each pattern dynamically as if the pattern
/// would have been put into a sequential queue.
struct PatternBuffer {
    /// Total number of bytes.
    len: usize,

    /// Number of acked bytes.
    acked: usize,

    /// The sequence number corresponding to `acked`.
    at: Option<TcpSeqNumber>,
}

/// The result memory representation.
///
/// Annotations on members are example values observed in real world usage of the original iperf
/// using pcap/Wireshark.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct WireResult {
    pub a: u32, // 00 00 00 00
    pub data_len: u32, // 00 02 0a 8a - total data
    pub delta_s: u32, // 00 00 00 01 - delta t (s)
    pub delta_ms: u32, // 00 00 4f ad - delta t (ms)
    pub e: u32, // 00 00 00 00
    pub f: u32, // 00 00 00 00
    pub packet_count: u32, // 00 00 00 5b - total packets
    pub h: u32, // 00 00 00 00
    pub i: u32, // 00 00 00 00
    pub j: u32, // 00 00 00 09
}

/// The local udp result merging local state and server sent result data.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Result {
    pub data_len: u32,
    pub delta_s: u32,
    pub delta_ms: u32,
    pub packet_count: u32,
    pub total_count: u32,
}

/// A locally created result, **not** sent by the remote.
///
/// There is no result communication for the TCP iperf2 instantiation. (It could, if the Linux
/// stack were to support half-closed streams in a nice manner, like this stack). But since the
/// protocol layer intrisically tracks most of the necessary data we can restore it on the client
/// side.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TcpResult {
    pub data_len: u32,
    pub duration: Duration,
    pub packet_count: u32,
}

/// The result of a server.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ServerResult {
    pub packet_size: u32,
    pub packet_count: u32,
    pub received_bytes: u64,
    pub total_count: u32,
    pub duration: Duration,
}

impl Iperf {
    pub fn new(config: &config::Client) -> Self {
        Iperf {
            connection: Connection::new(config),
            udp: Self::generate_udp(config),
        }
    }

    fn generate_udp(_: &config::Client) -> udp::Endpoint<'static> {
        // We only need a single connection entry.
        udp::Endpoint::new(vec![Connection::UDP_SRC_PORT])
    }
}

impl IperfTcp {
    pub fn new(config: &config::Client) -> Self {
        IperfTcp {
            client: Self::generate_client(config),
            tcp: Self::generate_tcp(config),
            result: None,
            first_sent: None,
            last_time: None,
        }
    }

    fn generate_client(client: &config::Client)
        -> tcp::Client<tcp::io::Sink, PatternBuffer>
    {
        let remote = client.host.into();
        let port = client.port;
        let sink = tcp::io::Sink::default();
        let pattern = PatternBuffer {
            len: client.total_bytes,
            acked: 0,
            at: None,
        };

        tcp::Client::new(remote, port, sink, pattern)
    }

    fn generate_tcp(_: &config::Client) -> tcp::Endpoint<'static> {
        let isn = tcp::IsnGenerator::from_std_hash();
        // We only need a single connection entry.
        tcp::Endpoint::new(
            Map::Pairs(Partial::new(
                vec![Default::default()].into())),
            SlotMap::new(
                vec![Default::default()].into(),
                vec![Default::default()].into()),
            isn)
    }
}

impl Connection {
    const UDP_SRC_PORT: u16 = 50020;

    fn new(config: &config::Client) -> Self {
        let config::Client {
            host: _, port: _,
            buffer_bytes: packet_size,
            total_bytes: remaining,
        } = config;
        let packet_size = *packet_size;
        let remaining = *remaining;

        assert!(packet_size >= 20, "Minimum packet size of 20 is required");

        Connection {
            send_init: Self::generate_udp_init(config),
            packet_size,
            remaining,
            // FIXME: support traffic shaping
            target_rate: None,
            sent_packets: 0,
            result: None,
            last_time: Instant::from_millis(0),
        }
    }

    fn generate_udp_init(config: &config::Client) -> udp::Init {
        udp::Init {
            source: ip::Source::Mask {
                subnet: Ipv4Subnet::ANY.into(),
            },
            src_port: Connection::UDP_SRC_PORT,
            dst_addr: config.host.into(),
            dst_port: config.port,
            payload: config.buffer_bytes,
        }
    }

    /// If we were to send a full-sized packet now, would we exceed our bandwidth target?
    fn should_send(&self, now: Instant) -> bool {
        if let Some(rate) = &self.target_rate {
            let allowed = rate.allowed_bytes(now);
            allowed >= self.packet_size as u128
        } else {
            true
        }
    }

    fn update_sent(&mut self, now: Instant) {
        if let Some(rate) = &mut self.target_rate {
            rate.update_sent(self.packet_size, now);
        }

        self.remaining = self.remaining
            .saturating_sub(self.packet_size);
        self.sent_packets += 1;
    }

    /// Fill the necessary part of the packet.
    fn fill(&mut self, packet: &mut [u8], time: Instant, count: u32) {
        assert!(packet.len() >= 20);
        crate::pattern::init(packet, 0);

        let secs = time.secs() as u32;
        let millis = time.millis() as u32;
        packet[0..4].copy_from_slice(&count.to_be_bytes());
        packet[4..8].copy_from_slice(&secs.to_be_bytes());
        packet[8..12].copy_from_slice(&millis.to_be_bytes());
        // For some reason, these bytes are always zeroed.
        packet[16..20].copy_from_slice(&[0, 0, 0, 0]);

        // Last packet marker.
        if self.remaining <= self.packet_size {
            packet[0] |= 0x80;
        }
    }

    fn error_shutdown(&mut self) {
        self.remaining = 0;
    }
}

impl Server {
    pub fn new(config: &config::Server) -> Self {
        Server {
            connection: ServerConnection::new(config),
            udp: Self::generate_udp(config),
        }
    }

    fn generate_udp(config: &config::Server) -> udp::Endpoint<'static> {
        udp::Endpoint::new(vec![config.port])
    }
}

impl ServerConnection {
    pub fn new(config: &config::Server) -> Self {
        let config::Server { host, port } = config;
        let source = host.map(|ip| ip::Source::Exact(ip.into()))
            .unwrap_or_else(|| ip::Source::Mask {
                subnet: Ipv4Subnet::ANY.into(),
            });

        ServerConnection {
            send_init: udp::Init {
                source: source,
                src_port: *port,
                dst_addr: Default::default(),
                dst_port: 0,
                payload: 20 + mem::size_of::<WireResult>(),
            },
            packet_size: 0,
            received_bytes: 0,
            max_packet_id: 0,
            received_packets: 0,
            result: None,
            begin_ts: Instant::from_millis(0),
            result_sent: false,
        }
    }

    fn fill_report(&self, payload: &mut [u8]) {
        // We prepared this packet, so assert is correct.
        assert_eq!(payload.len(), 20 + mem::size_of::<WireResult>());

        let be_result = WireResult {
            packet_count: u32::to_be(self.received_packets),
            .. WireResult::default()
        };

        let mem_result = &mut payload[20..][..mem::size_of::<WireResult>()];
        unsafe {
            ptr::write_unaligned(mem_result.as_mut_ptr() as *mut WireResult, be_result)
        };
    }

    /// Register a valid udp packet as having arrived.
    ///
    /// Panics if the validity invariant of length has not been checked prior.
    fn register(&mut self, payload: &[u8], time: Instant) {
        use core::convert::TryFrom;
        assert!(payload.len() >= 20);
        self.received_bytes = self.received_bytes.saturating_add(payload.len());

        let id_bytes = <[u8;4]>::try_from(&payload[0..4]).unwrap();
        let id = u32::from_be_bytes(id_bytes) & 0x7FFF_FFFF;
        let last = payload[0] & 0x80 != 0;

        // HACKY: we don't check that all packets but the last have maximum length but we just
        // assume that this setting was supplied and traffic shaping is not done by reducing
        // datagram lengths but by delayed packets.
        self.packet_size = self.packet_size.max(payload.len());
        self.max_packet_id = self.max_packet_id.max(id);
        self.received_packets += 1;

        if last {
            self.result = Some(ServerResult {
                packet_size: u32::try_from(self.packet_size)
                    .unwrap_or_else(|_| u32::max_value()),
                packet_count: self.received_packets,
                total_count: self.max_packet_id + 1,
                received_bytes: u64::try_from(self.received_bytes)
                    .unwrap_or_else(|_| u64::max_value()),
                duration: time - self.begin_ts,
            });
        }
    }

    fn error_shutdown(&mut self) {
        self.result = Some(ServerResult {
            packet_size: 0,
            packet_count: self.received_packets,
            total_count: self.max_packet_id + 1,
            received_bytes: 0,
            duration: Duration::from_millis(0),
        })
    }
}

impl SendRate {
    /// Called after a packet has been sent.
    fn update_sent(&mut self, sent: usize, now: Instant) {
        let allowed = self.allowed_bytes(now);
        self.wrapping_part_bytes = allowed
            .saturating_sub(sent as u128)
            as usize;
        self.last_time = now;
    }

    /// Allowed bandwidth use until the timestamp.
    fn allowed_bytes(&self, now: Instant) -> u128 {
        let diff_millis = (now - self.last_time).as_millis();
        let new_bytes = diff_millis
            .saturating_mul(self.bytes_per_sec as u128)
            / 1_000_000;
        let part = self.wrapping_part_bytes as u128;
        new_bytes + part
    }
}

impl<P: PayloadMut> ip::Send<P> for Iperf {
    fn send(&mut self, packet: ip::RawPacket<P>) {
        if self.connection.remaining > 0 {
            self.udp
                .send(&mut self.connection)
                .send(packet)
        }
    }
}

impl<P: PayloadMut> ip::Recv<P> for Iperf {
    fn receive(&mut self, packet: ip::InPacket<P>) {
        if self.connection.remaining == 0 && self.connection.result.is_none() {
            self.udp
                .recv(&mut self.connection)
                .receive(packet)
        }
    }
}

impl<P: PayloadMut> ip::Send<P> for Server {
    fn send(&mut self, packet: ip::RawPacket<P>) {
        if self.connection.result.is_some() && !self.connection.result_sent {
            self.udp
                .send(&mut self.connection)
                .send(packet)
        }
    }
}

impl<P: PayloadMut> ip::Recv<P> for Server {
    fn receive(&mut self, packet: ip::InPacket<P>) {
        // While we did not yet receive the last packet.
        if self.connection.result.is_none() {
            self.udp
                .recv(&mut self.connection)
                .receive(packet)
        }
    }
}

impl<P: PayloadMut> ip::Send<P> for IperfTcp {
    fn send(&mut self, packet: ip::RawPacket<P>) {
        if !self.client.is_closed() {
            self.tcp.send(&mut self.client)
                .send(packet)
        } else {
            self.result.get_or_insert_with(|| TcpResult {
                data_len: 0,
                duration: Instant::from_millis(0) - Instant::from_millis(0),
                packet_count: 0,
            });
        }

        if self.result.is_none() && false {
            let first = self.first_sent.unwrap();
            let last = self.last_time.unwrap();
            self.result = Some(TcpResult {
                data_len: self.client.send().len as u32,
                duration: last - first,
                packet_count: 0,
            });
        }
    }
}

impl<P: PayloadMut> ip::Recv<P> for IperfTcp {
    fn receive(&mut self, packet: ip::InPacket<P>) {
        if !self.client.is_closed() {
            self.tcp.recv(&mut self.client)
                .receive(packet)
        }
    }
}

impl<Nic> super::Client<Nic> for Iperf
where
    Nic: ethox::nic::Device,
    Nic::Payload: PayloadMut + Sized,
{
    fn result(&self) -> Option<super::Score> {
        self.connection.result.clone().map(|result| result.into())
    }
}

impl<Nic> super::Client<Nic> for IperfTcp
where
    Nic: ethox::nic::Device,
    Nic::Payload: PayloadMut + Sized,
{
    fn result(&self) -> Option<super::Score> {
        self.result.map(|result| result.into())
    }
}

impl<Nic> super::Client<Nic> for Server
where
    Nic: ethox::nic::Device,
    Nic::Payload: PayloadMut + Sized,
{
    fn result(&self) -> Option<super::Score> {
        if !self.connection.result_sent {
            return None;
        }

        self.connection.result.clone().map(|result| result.into())
    }
}

impl tcp::SendBuf for PatternBuffer {
    fn available(&self) -> tcp::AvailableBytes {
        tcp::AvailableBytes {
            total: self.len - self.acked,
            fin: true,
        }
    }

    fn fill(&mut self, buf: &mut [u8], begin: TcpSeqNumber) {
        const HEAD: [u8; 4] = [0x80, 0x00, 0x00, 0x00];

        let prev = self.at.expect("Fill must not be called before isn indication");
        let relative = begin - prev;

        let offset = (self.acked + relative) % 10;
        crate::pattern::init(buf, offset);

        // The first 4 byte are special.
        if let Some(head) = 4usize.checked_sub(relative + self.acked) {
            let head_len = 4 - head;
            buf[..head_len].copy_from_slice(&HEAD[head..]);
        }
    }

    fn ack(&mut self, ack: TcpSeqNumber) {
        let previous = *self.at.get_or_insert(ack);
        self.acked += ack - previous;
        self.at = Some(ack);
    }
}

impl<P: PayloadMut> udp::Send<P> for Connection {
    fn send(&mut self, packet: udp::RawPacket<P>) {
        let ts = packet.info().timestamp();

        if self.sent_packets > 0 {
            // Make sure to stay within bandwidth.
            if !self.should_send(ts) {
                return;
            }
        }

        let mut packet = match packet.prepare(self.send_init.clone()) {
            Ok(packet) => packet,
            // May simply require a lookup.
            Err(Error::Unreachable) => return,
            Err(_) => return self.error_shutdown(),
        };

        // Ensure we stay at a consistent sender address. Also reduces lookup in ip.
        if self.sent_packets == 0 {
            let source = packet.packet.get_ref().repr().src_addr();
            self.last_time = ts;
            self.send_init.source = ip::Source::Exact(source);
        }

        let count = self.sent_packets;
        self.fill(packet.packet.payload_mut_slice(), ts, count);
        self.update_sent(ts);

        match packet.send() {
            Ok(()) => (),
            Err(_) => return self.error_shutdown(),
        }
    }
}

impl<P: PayloadMut> udp::Recv<P> for Connection {
    fn receive(&mut self, packet: udp::Packet<P>) {
        let repr = packet.packet.repr();
        if repr.dst_port != self.send_init.src_port {
            return;
        }

        let payload = packet.packet.payload_slice();

        if payload.len() < 20 + mem::size_of::<WireResult>() {
            return;
        }

        let mem_result = &payload[20..][..mem::size_of::<WireResult>()];
        let be_result = unsafe {
            ptr::read_unaligned(mem_result.as_ptr() as *const WireResult)
        };

        let wire_result = WireResult {
            a: u32::from_be(be_result.a),
            data_len: u32::from_be(be_result.data_len),
            delta_s: u32::from_be(be_result.delta_s),
            delta_ms: u32::from_be(be_result.delta_ms),
            e: u32::from_be(be_result.e),
            f: u32::from_be(be_result.f),
            packet_count: u32::from_be(be_result.packet_count),
            h: u32::from_be(be_result.h),
            i: u32::from_be(be_result.i),
            j: u32::from_be(be_result.j),
        };

        self.result = Some(Result {
            data_len: wire_result.data_len,
            delta_s: wire_result.delta_s,
            delta_ms: wire_result.delta_ms,
            packet_count: wire_result.packet_count,
            total_count: self.sent_packets,
        });
    }
}

impl<P: PayloadMut> udp::Send<P> for ServerConnection {
    fn send(&mut self, packet: udp::RawPacket<P>) {
        let mut packet = match packet.prepare(self.send_init.clone()) {
            Ok(packet) => packet,
            // May simply require an arp lookup.
            Err(Error::Unreachable) => return,
            Err(_) => return self.error_shutdown(),
        };

        self.fill_report(packet.packet.payload_mut_slice());

        match packet.send() {
            Ok(()) => self.result_sent = true,
            Err(_) => return self.error_shutdown(),
        }
    }
}

impl<P: PayloadMut> udp::Recv<P> for ServerConnection {
    fn receive(&mut self, packet: udp::Packet<P>) {
        let udp::Packet { packet, control, } = packet;

        let ip_hdr = packet.get_ref().repr();
        let udp_hdr = packet.repr();

        if self.send_init.dst_port == 0 {
            // TODO: should we check validity before accepting?
            self.send_init.dst_addr = ip_hdr.src_addr();
            self.send_init.dst_port = udp_hdr.src_port;
            self.begin_ts = control.info().timestamp();
        } else if self.send_init.dst_addr != ip_hdr.src_addr()
            || self.send_init.dst_port != udp_hdr.src_port
        {
            // This packet was not from the original client we accepted.
            return;
        }

        let payload = packet.payload_slice();
        if payload.len() <= 20 {
            return;
        }

        self.register(payload, control.info().timestamp());
    }
}
