//! A very simple udp iperf protocol.
//!
//! For udp, tHe client (sender) simply floods the server with packets of client-side specified
//! length and bandwidth. A few bytes of metdata are provided in it, the rest is filled with the
//! repeating pattern `0123456789`. Technically, the implementation would wait for a single ack
//! packet from the server on the reverse path but it is not important for giving results. The
//! server seems to merely time-out after a while.
//!
//! There is no control channel as for iperf3. This may have negative impact on the accuracy of the
//! measurement but greatly simplifies the independent implementation for udp.
use core::{fmt, mem};

use ethox::layer::{ip, tcp, udp, Error};
use ethox::time::{Duration, Instant};
use ethox::wire::{Ipv4Subnet, PayloadMut, TcpSeqNumber};
use ethox::managed::{Map, Partial, SlotMap};

use super::config::Client;

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

struct Connection {
    /// The init parameters for udp.
    send_init: udp::Init,

    /// The size of each packet.
    packet_size: usize,

    /// Bytes to send. When lower than `packet_size`, we permit a single packet that is too small.
    remaining: usize,

    /// Bandwidth target.
    bytes_per_sec: usize,

    /// A counter of bytes, wrapping at the packet size.
    ///
    /// This represents partially sent packets at a certain timestamp.
    wrapping_part_bytes: usize,

    /// Number of sent packets.
    packet_count: u32,

    /// Time of the last packet.
    last_time: Instant,

    /// Result we got from the server.
    result: Option<Result>,
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

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Result {
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

/// A locall created result, **not** sent by the remote.
///
/// There is no result communication for the TCP iperf2 instantiation. (It could, if the Linux
/// stack were to support half-closed streams in a nice manner, like this stack). But since the
/// protocol layer intrisically tracks most of the necessary data we can restore it on the client
/// side.
#[derive(Clone, Copy)]
pub(crate) struct TcpResult {
    pub data_len: u32,
    pub duration: Duration,
    pub packet_count: u32,
}

impl Iperf {
    pub fn new(config: &Client) -> Self {
        Iperf {
            connection: Connection::new(config),
            udp: Self::generate_udp(config),
        }
    }

    pub fn result(&self) -> Option<Result> {
        self.connection.result
    }

    fn generate_udp(_: &Client) -> udp::Endpoint<'static> {
        // We only need a single connection entry.
        udp::Endpoint::new(vec![Default::default()])
    }
}

impl IperfTcp {
    pub fn new(config: &Client) -> Self {
        IperfTcp {
            client: Self::generate_client(config),
            tcp: Self::generate_tcp(config),
            result: None,
            first_sent: None,
            last_time: None,
        }
    }

    fn generate_client(client: &Client)
        -> tcp::Client<tcp::io::Sink, PatternBuffer>
    {
        let remote = client.host.into();
        let port = client.port;
        let sink = tcp::io::Sink::default();
        let pattern = PatternBuffer {
            len: client.bytes,
            acked: 0,
            at: None,
        };

        tcp::Client::new(remote, port, sink, pattern)
    }

    fn generate_tcp(_: &Client) -> tcp::Endpoint<'static> {
        let isn = tcp::IsnGenerator::from_std_hash();
        // We only need a single connection entry.
        tcp::Endpoint::new(
            Map::Pairs(Partial::new(vec![].into())),
            SlotMap::new(vec![].into(), vec![].into()),
            isn)
    }
}

impl Connection {
    fn new(config: &Client) -> Self {
        let Client {
            host: _, port: _,
            bytes: packet_size,
            length: remaining,
        } = config;
        let packet_size = *packet_size;
        let remaining = *remaining;

        assert!(packet_size >= 20, "Minimum packet size of 20 is required");

        Connection {
            send_init: Self::generate_udp_init(config),
            packet_size,
            remaining,
            bytes_per_sec: usize::max_value(),
            wrapping_part_bytes: 0,
            packet_count: 0,
            last_time: Instant::from_millis(0),
            result: None,
        }
    }

    fn generate_udp_init(config: &Client) -> udp::Init {
        udp::Init {
            source: ip::Source::Mask {
                subnet: Ipv4Subnet::ANY.into(),
            },
            src_port: 50020,
            dst_addr: config.host.into(),
            dst_port: config.port,
            payload: config.bytes,
        }
    }

    /// If we were to send a full-sized packet now, would we exceed our bandwidth target?
    fn should_send(&self, now: Instant) -> bool {
        let allowed = self.allowed_bytes(now);
        allowed >= self.packet_size as u128
    }

    /// Called after a packet has been sent.
    fn update_sent(&mut self, now: Instant) {
        let allowed = self.allowed_bytes(now);
        self.wrapping_part_bytes = allowed
            .saturating_sub(self.packet_size as u128)
            as usize;
        self.remaining = self.remaining
            .saturating_sub(self.packet_size);
        self.last_time = now;
        self.packet_count += 1;
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

    /// Fill the necessary part of the packet.
    fn fill(&mut self, packet: &mut [u8], time: Instant, count: u32) {
        static FILL_PATTERN: &[u8] = b"0123456789";
        assert!(packet.len() >= 20);

        packet
            .chunks_mut(10)
            .for_each(|chunk| chunk.copy_from_slice(&FILL_PATTERN[..chunk.len()]));

        let secs = time.secs() as u32;
        let millis = time.millis() as u32;
        packet[0..4].copy_from_slice(&count.to_be_bytes());
        packet[4..8].copy_from_slice(&secs.to_be_bytes());
        packet[8..12].copy_from_slice(&millis.to_be_bytes());
        // For some reason, these bytes are always zeroed.
        packet[16..20].copy_from_slice(&[0, 0, 0, 0]);

        // Last packet marker.
        if self.remaining < self.packet_size {
            packet[0] |= 0x80;
        }
    }

    fn error_shutdown(&mut self) {
        self.remaining = 0;
    }
}

impl<P: PayloadMut> ip::Send<P> for Iperf {
    fn send(&mut self, packet: ip::RawPacket<P>) {
        self.udp
            .send(&mut self.connection)
            .send(packet)
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
                data_len: unimplemented!(),
                duration: last - first,
                packet_count: unimplemented!(),
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
        Iperf::result(self).map(|result| result.into())
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

impl tcp::SendBuf for PatternBuffer {
    fn available(&self) -> tcp::AvailableBytes {
        tcp::AvailableBytes {
            total: self.len - self.acked,
            fin: true,
        }
    }

    fn fill(&mut self, buf: &mut [u8], begin: TcpSeqNumber) {
        const HEAD: [u8; 4] = [0x80, 0x00, 0x00, 0x00];
        const DIGIT: [u8; 10] = *b"0123456789";

        let prev = self.at.expect("Fill must not be called before isn indication");
        let relative = begin - prev;

        let offset = (self.acked + relative) % 10;

        buf.iter_mut().fold(offset, |pattern, byte| {
            *byte = DIGIT[pattern];
            (pattern + 1) % 10
        });

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

impl<P: PayloadMut> udp::Send<P> for &'_ mut Connection {
    fn send(&mut self, packet: udp::RawPacket<P>) {
        let ts = packet.handle.info().timestamp();

        if self.packet_count > 0 {
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
        if self.packet_count == 0 {
            let source = packet.packet.get_ref().repr().src_addr();
            self.last_time = ts;
            self.send_init.source = ip::Source::Exact(source);
        }

        let count = self.packet_count;
        self.fill(packet.packet.payload_mut_slice(), ts, count);
        self.update_sent(ts);

        match packet.send() {
            Ok(()) => (),
            Err(_) => return self.error_shutdown(),
        }
    }
}

impl<P: PayloadMut> udp::Recv<P> for &'_ mut Connection {
    fn receive(&mut self, packet: udp::Packet<P>) {
        let repr = packet.packet.repr();
        if repr.dst_port != self.send_init.src_port {
            return;
        }

        let payload = packet.packet.payload_slice();

        if payload.len() <= 20 + mem::size_of::<Result>() {
            return;
        }

        let mem_result = &payload[20..][..mem::size_of::<Result>()];
        let be_result = unsafe { &*(mem_result.as_ptr() as *const Result) };

        self.result = Some(Result {
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
        });
    }
}

impl fmt::Display for Result {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Emulate the iperf style:
        //
        // ```text
        // [  3]  0.0- 1.0 sec   131 KBytes  1.05 Mbits/sec   0.000 ms    0/   91 (0%)
        // ```
        write!(f,
           "[{ts}] {begin}-{end} sec\t{total} KBytes\t{rate} Mbits/sec\t{dt} ms\t\
            {loss}/\t{packets} ({loss_percent})",
           ts=3,
           begin=0.0,
           end=1.0,
           total=self.data_len/1024,
           rate=(self.data_len as f32)/(self.delta_s as f32 + self.delta_ms as f32/1000.0),
           dt=0.0,
           loss=0,
           packets=self.packet_count,
           loss_percent=(0 as f32)/(self.packet_count as f32)*100.0,
        )
    }
}
