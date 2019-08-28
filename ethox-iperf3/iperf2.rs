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
use ethox::layer::{ip, udp, Error};
use ethox::time::Instant;
use ethox::wire::{Ipv4Subnet, PayloadMut};
use super::config::Iperf3Config;

pub struct Iperf {
    connection: Connection,
    udp: udp::Endpoint<'static>,
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
}

impl Iperf {
    pub fn new(config: &Iperf3Config) -> Self {
        Iperf {
            connection: Connection::new(config),
            udp: Self::generate_udp(config),
        }
    }

    pub fn result(&self) -> Option<()> {
        if self.connection.remaining == 0 {
            Some(())
        } else {
            None
        }
    }

    fn generate_udp(_: &Iperf3Config) -> udp::Endpoint<'static> {
        // We only need a single connection entry.
        udp::Endpoint::new(vec![Default::default()])
    }
}

impl Connection {
    fn new(config: &Iperf3Config) -> Self {
        let Iperf3Config::Client {
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
        }
    }

    fn generate_udp_init(config: &Iperf3Config) -> udp::Init {
        let Iperf3Config::Client { host, port, bytes, ..  } = config;

        udp::Init {
            source: ip::Source::Mask {
                subnet: Ipv4Subnet::ANY.into(),
            },
            src_port: 50020,
            dst_addr: (*host).into(),
            dst_port: *port,
            payload: *bytes,
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

impl<P: PayloadMut> ip::Send<P> for &'_ mut Iperf {
    fn send(&mut self, packet: ip::RawPacket<P>) {
        self.udp
            .send(&mut self.connection)
            .send(packet)
    }
}

impl<P: PayloadMut> ip::Recv<P> for &'_ mut Iperf {
    fn receive(&mut self, _: ip::InPacket<P>) {
        // Do nothing ...
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
