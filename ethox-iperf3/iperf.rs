//! Implements iperf3 protocol, a mix of tcp and udp.
//!
//! For the performance measurements we use tcp purely for the communication channel. This has two
//! reasons: flow control, retransmit, .. are unfinished and udp allows a strict direct control
//! over packet sizes in comparison iperf3 as well.
//!
//! The protocol is a binary-json-mix. After the initial connect, the server controls the protocol
//! state of the client by sending single-byte TCP messages (see `State`). Ultimately one of these
//! signals the client to start sending data. Rate limiting seems to be the client's responsibility
//! and it ends the transfer (which happens in a separate channel, i.e. UDP here) by sending a
//! state change message on the control channel. The server the invokes the exchange of results and
//! the client acknowledges when it has displayed them and terminates the connection.
use core::fmt;
use core::convert::TryFrom;

use ethox::layer::{ip, tcp, udp};
use ethox::managed::{List, Map, SlotMap};
use ethox::time::Instant;
use ethox::wire::{IpProtocol, PayloadMut, TcpSeqNumber};
use super::config::Iperf3Config;

pub struct Iperf3 {
    config: Config,
    state: State,
    stream_handshake: Handshake,
    udp: udp::Endpoint<'static>,
    tcp: tcp::Endpoint<'static>,
    control: tcp::Client<IperfRecv, IperfSend>,
    result: Option<Result>,
}

#[derive(Clone, Debug)]
pub struct Result {
}

/// State communication client to server and server to client.
#[allow(unused)]
#[repr(i8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum State {
    None = 0 /* not part of original */,
    TestStart = 1,
    TestRunning = 2,
    ResultRequest = 3 /* not used */,
    TestEnd = 4,
    StreamBegin = 5 /* not used */,
    StreamRunning = 6 /* not used */,
    StreamEnd = 7 /* not used */,
    AllStreamsEnd = 8 /* not used */,
    ParamExchange = 9,
    CreateStreams = 10,
    ServerTerminate = 11,
    ClientTerminate = 12,
    ExchangeResults = 13,
    DisplayResults = 14,
    IperfStart = 15,
    IperfDone = 16,
    AccessDenied = (-1),
    ServerError = (-2),
}

/// Private configuration representation.
struct Config {
    /// The size of each udp packet except the last, which may be smaller.
    block_size: usize,

    /// Number of unsent bytes.
    remaining: usize,
}

/// The CreateStream handshake handler.
struct Handshake {
    shaken: bool,
}

struct IperfSend {
    from: tcp::io::SendFrom<Vec<u8>>,
}

struct IperfRecv {
    into: tcp::io::RecvInto<Vec<u8>>,
}

impl Iperf3 {
    /// Create a new iperf3 client.
    pub fn new(config: &Iperf3Config) -> Self {
        Iperf3 {
            config: Config::new(config),
            state: State::None,
            stream_handshake: Handshake { shaken: false, },
            udp: Self::generate_udp(config),
            tcp: Self::generate_tcp(config),
            control: Self::generate_control(config),
            result: None,
        }
    }

    /// The result once it is ready (may be a failure).
    pub fn result(&self) -> Option<Result> {
        self.result.clone()
    }

    // Keep in mind: \ at line end deletes the leading whitespace of the next line.
    // This makes the json quite beautiful as long as we not forget to \ at east line end.

    const UDP_PARAM: &'static str = "{\
        \"udp\":true,\
        \"omit\":0,\
        \"time\":0,\
        \"num\":512000,\
        \"parallel\":1,\
        \"len\":32768,\
        \"bandwidth\":1048576,\
        \"pacing_timer\":1000,\
        \"client_version\":\"3.7\"\
    }";
    const DEFAULT_REPORT: &'static str = "{\
        \"cpu_util_total\":1.204690149406533,\
        \"cpu_util_user\":0.28167023919975259,\
        \"cpu_util_system\":0.92301991020678031,\
        \"sender_has_retransmits\":0,\
        \"streams\":[\
            {\
                \"id\":1,\
                \"bytes\":524288,\
                \"retransmits\":-1,\
                \"jitter\":0,\
                \"errors\":0,\
                \"packets\":16,\
                \"start_time\":0,\
                \"end_time\":3.750127\
            }\
        ]\
    }";
    const SERVER_REPORT: &'static str = "{\
        \"cpu_util_total\":0.020832187832532142,\
        \"cpu_util_user\":0,\
        \"cpu_util_system\":0.020832187832532142,\
        \"sender_has_retransmits\":-1,\
        \"streams\":[\
            {\
                \"id\":1,\
                \"bytes\":524288,\
                \"retransmits\":-1,\
                \"jitter\":1.3123676140911693e-05,\
                \"errors\":0,\
                \"packets\":16,\
                \"start_time\":0,\
                \"end_time\":3.750182\
            }\
        ]\
    }";

    fn generate_udp(config: &Iperf3Config) -> udp::Endpoint<'static> {
        // We only need a single connection entry.
        udp::Endpoint::new(vec![Default::default()])
    }

    fn generate_tcp(config: &Iperf3Config) -> tcp::Endpoint<'static> {
        // We only need a single connection entry.
        tcp::Endpoint::new(
            Map::Pairs(List::new(vec![Default::default()].into())),
            SlotMap::new(vec![Default::default()].into(), vec![Default::default()].into()),
            tcp::IsnGenerator::from_std_hash())
    }

    fn generate_control(config: &Iperf3Config) -> tcp::Client<IperfRecv, IperfSend> {
        let Iperf3Config::Client { host, port, .. } = config;
        tcp::Client::new((*host).into(), *port, IperfRecv::new(), IperfSend::new())
    }

    /// Fill the necessary part of the packet.
    fn fill(&mut self, packet: &mut [u8], time: Instant, count: u32) {
        let secs = time.secs() as u32;
        let millis = time.millis() as u32;
        assert!(packet.len() >= 12);
        packet[0..4].copy_from_slice(&secs.to_be_bytes());
        packet[4..8].copy_from_slice(&millis.to_be_bytes());
        packet[8..12].copy_from_slice(&count.to_be_bytes());
    }
}

impl Config {
    pub fn new(from: &Iperf3Config) -> Self {
        let Iperf3Config::Client {
            bytes,
            length,
            ..
        } = *from;
        assert!(length >= 12, "Udp block size too small, must be at least 12");
        // TODO: for tcp length is something entirely different.
        Config {
            block_size: length,
            remaining: bytes,
        }
    }
}

impl IperfRecv {
    pub fn new() -> Self {
        IperfRecv {
            into: tcp::io::RecvInto::new(vec![0; 1 << 12]),
        }
    }

    pub fn recv_state(&mut self) -> Option<State> {
        let s = self.into.received().get(0).copied()?;
        let state = State::try_from(s as i8)?;
        self.bump(1);
        Some(state)
    }

    /// Get a received json representation.
    pub fn get_json(&self) -> Option<&[u8]> {
        let recv = self.into.received();
        let len = self.get_json_len()?;
        let len = usize::try_from(len)
            .ok().expect("32-bit+ platforms only");
        recv.get(4..len+4)
    }

    pub fn get_json_len(&self) -> Option<u32> {
        let recv = self.into.received();
        let raw_len = recv.get(..4)?;
        let raw_len = <[u8; 4]>::try_from(raw_len)
            .unwrap();
        Some(u32::from_be_bytes(raw_len))
    }

    pub fn bump_json(&mut self) -> Option<()> {
        let len = self.get_json_len()? + 4;
        self.bump(len);
        Some(())
    }

    fn bump(&mut self, num: u32) {
        assert_eq!(num as usize as u32, num);
        self.into.bump_to(num as usize);
    }
}

impl IperfSend {
    pub fn new() -> Self {
        IperfSend {
            from: tcp::io::SendFrom::new(vec![0; 1 << 12]),
        }
    }

    /// Queue a state transition to send.
    pub fn send_state(&mut self, state: State) {
        self.from.get_mut().push(state as i8 as u8);
    }

    /// Queue json formatted data for sending.
    ///
    /// ## Panics
    /// This method panics if the data is longer than `u32::MAX`.
    pub fn send_json(&mut self, data: &[u8]) {
        let len = u32::try_from(data.len())
            .expect("json data too long");
        self.from.get_mut().extend_from_slice(&len.to_be_bytes());
    }
}

impl<P: PayloadMut> ip::Recv<P> for &'_ mut Iperf3 {
    fn receive(&mut self, packet: ip::InPacket<P>) {
        match packet.packet.repr().protocol() {
            IpProtocol::Tcp => self.tcp.recv(&mut self.control).receive(packet),
            // We want to receive a single packet on udp: When creating streams we get one from the
            // server. I don't even know yet if its content is important.
            IpProtocol::Udp if self.state == State::CreateStreams =>
                self.udp.recv(&mut self.stream_handshake).receive(packet),
            _ => (),
        }
    }
}

impl<P: PayloadMut> ip::Send<P> for &'_ mut Iperf3 {
    fn send(&mut self, packet: ip::RawPacket<P>) {
        unimplemented!()
    }
}

impl<P: PayloadMut> udp::Recv<P> for &'_ mut Handshake {
    fn receive(&mut self, packet: udp::Packet<P>) {
        if packet.packet.repr().dst_port == 0 {
            self.shaken = true;
        }
    }
}

impl tcp::SendBuf for IperfSend {
    fn available(&self) -> tcp::AvailableBytes {
        self.from.available()
    }

    fn fill(&mut self, buf: &mut [u8], begin: TcpSeqNumber) {
        self.from.fill(buf, begin)
    }

    fn ack(&mut self, begin: TcpSeqNumber) {
        self.from.ack(begin)
    }
}

impl tcp::RecvBuf for IperfRecv {
    fn receive(&mut self, buf: &[u8], segment: tcp::ReceivedSegment) {
        self.into.receive(buf, segment)
    }

    fn ack(&mut self) -> TcpSeqNumber {
        self.into.ack()
    }

    fn window(&self) -> usize {
        self.into.window()
    }
}

impl fmt::Display for Result {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!()
    }
}

impl State {
    fn try_from(s: i8) -> Option<Self> {
        Some(match s {
            0 => State::None,
            1 => State::TestStart,
            2 => State::TestRunning,
            3 => State::ResultRequest,
            4 => State::TestEnd,
            5 => State::StreamBegin,
            6 => State::StreamRunning,
            7 => State::StreamEnd,
            8 => State::AllStreamsEnd,
            9 => State::ParamExchange,
            10 => State::CreateStreams,
            11 => State::ServerTerminate,
            12 => State::ClientTerminate,
            13 => State::ExchangeResults,
            14 => State::DisplayResults,
            15 => State::IperfStart,
            16 => State::IperfDone,
            -1 => State::AccessDenied,
            -2 => State::ServerError,
            _ => return None,
        })
    }
}
