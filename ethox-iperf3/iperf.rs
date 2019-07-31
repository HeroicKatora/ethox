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

use ethox::layer::{ip, tcp, udp};
use ethox::managed::{List, Map, SlotMap};
use ethox::wire::{IpProtocol, PayloadMut, TcpSeqNumber};
use super::config::Iperf3Config;

pub struct Iperf3 {
    config: Iperf3Config,
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

/// The CreateStream handshake handler.
struct Handshake {
}

struct IperfSend {
}

struct IperfRecv {
}

impl Iperf3 {
    /// Create a new iperf3 client.
    pub fn new(config: &Iperf3Config) -> Self {
        Iperf3 {
            config: config.clone(),
            state: State::None,
            stream_handshake: Handshake { },
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

    fn generate_udp(config: &Iperf3Config) -> udp::Endpoint<'static> {
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
        let Iperf3Config::Client { host, port, bytes: _, } = config;
        tcp::Client::new((*host).into(), *port, IperfRecv::new(), IperfSend::new())
    }
}

impl IperfRecv {
    pub fn new() -> Self {
        unimplemented!()
    }
}

impl IperfSend {
    pub fn new() -> Self {
        unimplemented!()
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
        unimplemented!()
    }
}

impl tcp::SendBuf for IperfSend {
    fn available(&self) -> tcp::AvailableBytes {
        unimplemented!()
    }

    fn fill(&mut self, buf: &mut [u8], begin: TcpSeqNumber) {
        unimplemented!()
    }

    fn ack(&mut self, begin: TcpSeqNumber) {
        unimplemented!()
    }
}

impl tcp::RecvBuf for IperfRecv {
    fn receive(&mut self, buf: &[u8], segment: tcp::ReceivedSegment) {
        unimplemented!()
    }

    fn ack(&mut self) -> TcpSeqNumber {
        unimplemented!()
    }

    fn window(&self) -> usize {
        unimplemented!()
    }
}

impl fmt::Display for Result {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!()
    }
}
