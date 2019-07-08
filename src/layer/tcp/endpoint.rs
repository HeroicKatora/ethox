//! Contains main TCP handling.
//!
//! Relevant material for reading:
//! Main TCP rfc (skip if confident): https://tools.ietf.org/html/rfc793
//! Errata and comments: https://tools.ietf.org/html/rfc1122#section-4.2
//!     Notably still assuming some good-faith on hosts
//! TCP congestion control: https://tools.ietf.org/html/rfc5681
//! Attack avoidance: https://tools.ietf.org/html/rfc5961
//! Selective ACKs: https://tools.ietf.org/html/rfc2018
//! RST handling specifically: https://www.snellman.net/blog/archive/2016-02-01-tcp-rst/
//!     OS comparison in particular
use crate::managed::{Map, SlotMap, slotmap::Key};
use crate::time::{Duration, Instant};
use crate::wire::{IpAddress, TcpRepr, TcpSeqNumber};

/// Handles TCP connection states.
pub struct Endpoint<'a> {
    ports: Map<'a, FourTuple, Key>,
    states: SlotMap<'a, Slot>,
}

/// The state of a connection.
///
/// Includes current state machine state, the configuratin state that is required to stay constant
/// during a connection, and the in- and out-buffers.
#[derive(Clone, Copy, Debug, Hash)]
struct Connection {
    /// The current state of the state machine.
    current: State,

    /// The previous state of the state machine.
    ///
    /// Required to correctly reset the state in closing the connection at RST. It is necessary to
    /// track *how* we ended up forming a (half-open) connection.
    previous: State,

    /// The flow control mechanism.
    ///
    /// Currently hard coded as TCP Reno but practically could also be an enum when we find a
    /// suitable common interface.
    flow_control: NewReno,

    /// The indicated receive window (rcwd) of the other side.
    receive_window: u32,

    /// The SMSS is the size of the largest segment that the sender can transmit.
    ///
    /// This value can be based on the maximum transmission unit of the network, the path MTU
    /// discovery [RFC1191, RFC4821] algorithm, RMSS (see next item), or other factors.  The size
    /// does not include the TCP/IP headers and options.
    sender_maximum_segment_size: u32,

    /// The RMSS is the size of the largest segment the receiver is willing to accept.
    ///
    /// This is the value specified in the MSS option sent by the receiver during connection
    /// startup.  Or, if the MSS option is not used, it is 536 bytes [RFC1122].  The size does not
    /// include the TCP/IP headers and options.
    receiver_maximum_segment_size: u32,

    /// The received byte offset when the last ack was sent.
    ///
    /// We SHOULD wait at most 2*RMSS bytes before sending the next ack. There is also a time
    /// requirement, see `last_ack_time`.
    last_ack_receive_offset: TcpSeqNumber,

    /// The time when the last ack was sent.
    ///
    /// We MUST NOT wait more than 500ms before sending the ACK after receiving some new segment
    /// bytes. However, we CAN wait shorter, see `last_ack_timeout`.
    last_ack_time: Instant,

    /// Timeout before sending the next ACK after a new segment.
    ///
    /// For compliance with RFC1122 this MUST NOT be greater than 500ms but it could be smaller.
    last_ack_timeout: Duration,

    /// If we are permitted to use SACKs.
    ///
    /// This is true if the SYN packet allowed it in its options since we support it [WIP].
    selective_acknowledgements: bool,

    /// The sending state.
    ///
    /// In RFC793 this is referred to as `SND`.
    send: Send,


    /// The receiving state.
    ///
    /// In RFC793 this is referred to as `RCV`.
    recv: Receive,
}

#[derive(Clone, Copy, Debug, Hash)]
struct Send {
    /// The next not yet acknowledged sequence number.
    ///
    /// In RFC793 this is referred to as `SND.UNA`.
    unacked: TcpSeqNumber,

    /// The next sequence number to use for transmission.
    ///
    /// In RFC793 this is referred to as `SND.NXT`.
    next: TcpSeqNumber,

    /// The send window size indicated by the receiver.
    ///
    /// Must not send packet containing a sequence number beyond `unacked + window`. In RFC793 this
    /// is referred to as `SND.WND`.
    window: u32,

    /// The initial sequence number.
    ///
    /// This is read-only and only kept for potentially reading it for debugging later. It
    /// essentially provides a way of tracking the sent data. In RFC793 this is referred to as
    /// `ISS`.
    initial_seq: TcpSeqNumber,
}

#[derive(Clone, Copy, Debug, Hash)]
struct Receive {
    /// The next expected sequence number.
    ///
    /// In comparison the RFC validity checks are done with `acked` to implemented delayed ACKs but
    /// appear consistent to the outside. In RFC793 this is referred to as `RCV.NXT`.
    next: TcpSeqNumber,

    /// The actually acknowledged sequence number.
    ///
    /// Implementing delayed ACKs (not sending acks for every packet) this tracks what we have
    /// publicly announed as our `NXT` sequence. Validity checks of incoming packet should be done
    /// relative to this value instead of `next`. In Linux, this is called `wup`.
    acked: TcpSeqNumber,

    /// The receive window size indicated by us.
    ///
    /// Incoming packet containing a sequence number beyond `unacked + window`. In RFC793 this
    /// is referred to as `SND.WND`.
    window: u32,

    /// The initial receive sequence number.
    ///
    /// This is read-only and only kept for potentially reading it for debugging later. It
    /// essentially provides a way of tracking the sent data. In RFC793 this is referred to as
    /// `ISS`.
    initial_seq: TcpSeqNumber,
}

/// State enum of the statemachine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum State {
    /// Marker state fo an unintended/uninitialized connection state.
    Closed,

    /// A listening connection.
    ///
    /// Akin to an open server socket. Can either be turned into SynSent or SynReceived depending
    /// on whether we receive a SYN or decide to open a connection.
    Listen,

    /// An open connection request.
    SynSent,

    /// Connection request we intend to answer, waiting on ack.
    SynReceived,

    /// An open connection.
    Established,

    /// Closed our side of the connection.
    FinWait1,

    /// Closing connection nicely, initiated by us and acknowledged.
    FinWait2,

    /// Closed both sides but we don't know the other knows.
    Closing,

    /// Both sides recognized connection as closed.
    TimeWait,

    /// Other side closed its connection.
    CloseWait,

    /// Connection closed after other side closed its already.
    LastAck,
}

/// Models TCP NewReno flow control and congestion avoidance.
#[derive(Clone, Copy, Debug, Hash)]
struct NewReno {
    /// Decider between slow-start and congestion.
    ///
    /// Set to MAX initially, then updated on occurance of congestion.
    ssthresh: u32,

    /// The window dictated by congestion.
    congestion_window: u32,

    /// Sender side end flag to fast recover.
    ///
    /// When in fast recover, declares the sent sequent number that must be acknowledged to end
    /// fast recover. Initially set to the initial sequence number (ISS).
    recover: TcpSeqNumber,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct FourTuple {
    src: IpAddress,
    dst: IpAddress,
    src_port: u16,
    dst_port: u16,
}

/// A connection slot.
///
/// Can be used to open or accept a new connection. Usage of this acts similar to a slotmap where a
/// dedicated `SlotIndex` allows referring to a connection outside of its lifetime without
/// introducing lifetime-tracked references and dependencies.
#[derive(Clone, Copy, Debug, Hash)]
pub struct Slot {
    connection: Connection,
}

/// The index of a connection.
///
/// Useful for storing in other structs to reference the connection at another point in time. Note
/// that the index will be invalidated when the connection itself is closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SlotKey {
    key: Key,
}

/// Output signals of the model.
///
/// Private representation since they also influence handling of the state itself.
#[derive(Clone, Copy, Default, Debug)]
struct Signals {
    /// If the state should be deleted.
    delete: bool,
}

impl Endpoint<'_> {
    pub fn get_mut(&mut self, index: SlotKey)
        -> Option<&mut Slot>
    {
        self.states.get_mut(index.key)
    }

    pub fn get(&self, index: SlotKey)
        -> Option<&Slot>
    {
        self.states.get(index.key)
    }

    /// Opens a new port for listening.
    fn listen(&mut self, ip: IpAddress, port: u32)
        -> Option<SlotKey>
    {
        unimplemented!()
    }

    /// Actively try to connect to a remote TCP.
    fn open(&mut self, tuple: FourTuple)
        -> Option<SlotKey>
    {
        unimplemented!()
    }
}

impl Connection {
    pub fn arrives(&mut self, segment: TcpRepr) -> Signals {
        let mut signals = Signals::default();

        signals
    }
}

impl Default for State {
    fn default() -> Self {
        State::Closed
    }
}
