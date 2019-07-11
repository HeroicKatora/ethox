use crate::time::{Duration, Instant};
use crate::wire::{IpAddress, TcpFlags, TcpRepr, TcpSeqNumber};

use super::endpoint::{
    Entry,
    EntryKey,
    FourTuple,
    SlotKey};

/// The state of a connection.
///
/// Includes current state machine state, the configuratin state that is required to stay constant
/// during a connection, and the in- and out-buffers.
#[derive(Clone, Copy, Debug, Hash)]
pub struct Connection {
    /// The current state of the state machine.
    pub current: State,

    /// The previous state of the state machine.
    ///
    /// Required to correctly reset the state in closing the connection at RST. It is necessary to
    /// track *how* we ended up forming a (half-open) connection.
    pub previous: State,

    /// The flow control mechanism.
    ///
    /// Currently hard coded as TCP Reno but practically could also be an enum when we find a
    /// suitable common interface.
    pub flow_control: NewReno,

    /// The indicated receive window (rcwd) of the other side.
    pub receive_window: u32,

    /// The SMSS is the size of the largest segment that the sender can transmit.
    ///
    /// This value can be based on the maximum transmission unit of the network, the path MTU
    /// discovery [RFC1191, RFC4821] algorithm, RMSS (see next item), or other factors.  The size
    /// does not include the TCP/IP headers and options.
    pub sender_maximum_segment_size: u32,

    /// The RMSS is the size of the largest segment the receiver is willing to accept.
    ///
    /// This is the value specified in the MSS option sent by the receiver during connection
    /// startup.  Or, if the MSS option is not used, it is 536 bytes [RFC1122].  The size does not
    /// include the TCP/IP headers and options.
    pub receiver_maximum_segment_size: u32,

    /// The received byte offset when the last ack was sent.
    ///
    /// We SHOULD wait at most 2*RMSS bytes before sending the next ack. There is also a time
    /// requirement, see `last_ack_time`.
    pub last_ack_receive_offset: TcpSeqNumber,

    /// The time when the last ack was sent.
    ///
    /// We MUST NOT wait more than 500ms before sending the ACK after receiving some new segment
    /// bytes. However, we CAN wait shorter, see `last_ack_timeout`.
    pub last_ack_time: Instant,

    /// Timeout before sending the next ACK after a new segment.
    ///
    /// For compliance with RFC1122 this MUST NOT be greater than 500ms but it could be smaller.
    pub last_ack_timeout: Duration,

    /// If we are permitted to use SACKs.
    ///
    /// This is true if the SYN packet allowed it in its options since we support it [WIP].
    pub selective_acknowledgements: bool,

    /// The sending state.
    ///
    /// In RFC793 this is referred to as `SND`.
    pub send: Send,


    /// The receiving state.
    ///
    /// In RFC793 this is referred to as `RCV`.
    pub recv: Receive,
}

#[derive(Clone, Copy, Debug, Hash)]
pub struct Send {
    /// The next not yet acknowledged sequence number.
    ///
    /// In RFC793 this is referred to as `SND.UNA`.
    pub unacked: TcpSeqNumber,

    /// The next sequence number to use for transmission.
    ///
    /// In RFC793 this is referred to as `SND.NXT`.
    pub next: TcpSeqNumber,

    /// The send window size indicated by the receiver.
    ///
    /// Must not send packet containing a sequence number beyond `unacked + window`. In RFC793 this
    /// is referred to as `SND.WND`.
    pub window: u32,

    /// The initial sequence number.
    ///
    /// This is read-only and only kept for potentially reading it for debugging later. It
    /// essentially provides a way of tracking the sent data. In RFC793 this is referred to as
    /// `ISS`.
    pub initial_seq: TcpSeqNumber,
}

#[derive(Clone, Copy, Debug, Hash)]
pub struct Receive {
    /// The next expected sequence number.
    ///
    /// In comparison the RFC validity checks are done with `acked` to implemented delayed ACKs but
    /// appear consistent to the outside. In RFC793 this is referred to as `RCV.NXT`.
    pub next: TcpSeqNumber,

    /// The actually acknowledged sequence number.
    ///
    /// Implementing delayed ACKs (not sending acks for every packet) this tracks what we have
    /// publicly announed as our `NXT` sequence. Validity checks of incoming packet should be done
    /// relative to this value instead of `next`. In Linux, this is called `wup`.
    pub acked: TcpSeqNumber,

    /// The receive window size indicated by us.
    ///
    /// Incoming packet containing a sequence number beyond `unacked + window`. In RFC793 this
    /// is referred to as `SND.WND`.
    pub window: u32,

    /// The initial receive sequence number.
    ///
    /// This is read-only and only kept for potentially reading it for debugging later. It
    /// essentially provides a way of tracking the sent data. In RFC793 this is referred to as
    /// `ISS`.
    pub initial_seq: TcpSeqNumber,
}

/// State enum of the statemachine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
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
pub struct NewReno {
    /// Decider between slow-start and congestion.
    ///
    /// Set to MAX initially, then updated on occurance of congestion.
    pub ssthresh: u32,

    /// The window dictated by congestion.
    pub congestion_window: u32,

    /// Sender side end flag to fast recover.
    ///
    /// When in fast recover, declares the sent sequent number that must be acknowledged to end
    /// fast recover. Initially set to the initial sequence number (ISS).
    pub recover: TcpSeqNumber,
}

/// Output signals of the model.
///
/// Private representation since they also influence handling of the state itself.
#[derive(Clone, Copy, Default, Debug)]
pub struct Signals {
    /// If the state should be deleted.
    delete: bool,

    /// Need to send some tcp answer.
    ///
    /// Since TCP must assume every packet to be potentially lost it is likely technically fine
    /// *not* to actually send the packet. In particular you could probably advance the internal
    /// state without acquiring packets to send out. This, however, sounds like a very bad idea.
    answer: Option<TcpRepr>,
}

/// An internal, lifetime erased trait for controlling connections of an `Endpoint`.
///
/// This decouples the required interface for a packet from the implementation details of
/// `Endpoint` which are the user-facing interaction points. Partially necessary since we don't
/// want to expose the endpoint's lifetime to the packet handler but also to establish a somewhat
/// cleaner boundary.
pub trait Endpoint {
    fn get(&self, index: SlotKey) -> Option<&Connection>;

    fn get_mut(&mut self, index: SlotKey) -> Option<&mut Connection>;

    fn entry(&mut self, index: SlotKey) -> Option<Entry>;

    fn listen(&mut self, ip: IpAddress, port: u16) -> Option<SlotKey>;

    fn open(&mut self, tuple: FourTuple) -> Option<SlotKey>;

    fn initial_seq_num(&mut self, id: FourTuple, time: Instant) -> TcpSeqNumber;
}

/// The interface to a single active connection on an endpoint.
pub struct Operator<'a> {
    endpoint: &'a mut Endpoint,
    connection_key: SlotKey,
}

impl Connection {
    pub fn arrives(&mut self, segment: TcpRepr, entry: EntryKey, time: Instant) -> Signals {
        match self.current {
            State::Closed => self.arrives_closed(segment),
            State::Listen => self.arrives_listen(segment, entry, time),
            State::Established => self.arrives_established(segment),
            _ => unimplemented!(),
        }
    }

    /// Answers packets on closed sockets with resets.
    ///
    /// Except when an RST flag is already set on the received packet. Probably the easiest packet
    /// flow.
    fn arrives_closed(&mut self, segment: TcpRepr) -> Signals {
        let mut signals = Signals::default();
        if segment.flags.rst() {
            // Avoid answering with RST when packet has RST set.
            // TODO: debug counters or tracing
            return signals;
        }

        if let Some(ack_number) = segment.ack_number {
            signals.answer = Some(TcpRepr {
                src_port: segment.dst_port,
                dst_port: segment.src_port,
                flags: {
                    let mut flags = TcpFlags::default();
                    flags.set_ack(true);
                    flags.set_rst(true);
                    flags
                },
                seq_number: ack_number,
                ack_number: None,
                window_len: 0,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None; 3],
                payload_len: 0,
            })
        } else {
            signals.answer = Some(TcpRepr {
                src_port: segment.dst_port,
                dst_port: segment.src_port,
                flags: {
                    let mut flags = TcpFlags::default();
                    flags.set_rst(true);
                    flags
                },
                seq_number: TcpSeqNumber(0),
                ack_number: Some(segment.seq_number + segment.sequence_len()),
                window_len: 0,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None; 3],
                payload_len: 0,
            })
        }

        return signals;
    }

    fn arrives_listen(&mut self, segment: TcpRepr, entry: EntryKey, time: Instant)
        -> Signals
    {
        let mut signals = Signals::default();
        if segment.flags.rst() {
            return signals;
        }

        if let Some(ack_number) = segment.ack_number { // What are you acking? A previous connection.
            signals.answer = Some(TcpRepr {
                src_port: segment.dst_port,
                dst_port: segment.src_port,
                flags: {
                    let mut flags = TcpFlags::default();
                    flags.set_ack(true);
                    flags.set_rst(true);
                    flags
                },
                seq_number: ack_number,
                ack_number: None,
                window_len: 0,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None; 3],
                payload_len: 0,
            });
            return signals;
        }

        if !segment.flags.syn() {
            // Doesn't have any useful flags. Why was this even sent?
            return signals;
        }

        unimplemented!("Change and setup connection four tuple (for isn also)");

        self.recv.next = segment.seq_number + 1;
        self.recv.initial_seq = segment.seq_number;

        let isn = entry.initial_seq_num(time);
        self.send.next = isn + 1;
        self.send.unacked = isn;
        self.send.initial_seq = isn;

        signals.answer = Some(TcpRepr {
            src_port: segment.dst_port,
            dst_port: segment.src_port,
            flags: {
                let mut flags = TcpFlags::default();
                flags.set_ack(true);
                flags.set_rst(true);
                flags
            },
            seq_number: isn,
            ack_number: Some(self.recv.next),
            window_len: 0,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            payload_len: 0,
        });

        signals
    }

    fn arrives_established(&mut self, segment: TcpRepr) -> Signals {
        unimplemented!()
    }
}

impl Operator<'_> {
    pub fn key(&self) -> SlotKey {
        self.connection_key
    }
}

impl<'a> Operator<'a> {
    /// Operate some connection.
    ///
    /// This returns `None` if the key does not refer to an existing connection.
    pub fn new(endpoint: &'a mut Endpoint, key: SlotKey) -> Option<Self> {
        let _ = endpoint.get(key)?;
        Some(Operator {
            endpoint,
            connection_key: key,
        })
    }

    pub fn arrives(&mut self, segment: TcpRepr, time: Instant) -> Signals {
        let (entry_key, connection) = self.entry().into_key_value();
        connection.arrives(segment, entry_key, time)
    }

    fn entry(&mut self) -> Entry {
        self.endpoint.entry(self.connection_key).unwrap()
    }
}

impl Default for State {
    fn default() -> Self {
        State::Closed
    }
}
