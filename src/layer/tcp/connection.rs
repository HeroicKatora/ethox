use core::convert::TryFrom;
use core::ops::Range;
use crate::time::{Duration, Expiration, Instant};
use crate::wire::{IpAddress, TcpFlags, TcpRepr, TcpSeqNumber};

use super::endpoint::{
    Entry,
    EntryKey,
    FourTuple,
    Slot,
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
    pub flow_control: Flow,

    /// The indicated receive window (rcwd) of the other side.
    pub receive_window: u32,

    /// The SMSS is the size of the largest segment that the sender can transmit.
    ///
    /// This value can be based on the maximum transmission unit of the network, the path MTU
    /// discovery [RFC1191, RFC4821] algorithm, RMSS (see next item), or other factors.  The size
    /// does not include the TCP/IP headers and options.
    pub sender_maximum_segment_size: u16,

    /// The RMSS is the size of the largest segment the receiver is willing to accept.
    ///
    /// This is the value specified in the MSS option sent by the receiver during connection
    /// startup.  Or, if the MSS option is not used, it is 536 bytes [RFC1122].  The size does not
    /// include the TCP/IP headers and options.
    pub receiver_maximum_segment_size: u16,

    /// The received byte offset when the last ack was sent.
    ///
    /// We SHOULD wait at most 2*RMSS bytes before sending the next ack. There is also a time
    /// requirement, see `last_ack_time`.
    pub last_ack_receive_offset: TcpSeqNumber,

    /// The time when the next ack must be sent.
    ///
    /// We MUST NOT wait more than 500ms before sending the ACK after receiving some new segment
    /// bytes. However, we CAN wait shorter, see `ack_timeout`.
    pub ack_timer: Expiration,

    /// Timeout before sending the next ACK after a new segment.
    ///
    /// For compliance with RFC1122 this MUST NOT be greater than 500ms but it could be smaller.
    pub ack_timeout: Duration,

    /// When to start retransmission and/or detect a loss.
    pub retransmission_timer: Instant,

    /// The duration of the retransmission timer.
    pub retransmission_timeout: Duration,

    /// Timeout of no packets in either direction after which restart is used.
    ///
    /// This will only occur if no data is to be transmitted in either direction as otherwise we
    /// would try sending or receive at least recovery packets. Well, the user could not have
    /// called us for a very long time but then this is also fine.
    pub restart_timeout: Duration,

    /// If we are permitted to use SACKs.
    ///
    /// This is true if the SYN packet allowed it in its options since we support it [WIP].
    pub selective_acknowledgements: bool,

    /// Counter of duplicated acks.
    pub duplicate_ack: u8,

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

    /// The time of the last valid packet.
    pub last_time: Instant,

    /// Number of bytes available for sending in total.
    ///
    /// In contrast to `unacked` this is the number of bytes that have not yet been sent. The
    /// driver will update this number prior to sending or receiving packets so that an optimal
    /// answer packet can be determined.
    pub unsent: usize,

    /// The send window size indicated by the receiver.
    ///
    /// Must not send packet containing a sequence number beyond `unacked + window`. In RFC793 this
    /// is referred to as `SND.WND`.
    pub window: u16,

    /// The window scale parameter.
    ///
    /// Guaranteed to be at most 14 so that shifting the window in a `u32`/`i32` is always safe.
    pub window_scale: u8,

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

    /// The time the last segment was sent.
    pub last_time: Instant,

    /// The receive window size indicated by us.
    ///
    /// Incoming packet containing a sequence number beyond `unacked + window`. In RFC793 this
    /// is referred to as `SND.WND`.
    pub window: u16,

    /// The window scale parameter.
    ///
    /// Guaranteed to be at most 14 so that shifting the window in a `u32`/`i32` is always safe.
    pub window_scale: u8,

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

/// Models TCP Reno flow control and congestion avoidance.
#[derive(Clone, Copy, Debug, Hash)]
pub struct Flow {
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
#[must_use = "Doesn't do anything on its own, make sure any answer is actually sent."]
pub struct Signals {
    /// If the state should be deleted.
    pub delete: bool,

    /// The user should be notified of this reset connection.
    pub reset: bool,

    /// There is valid data in the packet to receive.
    pub receive: bool,

    /// Whether the Operator could send data.
    pub may_send: bool,

    /// Need to send some tcp answer.
    ///
    /// Since TCP must assume every packet to be potentially lost it is likely technically fine
    /// *not* to actually send the packet. In particular you could probably advance the internal
    /// state without acquiring packets to send out. This, however, sounds like a very bad idea.
    pub answer: Option<TcpRepr>,
}

/// An ingoing communication.
#[derive(Debug)]
pub struct InPacket {
    /// Metadata of the tcp layer packet.
    pub segment: TcpRepr,

    /// The sender address.
    pub from: IpAddress,

    /// The arrival time of the packet at the nic.
    pub time: Instant,
}

#[derive(Debug)]
pub struct Segment {
    /// Representation for the packet.
    pub repr: TcpRepr,

    /// Range of the data within the (re-)transmit buffer.
    pub range: Range<usize>,
}

/// An internal, lifetime erased trait for controlling connections of an `Endpoint`.
///
/// This decouples the required interface for a packet from the implementation details of
/// `Endpoint` which are the user-facing interaction points. Partially necessary since we don't
/// want to expose the endpoint's lifetime to the packet handler but also to establish a somewhat
/// cleaner boundary.
pub trait Endpoint {
    fn get(&self, index: SlotKey) -> Option<&Slot>;

    fn get_mut(&mut self, index: SlotKey) -> Option<&mut Slot>;

    fn entry(&mut self, index: SlotKey) -> Option<Entry>;

    fn find_tuple(&mut self, tuple: FourTuple) -> Option<Entry>;

    fn source_port(&mut self, addr: IpAddress) -> Option<u16>;

    fn listen(&mut self, ip: IpAddress, port: u16) -> Option<SlotKey>;

    fn open(&mut self, tuple: FourTuple) -> Option<SlotKey>;

    fn initial_seq_num(&mut self, id: FourTuple, time: Instant) -> TcpSeqNumber;
}

/// The interface to a single active connection on an endpoint.
pub(crate) struct Operator<'a> {
    pub endpoint: &'a mut Endpoint,
    pub connection_key: SlotKey,
}

/// Internal return determining how a received ack is handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AckUpdate {
    TooLow,
    Duplicate,
    Updated {
        new_bytes: u32
    },
    Unsent,
}

/// Tcp repr without the connection meta data.
#[derive(Clone, Copy, Debug)]
struct InnerRepr {
    flags:        TcpFlags,
    seq_number:   TcpSeqNumber,
    ack_number:   Option<TcpSeqNumber>,
    window_len:   u16,
    window_scale: Option<u8>,
    max_seg_size: Option<u16>,
    sack_permitted: bool,
    sack_ranges:  [Option<(u32, u32)>; 3],
    payload_len:  u16,
}

impl Connection {
    /// Construct a closed connection with zeroed state.
    pub fn zeroed() -> Self {
        Connection {
            current: State::Closed,
            previous: State::Closed,
            flow_control: Flow {
                ssthresh: 0,
                congestion_window: 0,
                recover: TcpSeqNumber::default(),
            },
            receive_window: 0,
            sender_maximum_segment_size: 0,
            receiver_maximum_segment_size: 0,
            last_ack_receive_offset: TcpSeqNumber::default(),
            ack_timer: Expiration::Never,
            ack_timeout: Duration::from_millis(0),
            retransmission_timer: Instant::from_millis(0),
            retransmission_timeout: Duration::from_millis(0),
            restart_timeout: Duration::from_millis(0),
            selective_acknowledgements: false,
            duplicate_ack: 0,
            send: Send {
                unacked: TcpSeqNumber::default(),
                next: TcpSeqNumber::default(),
                last_time: Instant::from_millis(0),
                unsent: 0,
                window: 0,
                window_scale: 0,
                initial_seq: TcpSeqNumber::default(),
            },
            recv: Receive {
                next: TcpSeqNumber::default(),
                acked: TcpSeqNumber::default(),
                last_time: Instant::from_millis(0),
                window: 0,
                window_scale: 0,
                initial_seq: TcpSeqNumber::default(),
            },
        }
    }

    pub fn arrives(&mut self, incoming: &InPacket, entry: EntryKey) -> Signals {
        match self.current {
            State::Closed => self.arrives_closed(incoming),
            State::Listen => self.arrives_listen(incoming, entry),
            State::SynSent => self.arrives_syn_sent(incoming, entry),
            State::Established => self.arrives_established(incoming, entry),
            _ => unimplemented!(),
        }
    }

    pub fn open(&mut self, time: Instant, entry: EntryKey) -> Option<TcpRepr> {
        match self.current {
            State::Closed | State::Listen => (),
            _ => return None,
        }

        self.change_state(State::SynSent);
        self.send.initial_seq = entry.initial_seq_num(time);
        self.send.unacked = self.send.initial_seq;
        self.send.next = self.send.initial_seq + 1;

        Some(self.send_open(entry.four_tuple()))
    }

    /// Answers packets on closed sockets with resets.
    ///
    /// Except when an RST flag is already set on the received packet. Probably the easiest packet
    /// flow.
    fn arrives_closed(&mut self, incoming: &InPacket) -> Signals {
        let segment = &incoming.segment;
        let mut signals = Signals::default();
        if segment.flags.rst() {
            // Avoid answering with RST when packet has RST set.
            // TODO: debug counters or tracing
            return signals;
        }

        if let Some(ack_number) = segment.ack_number {
            signals.answer = Some(InnerRepr {
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
            }.send_back(segment));
        } else {
            signals.answer = Some(InnerRepr {
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
            }.send_back(segment));
        }

        return signals;
    }

    fn arrives_listen(&mut self, incoming: &InPacket, mut entry: EntryKey)
        -> Signals
    {
        let InPacket { segment, from, time, } = incoming;
        let mut signals = Signals::default();

        if segment.flags.rst() {
            return signals;
        }

        if let Some(ack_number) = segment.ack_number { // What are you acking? A previous connection.
            signals.answer = Some(InnerRepr {
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
            }.send_back(segment));
            return signals;
        }

        if !segment.flags.syn() {
            // Doesn't have any useful flags. Why was this even sent?
            return signals;
        }

        let current_four = entry.four_tuple();
        let new_four = FourTuple {
            remote: *from,
            .. current_four
        };
        entry.set_four_tuple(new_four);
        self.recv.next = segment.seq_number + 1;
        self.recv.initial_seq = segment.seq_number;

        let isn = entry.initial_seq_num(*time);
        self.send.next = isn + 1;
        self.send.unacked = isn;
        self.send.initial_seq = isn;

        signals.answer = Some(InnerRepr {
            flags: {
                let mut flags = TcpFlags::default();
                flags.set_ack(true);
                flags.set_rst(true);
                flags
            },
            seq_number: isn,
            ack_number: Some(self.ack_all()),
            window_len: self.recv.window,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            payload_len: 0,
        }.send_to(new_four));

        signals
    }

    fn arrives_syn_sent(&mut self, incoming: &InPacket, entry: EntryKey)
        -> Signals
    {
        let InPacket { segment, from, time, } = incoming;

        if let Some(ack) = segment.ack_number {
            if ack <= self.send.initial_seq || ack > self.send.next {
                if segment.flags.rst() { // Discard the segment
                    return Signals::default();
                }

                // Packet out of window. Send a RST with fitting sequence number.
                let mut signals = Signals::default();
                signals.answer = Some(InnerRepr {
                    flags: {
                        let mut flags = TcpFlags::default();
                        flags.set_rst(true);
                        flags
                    },
                    seq_number: ack,
                    ack_number: None,
                    window_len: 0,
                    window_scale: None,
                    max_seg_size: None,
                    sack_permitted: false,
                    sack_ranges: [None; 3],
                    payload_len: 0,
                }.send_back(segment));
                return signals;
            }
        }

        if segment.flags.rst() {
            // Can only reset the connection if you ack the SYN.
            if segment.ack_number.is_none() {
                return Signals::default();
            }

            return self.forced_close_by_reset();
        }

        if !segment.flags.syn() {
            // No control flags at all.
            return Signals::default();
        }

        self.recv.initial_seq = segment.seq_number;
        self.recv.next = segment.seq_number + 1;
        self.send.window = segment.window_len;
        self.send.window_scale = segment.window_scale.unwrap_or(0);

        // TODO: better mss
        self.sender_maximum_segment_size = segment.max_seg_size
            .unwrap_or(536)
            .max(536);
        self.receiver_maximum_segment_size = self.sender_maximum_segment_size;

        if let Some(ack) = segment.ack_number {
            self.send.unacked = ack;
        }

        // The SYN didn't actually ack our SYN. So change to SYN-RECEIVED.
        if self.send.unacked == self.send.initial_seq {
            self.change_state(State::SynReceived);

            let mut signals = Signals::default();
            signals.answer = Some(InnerRepr {
                flags: {
                    let mut flags = TcpFlags::default();
                    flags.set_syn(true);
                    flags
                },
                seq_number: self.send.initial_seq,
                ack_number: Some(self.ack_all()),
                window_len: self.recv.window,
                window_scale: Some(self.send.window_scale),
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None; 3],
                payload_len: 0,
            }.send_to(entry.four_tuple()));
            return signals;
        }

        self.change_state(State::Established);
        // The rfc would immediately ack etc. We may want to send data and that requires the
        // cooperation of io. Defer but mark as ack required immediately.
        self.ack_timer = Expiration::When(*time);
        return Signals::default();
    }

    fn arrives_established(&mut self, incoming: &InPacket, entry: EntryKey) -> Signals {
        // TODO: time for RTT estimation, ...
        let InPacket { segment, from, time: _, } = incoming;

        let acceptable = self.ingress_acceptable(segment);

        if !acceptable {
            if segment.flags.rst() {
                return self.forced_close_by_reset();
            }

            // TODO: find out why this triggers in a nice tcp connection (python -m http.server)
            let mut signals = Signals::default();
            signals.answer = Some(InnerRepr {
                flags: TcpFlags::default(),
                seq_number: self.send.next,
                ack_number: Some(self.recv.next),
                window_len: 0,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None; 3],
                payload_len: 0,
            }.send_to(entry.four_tuple()));
            return signals;
        }

        if segment.flags.syn() {
            debug_assert!(self.recv.in_window(segment.seq_number));

            // This is not acceptable, reset the connection.
            return self.force_close(segment, entry);
        }

        let ack = match segment.ack_number {
            // Not good, but not bad either.
            None => return Signals::default(),
            Some(ack) => ack,
        };

        match self.send.incoming_ack(ack) {
            AckUpdate::Unsent => {
                // That acked something we hadn't sent yet. A madlad at the other end.
                // Ignore the packet but we ack back the previous state.
                let mut signals = Signals::default();
                signals.answer = Some(InnerRepr {
                    flags: TcpFlags::default(),
                    seq_number: self.send.next,
                    ack_number: Some(self.recv.next),
                    window_len: 0,
                    window_scale: None,
                    max_seg_size: None,
                    sack_permitted: false,
                    sack_ranges: [None; 3],
                    payload_len: 0,
                }.send_to(entry.four_tuple()));

                return signals;
            },
            AckUpdate::Duplicate => {
                self.duplicate_ack = self.duplicate_ack.saturating_add(1);
            },
            // This is a reordered packet, potentially an attack. Do nothing.
            AckUpdate::TooLow => (),
            AckUpdate::Updated { new_bytes } => {
                self.send.window = segment.window_len;
                self.window_update(segment, new_bytes);
            },
        }

        // URG lol

        // Actually accept the segment data. Note that we do not control the receive buffer
        // ourselves but rather only know the precise buffer lengths at this point. Also, the
        // window we indicated to the remote may not reflect exactly what we can actually accept.
        // Furthermore, we a) want to piggy-back data on the ACK to reduce the number of packet
        // sent and b) may want to delay ACKs as given by data in flight and RTT considerations
        // such as RFC1122. Thus, we merely signal the precence of available data to the operator
        // above.
        let mut signals = Signals::default();
        signals.receive = true;
        signals
    }

    /// Determine if a packet should be deemed acceptable on an open connection.
    ///
    /// See: https://tools.ietf.org/html/rfc793#page-40
    fn ingress_acceptable(&self, repr: &TcpRepr) -> bool {
        match (self.recv.window, repr.payload_len) {
            (0, 0) => repr.seq_number == self.recv.next,
            (0, _) => self.recv.in_window(repr.seq_number),
            (_, 0) => false,
            (_, _) => self.recv.in_window(repr.seq_number)
                || self.recv.in_window(repr.seq_number + repr.payload_len.into() - 1),
        }
    }

    /// Close from an incoming reset.
    ///
    /// This shared logic is used by some states on receiving a packet with RST set.
    fn forced_close_by_reset(&mut self) -> Signals {
        self.change_state(State::Closed);

        let mut signals = Signals::default();
        signals.reset = true;
        signals.delete = true;
        return signals;
    }

    /// Close due to invalid incoming packet.
    ///
    /// As opposed to `forced_close_by_reset` this one is proactive and we send the RST.
    fn force_close(&mut self, segment: &TcpRepr, entry: EntryKey) -> Signals {
        self.change_state(State::Closed);

        let mut signals = Signals::default();
        signals.reset = true;
        signals.delete = true;
        signals.answer = Some(InnerRepr {
            flags: {
                let mut flags = TcpFlags::default();
                flags.set_rst(true);
                flags
            },
            seq_number: self.send.next,
            ack_number: Some(self.ack_all()),
            window_len: 0,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            payload_len: 0,
        }.send_to(entry.four_tuple()));
        signals
    }

    fn send_open(&mut self, to: FourTuple) -> TcpRepr {
        InnerRepr {
            flags: {
                let mut flags = TcpFlags::default();
                flags.set_syn(true);
                flags
            },
            seq_number: self.send.initial_seq,
            ack_number: None,
            window_len: 0,
            window_scale: Some(self.send.window_scale),
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            payload_len: 0,

        }.send_to(to)
    }

    /// Choose a next data segment to send.
    ///
    /// May choose to send an empty range for cases where there is no data to send but a delayed
    /// ACK is expected.
    pub fn next_send_segment(&mut self, available: usize, time: Instant, entry: EntryKey)
        -> Option<Segment>
    {
        // Convert the input to `u32`, our window can never be that large anyways.
        let available = u32::try_from(available)
            .ok().unwrap_or_else(u32::max_value);
        // Connection restarted after idle time.
        let last_time = self.recv.last_time.max(self.send.last_time);
        if time > last_time + self.restart_timeout {
            self.flow_control.congestion_window = self.restart_window();
        }

        if self.duplicate_ack >= 2 {
            // Fast retransmit?
            //
            // this would be a return path but just don't do anything atm.
        }

        if self.retransmission_timer > time {
            // Choose segments to retransmit:
            return unimplemented!();
        }

        let window = self.send.window();
            // .min(self.flow_control.congestion_window);
        let sent = self.send.in_flight();
        let max_sent = window.min(available);

        // TODO: may want to buffer. But that could be done in the upper `SendBuf` as well.
        // Probably even the better place as its more immediately accessible to the user.
        if sent < max_sent {
            // Send one new segment of new data.
            let end = sent.saturating_add(self.sender_maximum_segment_size.into()).min(max_sent);
            // UNWRAP: Available was larger than `end` so these will not fail (even on 16-bit
            // platforms where the buffer may be smaller than the `u32` window). Math:
            // `sent_u32 <= end_u32 <= available_u32 <= available_usize`
            let sent = usize::try_from(sent).unwrap();
            let end = usize::try_from(end).unwrap();
            let range = sent..end;
            assert!(range.len() > 0);

            let seq_number = self.send.next;
            self.send.next = self.send.next + range.len();
            return Some(Segment {
                repr: InnerRepr {
                    seq_number,
                    flags: TcpFlags::default(),
                    ack_number: Some(self.ack_all()),
                    window_len: self.recv.window,
                    window_scale: None,
                    max_seg_size: None,
                    sack_permitted: false,
                    sack_ranges: [None; 3],
                    payload_len: range.len() as u16,
                }.send_to(entry.four_tuple()),
                range,
            });
        }

        // dbg!(time, self.ack_timer);
        // There is nothing to send but we may need to ack anyways.
        if Expiration::When(time) >= self.ack_timer {
            dbg!(available, window, sent, max_sent);
            self.release_ack_timer(time);
            return Some(Segment {
                repr: InnerRepr {
                    seq_number: self.send.next,
                    flags: TcpFlags::default(),
                    ack_number: Some(self.ack_all()),
                    window_len: self.recv.window,
                    window_scale: None,
                    max_seg_size: None,
                    sack_permitted: false,
                    sack_ranges: [None; 3],
                    payload_len: 0,
                }.send_to(entry.four_tuple()),
                range: 0..0,
            });
        }

        None
    }

    fn window_update(&mut self, segment: &TcpRepr, new_bytes: u32) {
        let flow = &mut self.flow_control;
        if self.duplicate_ack > 0 {
            flow.congestion_window = flow.ssthresh;
        } else if flow.congestion_window <= flow.ssthresh {
            flow.congestion_window = flow.congestion_window.saturating_mul(2);
        } else {
            // https://tools.ietf.org/html/rfc5681, avoid cwnd flooding from ack splitting.
            let update = u32::from(self.sender_maximum_segment_size).min(new_bytes);
            flow.congestion_window = flow.congestion_window.saturating_add(update);
        }
    }

    pub fn set_recv_ack(&mut self, ack: TcpSeqNumber, now: Instant) {
        if !(self.recv.next < ack) {
            return;
        }

        self.recv.next = ack;
        let new_timer = Expiration::When(now + self.ack_timeout);
        self.ack_timer = self.ack_timer.min(new_timer);
    }

    pub fn get_send_ack(&self) -> TcpSeqNumber {
        self.send.unacked
    }

    /// Indicate sending an ack for all arrived packets.
    ///
    /// When delaying acks for better throughput we split the recv ack counter into two: One for
    /// the apparent state of actually sent acknowledgments and one for the acks we have queued.
    /// Sending a packet with the current received state catches the former up to the latter
    /// counter.
    fn ack_all(&mut self) -> TcpSeqNumber {
        self.recv.acked = self.recv.next;
        self.recv.next
    }

    fn change_state(&mut self, new: State) {
        self.previous = self.current;
        self.current = new;
        eprintln!("Changed state: {:?} -> {:?}", self.previous, self.current);
    }

    fn release_retransmit(&mut self, now: Instant) {
        self.retransmission_timer = now + self.retransmission_timeout;
    }

    fn release_ack_timer(&mut self, now: Instant) {
        if self.recv.next != self.recv.acked {
            self.ack_timer = Expiration::When(now + self.ack_timeout);
        } else {
            self.ack_timer = Expiration::Never;
        }
    }

    /// RFC5681 restart window.
    fn restart_window(&self) -> u32 {
        self.flow_control.congestion_window.min(self.send.window.into())
    }
}

impl Receive {
    fn in_window(&self, seq: TcpSeqNumber) -> bool {
        self.next.contains_in_window(seq, self.window.into())
    }

    pub fn update_window(&mut self, window: usize) {
        let max = u32::from(u16::max_value()) << self.window_scale;
        let capped = u32::try_from(window)
            .unwrap_or_else(|_| u32::max_value())
            .min(max);
        let scaled_down = (capped >> self.window_scale)
            + if capped % (1 << self.window_scale) == 0 { 0 }  else { 1 };
        self.window = u16::try_from(scaled_down).unwrap();
    }
}

impl Send {
    fn incoming_ack(&mut self, seq: TcpSeqNumber) -> AckUpdate {
        if seq < self.unacked {
            AckUpdate::TooLow
        } else if seq == self.unacked {
            AckUpdate::Duplicate
        } else if seq <= self.next {
            // FIXME: this calculation could be safe without `as` coercion.
            let new_bytes = (seq - self.unacked) as u32;
            self.unacked = seq;
            AckUpdate::Updated { new_bytes }
        } else {
            AckUpdate::Unsent
        }
    }

    /// Get the actual window (combination of indicated window and scale).
    fn window(&self) -> u32 {
        u32::from(self.window) << self.window_scale
    }

    /// Get the segments in flight.
    fn in_flight(&self) -> u32 {
        assert!(self.unacked <= self.next);
        (self.next - self.unacked) as u32
    }
}

impl Operator<'_> {
    pub fn key(&self) -> SlotKey {
        self.connection_key
    }

    pub fn four_tuple(&self) -> FourTuple {
        self.slot().four_tuple()
    }

    pub fn connection(&self) -> &Connection {
        self.slot().connection()
    }

    pub fn connection_mut(&mut self) -> &mut Connection {
        self.entry().into_key_value().1
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

    pub fn from_tuple(endpoint: &'a mut Endpoint, tuple: FourTuple) -> Result<Self, &'a mut Endpoint> {
        let key = match endpoint.find_tuple(tuple) {
            Some(entry) => Some(entry.slot_key()),
            None => None,
        };

        match key {
            Some(key) => Ok(Operator {
                endpoint,
                connection_key: key,
            }),
            None => Err(endpoint),
        }
    }

    pub fn arrives(&mut self, incoming: &InPacket) -> Signals {
        let (entry_key, connection) = self.entry().into_key_value();
        connection.arrives(incoming, entry_key)
    }

    pub fn next_send_segment(&mut self, available: usize, time: Instant)
        -> Option<Segment>
    {
        let (entry_key, connection) = self.entry().into_key_value();
        connection.next_send_segment(available, time, entry_key)
    }

    pub fn open(&mut self, time: Instant) -> Result<TcpRepr, crate::layer::Error> {
        let (entry_key, connection) = self.entry().into_key_value();
        connection.open(time, entry_key)
            .ok_or(crate::layer::Error::Illegal)
    }

    /// Remove the connection and close the operator.
    pub(crate) fn delete(mut self) -> &'a mut Endpoint {
        self.entry().remove();
        self.endpoint
    }


    fn entry(&mut self) -> Entry {
        self.endpoint.entry(self.connection_key).unwrap()
    }

    fn slot(&self) -> &Slot {
        self.endpoint.get(self.connection_key).unwrap()
    }
}

impl Default for State {
    fn default() -> Self {
        State::Closed
    }
}

impl InnerRepr {
    pub fn send_back(&self, incoming: &TcpRepr) -> TcpRepr {
        self.send_impl(incoming.dst_port, incoming.src_port)
    }

    pub fn send_to(&self, tuple: FourTuple) -> TcpRepr {
        self.send_impl(tuple.local_port, tuple.remote_port)
    }

    fn send_impl(&self, src: u16, dst: u16) -> TcpRepr {
        TcpRepr {
            src_port: src,
            dst_port: dst,
            seq_number: self.seq_number,
            flags: self.flags,
            ack_number: self.ack_number,
            window_len: self.window_len,
            window_scale: self.window_scale,
            max_seg_size: self.max_seg_size,
            sack_permitted: self.sack_permitted,
            sack_ranges: self.sack_ranges,
            payload_len: self.payload_len,
        }
    }
}
