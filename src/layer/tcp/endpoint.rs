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
use crate::wire::{IpAddress, TcpSeqNumber};
use crate::time::{Duration, Instant};

use super::connection::{
    Connection,
    NewReno,
    Send,
    State,
    Receive};

/// Handles TCP connection states.
pub struct Endpoint<'a> {
    ports: Map<'a, FourTuple, Key>,
    states: SlotMap<'a, Slot>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FourTuple {
    pub local: IpAddress,
    pub remote: IpAddress,
    pub local_port: u16,
    pub remote_port: u16,
}

/// A connection slot.
///
/// Can be used to open or accept a new connection. Usage of this acts similar to a slotmap where a
/// dedicated `SlotKey` allows referring to a connection outside of its lifetime without
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
    fn listen(&mut self, ip: IpAddress, port: u16)
        -> Option<SlotKey>
    {
        let key = FourTuple {
            local: ip,
            local_port: port,
            // Filled by the remote connection attempt.
            remote: IpAddress::Unspecified,
            remote_port: 0,
        };

        let (slot, state) = self.create_state(key)?;
        state.connection.current = State::Listen;
        Some(slot)
    }

    /// Actively try to connect to a remote TCP.
    fn open(&mut self, tuple: FourTuple)
        -> Option<SlotKey>
    {
        let (slot, _) = self.create_state(tuple)?;
        // Don't set to open yet, only after having sent the packet.
        Some(slot)
    }

    fn create_state(&mut self, tuple: FourTuple)
        -> Option<(SlotKey, &mut Slot)>
    {
        let state = self.create_connection();
        let (key, state) = unimplemented!();
        self.ports
            .entry(tuple)
            .vacant()?
            .insert(key);
        let key = SlotKey {
            key,
        };
        Some((key, state))
    }

    /// Initialize a closed connection.
    ///
    /// The raw method is near useless, transition the connection to an appropriate state
    /// afterwards.
    fn create_connection(&mut self) -> Connection {
        Connection {
            current: State::Closed,
            previous: State::Closed,
            flow_control: NewReno {
                congestion_window: 0,
                ssthresh: u32::max_value(),
                recover: TcpSeqNumber::default(),
            },
            receive_window: 0,
            sender_maximum_segment_size: 0,
            receiver_maximum_segment_size: 0,
            last_ack_receive_offset: TcpSeqNumber::default(),
            last_ack_time: Instant::from_millis(0),
            last_ack_timeout: Duration::from_millis(500),
            selective_acknowledgements: false,
            send: Send {
                unacked: TcpSeqNumber::default(),
                next: TcpSeqNumber::default(),
                window: 0,
                initial_seq: self.initial_seq_num(),
            },
            recv: Receive {
                acked: TcpSeqNumber::default(),
                next: TcpSeqNumber::default(),
                window: 0,
                initial_seq: TcpSeqNumber::default(),
            },
        }
    }

    fn initial_seq_num(&mut self) -> TcpSeqNumber {
        // FIXME: should choose one by pseudo-random.
        unimplemented!()
    }
}

impl super::connection::Endpoint for Endpoint<'_> {
    fn get(&self, index: SlotKey) -> Option<&Connection> {
        unimplemented!()
    }

    fn get_mut(&mut self, index: SlotKey) -> Option<&mut Connection> {
        unimplemented!()
    }

    fn listen(&mut self, ip: IpAddress, port: u16) -> Option<SlotKey> {
        unimplemented!()
    }

    fn open(&mut self, tuple: FourTuple) -> Option<SlotKey> {
        unimplemented!()
    }
}
