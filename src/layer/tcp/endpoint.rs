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
use crate::layer::ip;
use crate::managed::{Map, SlotMap, slotmap::Key};
use crate::wire::{IpAddress, TcpChecksum, TcpPacket, TcpSeqNumber};
use crate::wire::PayloadMut;
use crate::time::{Duration, Instant};

use super::connection::{
    Connection,
    NewReno,
    Send,
    State,
    Receive};
use super::packet::{In};
use super::siphash::IsnGenerator;

/// Handles TCP connection states.
pub struct Endpoint<'a> {
    ports: Map<'a, FourTuple, Key>,
    states: SlotMap<'a, Slot>,
    isn_generator: IsnGenerator,
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
///
/// Contains the four-tuple which maps to the slot, completing the loop for lookups
/// (slotkey->4tuple,4tuple->slotkey).
#[derive(Clone, Copy, Debug, Hash)]
pub struct Slot {
    addr: FourTuple,
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

/// An endpoint borrowed for receiving.
///
/// Dispatching to higher protocols is configurerd here, and not in the endpoint state.
pub struct Receiver<'a, 'e, H> {
    endpoint: Borrow<'a, 'e>,

    /// The upper protocol receiver.
    handler: H,
}

struct Borrow<'a, 'e> {
    // TODO: could be immutable as well, just disallowing updates. Evaluate whether this is useful
    // or needed somewhere.
    inner: &'a mut Endpoint<'e>,
}

/// A partially mutable reference to a connection.
///
/// Retrieving an `Entry` for a given `SlotKey` consists of slicing the internal representation of
/// the `Endpoint` in such a way that it is possible to consistently change the four-tuple mapping
/// to that connection, to modify the connection itself, and to access the initial sequence number
/// generator.
pub struct Entry<'a> {
    ports: &'a mut PortMap,
    isn: &'a IsnGenerator,
    slot: &'a mut Slot,
}

/// A mutable reference to the key-structure of a connection.
///
/// From an `Entry` split into the connection and the keys referring to it in such a manner that
/// the keys can be edited without affecting the connection itself.
pub struct EntryKey<'a> {
    ports: &'a mut PortMap,
    isn: &'a IsnGenerator,
    key_in_slot: &'a mut FourTuple,
}

/// Provides remapping a `SlotKey` under a different four tuple.
///
/// Erases the lifetime from the underlying `Map` itself.
trait PortMap {
    /// Note: does not permit failure so we must never expose it.
    fn remap(&mut self, old: FourTuple, new: FourTuple);
}

impl Endpoint<'_> {
    pub fn get_mut(&mut self, index: SlotKey)
        -> Option<&mut Slot>
    {
        self.states.get_mut(index.key)
    }

    pub fn entry(&mut self, index: SlotKey)
        -> Option<Entry>
    {
        let slot = self.states.get_mut(index.key)?;

        Some(Entry {
            ports: &mut self.ports,
            isn: &mut self.isn_generator,
            slot,
        })
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

        let (key, state) = self.create_state(key)?;
        state.connection.current = State::Listen;
        Some(key)
    }

    /// Actively try to connect to a remote TCP.
    fn open(&mut self, tuple: FourTuple)
        -> Option<SlotKey>
    {
        let (key, _) = self.create_state(tuple)?;
        // Don't set to open yet, only after having sent the packet.
        Some(key)
    }

    fn create_state(&mut self, addr: FourTuple)
        -> Option<(SlotKey, &mut Slot)>
    {
        let connection = self.create_connection();

        let vacant = self.ports
            .entry(addr)
            .vacant()?;

        // FIXME: would be nicer to have an `Entry` api on the slotmap for peace of mind. It is
        // however mostly inconsequential right now.
        //
        // Reserves a slot, don't lose the key or we'd leak that reservation.
        let (key, slot) = self.states
            .reserve()?;

        slot.connection = connection;
        slot.addr = addr;
        vacant.insert(key);

        let key = SlotKey {
            key,
        };

        Some((key, slot))
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
                unsent: 0,
                window: 0,
                initial_seq: TcpSeqNumber::default(),
            },
            recv: Receive {
                acked: TcpSeqNumber::default(),
                next: TcpSeqNumber::default(),
                window: 0,
                initial_seq: TcpSeqNumber::default(),
            },
        }
    }

    fn initial_seq_num(&mut self, id: FourTuple, time: Instant) -> TcpSeqNumber {
        self.isn_generator.get_isn(id, time)
    }
}

impl<'ep> Endpoint<'ep> {
    pub fn recv<H>(&mut self, handler: H) -> Receiver<'_, 'ep, H> {
        Receiver { endpoint: self.borrow(), handler }
    }

    fn borrow(&mut self) -> Borrow<'_, 'ep> {
        Borrow { inner: self, }
    }
}

impl<'a> Entry<'a> {
    pub fn into_key_value(self) -> (EntryKey<'a>, &'a mut Connection) {
        let entry_key = EntryKey {
            ports: self.ports,
            isn: self.isn,
            key_in_slot: &mut self.slot.addr,
        };

        let connection = &mut self.slot.connection;

        (entry_key, connection)
    }

    pub fn remove(self) {
        unimplemented!()
    }
}

impl EntryKey<'_> {
    pub fn initial_seq_num(&self, time: Instant) -> TcpSeqNumber {
        self.isn.get_isn(*self.key_in_slot, time)
    }

    pub fn four_tuple(&self) -> FourTuple {
        *self.key_in_slot
    }

    /// Move the connection state to a new connection tuple.
    ///
    /// # Panics
    /// `new` must not be taken by any other connection yet.
    pub fn set_four_tuple(&mut self, new: FourTuple) {
        self.ports.remap(*self.key_in_slot, new);
        *self.key_in_slot = new;
    }
}

impl super::connection::Endpoint for Endpoint<'_> {
    fn get(&self, index: SlotKey) -> Option<&Connection> {
        Endpoint::get(self, index).map(|slot| &slot.connection)
    }

    fn get_mut(&mut self, index: SlotKey) -> Option<&mut Connection> {
        Endpoint::get_mut(self, index).map(|slot| &mut slot.connection)
    }

    fn entry(&mut self, index: SlotKey) -> Option<Entry> {
        Endpoint::entry(self, index)
    }

    fn listen(&mut self, ip: IpAddress, port: u16) -> Option<SlotKey> {
        Endpoint::listen(self, ip, port)
    }

    fn open(&mut self, tuple: FourTuple) -> Option<SlotKey> {
        Endpoint::open(self, tuple)
    }

    fn initial_seq_num(&mut self, id: FourTuple, time: Instant) -> TcpSeqNumber {
        Endpoint::initial_seq_num(self, id, time)
    }
}

impl PortMap for Map<'_, FourTuple, Key> {
    fn remap(&mut self, old: FourTuple, new: FourTuple) {
        let old = self.entry(old)
            .occupied()
            // FIXME: unwrap justified? Seems like it may not.
            .unwrap();
        let value = *old.get();
        old.remove();

        self.entry(new)
            .vacant()
            // FIXME: nearly justified but how to ensure it was not mapped?
            .unwrap()
            .insert(value);
    }
}

impl<H, P> ip::Recv<P> for Receiver<'_, '_, H>
where
    P: PayloadMut,
    H: super::Recv<P>,
{
    fn receive(&mut self, ip_packet: ip::InPacket<P>) {
        let ip::InPacket { mut handle, packet } = ip_packet;
        let repr = packet.repr();

        let checksum = TcpChecksum::Manual {
            src_addr: repr.src_addr(),
            dst_addr: repr.dst_addr(),
        };

        let packet = match TcpPacket::new_checked(packet, checksum) {
            Ok(packet) => packet,
            // TODO: error logging.
            Err(_) => return,
        };

        let arrived = match In::from_arriving(self.endpoint.inner, handle.borrow_mut(), packet) {
            Ok(arrived) => arrived,

            // TODO: error logging.
            Err(_) => return,
        };

        self.handler.receive(arrived)
    }
}

