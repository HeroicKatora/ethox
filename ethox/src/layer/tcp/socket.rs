//! All the interop for a more 'socket' like interface.
//!
//! An actual socket layer requires allocation all buffers and depends on a few details in the
//! layer below and these do not (that was not the end goal but some may be added in the future),
//! but it tries to give a slightly more familiar interface.
use super::{InPacket, RawPacket, Recv, RecvBuf, Send, SendBuf, SlotKey};
use crate::wire::{ip::Address, PayloadMut};

/// A tcp handler for a client (actively opened connection).
///
/// Groups the user buffers and some additional cached connection state to provide maximally
/// generic implementations of [`tcp::Send`] and [`tcp::Recv`]. Note that writing and reading data
/// from the underlying stream still depends on what methods the buffers offer. For these reasons,
/// it is possible to access them with the [`send`] and [`recv`] methods (and mutable variants
/// thereof) respectively.
///
/// ## Things that do not work yet
///
/// There should be a `bind` constructor but currently the local address can only be deduced
/// automatically.
///
/// Error handling is also suboptimal and mostly close the connection.
///
/// [`tcp::Send`]: ../trait.Send.html
/// [`tcp::Recv`]: ../trait.Recv.html
pub struct Client<R, S> {
    state: ClientState,
    recv: R,
    send: S,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ClientState {
    Uninstantiated {
        remote: Address,
        remote_port: u16,
    },
    InStack {
        key: SlotKey,
    },
    Finished,
}

impl<R, S> Client<R, S>
where
    R: RecvBuf,
    S: SendBuf,
{
    /// Create a client connecting to a remote on some automatically derived local address.
    pub fn new(
        remote: Address,
        remote_port: u16,
        recv: R,
        send: S,
    ) -> Self {
        Client {
            state: ClientState::Uninstantiated {
                remote,
                remote_port,
            },
            recv,
            send,
        }
    }
}

impl<R, S> Client<R, S> {
    /// Get a reference to the receive buffer.
    pub fn recv(&self) -> &R {
        &self.recv
    }

    /// Get a mutable reference to the receive buffer.
    ///
    /// You should probably only use this to retrieve data from the acknowledged portion of the
    /// buffer.
    pub fn recv_mut(&mut self) -> &mut R {
        &mut self.recv
    }

    /// Get a reference to the send buffer.
    pub fn send(&self) -> &S {
        &self.send
    }

    /// Get a mutable reference to the send buffer.
    ///
    /// You should only use this to append additional data or remove acknowledged data, and not to
    /// modify data that has already been sent but is still in the retransmission window.
    ///
    /// (Admittedly, you could use this to probe other network stacks on their handling of
    /// conflicting retransmitted segments. That would be annoying but, and this should not be read
    /// as an endorsement of blackhat hacking, somewhat cool).
    pub fn send_mut(&mut self) -> &mut S {
        &mut self.send
    }

    /// Check if the connection was closed.
    pub fn is_closed(&self) -> bool {
        match self.state {
            ClientState::Finished => true,
            _ => false,
        }
    }

    /// Get the key of the active connection.
    ///
    /// The key can be used to manually attach to the connection during rx and tx operations or to
    /// query the state from the endpoint at any point.
    ///
    /// Returns `None` when no connection has been established yet or the connection is already
    /// terminated.
    pub fn connection_key(&self) -> Option<SlotKey> {
        match self.state {
            ClientState::InStack { key } => Some(key),
            _ => None,
        }
    }
}

impl<R, S, P> Recv<P> for &'_ mut Client<R, S>
where
    R: RecvBuf,
    S: SendBuf,
    P: PayloadMut,
{
    fn receive(&mut self, packet: InPacket<P>) {
        let key = match self.state {
            // We really need to send first.
            ClientState::InStack { key } => key,
            _ => return,
        };

        // Not a packet for our connection. Ignore.
        if packet.key() != Some(key) {
            return;
        }

        match packet {
            InPacket::Stray(_) | InPacket::Sending(_) => (),
            InPacket::Closed(_) | InPacket::Closing(_) => {
                self.state = ClientState::Finished;
            },
            InPacket::Open(mut open) => {
                open.read(&mut self.recv);
                let _ = open.write(&mut self.send);
            },
        }
    }
}

impl<R, S, P> Send<P> for &'_ mut Client<R, S>
where
    R: RecvBuf,
    S: SendBuf,
    P: PayloadMut,
{
    fn send(&mut self, packet: RawPacket<P>) {
        let open = match self.state {
            ClientState::Uninstantiated { remote, remote_port } => {
                match packet.open(remote, remote_port) {
                    Ok(open) => {
                        self.state = ClientState::InStack { key: open.key() };
                        open
                    },
                    Err(crate::layer::Error::Exhausted) => return,
                    // TODO: error handling.
                    Err(_other) => {
                        // TODO: error debgugging.
                        self.state = ClientState::Finished;
                        return;
                    },
                }
            },
            ClientState::InStack { key } => {
                match packet.attach(key) {
                    Ok(open) => open,
                    // TODO: error handling.
                    Err(_) => return self.state = ClientState::Finished,
                }
            },
            ClientState::Finished => return,
        };

        // TODO: error handling.
        let _ = open.write(&mut self.send);
    }
}
