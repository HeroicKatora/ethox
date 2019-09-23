//! All the interop for a more 'socket' like interface.
//!
//! An actual socket layer requires allocation all buffers and depends on a few details in the
//! layer below and these do not (that was not the end goal but some may be added in the future),
//! but it tries to give a slightly more familiar interface.
use super::{InPacket, RawPacket, Recv, RecvBuf, Send, SendBuf, SlotKey};
use crate::wire::{IpAddress, PayloadMut};

pub struct Client<R, S> {
    state: ClientState,
    recv: R,
    send: S,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ClientState {
    Uninstantiated {
        remote: IpAddress,
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
    pub fn new(
        remote: IpAddress,
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
    /// modify data that has already been sent but is still in the retranmission window.
    ///
    /// (Admitteldy, you could use this to probe other network stacks on their handling of
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
                    // TODO: error handling.
                    Err(crate::layer::Error::Exhausted) => return,
                    Err(other) => {
                        dbg!(other);
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
