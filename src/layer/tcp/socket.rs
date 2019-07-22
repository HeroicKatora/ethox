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
            InPacket::Open(open) => {
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
        match self.state {
            ClientState::Uninstantiated { remote, remote_port } => {
                match packet.open(remote, remote_port) {
                    Ok(sending) => {
                        self.state = ClientState::InStack { key: sending.key() };
                    },
                    // TODO: error handling.
                    Err(_) => self.state = ClientState::Finished,
                }
            },
            ClientState::InStack { key } => {
                match packet.attach(key) {
                    Ok(open) => {
                        let _ = open.write(&mut self.send);
                    },
                    Err(_) => (),
                }
            },
            ClientState::Finished => (),
        }
    }
}
