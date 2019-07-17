//! All the interop for a more 'socket' like interface.
//!
//! An actual socket layer requires allocation all buffers and depends on a few details in the
//! layer below and these do not (that was not the end goal but some may be added in the future),
//! but it tries to give a slightly more familiar interface.
use super::{InPacket, Recv, RecvBuf, SendBuf, SlotKey};
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
}

impl<R, S, P> Recv<P> for Client<R, S>
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
        match packet {
            InPacket::Closed(_) | InPacket::Stray(_) | InPacket::Sending(_) => (),
            InPacket::Open(mut open) => {
                if open.key() != key {
                    return;
                }

                open.read(&mut self.recv);
                let send = open.write(&mut self.send);
            },
            InPacket::Closing(closing) => {
            },
        }
    }
}
