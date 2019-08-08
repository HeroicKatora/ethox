// Copyright (C) 2016 whitequark@whitequark.org
// Copyright (C) 2019 Andreas Molzer <andreas.molzer@tum.de>
//
// in large parts from `smoltcp` originally distributed under 0-clause BSD
use std::{mem, io};
use std::os::unix::io::{RawFd, AsRawFd};
use std::time::SystemTime;

use libc;
use super::{ifreq, linux, test_result, FdResult, IoLenResult};

use crate::nic::{self, Capabilities, Device, Packet, Personality};
use crate::nic::common::{EnqueueFlag, PacketInfo};
use crate::managed::Partial;
use crate::wire::PayloadMut;

mod tap_traits {
    #[cfg(target_os = "linux")]
    pub use super::linux::IfIndex;
    #[cfg(target_os = "linux")]
    pub use super::linux::NetdeviceMtu;
}

use tap_traits::{IfIndex, NetdeviceMtu};

#[derive(Debug)]
pub struct RawSocketDesc {
    lower: libc::c_int,
    ifreq: ifreq
}

#[derive(Debug)]
pub struct RawSocket<C> {
    inner: RawSocketDesc,
    buffer: Partial<C>,
    last_err: Option<io::Error>,
    capabilities: Capabilities,
}

enum Received {
    NoData,
    Ok,
    Err(crate::layer::Error),
}

impl AsRawFd for RawSocketDesc {
    fn as_raw_fd(&self) -> RawFd {
        self.lower
    }
}

impl<C> AsRawFd for RawSocket<C> {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl RawSocketDesc {
    pub fn new(name: &str) -> io::Result<RawSocketDesc> {
        let lower = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                linux::ETH_P_ALL.to_be() as i32)
        };

        test_result(FdResult(lower))?;

        Ok(RawSocketDesc {
            lower,
            ifreq: ifreq::new(name),
        })
    }

    pub fn interface_mtu(&mut self) -> io::Result<usize> {
        self.ifreq.get_mtu(self.lower)
            .map(|mtu| mtu as usize)
    }

    pub fn bind_interface(&mut self) -> io::Result<()> {
        let sockaddr = libc::sockaddr_ll {
            sll_family:   libc::AF_PACKET as u16,
            sll_protocol: linux::ETH_P_ALL.to_be() as u16,
            sll_ifindex:  self.ifreq.get_if_index(self.lower)?,
            sll_hatype:   1,
            sll_pkttype:  0,
            sll_halen:    6,
            sll_addr:     [0; 8],
        };

        let res = unsafe {
            libc::bind(
                self.lower,
                &sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as u32)
        };

        test_result(FdResult(res))
    }

    pub fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let len = unsafe {
            libc::recv(
                self.lower,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0)
        };
        test_result(IoLenResult(len))?;
        Ok(len as usize)
    }

    pub fn send(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let len = unsafe {
            libc::send(
                self.lower,
                buffer.as_ptr() as *const libc::c_void,
                buffer.len(),
                0)
        };
        test_result(IoLenResult(len))?;
        Ok(len as usize)
    }
}

impl<C: PayloadMut> RawSocket<C> {
    pub fn new(name: &str, buffer: C) -> io::Result<Self> {
        let mut inner = RawSocketDesc::new(name)?;
        inner.bind_interface()?;
        Ok(RawSocket {
            inner,
            buffer: Partial::new(buffer),
            last_err: None,
            capabilities: Capabilities::no_support(),
        })
    }

    /// Get the currently configured capabilities.
    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    /// Get a mutable reference to the capability configuration.
    ///
    /// Allows disabling of checksum tests.
    pub fn capabilities_mut(&mut self) -> &mut Capabilities {
        &mut self.capabilities
    }

    /// Take the last io error returned by the OS.
    pub fn last_err(&mut self) -> Option<io::Error> {
        self.last_err.take()
    }

    /// Resize the partial buffer to its full length.
    fn recycle(&mut self) {
        let length = self.buffer
            .inner()
            .payload()
            .as_slice()
            .len();
        self.buffer.set_len_unchecked(length);
    }

    /// Send the current buffer as a packet.
    fn send(&mut self) -> nic::Result<()> {
        let result = self.inner.send(self.buffer.payload_mut().as_mut_slice());
        match result {
            Ok(_) => Ok(()),
            Err(err) => Err(self.store_err(err))
        }
    }

    fn recv(&mut self) -> Received {
        self.recycle();
        let result = self.inner.recv(self.buffer.payload_mut().as_mut_slice());
        match result {
            Ok(len) => {
                self.buffer.set_len_unchecked(len);
                Received::Ok
            },
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Received::NoData,
            Err(err) => Received::Err(self.store_err(err)),
        }
    }

    fn store_err(&mut self, err: io::Error) -> crate::layer::Error {
        let as_nic = crate::layer::Error::Illegal;
        self.last_err = Some(err);
        as_nic
    }

    fn current_info(&self) -> PacketInfo {
        PacketInfo {
            timestamp: SystemTime::now().into(),
            capabilities: self.capabilities,
        }
    }
}

impl Drop for RawSocketDesc {
    fn drop(&mut self) {
        unsafe { libc::close(self.lower); }
    }
}

impl<C: PayloadMut> Device for RawSocket<C> {
    type Handle = EnqueueFlag;
    type Payload = Partial<C>;

    /// A description of the device.
    ///
    /// Could be dynamically configured but the optimizer and the user is likely happier if the
    /// implementation does not take advantage of this fact.
    fn personality(&self) -> Personality {
        Personality::baseline()
    }

    fn tx(&mut self, _: usize, mut sender: impl nic::Send<Self::Handle, Self::Payload>)
        -> nic::Result<usize>
    {
        let mut handle = EnqueueFlag::set_true(self.current_info());
        self.recycle();
        sender.send(Packet {
            handle: &mut handle,
            payload: &mut self.buffer,
        });

        if handle.was_sent() {
            self.send()?;
        }

        Ok(1)
    }

    fn rx(&mut self, _: usize, mut receptor: impl nic::Recv<Self::Handle, Self::Payload>)
        -> nic::Result<usize>
    {
        match self.recv() {
            Received::Ok => (),
            Received::Err(err) => return Err(err),
            Received::NoData => return Ok(0),
        }

        let mut handle = EnqueueFlag::set_true(self.current_info());
        receptor.receive(Packet {
            handle: &mut handle,
            payload: &mut self.buffer,
        });

        if handle.was_sent() {
            self.send()?;
        }

        Ok(1)
    }
}

