// Copyright (C) 2016 whitequark@whitequark.org
// Copyright (C) 2019 Andreas Molzer <andreas.molzer@tum.de>
//
// in large parts from `smoltcp` originally distributed under 0-clause BSD
use core::mem;
#[cfg(feature = "std")]
use std::os::unix::io::{RawFd, AsRawFd};

use libc;
use super::{ifreq, linux, now, Errno, FdResult, LibcResult, IoLenResult};

use crate::nic::{self, Capabilities, Device, Packet, Personality};
use crate::nic::common::{EnqueueFlag, PacketInfo};
use crate::managed::Partial;
use crate::wire::PayloadMut;

mod tap_traits {
    #[cfg(target_os = "linux")]
    pub(crate) use super::linux::IfIndex;
    #[cfg(target_os = "linux")]
    pub(crate) use super::linux::NetdeviceMtu;

    // for other OS's, other traits might be used instead.
}

use tap_traits::{IfIndex, NetdeviceMtu};

/// A static descriptor for interacting with a raw socket.
///
/// Contains the file descriptor and a pre-filled `ifreq` structure with the interface name that is
/// required for `ioctl` calls. This offers the raw methods for reading and writing but does not
/// encapsulate an actual `nic::Device`. Wrap it in a [`RawSocket`] with a buffer for this.
///
/// [`RawSocket`]: struct.RawSocket.html
#[derive(Debug)]
pub struct RawSocketDesc {
    lower: libc::c_int,
    ifreq: ifreq
}

/// A raw socket with buffer, usable as a network device.
///
/// Uses the errno principle for storing the last underlying error on a failed operation.
///
/// The device capabilities are mutable and not automatically deduced. For example, a local veth
/// pair (connecting two network namespaces) could be allowed to elide all checksums.
///
/// The `nic::Device` implementation always sends and receives at most one buffer at a time. It
/// will also block on sending but is non-blocking during receiving. This is not quite a bug. It's
/// intended as while the buffer is filled for sending, there are no resources for any other
/// operation. But it arguably could instead simply yield no buffer in any rx-tx block while the
/// buffer is already in-use. However, this implementation was slightly simpler and tap interface
/// is not the main use case. Patches are accepted.
#[derive(Debug)]
pub struct RawSocket<C> {
    inner: RawSocketDesc,
    buffer: Partial<C>,
    last_err: Option<Errno>,
    capabilities: Capabilities,
}

enum Received {
    NoData,
    Ok,
    Err(crate::layer::Error),
}

#[cfg(feature = "std")]
impl AsRawFd for RawSocketDesc {
    fn as_raw_fd(&self) -> RawFd {
        self.lower
    }
}

#[cfg(feature = "std")]
impl<C> AsRawFd for RawSocket<C> {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl RawSocketDesc {
    /// Try to open a socket for the named interface.
    ///
    /// Note that this does *not* yet bind the interface to the socket, it only creates the
    /// necessary structures involved in doing so. Call [`bind_interface`] afterwards.
    ///
    /// [`bind_interface`]: #method.bind_interface
    pub fn new(name: &str) -> Result<RawSocketDesc, Errno> {
        let lower = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                linux::ETH_P_ALL.to_be() as i32)
        };

        FdResult(lower).errno()?;

        Ok(RawSocketDesc {
            lower,
            ifreq: ifreq::new(name),
        })
    }

    /// Query the interface MTU, as reported by the OS.
    pub fn interface_mtu(&mut self) -> Result<usize, Errno> {
        self.ifreq.get_mtu(self.lower)
            .map(|mtu| mtu as usize)
    }

    /// Update the file descriptor to the named interface.
    ///
    /// See `bind` with `AF_PACKET` and `ETH_P_ALL` for error and a discussion of platform
    /// requirements and checks.
    pub fn bind_interface(&mut self) -> Result<(), Errno> {
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

        FdResult(res).errno()
    }

    /// Receive a single frame into the buffer.
    ///
    /// Note that the socket will have been opened with `O_NONBLOCK` so that this only returns an
    /// `Ok` when a buffer is ready.
    pub fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, Errno> {
        let len = unsafe {
            libc::recv(
                self.lower,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0)
        };
        IoLenResult(len).errno()?;
        Ok(len as usize)
    }

    /// Send a single frame from a buffer.
    pub fn send(&mut self, buffer: &[u8]) -> Result<usize, Errno> {
        let len = unsafe {
            libc::send(
                self.lower,
                buffer.as_ptr() as *const libc::c_void,
                buffer.len(),
                0)
        };
        IoLenResult(len).errno()?;
        Ok(len as usize)
    }
}

impl<C: PayloadMut> RawSocket<C> {
    /// Open a raw socket by name with one buffer for packets.
    pub fn new(name: &str, buffer: C) -> Result<Self, Errno> {
        let mut inner = RawSocketDesc::new(name)?;
        inner.bind_interface()?;
        Self::with_descriptor(inner, buffer)
    }

    /// Wrap an existing descriptor and buffer into a device.
    ///
    /// The socket needs to already be bound to the interface otherwise errors to all calls will be
    /// the consequence.
    pub fn with_descriptor(
        inner: RawSocketDesc,
        buffer: C,
    ) -> Result<Self, Errno> {
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
    pub fn last_err(&mut self) -> Option<Errno> {
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
            Err(ref err) if err.0 == libc::EWOULDBLOCK => Received::NoData,
            Err(err) => Received::Err(self.store_err(err)),
        }
    }

    fn store_err(&mut self, err: Errno) -> crate::layer::Error {
        let as_nic = crate::layer::Error::Illegal;
        self.last_err = Some(err);
        as_nic
    }

    fn current_info(&self) -> PacketInfo {
        PacketInfo {
            timestamp: now().unwrap(),
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

