// Copyright (C) 2016 whitequark@whitequark.org
// Copyright (C) 2019 Andreas Molzer <andreas.molzer@tum.de>
//
// in large parts from `smoltcp` originally distributed under 0-clause BSD
#[cfg(feature = "std")]
use std::os::unix::io::{RawFd, AsRawFd};

use libc;
use super::{now, Errno, FdResult, IoLenResult, LibcResult, ifreq};

use crate::nic::{self, Capabilities, Device, Packet, Personality};
use crate::nic::common::{EnqueueFlag, PacketInfo};
use crate::managed::Partial;
use crate::wire::PayloadMut;

mod tap_traits {
    #[cfg(target_os = "linux")]
    pub(crate) use super::super::linux::TunSetIf;
    #[cfg(target_os = "linux")]
    pub(crate) use super::super::linux::NetdeviceMtu;

    // for other OS's, other traits might be used instead.
}

use tap_traits::{NetdeviceMtu, TunSetIf};

/// A static descriptor for interacting with a tap interface.
///
/// Contains the file descriptor and a pre-filled `ifreq` structure with the interface name that is
/// required for `ioctl` calls. This offers the raw methods for reading and writing but does not
/// encapsulate an actual `nic::Device`. Wrap it in a [`TapInterface`] with a buffer for this.
///
/// [`TapInterface`]: struct.TapInterface.html
#[derive(Debug)]
pub struct TapInterfaceDesc {
    lower: libc::c_int,
    ifreq: ifreq
}

/// A tap interface with buffer, usable as a network device.
///
/// The `nic::Device` implementation always sends and receives at most one buffer at a time. It
/// will also block on sending but is non-blocking during receiving. This is not quite a bug. It's
/// intended as while the buffer is filled for sending, there are no resources for any other
/// operation. But it arguably could instead simply yield no buffer in any rx-tx block while the
/// buffer is already in-use. However, this implementation was slightly simpler and tap interface
/// is not the main use case. Patches are accepted.
#[derive(Debug)]
pub struct TapInterface<C> {
    inner: TapInterfaceDesc,
    buffer: Partial<C>,
    last_err: Option<Errno>,
}

enum Received {
    NoData,
    Ok,
    Err(crate::layer::Error),
}

#[cfg(feature = "std")]
impl AsRawFd for TapInterfaceDesc {
    fn as_raw_fd(&self) -> RawFd {
        self.lower
    }
}

#[cfg(feature = "std")]
impl<C> AsRawFd for TapInterface<C> {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

static TAP_PATH: &'static [u8] = b"/dev/net/tun\0";

impl TapInterfaceDesc {
    /// Try to open a socket for the named interface.
    ///
    /// Note that this does *not* yet set the interface for the file descriptor, it only creates
    /// the necessary structures involved in doing so. Call [`attach_interface`] afterwards.
    ///
    /// [`attach_interface`]: #method.attach_interface
    pub fn new(name: &str) -> Result<TapInterfaceDesc, Errno> {
        let lower = unsafe {
            libc::open(
                TAP_PATH.as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_NONBLOCK)
        };

        FdResult(lower).errno()?;

        Ok(TapInterfaceDesc {
            lower,
            ifreq: ifreq::new(name),
        })
    }

    /// Update the file descriptor to the named interface.
    ///
    /// See `ioctl` with `TUNSETIFF` for details on errors.
    pub fn attach_interface(&mut self) -> Result<(), Errno> {
        self.ifreq.tun_set_tap(self.lower)
    }

    /// Try to find the mtu of the tap.
    ///
    /// Works (more or less) by opening an `AF_INET/PROTO_IP` socket and querying its mtu.
    pub fn interface_mtu(&mut self) -> Result<usize, Errno> {
        let lower = unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_IP)
        };

        FdResult(lower).errno()?;

        let mtu = self.ifreq.get_mtu(self.lower)
            .map(|mtu| mtu as usize);

        unsafe { libc::close(lower); }

        mtu
    }

    /// Receive a single message on the tap into the buffer.
    pub fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, Errno> {
        let len = unsafe {
            libc::read(
                self.lower,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len())
        };
        IoLenResult(len).errno()?;
        Ok(len as usize)
    }

    /// Send a single message onto the tap from the buffer.
    pub fn send(&mut self, buffer: &[u8]) -> Result<usize, Errno> {
        let len = unsafe {
            libc::write(
                self.lower,
                buffer.as_ptr() as *const libc::c_void,
                buffer.len())
        };
        IoLenResult(len).errno()?;
        Ok(len as usize)
    }
}

impl<C: PayloadMut> TapInterface<C> {
    /// Open a tap interface by name with one buffer for packets.
    pub fn new(name: &str, buffer: C) -> Result<Self, Errno> {
        let inner = TapInterfaceDesc::new(name)?;
        Self::with_descriptor(inner, buffer)
    }

    /// Wrap an existing descriptor with a buffer into a device.
    pub fn with_descriptor(
        mut inner: TapInterfaceDesc,
        buffer: C,
    ) -> Result<Self, Errno> {
        inner.attach_interface()?;
        Ok(TapInterface {
            inner,
            buffer: Partial::new(buffer),
            last_err: None,
        })
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

    /// Send the current buffer as a frame.
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
        let as_nic = io_error_to_layer(&err);
        self.last_err = Some(err);
        as_nic
    }

    fn current_info() -> PacketInfo {
        PacketInfo {
            timestamp: now().unwrap(),
            capabilities: Capabilities::no_support(),
        }
    }
}

impl Drop for TapInterfaceDesc {
    fn drop(&mut self) {
        unsafe { libc::close(self.lower); }
    }
}

impl<C: PayloadMut> Device for TapInterface<C> {
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
        let mut handle = EnqueueFlag::set_true(Self::current_info());
        self.recycle();
        sender.send(Packet {
            handle: &mut handle,
            payload: &mut self.buffer,
        });

        if handle.was_sent() {
            self.send()?;
            Ok(1)
        } else {
            Ok(0)
        }
    }

    fn rx(&mut self, _: usize, mut receptor: impl nic::Recv<Self::Handle, Self::Payload>)
        -> nic::Result<usize>
    {
        match self.recv() {
            Received::Ok => (),
            Received::Err(err) => return Err(err),
            Received::NoData => return Ok(0),
        }

        let mut handle = EnqueueFlag::set_true(Self::current_info());
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

fn io_error_to_layer(_: &Errno) -> crate::layer::Error {
    // FIXME: not the best feed back.
    crate::layer::Error::Illegal 
}
