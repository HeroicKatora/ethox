// Copyright (C) 2016 whitequark@whitequark.org
// Copyright (C) 2019 Andreas Molzer <andreas.molzer@tum.de>
//
// in large parts from `smoltcp` originally distributed under 0-clause BSD
use std::io;
use std::os::unix::io::{RawFd, AsRawFd};

use libc;
use super::{FdResult, IoLenResult, ifreq, test_result};

use crate::nic::{self, Device, Packet, Personality, common::EnqueueFlag};
use crate::managed::Partial;
use crate::wire::PayloadMut;

mod tap_traits {
    #[cfg(target_os = "linux")]
    pub use super::super::linux::TunSetIf;

    #[cfg(target_os = "linux")]
    pub use super::super::linux::NetdeviceMtu;
}

use tap_traits::{NetdeviceMtu, TunSetIf};

#[derive(Debug)]
pub struct TapInterfaceDesc {
    lower: libc::c_int,
    ifreq: ifreq
}

#[derive(Debug)]
pub struct TapInterface<C> {
    inner: TapInterfaceDesc,
    buffer: Partial<C>,
    last_err: Option<io::Error>,
}

enum Received {
    NoData,
    Ok,
    Err(crate::layer::Error),
}

impl AsRawFd for TapInterfaceDesc {
    fn as_raw_fd(&self) -> RawFd {
        self.lower
    }
}

impl<C> AsRawFd for TapInterface<C> {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

static TAP_PATH: &'static [u8] = b"/dev/net/tun\0";

impl TapInterfaceDesc {
    pub fn new(name: &str) -> io::Result<TapInterfaceDesc> {
        let lower = unsafe {
            libc::open(
                TAP_PATH.as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_NONBLOCK)
        };

        test_result(FdResult(lower))?;

        Ok(TapInterfaceDesc {
            lower,
            ifreq: ifreq::new(name),
        })
    }

    pub fn attach_interface(&mut self) -> io::Result<()> {
        self.ifreq.tun_set_tap(self.lower)
    }

    /// Try to find the mtu of the tap.
    ///
    /// Works (more or less) by opening an `AF_INET/PROTO_IP` socket and querying its mtu.
    pub fn interface_mtu(&mut self) -> io::Result<usize> {
        let lower = unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_IP)
        };

        test_result(FdResult(lower))?;

        let mtu = self.ifreq.get_mtu(self.lower)
            .map(|mtu| mtu as usize);

        unsafe { libc::close(lower); }

        mtu
    }

    pub fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let len = unsafe {
            libc::read(
                self.lower,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len())
        };
        test_result(IoLenResult(len))?;
        Ok(len as usize)
    }

    pub fn send(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let len = unsafe {
            libc::write(
                self.lower,
                buffer.as_ptr() as *const libc::c_void,
                buffer.len())
        };
        test_result(IoLenResult(len))?;
        Ok(len as usize)
    }
}

impl<C: PayloadMut> TapInterface<C> {
    pub fn new(name: &str, buffer: C) -> io::Result<Self> {
        let mut inner = TapInterfaceDesc::new(name)?;
        inner.attach_interface()?;
        Ok(TapInterface {
            inner,
            buffer: Partial::new(buffer),
            last_err: None,
        })
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
        let as_nic = io_error_to_layer(&err);
        self.last_err = Some(err);
        as_nic
    }
}

impl Drop for TapInterfaceDesc {
    fn drop(&mut self) {
        unsafe { libc::close(self.lower); }
    }
}

impl<'a, C: PayloadMut + 'a> Device<'a> for TapInterface<C> {
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
        let mut handle = EnqueueFlag::SetTrue(false);
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

        let mut handle = EnqueueFlag::NotPossible;
        receptor.receive(Packet {
            handle: &mut handle,
            payload: &mut self.buffer,
        });

        Ok(1)
    }
}

fn io_error_to_layer(_: &io::Error) -> crate::layer::Error {
    // FIXME: not the best feed back.
    crate::layer::Error::Illegal 
}
