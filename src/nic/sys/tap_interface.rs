// Copyright (C) 2016 whitequark@whitequark.org
// Copyright (C) 2019 Andreas Molzer <andreas.molzer@tum.de>
//
// in large parts from `smoltcp` originally distributed under 0-clause BSD
use std::io;
use std::os::unix::io::{RawFd, AsRawFd};

use libc;
use super::{FdResult, IoLenResult, ifreq, test_result};

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

impl AsRawFd for TapInterfaceDesc {
    fn as_raw_fd(&self) -> RawFd {
        self.lower
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

impl Drop for TapInterfaceDesc {
    fn drop(&mut self) {
        unsafe { libc::close(self.lower); }
    }
}
