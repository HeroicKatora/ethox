// Copyright (C) 2016 whitequark@whitequark.org
// Copyright (C) 2019 Andreas Molzer <andreas.molzer@tum.de>
//
// in large parts from `smoltcp` originally distributed under 0-clause BSD
use std::{mem, io};
use std::os::unix::io::{RawFd, AsRawFd};

use libc;
use super::{ifreq, linux, test_result, FdResult, IoLenResult};

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

impl AsRawFd for RawSocketDesc {
    fn as_raw_fd(&self) -> RawFd {
        self.lower
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

impl Drop for RawSocketDesc {
    fn drop(&mut self) {
        unsafe { libc::close(self.lower); }
    }
}
