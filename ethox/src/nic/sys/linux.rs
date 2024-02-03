// Copyright (C) 2016 whitequark@whitequark.org
// Copyright (C) 2019 Andreas Molzer <andreas.molzer@tum.de>
//
// in large parts from `smoltcp` originally distributed under 0-clause BSD
use super::{ifreq, Errno, LibcResult, IoctlResult};
use libc;

pub(crate) const ETH_P_ALL:    libc::c_short = 0x0003;

/// Adds a method to open a tap.
///
/// This is an extension trait implemented for `ifreq` in Linux.
pub(crate) trait TunSetIf {
    /// Attach to an existing interface or create a new one.
    fn tun_set_if(&mut self, fd: libc::c_int, kind: libc::c_int) -> Result<(), Errno>;

    /// Convenience method over`set_if` when `kind` is a tap.
    fn tun_set_tap(&mut self, fd: libc::c_int) -> Result<(), Errno>;
}

/// Adds a method to interact with the mtu.
pub(crate) trait NetdeviceMtu {
    fn get_mtu(&mut self, fd: libc::c_int) -> Result<libc::c_int, Errno>;
}

pub(crate) trait IfIndex {
    fn get_if_index(&mut self, fd: libc::c_int) -> Result<libc::c_int, Errno>;
}

impl ifreq {
    pub(crate) const SIOCGIFMTU:   libc::Ioctl = 0x8921;
    pub(crate) const SIOCGIFINDEX: libc::Ioctl = 0x8933;

    pub(crate) const TUNSETIFF:    libc::Ioctl = 0x400454CA;
    pub(crate) const IFF_TAP:      libc::c_int  = 0x0002;
    pub(crate) const IFF_NO_PI:    libc::c_int  = 0x1000;
}

impl TunSetIf for ifreq {
    fn tun_set_if(&mut self, fd: libc::c_int, kind: libc::c_int) -> Result<(), Errno> {
        #[repr(C)]
        #[derive(Debug)]
        struct Request {
            interface: ifreq,
            kind: libc::c_int,
        }

        let mut request = Request {
            interface: *self,
            kind,
        };

        let res = unsafe {
            libc::ioctl(fd, Self::TUNSETIFF, &mut request as *mut _)
        };

        IoctlResult(res).errno()?;

        Ok(())
    }

    fn tun_set_tap(&mut self, fd: libc::c_int) -> Result<(), Errno> {
        self.tun_set_if(fd, Self::IFF_TAP | Self::IFF_NO_PI)
    }
}

impl NetdeviceMtu for ifreq {
    fn get_mtu(&mut self, fd: libc::c_int) -> Result<libc::c_int, Errno> {
        #[repr(C)]
        struct Request {
            interface: ifreq,
            ifr_mtu: libc::c_int,
        }

        let mut request = Request {
            interface: *self,
            ifr_mtu: 0,
        };

        let res = unsafe {
            libc::ioctl(fd, Self::SIOCGIFMTU, &mut request as *mut _)
        };

        IoctlResult(res).errno()?;

        Ok(request.ifr_mtu)
    }
}

impl IfIndex for ifreq {
    fn get_if_index(&mut self, fd: libc::c_int) -> Result<libc::c_int, Errno> {
        #[repr(C)]
        struct Request {
            interface: ifreq,
            ifr_ifindex: libc::c_int,
        }

        let mut request = Request {
            interface: *self,
            ifr_ifindex: 0,
        };

        let res = unsafe {
            libc::ioctl(fd, Self::SIOCGIFINDEX, &mut request as *mut _)
        };

        IoctlResult(res).errno()?;

        Ok(request.ifr_ifindex)
    }
}
