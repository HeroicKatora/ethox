#![allow(unsafe_code)]
// Copyright (C) 2016 whitequark@whitequark.org
// Copyright (C) 2019 Andreas Molzer <andreas.molzer@tum.de>
//
// in large parts from `smoltcp` originally distributed under 0-clause BSD
//
// Applies to files in this folder unless otherwise noted. These are:
// * `bpf.rs`
// * `linux.rs`
// * `mod.rs`
// * `raw_socket.rs`
// * `tap_interface.rs`
use std::{mem, ptr, io};
use std::os::unix::io::RawFd;

use libc;
use crate::time::Duration;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
mod raw_socket;
#[cfg(target_os = "linux")]
mod tap_interface;

/// Module importing all types that should be exported.
///
/// Allows keeping all the `cfg` bits inside this module by enabling a controlled glob import from
/// the super module.
pub mod exports {
    #[cfg(target_os = "linux")]
    pub use super::tap_interface::{TapInterface, TapInterfaceDesc};
    #[cfg(target_os = "linux")]
    pub use super::raw_socket::{RawSocket, RawSocketDesc};
}

/// Wait until given file descriptor becomes readable, but no longer than given timeout.
pub fn wait(fd: RawFd, duration: Option<Duration>) -> io::Result<()> {
    let mut readfds;

    unsafe {
        readfds = mem::uninitialized::<libc::fd_set>();
        libc::FD_ZERO(&mut readfds);
        libc::FD_SET(fd, &mut readfds);
    }

    let mut timeout = libc::timeval { tv_sec: 0, tv_usec: 0 };
    let timeout = duration.map(|duration| {
        timeout.tv_usec = duration.as_micros() as libc::suseconds_t;
        &mut timeout
    });

    let timeout_ptr = timeout
        .map(|reference| reference as *mut _)
        .unwrap_or_else(ptr::null_mut);

    let res = unsafe {
        libc::select(
            fd + 1,
            &mut readfds,
            ptr::null_mut(),
            ptr::null_mut(),
            timeout_ptr)
    };

    test_result(FdResult(res))
}

#[derive(Clone, Copy)]
struct FdResult(pub libc::c_int);

#[derive(Clone, Copy)]
struct IoLenResult(pub libc::ssize_t);

type IoctlResult = FdResult;
#[allow(non_snake_case)] // Emulate type alias also importing constructor.
fn IoctlResult(val: libc::c_int) -> IoctlResult { FdResult(val) }

trait LibcResult: Copy {
    fn is_fail(self) -> bool;
}

fn test_result(ret: impl LibcResult) -> io::Result<()> {
    if ret.is_fail() {
        Err(io::Error::last_os_error()) 
    } else {
        Ok(())
    }
}

impl LibcResult for FdResult {
    fn is_fail(self) -> bool {
        self.0 == -1
    }
}

impl LibcResult for IoLenResult {
    fn is_fail(self) -> bool {
        self.0 == -1
    }
}

/// Base for an if ioctl request.
///
/// Contains the name of the interface.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct ifreq {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
}

impl ifreq {
    fn new(name: &str) -> Self {
        let mut ifr_name = [0; libc::IF_NAMESIZE];

        for (i, byte) in name.as_bytes().iter().enumerate() {
            ifr_name[i] = *byte as libc::c_char
        }

        ifreq {
            ifr_name,
        }
    }
}

