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
use core::mem;
#[cfg(feature = "std")]
use std::{io, ptr};
#[cfg(feature = "std")]
use std::os::unix::io::RawFd;

use libc;
use crate::time::Instant;
#[cfg(feature = "std")]
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
    #[cfg(feature = "std")]
    pub use super::wait as sys_wait;
    pub use super::Errno;
}

#[cfg(feature = "std")]
/// Wait until given file descriptor becomes readable, but no longer than given timeout.
pub fn wait(fd: RawFd, duration: Option<Duration>) -> Result<(), Errno> {
    let mut readfds;

    unsafe {
        let mut readfds_init = mem::MaybeUninit::<libc::fd_set>::uninit();
        libc::FD_ZERO(readfds_init.as_mut_ptr());
        libc::FD_SET(fd, readfds_init.as_mut_ptr());
        readfds = readfds_init.assume_init();
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

    FdResult(res).errno()
}

/// An errno value.
///
/// This is used as the error representation of raw libc calls. It can be converted into a
/// `std::io::Error` when the `std` feature is enabled, where it will consequently have much more
/// extensive error information.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Errno(pub libc::c_int);

#[derive(Clone, Copy)]
struct FdResult(pub libc::c_int);

#[derive(Clone, Copy)]
struct IoLenResult(pub libc::ssize_t);

#[derive(Clone, Copy)]
struct ClockResult(pub libc::c_int);

type IoctlResult = FdResult;
#[allow(non_snake_case)] // Emulate type alias also importing constructor.
fn IoctlResult(val: libc::c_int) -> IoctlResult { FdResult(val) }

/// Base for an if ioctl request.
///
/// Contains the name of the interface.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct ifreq {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
}

/// Trait for interpreting integer return values.
///
/// Failure signals may vary between:
/// * `-1`
/// * arbitrary negative values
/// * non-zero
trait LibcResult: Copy {
    fn is_fail(self) -> bool;

    fn errno(self) -> Result<(), Errno> {
        if self.is_fail() {
            Err(Errno::new())
        } else {
            Ok(())
        }
    }
}

impl Errno {
    pub fn new() -> Errno {
        Errno(unsafe { *libc::__errno_location() })
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

impl LibcResult for ClockResult {
    fn is_fail(self) -> bool {
        self.0 == -1
    }
}

#[cfg(feature = "std")]
impl From<Errno> for io::Error {
    fn from(err: Errno) -> io::Error {
        io::Error::from_raw_os_error(err.0 as i32)
    }
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

fn now() -> Result<Instant, Errno> {
   let ts = unsafe {
       let mut ts = mem::MaybeUninit::<libc::timespec>::uninit();
       let res = libc::clock_gettime(libc::CLOCK_MONOTONIC, ts.as_mut_ptr());

       ClockResult(res).errno()?;

       ts.assume_init()
   };

   Ok(Instant::from_millis(ts.tv_sec*1000 + ts.tv_nsec/1000_000))
}
