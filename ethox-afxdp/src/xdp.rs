//! Specify and implement how we treat XDP receive.
//!
//! As part of receive operation we _must_ setup an XDP program at each device. Note: per-device
//! and _not_ per-queue. If there are multiple queues on a device then there is only one program.
//! That program routes packages to the right XSK queue.
//!
//! The implementation tries to do as little as possible. We don't create a program, but we offer
//! some primitive mechanism to insert the current FD into an existing program. The prominent way
//! being that a file descriptor is inserted into a map, keyed but the queue ID.
use core::ffi::CStr;
use crate::bpf;

use xdpilone::{xsk::IfInfo, Errno};

pub enum XdpRxMethod {
    /// Attach to the xdp-tools/XSK default program.
    ///
    /// Will search this program in the chain attached to the device, find the suitable `xsk_map`
    /// for the file descriptors and insert the file descriptor at the queue index.
    DefaultProgram,
}

#[derive(Debug)]
pub enum AttachError {
    NoSuchProgram,
    ProgramVersionTooHigh,
    NoSuchMap,
    FdError(Errno),
}

/// A file descriptor we have to close.
/// FIXME: when stable, use the `std` struct for this.
struct CloseFd(libc::c_int);

pub struct XdpMapFd {
    /// The *owned* file descriptor for an XDP program attached to a device.
    prog_fd: CloseFd,
}

impl XdpRxMethod {
    pub fn attach(self, interface: &IfInfo) -> Result<XdpMapFd, AttachError> {
        // For a compile error when other methods are added.
        let XdpRxMethod::DefaultProgram = self;

        todo!()
    }

    fn find_default_program(
        interface: &IfInfo,
        prog_name: &CStr,
        version_name: &CStr,
    ) -> Result<CloseFd, AttachError> {
        let idx = interface.ifindex();
        todo!()
    }
}

impl Drop for CloseFd {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.0) };
    }
}

pub fn xdp_multiprog__get_from_ifindex() {}
pub fn xdp_multiprog__next_prog() {}
pub fn xdp_multiprog__from_fd() {}
pub fn xdp_multiprog__fill_from_fd() {}
pub fn xdp_multiprog__from_id() {}
pub fn xdp_multiprog__close() {}

pub fn xdp_program__from_fd() {}
pub fn xdp_program__name() {}
pub fn xdp_program__bpf() {}
pub fn xdp_program__clone() {}
pub fn xdp_program__close() {}
