//! Specify and implement how we treat XDP receive.
//!
//! As part of receive operation we _must_ setup an XDP program at each device. Note: per-device
//! and _not_ per-queue. If there are multiple queues on a device then there is only one program.
//! That program routes packages to the right XSK queue.
//!
//! The implementation tries to do as little as possible. We don't create a program, but we offer
//! some primitive mechanism to insert the current FD into an existing program. The prominent way
//! being that a file descriptor is inserted into a map, keyed but the queue ID.
use alloc::{boxed::Box, vec::Vec};
use core::ffi::CStr;
use core::num::{NonZeroU32, NonZeroU8};

use bpf_lite::bpf::{BpfMapInfo, BpfProgInfo, BpfProgOut};
use bpf_lite::{sys::ArcTable as BpfSys, Netlink, NetlinkRecvBuffer, ProgramFd};
use xdpilone::xsk::IfInfo;

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
    UnknownAttachMode,
    NoLegacySupport,
    BadProgConfigMap,
}

/// A file descriptor we have to close.
/// FIXME: when stable, use the `std` struct for this.
struct CloseFd(libc::c_int);

#[derive(Debug)]
pub struct Errno(libc::c_int);

pub struct XdpMapFd {
    /// The *owned* file descriptor for an XDP program attached to a device.
    prog_fd: CloseFd,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct AttachMode(NonZeroU8);

pub struct XdpMultiprog {
    main: Option<Box<XdpProg>>,
    prog: Vec<XdpProg>,
    hw: Option<Box<XdpProg>>,
    attach_mode: Option<AttachMode>,
    dispatch_config: Box<XdpDispatcherConfig>,
    num_links: usize,
    is_loaded: bool,
    ifindex: u32,
}

pub struct XdpProg {
    fd: ProgramFd,
}

/// Temporary struct, reduced info from `XdpQuery` based on the attach mode.
struct IfindexProgInfo {
    main_id: u32,
    hw_id: u32,
    attach_mode: Option<AttachMode>,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct XdpDispatcherConfig {
    pub num_progs_enabled: u8,
    pub chain_call_actions: [u32; Self::MAX_DISPATCHER_ACTIONS],
    pub run_prios: [u32; Self::MAX_DISPATCHER_ACTIONS],
}

unsafe impl bytemuck::Zeroable for XdpDispatcherConfig {}
unsafe impl bytemuck::AnyBitPattern for XdpDispatcherConfig {}

impl XdpRxMethod {
    pub fn attach(&self, interface: &IfInfo) -> Result<XdpMapFd, AttachError> {
        // For a compile error when other methods are added.
        let XdpRxMethod::DefaultProgram = self;
        let systable = bpf_lite::sys::SysVTable::new();
        let mut netlink = Netlink::open(systable)?;
        let mut buffer = NetlinkRecvBuffer::new();

        let mut multiprog = XdpMultiprog::from_if(&mut netlink, &mut buffer, interface)?;
        multiprog.fill_from_fds(netlink.sys())?;

        todo!()
    }

    fn find_default_program(
        netlink: &mut Netlink,
        interface: &IfInfo,
        prog_name: &CStr,
        version_name: &CStr,
    ) -> Result<CloseFd, AttachError> {
        let idx = interface.ifindex();
        todo!()
    }
}

impl XdpMultiprog {
    pub fn from_if(
        netlink: &mut Netlink,
        buffer: &mut NetlinkRecvBuffer,
        interface: &IfInfo,
    ) -> Result<Self, AttachError> {
        let prog_id = Self::get_ifindex_prog_id(netlink, buffer, interface.ifindex())?;
        let mut this = Self::from_ids(netlink.sys(), prog_id.main_id, prog_id.hw_id, interface)?;
        this.attach_mode = prog_id.attach_mode;
        Ok(this)
    }

    pub fn from_ids(
        bpf: &BpfSys,
        id: u32,
        hw_id: u32,
        interface: &IfInfo,
    ) -> Result<Self, AttachError> {
        let main = NonZeroU32::new(id)
            .map_or(Ok::<_, AttachError>(None), |nz| {
                let program = bpf.get_progfd_by_id(nz.into())?;
                Ok(Some(program))
            })?
            .map(XdpProg::from_raw);

        let hw = NonZeroU32::new(hw_id)
            .map_or(Ok::<_, AttachError>(None), |nz| {
                let program = bpf.get_progfd_by_id(nz.into())?;
                Ok(Some(program))
            })?
            .map(XdpProg::from_raw);

        Ok(XdpMultiprog {
            main,
            prog: Vec::new(),
            dispatch_config: Box::new(XdpDispatcherConfig::default()),
            hw,
            num_links: 0,
            is_loaded: false,
            ifindex: interface.ifindex(),
            attach_mode: None,
        })
    }

    fn get_ifindex_prog_id(
        netlink: &mut Netlink,
        buffer: &mut NetlinkRecvBuffer,
        ifindex: u32,
    ) -> Result<IfindexProgInfo, AttachError> {
        let xdp = netlink.xdp_query(ifindex, buffer)?;
        let attach_mode = AttachMode::new(xdp.attach_mode);
        let (main_id, hw_id);
        match attach_mode {
            Some(AttachMode::DRV) => {
                main_id = xdp.drv_prog_id;
                hw_id = 0;
            }
            Some(AttachMode::SKB) => {
                main_id = xdp.skb_prog_id;
                hw_id = 0;
            }
            Some(AttachMode::HW) => {
                main_id = 0;
                hw_id = xdp.hw_prog_id;
            }
            // FIXME: support multi. Differentiate between attach mode returned by XDP and the
            // effective one to use. I.e. libxdp will try DRV if non-zero then SKB and otherwise
            // unspecified mode (None).
            _ => return Err(AttachError::UnknownAttachMode),
        }

        Ok(IfindexProgInfo {
            hw_id,
            main_id,
            attach_mode,
        })
    }

    fn fill_from_fds(&mut self, sys: &BpfSys) -> Result<(), AttachError> {
        let mut prog_info = BpfProgInfo::default();
        let mut map_info = BpfMapInfo::default();

        'main: {
            if let Some(main) = &self.main {
                let mut map_ids = [0u32; 1];
                sys.get_progfd_info(&main.fd, &mut prog_info, {
                    let mut out = BpfProgOut::default();
                    out.map_ids = Some(&mut map_ids[..]);
                    out
                })?;

                if prog_info.btf_id == 0 {
                    break 'main;
                }

                // FIXME: btf__load_from_kernel_by_id
                // err = check_dispatcher_version(info.name, btf);

                if prog_info.nr_map_ids != 1 {
                    return Err(AttachError::NoSuchMap);
                }

                let map_id = NonZeroU32::new(map_ids[0]).ok_or(AttachError::NoSuchMap)?;
                let mut map_fd = sys.get_mapfd_by_id(map_id.into())?;

                sys.get_mapfd_info_mut(&mut map_fd, &mut map_info)?;

                let map_key = 0u32;
                if map_info.key_size != core::mem::size_of_val(&map_key) as u32
                    || map_info.value_size != core::mem::size_of_val(&*self.dispatch_config) as u32
                {
                    return Err(AttachError::BadProgConfigMap);
                }

                sys.lookup_map_element(&map_fd, &map_key, &mut *self.dispatch_config)?;

                // FIXME: bpf_map_lookup_elem
                self.link_pinned_progs(sys)?;
            }
        }

        if let Some(_) = self.hw {
            if self.prog.is_empty() {
                return Err(AttachError::NoLegacySupport);
            }
        }

        self.is_loaded = true;

        Ok(())
    }

    fn link_pinned_progs(&mut self, sys: &BpfSys) -> Result<(), AttachError> {
        todo!()
    }
}

impl XdpDispatcherConfig {
    const MAX_DISPATCHER_ACTIONS: usize = 10;
}

impl AttachMode {
    pub const ATTACHED_DRV: u8 = 1;
    pub const ATTACHED_SKB: u8 = 2;
    pub const ATTACHED_HW: u8 = 3;
    pub const ATTACHED_MULTI: u8 = 4;

    pub const DRV: Self = Self::ensure_mode(AttachMode::new(Self::ATTACHED_DRV));
    pub const SKB: Self = Self::ensure_mode(AttachMode::new(Self::ATTACHED_SKB));
    pub const HW: Self = Self::ensure_mode(AttachMode::new(Self::ATTACHED_HW));

    pub const fn new(id: u8) -> Option<Self> {
        if !matches!(
            id,
            Self::ATTACHED_DRV | Self::ATTACHED_SKB | Self::ATTACHED_HW | Self::ATTACHED_MULTI
        ) {
            return None;
        }

        match NonZeroU8::new(id) {
            None => None,
            Some(id) => Some(AttachMode(id)),
        }
    }

    const fn ensure_mode(mode: Option<AttachMode>) -> Self {
        match mode {
            Some(mode) => mode,
            None => panic!("Compile error"),
        }
    }
}

impl XdpProg {
    fn from_raw(fd: ProgramFd) -> Box<Self> {
        Box::new(XdpProg { fd })
    }
}

impl Drop for CloseFd {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.0) };
    }
}

pub fn xdp_program__from_fd() {}
pub fn xdp_program__name() {}
pub fn xdp_program__bpf() {}
pub fn xdp_program__clone() {}
pub fn xdp_program__close() {}

impl From<xdpilone::Errno> for Errno {
    fn from(err: xdpilone::Errno) -> Self {
        Errno(err.get_raw())
    }
}

impl From<bpf_lite::Errno> for Errno {
    fn from(err: bpf_lite::Errno) -> Self {
        Errno(err.get_raw())
    }
}

impl From<xdpilone::Errno> for AttachError {
    #[track_caller]
    fn from(err: xdpilone::Errno) -> Self {
        AttachError::FdError(err.into())
    }
}

impl From<bpf_lite::Errno> for AttachError {
    #[track_caller]
    fn from(err: bpf_lite::Errno) -> Self {
        AttachError::FdError(err.into())
    }
}
