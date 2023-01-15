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
use core::num::{NonZeroU32, NonZeroU8};

use alloc::{boxed::Box, format, string::String, vec::Vec};

use bpf_lite::bpf::{BpfMapInfo, BpfProgInfo, BpfProgOut};
use bpf_lite::MapFd;
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
    InternalError,
}

pub struct AttachmentMap {
    main_prog: ChainedProg,
    main_map: XdpMap,
}

/// A file descriptor we have to close.
/// FIXME: when stable, use the `std` struct for this.
struct CloseFd(libc::c_int);

#[derive(Debug)]
pub struct Errno(libc::c_int);

impl Errno {
    pub(crate) fn new() -> Errno {
        Errno(unsafe { *libc::__errno_location() })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct AttachMode(NonZeroU8);

pub struct XdpMultiprog {
    main: Option<Box<XdpProg>>,
    prog: Vec<ChainedProg>,
    hw: Option<Box<XdpProg>>,
    dispatch_config: Box<XdpDispatcherConfig>,

    prog_info: IfindexProgInfo,
    num_links: usize,
    is_loaded: bool,
    ifindex: u32,
}

/// A program descriptor, with its loaded information.
pub struct XdpProg {
    fd: ProgramFd,
    config: Box<BpfProgInfo>,
    // The ids of maps attach to the program.
    maps: Vec<u32>,
}

pub struct XdpMap {
    map: MapFd,
    config: Box<BpfMapInfo>,
}

pub struct ChainedProg {
    prog: XdpProg,
    chain_call_actions: u32,
    run_prio: u32,
}

/// Reduced info from `XdpQuery` based on the attach mode.
#[derive(Clone, Copy)]
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
    pub fn attach(
        &self,
        interface: &IfInfo,
        xsk: libc::c_int,
    ) -> Result<AttachmentMap, AttachError> {
        // For a compile error when other methods are added.
        let XdpRxMethod::DefaultProgram = self;
        let systable = bpf_lite::sys::SysVTable::new();
        let mut netlink = Netlink::open(systable)?;
        let mut buffer = NetlinkRecvBuffer::new();

        let mut multiprog = XdpMultiprog::from_if(&mut netlink, &mut buffer, interface)?;
        multiprog.fill_from_fds(netlink.sys())?;

        let idx = Self::find_default_program(
            netlink.sys(),
            &multiprog,
            CStr::from_bytes_with_nul(b"xsk_def_prog\0").unwrap(),
            CStr::from_bytes_with_nul(b"xsk_prog_version\0").unwrap(),
        )?;

        let chained_prog = &mut multiprog.prog[idx];
        let mut chained_map = Self::lookup_bpf_map(netlink.sys(), chained_prog, &mut |info| {
            info.key_size == 4 && info.value_size == 4 && {
                if let Some(name_len) = info.name.iter().position(|&c| c == b'\0') {
                    info.name[..=name_len] == *b"xsks_map\0"
                } else {
                    false
                }
            }
        })?;

        // FIXME: there's some funky stuff with refcount going on in xdp-tools/libxdp. We don't
        // really do that right now and trust the environment. We shouln't.

        Self::update_map(netlink.sys(), &mut chained_map, interface, xsk)?;

        // Preserve the utilized state, from the BPF overview.
        let main_prog = multiprog.prog.remove(idx);
        Ok(AttachmentMap {
            main_prog,
            main_map: chained_map,
        })
    }

    fn find_default_program(
        bpf: &BpfSys,
        multiprog: &XdpMultiprog,
        prog_name: &CStr,
        version_name: &CStr,
    ) -> Result<usize, AttachError> {
        let (idx, program) = multiprog
            .prog
            .iter()
            .enumerate()
            .find_map(|(idx, chained)| {
                let name = chained.prog.name();

                if name == Some(prog_name) {
                    return Some((idx, chained));
                }

                None
            })
            .ok_or(AttachError::NoSuchProgram)?;

        // let version = Self::check_program_version(bpf, program, version_name)?;
        Ok(idx)
    }

    fn lookup_bpf_map(
        bpf: &BpfSys,
        chained: &mut ChainedProg,
        fn_: &mut dyn FnMut(&mut BpfMapInfo) -> bool,
    ) -> Result<XdpMap, AttachError> {
        let mut map_info = BpfMapInfo::default();

        for &map_id in chained.prog.get_maps(bpf)? {
            let map_id = match NonZeroU32::new(map_id) {
                None => continue,
                Some(nz) => nz,
            };

            let mut map = bpf.get_mapfd_by_id(map_id.into())?;
            bpf.get_mapfd_info_mut(&mut map, &mut map_info)?;

            if fn_(&mut map_info) {
                let config = Box::new(map_info);
                return Ok(XdpMap { map, config });
            }
        }

        Err(AttachError::NoSuchMap)
    }

    fn update_map(
        sys: &BpfSys,
        chained_map: &mut XdpMap,
        interface: &IfInfo,
        xsk: libc::c_int,
    ) -> Result<(), AttachError> {
        sys.map_update_element(&chained_map.map, &interface.queue_id(), &xsk)?;
        Ok(())
    }
}

impl XdpMultiprog {
    pub fn from_if(
        netlink: &mut Netlink,
        buffer: &mut NetlinkRecvBuffer,
        interface: &IfInfo,
    ) -> Result<Self, AttachError> {
        let prog_id = Self::get_ifindex_prog_id(netlink, buffer, interface.ifindex())?;
        let mut this = Self::from_ids(netlink.sys(), &prog_id, interface)?;
        Ok(this)
    }

    fn from_ids(
        bpf: &BpfSys,
        prog_info: &IfindexProgInfo,
        interface: &IfInfo,
    ) -> Result<Self, AttachError> {
        let main = NonZeroU32::new(prog_info.main_id)
            .map_or(Ok::<_, AttachError>(None), |nz| {
                let program = bpf.get_progfd_by_id(nz.into())?;
                Ok(Some(program))
            })?
            .map(|fd| XdpProg::new(bpf, fd))
            .transpose()?
            .map(Box::new);

        let hw = NonZeroU32::new(prog_info.hw_id)
            .map_or(Ok::<_, AttachError>(None), |nz| {
                let program = bpf.get_progfd_by_id(nz.into())?;
                Ok(Some(program))
            })?
            .map(|fd| XdpProg::new(bpf, fd))
            .transpose()?
            .map(Box::new);

        Ok(XdpMultiprog {
            main,
            prog: Vec::new(),
            dispatch_config: Box::new(XdpDispatcherConfig::default()),
            hw,
            num_links: 0,
            is_loaded: false,
            ifindex: interface.ifindex(),
            prog_info: prog_info.clone(),
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

                sys.map_lookup_element(&map_fd, &map_key, &mut *self.dispatch_config)?;

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
        use core::fmt::Write as _;

        struct BpfLock {
            dirfd: CloseFd,
        }

        impl BpfLock {
            fn new(bpffs: &mut String) -> Result<Self, AttachError> {
                // On success we'll truncate it back to this len (which includes nul-termination);
                let len = bpffs.len();
                assert!(len > 0);

                Self::mk_lock_dir(bpffs)?;
                let dir_path = CStr::from_bytes_with_nul(bpffs.as_bytes())
                    .map_err(|_| AttachError::InternalError)?;

                let dirfd = unsafe { libc::open(dir_path.as_ptr(), libc::O_DIRECTORY) };

                if dirfd < 0 {
                    return Err(AttachError::FdError(Errno::new()));
                }

                let dirfd = CloseFd(dirfd);

                if unsafe { libc::flock(dirfd.0, libc::LOCK_EX) } < 0 {
                    return Err(AttachError::FdError(Errno::new()));
                }

                bpffs.truncate(len);
                let _ = bpffs.pop();
                bpffs.push('\0');

                Ok(BpfLock { dirfd })
            }

            /// Create the state directory, modify bpffs to its path.
            fn mk_lock_dir(bpffs: &mut String) -> Result<(), AttachError> {
                // Remove nul-terminator.
                let _ = bpffs.pop();
                bpffs.push_str("/xdp\0");

                let state_subdir = CStr::from_bytes_with_nul(bpffs.as_bytes())
                    .map_err(|_| AttachError::InternalError)?;

                match unsafe { libc::mkdir(state_subdir.as_ptr(), libc::S_IRWXU) } {
                    0 => {}
                    _ if Errno::new().0 == libc::EEXIST => {}
                    _ => return Err(AttachError::FdError(Errno::new())),
                }

                Ok(())
            }
        }

        impl Drop for BpfLock {
            fn drop(&mut self) {
                let _ = unsafe { libc::flock(self.dirfd.0, libc::LOCK_UN) };
            }
        }

        const BPF_SYS_FS: &str = "/sys/fs/bpf";
        let mut path = format!("{}\0", BPF_SYS_FS);
        let _lock = BpfLock::new(&mut path);

        path.truncate(BPF_SYS_FS.len());
        write!(
            &mut path,
            "/xdp/dispatch-{ifi}-{prog}\0",
            ifi = self.ifindex,
            prog = self.prog_info.main_id,
        )
        .unwrap();

        let mut statbuf = core::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::stat(
                CStr::from_bytes_with_nul(path.as_bytes())
                    .map_err(|_| AttachError::InternalError)?
                    .as_ptr(),
                statbuf.as_mut_ptr(),
            )
        } < 0
        {
            return Err(AttachError::FdError(Errno::new()));
        }

        let dir_path_len = path.len() - 1;
        for i in 0..self.dispatch_config.num_progs_enabled {
            path.truncate(dir_path_len);
            write!(&mut path, "/prog{i}-prog\0", i = i).unwrap();

            let prog = sys.get_progfd_pinned(
                CStr::from_bytes_with_nul(path.as_bytes())
                    .map_err(|_| AttachError::InternalError)?,
            )?;

            self.prog.push(ChainedProg {
                prog: XdpProg::new(sys, prog)?,
                chain_call_actions: self.dispatch_config.chain_call_actions[usize::from(i)]
                    & !(1 << 31),
                run_prio: self.dispatch_config.run_prios[usize::from(i)],
            });
        }

        Ok(())
    }
}

impl XdpProg {
    pub fn new(sys: &BpfSys, fd: ProgramFd) -> Result<Self, AttachError> {
        let mut config = Box::new(BpfProgInfo::default());
        sys.get_progfd_info(&fd, &mut config, Default::default())?;

        Ok(XdpProg {
            fd,
            config,
            maps: Vec::new(),
        })
    }

    pub fn name(&self) -> Option<&CStr> {
        let end = self.config.name.iter().position(|&x| x == b'\0')?;
        CStr::from_bytes_with_nul(&self.config.name[..=end]).ok()
    }

    pub fn get_maps(&mut self, bpf: &BpfSys) -> Result<&[u32], AttachError> {
        if self.config.nr_map_ids as usize <= self.maps.len() {
            return Ok(self.maps.as_slice());
        }

        self.maps.resize(self.config.nr_map_ids as usize, 0);
        bpf.get_progfd_info(&self.fd, &mut self.config, {
            let mut out = BpfProgOut::default();
            out.map_ids = Some(&mut self.maps[..]);
            out
        })?;

        Ok(self.maps.as_slice())
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

impl Drop for CloseFd {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.0) };
    }
}

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
