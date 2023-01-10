use xdpilone::Errno;

#[repr(u32)]
pub enum BpfCmd {
    MapCreate,
    MapLookupElem,
    MapUpdateElem,
    MapDeleteElem,
    MapGetNextKey,
    ProgLoad,
    ObjPin,
    ObjGet,
    ProgAttach,
    ProgDetach,
    ProgTestRun,
    ProgGetNextId,
    MapGetNextId,
    ProgGetFdById,
    MapGetFdById,
    ObjGetInfoByFd,
    ProgQuery,
    RawTracepointOpen,
    BtfLoad,
    BtfGetFdById,
    TaskFdQuery,
    MapLookupAndDeleteElem,
    MapFreeze,
    BtfGetNextId,
    MapLookupBatch,
    MapLookupAndDeleteBatch,
    MapUpdateBatch,
    MapDeleteBatch,
    LinkCreate,
    LinkUpdate,
    LinkGetFdById,
    LinkGetNextId,
    EnableStats,
    IterCreate,
    LinkDetach,
    ProgBindMap,
}

#[repr(C)]
pub struct BpfProgQuery {
    pub target_fd: u32,
    pub attach_type: u32,
    pub query_flags: u32,
    pub attach_flags: u32,
    /// Pointer to a buffer for prog ids, must be aligned.
    /// Kernel assumes it to be valid for `prog_cnt` elements on entry.
    pub prog_ids: *mut u64,
    pub prog_cnt: u32,
}

#[repr(C)]
pub struct BpfGetId {
    #[doc(
        alias = "prog_id",
        alias = "start_id",
        alias = "map_id",
        alias = "btf_id",
        alias = "link_id"
    )]
    pub id: u32,
    pub next_id: u32,
    pub open_flags: u32,
}

impl BpfCmd {
    #[allow(non_upper_case_globals)]
    const BpfProgRun: Self = Self::ProgTestRun;
}

/// Do the `bpf` syscall.
///
/// The caller guarantees that their arguments conform to the expected pointers, i.e. the cmd type
/// dictates the layout for `attr` and expected size.
unsafe fn sys_bpf(cmd: libc::c_long, attr: *mut libc::c_void, size: libc::c_ulong) -> libc::c_long {
    return libc::syscall(libc::SYS_bpf, cmd, attr, size);
}

impl Default for BpfProgQuery {
    fn default() -> Self {
        BpfProgQuery {
            target_fd: 0,
            attach_type: 0,
            query_flags: 0,
            attach_flags: 0,
            prog_ids: core::ptr::null_mut(),
            prog_cnt: 0,
        }
    }
}

impl BpfProgQuery {
    pub fn init(ifindex: u32) -> Result<Self, Errno> {
        todo!()
    }

    pub fn query(&mut self, buf: &mut [u64]) -> Result<(), Errno> {
        let prog_cnt = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let size = core::mem::size_of_val(self) as libc::c_ulong;

        self.prog_ids = buf.as_mut_ptr();
        self.prog_cnt = prog_cnt;

        if unsafe {
            sys_bpf(
                BpfCmd::ProgQuery as libc::c_long,
                (self) as *mut _ as *mut libc::c_void,
                size,
            )
        } < 0
        {
            return Err(Errno::new());
        };

        Ok(())
    }
}
