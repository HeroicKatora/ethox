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
