pub struct Umem;
pub struct Rx;
pub struct Tx;

impl Umem {
}

pub struct Key;

pub struct SinglePool {
    umem: Umem,
}

/// A pool distributes the `Umem` slots.
///
/// When we give a buffer kernel it removes it from the user-space available buffers, while
/// providing us with a unique access key (not quite ghost-cell). All with `&self` and shared
/// between packet buffers.
pub(crate) trait PoolStrategy {
    /// Get a key, only for this pool.
    fn alloc(&self) -> Option<Key>;
    /// Give back a key.
    fn dealloc(&self, _: Key);
    /// Mark key as donated to the kernel.
    fn donate_to_kernel(&self, _: Key);
    /// Mark key as having been returned by the kernel.
    fn repossess_from_kernel(&self, _: Key);
    /// Block until keys are back from the kernel.
    /// Loops with the callback until that is the case. It may poll the kernel to try to repossess
    /// additional buffers. If it panics, then the process abort. 
    fn block_on(&self, _: &mut dyn FnMut(&dyn PoolStrategy));
}

/// An owned collection of packets from a pool.
pub(crate) struct Buffer<Pool: PoolStrategy> {
    pool: Pool,
}
