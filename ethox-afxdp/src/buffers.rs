//! Buffer management, logical core.
use alloc::{collections::VecDeque, vec::Vec};

/// An owning index of a buffer in the `Umem`.
///
/// This owns a whole buffer, with the size used in the construction configuration of the umem
/// ring. For calls that require a distinct length (sent by transmit, received from receive) the
/// structure `Buffer` is used instead.
///
/// This is a unique token on this ring, you can't *safely* get access to a copy.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OwnedBuf(pub(crate) u32);

/// Our owned state reflecting the queue metadata (number of buffers, WIP: expected latency) that
/// we cached. This is also the state machine core that decides which buffers to move where.
///
/// This struct's purpose as separate from `AfXdp` is two-fold. Making management a sans-IO module
/// allows us to test the logic, in particular liveness and other invariants more easily. Secondly,
/// we can take a mutable borrow without borrowing the XDP device handles.
pub struct BufferManagement {
    /// Free buffers with no assigned use.
    free: VecDeque<OwnedBuf>,

    /// Number of packet buffers to reserve for receive.
    watermark_rx: usize,
    /// The target of packet buffers in the fill queue we aim for.
    ///
    /// A higher target keeps the queue filled under receive pressure but consumes more buffers
    /// that could be utilized elsewhere.
    target_rx: usize,
    /// Number of packet buffers to reserve for transmission.
    watermark_tx: usize,
    /// The target of packet buffers in the transmit queue we aim for.
    ///
    /// A higher target allows more packets to be queued, increasing latency while allowing for
    /// larger bursts. Also, the buffers consumed are not available elsewhere.
    target_tx: usize,

    /// Packets currently in the RX system (>=watermark_rx).
    current_rx: usize,
    /// Packets currently in the TX system (>=watermark_tx).
    current_tx: usize,

    // Buffer tracking of free float.
    /// Number of essential RX buffers in the free state.
    essential_free_rx: usize,
    /// Number of essential TX buffers in the free state.
    essential_free_tx: usize,
}

/// Reference to some buffers that may be transmitted.
pub struct TxLease<'lt> {
    free: &'lt mut VecDeque<OwnedBuf>,
    /// Number of buffers available to transmit.
    capacity: usize,
}

/// Reference to some buffers that have been received.
pub struct RxLease<'lt> {
    free: &'lt mut VecDeque<OwnedBuf>,
    /// Number of buffers that need not be preserved in Rx.
    rx_omit: usize,
}

/// Reference to some buffers that have been completed.
pub struct CqLease<'lt> {
    free: &'lt mut VecDeque<OwnedBuf>,
    /// Number of buffers that need not be preserved in Tx.
    non_essential: usize,
}

/// Reference to some buffers that can be filled with received data.
pub struct FqLease<'lt> {
    free: &'lt mut VecDeque<OwnedBuf>,
    /// Number of buffers available in the queue.
    capacity: usize,
}

/// Buffer management operations.
///
/// All operations should ensure our local liveness properties:
/// * Assuming the network card will eventually transmit queued packet and put them into the
///   completion queue then:
/// * Eventually some buffers are available for the fill queue (i.e. currently inserted or in the
///   `pending_fx` buffer).
/// * Eventually a call to `tx` can enqueue at least one buffer.
///
/// This is maintained by treating rx&tx as two separate systems of buffers, with some auxiliary
/// buffers floating freely between the two. This is _not_ optimal for latency. The pending
/// transmit queues might still grow large of receive packets sparse if all floating buffers are in
/// one of the two systems (especially if multiple sockets are involved). But real-time with small
/// guarantees is better than none.
///
/// It follows that, in the current implementation, the total number of buffers should not exceed
/// `PENDING_LEN` as this many buffers could be put into any queue. Packets would need to be
/// assigned as free floating buffers otherwise, dropping any egress or ingress content they have.
/// Not incorrect, but very inconvenient.
///
/// Invariants to uphold everywhere:
/// * Number of buffers in `free`, `pending_fx`, and the fill queue is at least `watermark_rx`.
/// * Number of buffers in `free`, `pending_tx`, and the completion queue is at least `watermark_tx`.
impl BufferManagement {
    pub fn new(free: Vec<OwnedBuf>) -> Self {
        BufferManagement {
        free: free.into_iter().collect(),
        watermark_rx: 16,
        target_rx: 32,
        watermark_tx: 16,
        target_tx: 32,
        current_rx: 0,
        current_tx: 0,
        essential_free_rx: 16,
        essential_free_tx: 16,
    }
    }

    /// Cleanup the receive queue.
    ///
    /// Other packets are set aside into our fill queue. Note: sending as an 'instant response' is
    /// not guaranteed! The implementation should inspect the handles in a smarter way to avoid us
    /// dropping a retransmit here.
    ///
    /// Postcondition:
    /// * `queue_rx` is empty.
    fn post_rx(&mut self) {
        // How many packets can leave the RX loop? These all come from the fill queue.
        let spill = self.current_rx.saturating_sub(self.watermark_rx);
        let essential = self.current_rx - spill;
        // Essential packets are reserved for RX tasks.
        self.essential_free_rx += essential;
        // All other packets leave the RX assignment and are floating again.
        self.current_rx -= spill;

        // None of the packets are allowed to get sent (these packets leave the RX system).
        if spill == 0 {
            todo!();
            return;
        }

        let mut tx = 0;
        todo!();

        self.current_tx += tx;
    }

    /// Cleanup the transmit queue according to handles.
    ///
    /// Other packets are set aside into our fill queue.
    /// * `queue_tx` is empty.
    fn post_tx(&mut self) {
        let mut freed = 0;
        todo!();

        // Number of essential packets freed.
        let float = self.watermark_tx.saturating_sub(self.current_tx - freed);
        self.current_tx -= freed;
        self.essential_free_tx += float;
    }

    /// Prepare to receive some buffers, potentially rerouting them directly.
    pub fn pre_rx(&mut self, available: u32) -> RxLease<'_> {
        // Buffers are `current_rx`.
        todo!()
    }

    /// Prepare some buffers from the free floating buffer.
    ///
    /// Precondition:
    /// `self.queue_rx` is empty.
    pub fn pre_tx(&mut self, max: u32) -> TxLease<'_> {
        // We reserve the tx buffers into the lease.
        debug_assert!(self.essential_free_rx + self.essential_free_tx <= self.free.len());
        let capacity = (self.free.len() - self.essential_free_rx).min(max as usize);
        // Essential buffers are removed 'first'.
        self.essential_free_tx = self.essential_free_tx.saturating_sub(capacity);
        self.current_tx += capacity;
        debug_assert!(self.essential_free_rx + self.essential_free_tx <= self.free.len());

        TxLease {
            free: &mut self.free,
            capacity,
        }
    }

    /// Prepare to complete some buffers, potentially rerouting them directly.
    pub fn pre_cq(&mut self, available: usize) -> CqLease<'_> {
        // Buffers are `current_tx`. How many to keep this way?
        debug_assert!(self.watermark_tx >= self.essential_free_tx);
        let missing = self.watermark_tx - self.essential_free_tx;
        // Ensure that at least the lower watermark is preserved.
        debug_assert!(self.current_tx >= missing);
        let non_essential = self.current_tx - missing;

        CqLease {
            free: &mut self.free,
            non_essential,
        }
    }

    /// Prepare some buffers from the free buffers for the fill queue.
    pub fn pre_fq(&mut self, max: usize) -> FqLease<'_> {
        debug_assert!(self.essential_free_rx + self.essential_free_tx <= self.free.len());
        let capacity = (self.free.len() - self.essential_free_rx - self.essential_free_tx).min(max);

        FqLease {
            free: &mut self.free,
            capacity,
        }
    }

    /// Gather packet buffers from the completion queue.
    fn periodic_reap_cq(&mut self) -> usize {
        todo!()
    }

    /// Gather some free packet buffers into the fill queue.
    ///
    /// Call this eventually after buffers from the fill queue have been consumed. Never consumes
    /// too many packets to starve the transmit queue.
    fn periodic_reap_fq(&mut self) -> usize {
        debug_assert!(self.essential_free_rx + self.essential_free_tx <= self.free.len());
        todo!();
    }
}

impl TxLease<'_> {
    pub fn skip(&mut self) {
        debug_assert!(self.capacity > 0);
        self.capacity -= 1;
        let buf = self.free.pop_front().unwrap();
        self.free.push_back(buf);
    }

    pub fn pop_buf(&mut self) -> OwnedBuf {
        debug_assert!(self.capacity > 0);
        self.capacity -= 1;
        self.free.pop_front().unwrap()
    }
}
