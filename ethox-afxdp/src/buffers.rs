//! Buffer management, logical core.
use alloc::{collections::VecDeque, vec::Vec};

use crate::Buffer;

/// An owning index of a buffer in the `Umem`.
///
/// This owns a whole buffer, with the size used in the construction configuration of the umem
/// ring. For calls that require a distinct length (sent by transmit, received from receive) the
/// structure `Buffer` is used instead.
///
/// This is a unique token on this ring, you can't *safely* get access to a copy.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OwnedBuf(pub(crate) u32);

// FIXME: use impl-type alias?
type PktCtr = u32;

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
    lowmark_rx: PktCtr,
    /// The target of packet buffers in the fill queue we aim for.
    ///
    /// A higher target keeps the queue filled under receive pressure but consumes more buffers
    /// that could be utilized elsewhere.
    target_rx: PktCtr,
    /// Number of packet buffers to reserve for transmission.
    lowmark_tx: PktCtr,
    /// The target of packet buffers in the transmit queue we aim for.
    ///
    /// A higher target allows more packets to be queued, increasing latency while allowing for
    /// larger bursts. Also, the buffers consumed are not available elsewhere.
    target_tx: PktCtr,

    /// Packets currently in the RX system (>=lowmark_rx).
    current_rx: PktCtr,
    /// Packets currently in the TX system (>=lowmark_tx).
    current_tx: PktCtr,

    // Buffer tracking of free float.
    /// Number of essential RX buffers in the free state.
    essential_free_rx: PktCtr,
    /// Number of essential TX buffers in the free state.
    essential_free_tx: PktCtr,
}

/// Reference to some buffers that may be transmitted.
pub struct TxLease<'lt> {
    free: &'lt mut VecDeque<OwnedBuf>,
    essential_free_tx: &'lt mut PktCtr,
    current_tx: &'lt mut PktCtr,
    /// Number of buffers available to transmit.
    tx_capacity: PktCtr,
    /// Number of buffers that are essential.
    tx_essential: PktCtr,
}

/// Reference to some buffers that have been received.
pub struct RxLease<'lt> {
    free: &'lt mut VecDeque<OwnedBuf>,
    essential_free_rx: &'lt mut PktCtr,
    current_rx: &'lt mut PktCtr,
    /// Number of buffers that need not be preserved in Rx.
    rx_omit: PktCtr,
    /// Number of essential buffers in Rx.
    rx_essential: PktCtr,
}

/// Reference to some buffers that have been completed.
pub struct CqLease<'lt> {
    free: &'lt mut VecDeque<OwnedBuf>,
    /// Number of buffers that need not be preserved in Tx.
    non_essential: PktCtr,
}

/// Reference to some buffers that can be filled with received data.
pub struct FqLease<'lt> {
    free: &'lt mut VecDeque<OwnedBuf>,
    /// Number of buffers available in the queue.
    rx_capacity: PktCtr,
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
/// * Number of buffers in `free`, `pending_fx`, and the fill queue is at least `lowmark_rx`.
/// * Number of buffers in `free`, `pending_tx`, and the completion queue is at least `lowmark_tx`.
impl BufferManagement {
    pub fn new(free: Vec<OwnedBuf>) -> Self {
        let lowmark_rx = 16;
        let lowmark_tx = 16;

        assert!(free.len() as PktCtr as usize == free.len());

        assert!(
            free.len() >= (lowmark_rx + lowmark_tx) as usize,
            "Too few buffers: {}",
            free.len()
        );

        BufferManagement {
            free: free.into_iter().collect(),
            lowmark_rx,
            target_rx: 32,
            lowmark_tx,
            target_tx: 32,
            current_rx: 0,
            current_tx: 0,
            essential_free_rx: lowmark_rx,
            essential_free_tx: lowmark_tx,
        }
    }

    /// For the two queues we produce, we recommend some amount of buffers.
    pub fn recommended_fq_fill(&self) -> u32 {
        self.target_rx.saturating_sub(self.current_rx)
    }

    /// For the two queues we produce, we recommend some amount of buffers.
    ///
    /// This is not necessarily the amount of buffers that _can_ be transmitted when considering
    /// the available buffers. It is rather the maximum buffers that _should_ be in the transmit
    /// queue at once. (Essentially to meet latency targets).
    pub fn recommended_tx_fill(&self) -> u32 {
        self.target_tx.saturating_sub(self.current_tx)
    }

    pub fn push_complete(&mut self, owned: OwnedBuf) {
        debug_assert!(self.current_tx > 0);
        let is_essential = self.essential_free_tx < self.lowmark_tx;

        self.current_tx -= 1;
        self.essential_free_tx += PktCtr::from(is_essential);
        self.free.push_back(owned);
    }

    /// Prepare to receive some buffers, potentially rerouting them directly.
    pub fn pre_rx(&mut self, available: u32) -> RxLease<'_> {
        self.pre_transaction_debug_assert();
        let in_send_rx = self.lowmark_rx - self.essential_free_rx;
        debug_assert!(self.current_rx >= in_send_rx);

        let rx_omit = (self.current_rx - in_send_rx).min(available);
        let rx_essential = available - rx_omit;

        // Buffers are still in `current_rx`.
        RxLease {
            free: &mut self.free,
            essential_free_rx: &mut self.essential_free_rx,
            current_rx: &mut self.current_rx,
            rx_omit,
            rx_essential,
        }
    }

    /// Prepare some buffers from the free floating buffer.
    ///
    /// This moves the buffers logically into the TX lease, which is part of the `current_tx`.
    pub fn pre_tx(&mut self, max: u32) -> TxLease<'_> {
        // We reserve the tx buffers into the lease.
        self.pre_transaction_debug_assert();

        let tx_capacity = (self.free_len() - self.essential_free_rx).min(max);
        // Essential buffers are removed 'first'.
        let new_essential_free_tx = self.essential_free_tx.saturating_sub(tx_capacity);
        let tx_essential = self.essential_free_tx - new_essential_free_tx;

        // Ensure the invariant would be upheld when reassigning counts.
        debug_assert!(tx_essential <= tx_capacity);
        debug_assert!(self.current_tx + tx_essential + new_essential_free_tx >= self.lowmark_tx);
        debug_assert!(self.essential_free_rx + new_essential_free_tx <= self.free_len());

        self.essential_free_tx = new_essential_free_tx;
        self.current_tx += tx_capacity;

        TxLease {
            free: &mut self.free,
            essential_free_tx: &mut self.essential_free_tx,
            current_tx: &mut self.current_tx,
            tx_capacity,
            tx_essential,
        }
    }

    /// Prepare to complete some buffers, potentially rerouting them directly.
    pub fn pre_cq(&mut self, available: PktCtr) -> CqLease<'_> {
        self.pre_transaction_debug_assert();
        // Buffers are `current_tx`. How many to keep this way?
        debug_assert!(self.lowmark_tx >= self.essential_free_tx);
        let missing = self.lowmark_tx - self.essential_free_tx;
        // Ensure that at least the lower watermark is preserved.
        debug_assert!(self.current_tx >= missing);
        let non_essential = self.current_tx - missing;

        CqLease {
            free: &mut self.free,
            non_essential,
        }
    }

    /// Prepare some buffers from the free buffers for the fill queue.
    pub fn pre_fq(&mut self, max: PktCtr) -> FqLease<'_> {
        self.pre_transaction_debug_assert();

        let rx_capacity = (self.free_len() - self.essential_free_tx).min(max);
        let new_essential_free_rx = self.essential_free_rx.saturating_sub(rx_capacity);
        let rx_essential = self.essential_free_rx - new_essential_free_rx;

        self.essential_free_rx = new_essential_free_rx;
        self.current_rx += rx_capacity;

        FqLease {
            free: &mut self.free,
            rx_capacity,
        }
    }

    /// Gather packet buffers from the completion queue.
    fn periodic_reap_cq(&mut self) -> PktCtr {
        self.pre_transaction_debug_assert();

        todo!()
    }

    /// Gather some free packet buffers into the fill queue.
    ///
    /// Call this eventually after buffers from the fill queue have been consumed. Never consumes
    /// too many packets to starve the transmit queue.
    fn periodic_reap_fq(&mut self) -> PktCtr {
        self.pre_transaction_debug_assert();

        todo!();
    }

    fn free_len(&self) -> PktCtr {
        debug_assert!(PktCtr::try_from(self.free.len()).is_ok());
        self.free.len() as PktCtr
    }

    /// Assert that the invariants hold before starting a transaction.
    ///
    /// Correctness is ensured by the library cooperating, i.e. treating the `*Lease` types as
    /// essentially linear. However, to ensure that this is implemented correctly we can test the
    /// invariants at runtime.
    fn pre_transaction_debug_assert(&self) {
        debug_assert!(self.essential_free_rx + self.essential_free_tx <= self.free_len());

        debug_assert!(self.essential_free_rx <= self.lowmark_rx);
        debug_assert!(self.essential_free_tx <= self.lowmark_tx);

        debug_assert!(self.current_tx >= self.lowmark_tx - self.essential_free_tx);
        debug_assert!(self.current_rx >= self.lowmark_rx - self.essential_free_rx);
    }
}

impl OwnedBuf {
    /// Remove the owned token, leaving an invalid one behind.
    ///
    /// Really we'd like the token to be NonMaxU32 or something similar, so that the range [0; N)
    /// is `Some` and the maximum is a niche for `None`. This then has no overhead for accessing
    /// valid tokens. Alas, Rust does not yet allow this. So instead the library reserves the right
    /// to invalidate a token. It only does this for token values that it _doesn't_ return to the
    /// user.
    pub(crate) fn take_private(&mut self) -> OwnedBuf {
        OwnedBuf(core::mem::replace(&mut self.0, u32::MAX))
    }
}

impl TxLease<'_> {
    pub fn skip(&mut self, buf: OwnedBuf) {
        debug_assert!(self.tx_capacity > 0);
        debug_assert!(self.tx_capacity >= self.tx_essential);
        // Prefer to skip a non-essential buffer.
        let is_essential = PktCtr::from(self.tx_capacity == self.tx_essential);

        self.tx_essential -= is_essential;
        self.tx_capacity -= 1;
        *self.current_tx -= 1;
        *self.essential_free_tx += is_essential;

        self.free.push_back(buf);
    }

    pub fn pop_buf(&mut self) {
        debug_assert!(self.tx_capacity > 0);
        // Prefer to send an essential buffer.
        let is_essential = PktCtr::from(self.tx_essential > 0);

        self.tx_essential -= is_essential;
        self.tx_capacity -= 1;
        // current_tx and essential_free_tx already up-to-date.
    }

    /// The number of packets available to send.
    pub fn init_bufs(&mut self, bufs: &mut [Buffer]) -> usize {
        assert!(bufs.len() >= self.tx_capacity as usize);
        for slot in &mut bufs[..self.tx_capacity as usize] {
            let buf = self.free.pop_front().unwrap();
            slot.idx = buf;
        }

        self.tx_capacity as usize
    }

    /// Called to assert that the linearity of buffers was adhered to.
    ///
    /// The library, internally, should call `skip` or `pop_buf` for each of the buffers that has
    /// been filled at `init_bufs`. Otherwise, the buffer manager looses track of some of them. We
    /// only do this with debug assertions enabled; and not as a `Drop` as it should not be called
    /// during panicking and to not influence the type otherwise.
    pub fn debug_assert_done(self) {
        debug_assert!(self.tx_essential == 0);
        debug_assert!(self.tx_capacity == 0);
    }
}

/// Cleanup the receive queue.
///
/// Other packets are set aside into our fill queue. Note: sending as an 'instant response' is
/// not guaranteed! The implementation should inspect the handles in a smarter way to avoid us
/// dropping a retransmit here.
impl RxLease<'_> {
    /// Keep the packet in Rx, directly routing to refill.
    pub fn refill(&mut self) {
        debug_assert!(self.rx_essential > 0);
        self.rx_essential -= 1;
    }

    pub fn release_buf(&mut self, buf: OwnedBuf) {
        let new_essential = self.rx_essential.saturating_sub(1);
        *self.essential_free_rx += PktCtr::from(new_essential < self.rx_essential);
        self.rx_essential = new_essential;
        self.free.push_back(buf);
    }
}

impl FqLease<'_> {
    pub fn iter(&mut self) -> impl Iterator<Item = OwnedBuf> + '_ {
        let count = self.rx_capacity;
        (0..count).map(|_| {
            self.rx_capacity -= 1;
            self.free.pop_front().unwrap()
        })
    }

    pub fn debug_assert_done(self) {
        debug_assert!(self.rx_capacity == 0);
    }
}
