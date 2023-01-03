#![no_std]
extern crate alloc;

use core::cell::UnsafeCell;
use core::ptr::NonNull;

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use xdpilone::xsk::{
    IfInfo, XskDeviceQueue, XskRxRing, XskSocket, XskSocketConfig, XskTxRing, XskUmem, XskUser,
};

use arraydeque::{ArrayDeque, Wrapping};

use ethox::nic::Device;
use ethox::wire::{payload, Payload, PayloadMut};

/// Handled to some area of memory controlled by us.
///
/// This way, the socket can optionally *own* a handle to that memory region, allowing it to drop
/// it at the expected time.
unsafe trait MemoryArea: Send + Sync + 'static {
    fn as_ptr(&self) -> NonNull<[UnsafeCell<u8>]>;
}

pub struct UmemBuilder {
    #[allow(dead_code)]
    umem: XskUmem,
    /// Is the file descriptor of the `umem` itself used as rx/tx?
    initial_socket: Option<()>,
    memory: Option<Arc<dyn MemoryArea>>,
    /// The physical devices managed on this `umem`.
    device: Vec<XskDeviceQueue>,
    /// The user queues.
    rxtx: Vec<XskUser>,
    /// Physical receive interfaces.
    rx: Vec<XskRxRing>,
    /// Physical transmit interfaces.
    tx: Vec<XskTxRing>,
}

/// Data that is fixed for a `Umem` region.
pub struct XdpBuilderOptions {
    /// Optionally, a handle to the memory region to own.
    pub memory: Option<Arc<dyn MemoryArea>>,
}

pub struct DeviceOptions<'lt> {
    pub ifinfo: &'lt IfInfo,
    pub config: &'lt XskSocketConfig,
}

#[derive(Debug)]
pub struct UmemBuilderError {
    _inner: Box<dyn core::fmt::Debug + Send + Sync + 'static>,
}

pub struct AfXdp {
    #[allow(dead_code)]
    /// Free buffers with no assigned use.
    free: Vec<OwnedBuf>,

    // A buffer of handles we use temporarily to communicate with the sender and receiver.
    handles: Box<[Handle]>,

    tx: Vec<XskTxRing>,
    rx: Vec<XskRxRing>,

    /// Gathered statistics about socket usage, buffer usage, etc.
    #[allow(dead_code)]
    stats: Box<Stats>,

    /// Number of packet buffers to reserve for receive.
    watermark_rx: usize,
    /// Number of packet buffers to reserve for transmission.
    watermark_tx: usize,

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

/// An owning index of a buffer in the `Umem`.
///
/// This owns a whole buffer, with the size used in the construction configuration of the umem
/// ring. For calls that require a distinct length (sent by transmit, received from receive) the
/// structure `Buffer` is used instead.
///
/// This is a unique token on this ring, you can't *safely* get access to a copy.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OwnedBuf(u32);

#[derive(Default)]
struct Stats {}

/// The buffer representation while owned by User-Space during Rx/TX operations.
pub struct Buffer {
    /// The complete view of this buffer.
    addr: NonNull<[u8]>,
    /// The index which we use to own the buffer.
    idx: OwnedBuf,
    /// The logical length of this buffer.
    len: u16,
}

#[derive(Clone, Copy)]
pub struct Handle {
    /// Where should we submit this buffer.
    send: Option<u16>,
}

/// Designate the fate of a buffer after its operation.
pub enum Destination {
    /// Do not use the buffer for anything in particular.
    Free,
    /// Submit this descriptor to a transmit queue.
    Tx(u16),
    /// Keep the buffer on a local queue (unimplemented at the moment).
    Keep(u16),
    /// Submit the buffer to the Fill queue to be received.
    Fill,
}

pub struct IoReport {
    pub egress: usize,
    pub ingress: usize,
    _inner: (),
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
impl AfXdp {
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
            self.free.extend(self.queue_rx.drain(..));
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

    /// Accept some buffers from the `afxdp` receive buffer.
    ///
    /// Precondition:
    /// `self.queue_rx` is empty.
    fn pre_rx(&mut self, max: usize) -> usize {
        todo!();
    }

    /// Prepare some buffers from the free floating buffer.
    ///
    /// Precondition:
    /// `self.queue_rx` is empty.
    fn pre_tx(&mut self, max: usize) -> usize {
        debug_assert!(self.essential_free_rx + self.essential_free_tx <= self.free.len());
        let actual = (self.free.len() - self.essential_free_rx).min(max);
        self.essential_free_tx = self.essential_free_tx.saturating_sub(actual);
        self.current_tx += actual;
        debug_assert!(self.essential_free_rx + self.essential_free_tx <= self.free.len());

        todo!();
        actual
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

    /// Handle fill and completion queue actions with the kernel.
    ///
    /// Run this periodically.
    pub fn do_io(&mut self) -> Result<IoReport, UmemError> {
        for tx in &mut self.tx {
            if tx.needs_wakeup() {
                tx.wake();
            }
        }

        Ok(IoReport {
            egress: 0,
            ingress: 0,
            _inner: (),
        })
    }
}

impl UmemBuilder {
    /// Create a umem over a custom memory region to use for buffers.
    ///
    /// # Safety
    ///
    /// Guarantee that the memory region that had been used to construct the buffer is not aliased.
    pub unsafe fn new(umem: XskUmem, opt: &XdpBuilderOptions) -> Result<Self, UmemBuilderError> {
        Ok(UmemBuilder { ..todo!() })
    }

    /// Bind a new socket into this interface.
    ///
    /// Note: currently, only exactly one socket is supported. Multi-Socket support may get added
    /// to ethox at some point in the future...
    pub fn with_socket(&mut self, bind: DeviceOptions) -> Result<(), UmemBuilderError> {
        // Use either the builtin file descriptor or a fresh one if that's already been used.
        let socket = self
            .initial_socket
            .take()
            .map_or_else(
                || XskSocket::new(&bind.ifinfo),
                |()| XskSocket::with_shared(&bind.ifinfo, &self.umem),
            )
            .map_err(Self::errno_err)?;

        let rxtx = self
            .umem
            .rx_tx(&socket, &bind.config)
            .map_err(Self::errno_err)?;

        if bind.config.rx_size.is_some() {
            self.rx.push(rxtx.map_rx().map_err(Self::errno_err)?);
        }

        if bind.config.tx_size.is_some() {
            self.tx.push(rxtx.map_tx().map_err(Self::errno_err)?);
        }

        self.rxtx.push(rxtx);

        Ok(())
    }

    /// Finalize the builder, returning a configured interface.
    pub fn build(mut self) -> Result<AfXdp, UmemBuilderError> {
        let sock = match self.device.pop() {
            Some(sock) => sock,
            None => panic!("no socket"), // FIXME: error
        };

        let free = (0..self.umem.len_frames()).map(OwnedBuf).collect();

        Ok(AfXdp {
            tx: self.tx,
            rx: self.rx,
            handles: alloc::vec![Handle { send: None }; 2048].into_boxed_slice(),
            stats: Box::new(Stats::default()),
            free,
            watermark_rx: 16,
            watermark_tx: 16,
            current_rx: 0,
            current_tx: 0,
            essential_free_rx: 16,
            essential_free_tx: 16,
        })
    }

    fn errno_err(err: xdpilone::Errno) -> UmemBuilderError {
        UmemBuilderError {
            _inner: Box::new(err),
        }
    }
}

impl Default for XdpBuilderOptions {
    fn default() -> Self {
        XdpBuilderOptions { memory: None }
    }
}

impl Device for AfXdp {
    type Payload = Buffer;

    type Handle = Handle;

    fn personality(&self) -> ethox::nic::Personality {
        ethox::nic::Personality::baseline()
    }

    fn tx(
        &mut self,
        max: usize,
        mut sender: impl ethox::nic::Send<Self::Handle, Self::Payload>,
    ) -> ethox::layer::Result<usize> {
        let max = self.handles.len().min(max);
        let count = self.pre_tx(max);
        todo!();
        sender.sendv(packets);
        self.post_tx();
        Ok(count)
    }

    fn rx(
        &mut self,
        max: usize,
        mut receiver: impl ethox::nic::Recv<Self::Handle, Self::Payload>,
    ) -> ethox::layer::Result<usize> {
        let max = self.handles.len().min(max);
        let count = self.pre_rx(max);
        todo!();
        receiver.receivev(packets);
        self.post_rx();
        Ok(count)
    }
}

impl Payload for Buffer {
    fn payload(&self) -> &payload {
        // Safety: we can reference the `OwnedBuf` (`idx`) to this at the moment.
        let _: &_ = &self.idx;
        unsafe { self.addr.as_ref() }.into()
    }
}

impl PayloadMut for Buffer {
    fn payload_mut(&mut self) -> &mut payload {
        // Safety: we own the `OwnedBuf` (`idx`) to this at the moment.
        let _: &mut _ = &mut self.idx;
        unsafe { self.addr.as_mut() }.into()
    }

    fn resize(&mut self, length: usize) -> Result<(), ethox::wire::PayloadError> {
        if let Ok(len) = u16::try_from(length) {
            Ok(self.len = len)
        } else {
            Err(ethox::wire::PayloadError::BadSize)
        }
    }

    fn reframe(&mut self, reframe: ethox::wire::Reframe) -> Result<(), ethox::wire::PayloadError> {
        // Nothing special to do, we never overwrite data here.
        self.resize(reframe.length)
    }
}

impl ethox::nic::Handle for Handle {
    fn queue(&mut self) -> ethox::layer::Result<()> {
        self.send = Some(0);
        Ok(())
    }

    fn info(&self) -> &dyn ethox::nic::Info {
        self
    }
}

impl ethox::nic::Info for Handle {
    fn timestamp(&self) -> ethox::time::Instant {
        todo!()
    }

    fn capabilities(&self) -> ethox::nic::Capabilities {
        ethox::nic::Capabilities::no_support()
    }
}
