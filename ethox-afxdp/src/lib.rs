#![no_std]
extern crate alloc;

use afxdp::buf_mmap::BufMmap;
use afxdp::mmap_area::{MmapArea, MmapAreaOptions, MmapError};
use afxdp::socket::{Socket, SocketOptions, SocketRx, SocketTx, SocketNewError};
use afxdp::umem::{Umem, UmemCompletionQueue, UmemError, UmemFillQueue, UmemNewError};
use afxdp::PENDING_LEN;
use alloc::{boxed::Box, sync::Arc, vec::Vec};

use arraydeque::{ArrayDeque, Wrapping};

use ethox::nic::Device;
use ethox::wire::{payload, Payload, PayloadMut};

#[derive(Default, Clone, Copy)]
pub struct BufTag;

pub struct UmemBuilder {
    #[allow(dead_code)]
    umem: Arc<Umem<'static, BufTag>>,
    link_fq: UmemFillQueue<'static, BufTag>,
    link_cq: UmemCompletionQueue<'static, BufTag>,
    buffers: Vec<BufMmap<'static, BufTag>>,
    sock: Vec<SocketFull>,
}

struct SocketFull {
    rx: SocketRx<'static, BufTag>,
    tx: SocketTx<'static, BufTag>,
    #[allow(dead_code)]
    sock: Arc<Socket<'static, BufTag>>,
}

/// Data that is fixed for a `Umem` region.
pub struct UmemBuilderOptions {
    /// The buffer count.
    pub buf_num: usize,
    /// The size of each buffer (power-of-two).
    pub buf_size: usize,
    /// Number of descriptors in the producer on kernel side.
    pub xsk_prod_desc_num: u32,
    /// Number of descriptors in the consumer on kernel side.
    pub xsk_cons_desc_num: u32,
}

/// Options for binding a socket as AF XDP.
pub struct BuilderBindOptions {
    /// The name of the interface device (e.g. `enp8s0`).
    pub name: alloc::string::String,
    /// The channel, usually 0 unless running multiple queues on this device.
    pub channel: usize,
    pub rx_ring_desc_num: u32,
    pub tx_ring_desc_num: u32,
}

#[derive(Debug)]
pub struct UmemBuilderError {
    _inner: Box<dyn core::fmt::Debug + Send + Sync + 'static>,
}

pub struct AfXdp {
    rx: SocketRx<'static, BufTag>,
    tx: SocketTx<'static, BufTag>,
    #[allow(dead_code)]
    sock: Arc<Socket<'static, BufTag>>,

    link_fq: UmemFillQueue<'static, BufTag>,
    link_cq: UmemCompletionQueue<'static, BufTag>,

    /// the temporary pool of mapped buffers received.
    queue_rx: Vec<BufMmap<'static, BufTag>>,
    /// the temporary pool of mapped buffers ready to fill with transmit data.
    queue_tx: Vec<BufMmap<'static, BufTag>>,

    /// free buffers with no assigned use.
    free: Vec<BufMmap<'static, BufTag>>,
    pending_rx: ArrayDeque<[BufMmap<'static, BufTag>; PENDING_LEN], Wrapping>,
    /// the temporary pool of mapped buffers ready to add to fill queue.
    pending_fq: Vec<BufMmap<'static, BufTag>>,
    /// Buffers enqueued for transmit in order.
    pending_tx: ArrayDeque<[BufMmap<'static, BufTag>; PENDING_LEN], Wrapping>,
    pending_cq: Vec<BufMmap<'static, BufTag>>,

    // A buffer of handles we use temporarily to communicate with the sender and receiver.
    handles: Box<[Handle]>,

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

#[derive(Default)]
struct Stats {}

#[repr(transparent)]
pub struct Buffer(BufMmap<'static, BufTag>);

#[derive(Clone, Copy)]
pub struct Handle {
    /// Should we send? TODO: allow more than one transmit queue.
    send: Option<u16>,
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
        for (packet, hdl) in self.queue_rx.drain(..).zip(&self.handles[..]) {
            match hdl.send {
                Some(0) if tx < spill => {
                    tx += 1;
                    self.pending_tx.push_back(packet);
                }
                _ => self.free.push(packet),
            }
        }

        self.current_tx += tx;
    }

    /// Cleanup the transmit queue according to handles.
    ///
    /// Other packets are set aside into our fill queue.
    /// * `queue_tx` is empty.
    fn post_tx(&mut self) {
        let mut freed = 0;
        for (packet, hdl) in self.queue_tx.drain(..).zip(&self.handles[..]) {
            match hdl.send {
                Some(0) => {
                    self.pending_tx.push_back(packet);
                }
                _ => {
                    freed += 1;
                    self.free.push(packet);
                }
            }
        }

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
        let actual = self.pending_rx.len().min(max);
        self.queue_rx.extend(self.pending_rx.drain(..actual));
        actual
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

        self.queue_rx.extend(self.pending_rx.drain(..actual));
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
        let batch = 16;
        debug_assert!(self.essential_free_rx + self.essential_free_tx <= self.free.len());
        let actual = (self.free.len() - self.essential_free_tx).min(batch);
        todo!();

        self.pending_fq.extend(self.free.drain(..actual));
    }

    /// Handle fill and completion queue actions with the kernel.
    ///
    /// Run this periodically.
    pub fn do_io(&mut self) -> Result<IoReport, UmemError> {
        if self.tx.needs_wakeup() || self.link_fq.needs_wakeup() {
            self.rx.wake();
        }

        let batch = 16;
        let igress_err = self.rx.try_recv(&mut self.pending_rx, batch, BufTag);
        let ogress_err = self.tx.try_send(&mut self.pending_tx, batch);

        // Periodic maintenance tasks, the two kernel queues.
        self.periodic_reap_fq();
        let fill_err = self.link_fq.fill(&mut self.pending_fq, batch);
        let complete_err = self.link_cq.service(&mut self.pending_cq, batch);
        self.periodic_reap_cq();

        let _ = igress_err.and(ogress_err);
        let _ = fill_err.and(complete_err);

        Ok(IoReport {
            egress: 0,
            ingress: 0,
            _inner: (),
        })
    }
}

impl UmemBuilder {
    pub fn new(opt: &UmemBuilderOptions) -> Result<Self, UmemBuilderError> {
        let options = MmapAreaOptions { huge_tlb: false };
        let (area, buffers) =
            MmapArea::new(opt.buf_num, opt.buf_size, options).map_err(Self::mmap_err)?;

        let (umem, link_cq, link_fq) =
            afxdp::umem::Umem::new(area.clone(), opt.xsk_cons_desc_num, opt.xsk_prod_desc_num)
                .map_err(Self::umem_err)?;

        Ok(UmemBuilder {
            umem,
            link_fq,
            link_cq,
            buffers,
            sock: Vec::with_capacity(1),
        })
    }

    /// Bind a new socket into this interface.
    ///
    /// Note: currently, only exactly one socket is supported. Multi-Socket support may get added
    /// to ethox at some point in the future...
    pub fn with_socket(
        &mut self,
        bind: &BuilderBindOptions,
        sock: SocketOptions,
    ) -> Result<(), UmemBuilderError> {
        let (sock, rx, tx) = Socket::new(
            self.umem.clone(),
            &bind.name,
            bind.channel,
            bind.rx_ring_desc_num,
            bind.tx_ring_desc_num,
            sock,
        )
        .map_err(Self::sock_err)?;

        self.sock.push(SocketFull { sock, rx, tx });

        Ok(())
    }

    /// Finalize the builder, returning a configured interface.
    pub fn build(mut self) -> Result<AfXdp, UmemBuilderError> {
        let sock = match self.sock.pop() {
            Some(sock) => sock,
            None => panic!("no socket"), // FIXME: error
        };

        Ok(AfXdp {
            rx: sock.rx,
            tx: sock.tx,
            sock: sock.sock,
            link_fq: self.link_fq,
            link_cq: self.link_cq,
            queue_rx: Vec::with_capacity(16),
            queue_tx: Vec::with_capacity(16),
            free: self.buffers,
            pending_rx: Default::default(),
            pending_fq: Default::default(),
            pending_tx: Default::default(),
            pending_cq: Default::default(),
            handles: alloc::vec![Handle { send: None }; 2048].into_boxed_slice(),
            stats: Box::new(Stats::default()),
            watermark_rx: 16,
            watermark_tx: 16,
            current_rx: 0,
            current_tx: 0,
            essential_free_rx: 16,
            essential_free_tx: 16,
        })
    }

    fn umem_err(err: UmemNewError) -> UmemBuilderError {
        UmemBuilderError {
            _inner: Box::new(err),
        }
    }

    fn sock_err(err: SocketNewError) -> UmemBuilderError {
        UmemBuilderError {
            _inner: Box::new(err),
        }
    }

    fn mmap_err(err: MmapError) -> UmemBuilderError {
        UmemBuilderError {
            _inner: Box::new(err),
        }
    }
}

impl Default for UmemBuilderOptions {
    fn default() -> Self {
        UmemBuilderOptions {
            buf_num: 2048,
            buf_size: (1 << 16),
            xsk_prod_desc_num: 2048,
            xsk_cons_desc_num: 2048,
        }
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

        let packets = self
            .queue_tx
            .iter_mut()
            .zip(&mut self.handles[..])
            .take(max)
            .map(|(payload, handle)| ethox::nic::Packet {
                handle,
                payload: unsafe { core::mem::transmute::<_, &mut Buffer>(payload) },
            });

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

        let packets = self
            .queue_rx
            .iter_mut()
            .take(max)
            .zip(&mut self.handles[..])
            .map(|(payload, handle)| ethox::nic::Packet {
                handle,
                payload: unsafe { core::mem::transmute::<_, &mut Buffer>(payload) },
            });

        receiver.receivev(packets);
        self.post_rx();
        Ok(count)
    }
}

impl Payload for Buffer {
    fn payload(&self) -> &payload {
        afxdp::buf::Buf::get_data(&self.0).into()
    }
}

impl PayloadMut for Buffer {
    fn payload_mut(&mut self) -> &mut payload {
        afxdp::buf::Buf::get_data_mut(&mut self.0).into()
    }

    fn resize(&mut self, length: usize) -> Result<(), ethox::wire::PayloadError> {
        if let Ok(len) = u16::try_from(length) {
            Ok(afxdp::buf::Buf::set_len(&mut self.0, len))
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
