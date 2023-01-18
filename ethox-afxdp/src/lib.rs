#![no_std]
extern crate alloc;

macro_rules! eprint {
    ($msg:literal, $($arg:expr),*) => {
        match ::alloc::format!($msg, $($arg),*) {
            msg => {
                unsafe { libc::write(2, msg.as_bytes().as_ptr() as *const _, msg.len()) };
                $($arg)*
            }
        }
    }
}

mod buffers;
mod ring;
mod xdp;

use self::buffers::{BufferManagement, OwnedBuf, RxLease, TxLease};

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use alloc::{boxed::Box, sync::Arc, vec::Vec};

use xdpilone::{
    DeviceQueue, IfInfo, ReadRx, RingRx, RingTx, Socket, SocketConfig, Umem, UmemConfig, User,
    WriteFill, WriteTx,
};

use ethox::nic::Device;
use ethox::wire::{payload, Payload, PayloadMut};

/// Handled to some area of memory controlled by us.
///
/// This way, the socket can optionally *own* a handle to that memory region, allowing it to drop
/// it at the expected time.
pub unsafe trait MemoryArea: Send + Sync + 'static {
    fn as_ptr(&self) -> NonNull<[u8]>;
}

pub struct AfXdpBuilder {
    umem: Umem,
    /// Is the file descriptor of the `umem` itself used as rx/tx?
    initial_socket: Option<()>,
    /// The memory RAII, only kept alive after the constructor.
    memory: Option<Arc<dyn MemoryArea>>,
    /// The physical devices managed on this `umem`.
    device: Vec<DeviceQueue>,
    /// The user queues.
    rxtx: Vec<User>,
    /// Physical receive interfaces.
    rx: Vec<RingRx>,
    rx_info: Vec<RxInfo>,
    /// Physical transmit interfaces.
    tx: Vec<RingTx>,
}

struct RxInfo {
    if_info: IfInfo,
    method: xdp::XdpRxMethod,
}

/// Data that is fixed for a `Umem` region.
pub struct XdpBuilderOptions {
    /// Optionally, a handle to the memory region to own.
    pub memory: Option<Arc<dyn MemoryArea>>,
}

pub struct DeviceOptions<'lt> {
    pub ifinfo: &'lt IfInfo,
    pub config: &'lt SocketConfig,
}

#[derive(Debug)]
pub struct AfXdpBuilderError {
    _inner: Box<dyn core::fmt::Debug + Send + Sync + 'static>,
}

pub struct AfXdp {
    umem: Umem,
    #[allow(dead_code)]
    memory: Option<Arc<dyn MemoryArea>>,

    #[allow(dead_code)]
    /// The queue's own device handle.
    device_handle: Arc<DeviceHandle>,
    /// A buffer of handles we use temporarily to communicate with the sender and receiver.
    handles: Box<[Handle]>,
    /// A buffer for constructed, owned packets. Partially initialized while in progress.
    packets: Box<[Buffer]>,

    tx: Option<RingTx>,
    // FIXME: figure out how to handle multiple receive rings.
    rx: Option<RingRx>,
    /// The fill/completion queue.
    sock: DeviceQueue,

    /// Gathered statistics about socket usage, buffer usage, etc.
    #[allow(dead_code)]
    stats: Box<Stats>,

    buffers: BufferManagement,
}

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

#[derive(Clone)]
pub struct Handle {
    /// Where should we submit this buffer.
    send: Destination,
    /// Shared state of the device.
    shared: Arc<DeviceHandle>,
}

/// The state shared between handles.
///
/// This allows a handle to own some unique aspects of a buffer, as well as share common controls
/// without involving lifetimes. That is, a single allocation exists for expensive to create state,
/// e.g., current synchronous timestamp data (clock), tracking of allowed destinations. This is
/// efficient because the allocation is never de-allocated while the device lives.
#[derive(Default)]
struct DeviceHandle {
    /// Atomic timestamp, only the device writes, handles read.
    /// Access is made non-tearing by not writing while a tx/rx happens, i.e. synchronization in
    /// those queues.
    ts_seconds: AtomicU64,
    ts_nanos: AtomicU32,
}

/// Designate the fate of a buffer after its operation.
#[derive(Clone, Copy, Debug)]
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

/// Borrowed queue/buffer states while receiving.
struct PreparedRx<'lt> {
    umem: &'lt mut Umem,
    this: Option<ReadRx<'lt>>,
    /// The fill queue to instantly re-queue buffers to fill.
    ///
    /// That keeps them in the RX portion of the buffer manager without going through the VecDeque.
    this_fq: WriteFill<'lt>,
    /// Number of packets that are received.
    lease: RxLease<'lt>,
    packets: &'lt mut [Buffer],
    handle: &'lt mut [Handle],
}

struct PreparedTx<'lt> {
    umem: &'lt mut Umem,
    this: Option<WriteTx<'lt>>,
    /// Number of packets that are sent.
    lease: TxLease<'lt>,
    packets: &'lt mut [Buffer],
    handle: &'lt mut [Handle],
}

impl AfXdp {
    /// Accept some buffers from the `afxdp` receive buffer.
    ///
    /// Precondition:
    /// `self.queue_rx` is empty.
    fn pre_rx(&mut self, max: u32) -> PreparedRx<'_> {
        let mut this = match self.rx.as_mut() {
            None => None,
            Some(rx) => Some(rx.receive(max)),
        };

        let this_fq = self.sock.fill(self.buffers.recommended_fq_fill());

        let actual = this.as_ref().map_or(0, |rx| rx.capacity());
        let lease = self.buffers.pre_rx(actual);
        let umem = &mut self.umem;

        let handle = &mut self.handles[..actual as usize];
        let packets = &mut self.packets[..actual as usize];

        'pkt: {
            let mut packets = packets.iter_mut();
            let mut handles = handle.iter_mut();
            // FIXME: incorrect frame size in general. Also, strength reduce for the division?
            let frame_size = u64::from(UmemConfig::default().frame_size);

            if let Some(rx) = &mut this {
                loop {
                    let pkt = match packets.next() {
                        Some(pkt) => pkt,
                        None => break 'pkt,
                    };

                    let hdl = match handles.next() {
                        Some(hdl) => hdl,
                        None => break 'pkt,
                    };

                    let desc = match rx.read() {
                        Some(desc) => desc,
                        None => break 'pkt,
                    };

                    // FIXME: this is soundness critical and must be reviewed.
                    let buf_id = (desc.addr / frame_size) as u32;
                    let buf_off = desc.addr % frame_size;

                    // eprint!("Receiving frame {:?}\n", (buf_id, buf_off));
                    let frame = umem.frame(xdpilone::BufIdx(buf_id)).unwrap();
                    // FIXME: there _needs_ to be cleaner solutions.
                    let inner_ptr =
                        unsafe { (frame.addr.as_ptr() as *mut u8).offset(buf_off as isize) };
                    let inner_len =
                        unsafe { frame.addr.as_ref().len() }.saturating_sub(buf_off as usize);
                    let inner_addr = core::ptr::slice_from_raw_parts_mut(inner_ptr, inner_len);

                    pkt.idx = OwnedBuf(buf_id);
                    pkt.addr = core::ptr::NonNull::new(inner_addr).unwrap();
                    pkt.len = desc.len as u16;

                    hdl.send = Destination::Fill;
                }
            }
        }

        PreparedRx {
            umem,
            this,
            this_fq,
            lease,
            packets,
            handle,
        }
    }

    fn pre_tx(&mut self, max: u32) -> PreparedTx<'_> {
        let this = match self.tx.as_mut() {
            None => None,
            Some(tx) => Some(tx.transmit(max)),
        };

        let capacity = this.as_ref().map_or(0, |tx| tx.capacity());
        let mut lease = self.buffers.pre_tx(capacity);
        let umem = &mut self.umem;

        // We're extracting packets from our buffer, let the lease do that.
        let actual = lease.init_bufs(&mut self.packets);
        let handle = &mut self.handles[..actual as usize];
        let packets = &mut self.packets[..actual as usize];

        // FIXME: of course this isn't right..
        let frame_size = (UmemConfig::default().frame_size) as u16;
        for (pkt, hdl) in packets.iter_mut().zip(&mut *handle) {
            let frame = umem.frame(xdpilone::BufIdx(pkt.idx.0)).unwrap();

            pkt.addr = frame.addr;
            pkt.len = frame_size;

            // Reset the state of the handle.
            hdl.send = Destination::Free;
        }

        PreparedTx {
            umem,
            this,
            lease,
            packets,
            handle,
        }
    }

    /// Handle fill and completion queue actions with the kernel.
    ///
    /// Run this periodically.
    pub fn do_io(&mut self) -> ethox::layer::Result<IoReport> {
        // Note: acknowledge we may have multiple TX, but then the work might be awkwardly high per
        // iteration. Currently this iterator is an Option.
        for tx in &mut self.tx {
            if tx.needs_wakeup() {
                tx.wake();
            }
        }

        '_cq: {
            let frame_size = u64::from(UmemConfig::default().frame_size);
            let mut cq = self.sock.complete(16);

            while let Some(cid) = cq.read() {
                let pkt_id = (cid / frame_size) as u32;
                self.buffers.push_complete(OwnedBuf(pkt_id));
            }

            cq.release();
        }

        '_fq: {
            let frame_count = self.buffers.recommended_fq_fill();
            let mut fq = self.sock.fill(frame_count);
            let mut frames = self.buffers.pre_fq(fq.capacity());

            let bufs = frames.iter().map(|OwnedBuf(idx): OwnedBuf| {
                let frame = self.umem.frame(xdpilone::BufIdx(idx)).unwrap();
                frame.offset
            });

            let _count = fq.insert(bufs);

            frames.debug_assert_done();
            fq.commit();
            // eprint!("Pending bufs: {}\n", fq.pending());
        }

        if self.sock.needs_wakeup() {
            self.sock.wake();
        }

        Ok(IoReport {
            egress: 0,
            ingress: 0,
            _inner: (),
        })
    }
}

impl AfXdpBuilder {
    /// Create a umem over a custom memory region to use for buffers.
    ///
    /// # Safety
    ///
    /// Guarantee that the memory region that had been used to construct the buffer is not aliased.
    pub unsafe fn new(umem: Umem, opt: &XdpBuilderOptions) -> Result<Self, AfXdpBuilderError> {
        Ok(AfXdpBuilder {
            umem,
            initial_socket: Some(()),
            memory: opt.memory.clone(),
            device: Vec::new(),
            rxtx: Vec::new(),
            rx: Vec::new(),
            rx_info: Vec::new(),
            tx: Vec::new(),
        })
    }

    pub fn from_boxed_slice<P: 'static>(
        memory: Box<[P]>,
        config: UmemConfig,
    ) -> Result<Self, AfXdpBuilderError> {
        /// A type that holds onto a memory allocation, but not the values.
        struct MemoryFromBox<P> {
            inner: NonNull<[P]>,
            // Not stable to do this on the pointer. Also, this will statically not overflow.
            size_of_val: usize,
        }

        impl<P> MemoryFromBox<P> {
            pub fn new(mem: Box<[P]>) -> Self {
                let memory = Box::leak(mem);
                let size_of_val = core::mem::size_of_val(memory);
                let inner = NonNull::from(memory);

                // Safety: we own these values as we just leaked them.
                unsafe { core::ptr::drop_in_place(inner.as_ptr()) };

                MemoryFromBox { inner, size_of_val }
            }
        }

        impl<P> Drop for MemoryFromBox<P> {
            fn drop(&mut self) {
                let inner = self.inner.cast::<core::mem::MaybeUninit<P>>();
                let len = self.inner.len();
                let slice = core::ptr::slice_from_raw_parts_mut(inner.as_ptr(), len);

                // Now deallocate the memory itself. Safety: this comes from `Box::leak` as above.
                // The layout of `MaybeUninit<P>` is the same as `P` by construction.
                let _ = unsafe { Box::from_raw(slice) };
            }
        }

        // Safety: yes, universally. The argument `P` is preserved only for its layout. No access
        // to any such object is provided through any means.
        unsafe impl<P> Sync for MemoryFromBox<P> {}
        unsafe impl<P> Send for MemoryFromBox<P> {}

        // Safety: is implemented as required, pointing to a memory location not aliased anywhere
        // due to it coming from an owned `Box` allocation.
        // Safety: in bounds of the memory by `core::mem::size_of_val()`
        unsafe impl<P: 'static> MemoryArea for MemoryFromBox<P> {
            fn as_ptr(&self) -> NonNull<[u8]> {
                let nn: NonNull<u8> = self.inner.cast();
                let raw = core::ptr::slice_from_raw_parts_mut(nn.as_ptr(), self.size_of_val);
                NonNull::new(raw).unwrap()
            }
        }

        let memory = MemoryFromBox::new(memory);
        // Safety: `memory` preserves the allocation while the umem is alive.
        let umem =
            unsafe { Umem::new(config, memory.as_ptr()) }.map_err(AfXdpBuilderError::umem_error)?;
        let ref options = XdpBuilderOptions {
            memory: Some(Arc::new(memory)),
        };

        unsafe { Self::new(umem, options) }
    }

    /// Bind a new socket into this interface.
    ///
    /// Note: currently, only exactly one socket is supported. Multi-Socket support may get added
    /// to ethox at some point in the future...
    pub fn with_socket(&mut self, bind: DeviceOptions) -> Result<(), AfXdpBuilderError> {
        // Use either the builtin file descriptor or a fresh one if that's already been used.
        let socket = self
            .initial_socket
            .take()
            .map_or_else(
                || Socket::new(&bind.ifinfo),
                |()| Socket::with_shared(&bind.ifinfo, &self.umem),
            )
            .map_err(Self::errno_err)?;

        // We MUST create the fc/cq first. This tells the kernel we're actually ready to listen to
        // this socket, otherwise bind below will fail with `EINVAL`.
        let device = self.umem.fq_cq(&socket).map_err(Self::errno_err)?;

        let rxtx = self
            .umem
            .rx_tx(&socket, &bind.config)
            .map_err(Self::errno_err)?;

        if bind.config.rx_size.is_some() {
            self.rx.push(rxtx.map_rx().map_err(Self::errno_err)?);

            self.rx_info.push(RxInfo {
                if_info: bind.ifinfo.clone(),
                method: xdp::XdpRxMethod::DefaultProgram,
            });
        }

        if bind.config.tx_size.is_some() {
            self.tx.push(rxtx.map_tx().map_err(Self::errno_err)?);
        }

        self.umem.bind(&rxtx).map_err(Self::errno_err)?;

        self.device.push(device);
        self.rxtx.push(rxtx);

        Ok(())
    }

    /// Finalize the builder, returning a configured interface.
    pub fn build(mut self) -> Result<AfXdp, AfXdpBuilderError> {
        let sock = match self.device.pop() {
            Some(_) if !self.device.is_empty() => {
                return Err(AfXdpBuilderError::unsupported_too_many_devices())
            }
            Some(sock) => sock,
            None => return Err(AfXdpBuilderError::no_device()),
        };

        let tx = match self.tx.len() {
            0 | 1 => self.tx.pop(),
            _ => return Err(AfXdpBuilderError::unsupported_too_many_tx()),
        };

        let rx = match self.rx.len() {
            0 | 1 => self.rx.pop(),
            _ => return Err(AfXdpBuilderError::unsupported_too_many_rx()),
        };

        if let Some(rx_info) = self.rx_info.get(0) {
            let rx = rx.as_ref().unwrap();

            rx_info
                .method
                .attach(&rx_info.if_info, rx.as_raw_fd())
                .map_err(AfXdpBuilderError::attach_error)?;
        }

        let free = (0..self.umem.len_frames()).map(OwnedBuf).collect();
        let device_handle = Arc::<DeviceHandle>::default();

        let buffer_slots: usize = 32;

        let handles = core::iter::repeat_with(|| Handle {
            send: Destination::Free,
            shared: device_handle.clone(),
        })
        .take(buffer_slots)
        .collect::<Vec<_>>()
        .into_boxed_slice();

        let packets = Vec::from_iter(
            core::iter::repeat_with(|| Buffer {
                idx: OwnedBuf(u32::MAX),
                addr: NonNull::from(&mut []),
                len: 0,
            })
            .take(buffer_slots),
        )
        .into_boxed_slice();

        Ok(AfXdp {
            tx,
            rx,
            sock,
            device_handle,
            handles,
            packets,
            stats: Box::new(Stats::default()),
            buffers: BufferManagement::new(free),

            // Move the umem, and potentially its guarding memory, to the new struct.
            umem: self.umem,
            memory: self.memory,
        })
    }

    fn errno_err(err: xdpilone::Errno) -> AfXdpBuilderError {
        AfXdpBuilderError {
            _inner: Box::new(err),
        }
    }
}

impl PreparedRx<'_> {
    pub(crate) fn close(mut self) {
        let mut rx = match self.this {
            None => return,
            Some(rx) => rx,
        };

        let mut fill_space = self.this_fq.capacity();
        for (buf, handle) in self.packets.iter_mut().zip(self.handle) {
            match handle.send {
                Destination::Fill if fill_space > 0 => {
                    let owned_id = buf.idx.take_private();
                    let frame = self.umem.frame(xdpilone::BufIdx(owned_id.0)).unwrap();

                    self.this_fq.insert_once(frame.offset);
                    fill_space -= 1;
                    self.lease.refill();
                }
                Destination::Free | _ => {
                    self.lease.release_buf(buf.idx.take_private());
                    continue;
                }
            }
        }

        rx.release();
    }
}

impl PreparedTx<'_> {
    pub(crate) fn close(mut self) {
        let mut tx = match self.this {
            None => return,
            Some(tx) => tx,
        };

        for (buf, handle) in self.packets.iter_mut().zip(self.handle) {
            let sent = match handle.send {
                Destination::Tx(0) => {
                    self.lease.pop_buf();
                    buf.idx.take_private()
                }
                _ => {
                    self.lease.skip(buf.idx.take_private());
                    continue;
                }
            };

            /*
            if let Ok(frm) = ethox::wire::ethernet::Frame::new_checked(buf.payload()) {
                let pp = ethox::wire::PrettyPrinter::<ethox::wire::ethernet::frame>::print(&frm);
                eprint!("<-- {}\n", pp);
            }; */

            let frame = self.umem.frame(xdpilone::BufIdx(sent.0)).unwrap();
            let desc = frame.as_xdp_with_len(u32::from(buf.len));
            // eprint!("Inserting into TX: {:?}", desc);

            tx.insert_once(desc);
        }

        self.lease.debug_assert_done();
        tx.commit();
    }
}

impl AfXdp {}

impl AfXdpBuilderError {
    fn attach_error(err: xdp::AttachError) -> Self {
        AfXdpBuilderError {
            _inner: Box::new(err),
        }
    }

    fn umem_error(err: xdpilone::Errno) -> Self {
        AfXdpBuilderError {
            _inner: Box::new(err),
        }
    }

    fn no_device() -> AfXdpBuilderError {
        AfXdpBuilderError {
            _inner: Box::new("no such device"),
        }
    }

    fn unsupported_too_many_devices() -> AfXdpBuilderError {
        AfXdpBuilderError {
            _inner: Box::new("too many devices, only one supported for now"),
        }
    }

    fn unsupported_too_many_tx() -> AfXdpBuilderError {
        AfXdpBuilderError {
            _inner: Box::new("too many TX, only one supported for now"),
        }
    }

    fn unsupported_too_many_rx() -> AfXdpBuilderError {
        AfXdpBuilderError {
            _inner: Box::new("too many RX, only one supported for now"),
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
        // FIXME: we shouldn't check this every time..
        self.do_io()?;

        let max = self.handles.len().min(max);
        let max = u32::try_from(max).unwrap_or(u32::MAX);
        let recommend = self.buffers.recommended_tx_fill();
        let max = max.min(recommend);

        let lease = self.pre_tx(max);

        let count = lease.packets.len();
        debug_assert!(lease.handle.len() == count);

        let packets = lease
            .packets
            .iter_mut()
            .zip(lease.handle.iter_mut())
            .map(|(pkt, hdl)| ethox::nic::Packet {
                payload: pkt,
                handle: hdl,
            });

        sender.sendv(packets);
        lease.close();

        Ok(count)
    }

    fn rx(
        &mut self,
        max: usize,
        mut receiver: impl ethox::nic::Recv<Self::Handle, Self::Payload>,
    ) -> ethox::layer::Result<usize> {
        // FIXME: we shouldn't check this every time..
        self.do_io()?;

        let max = self.handles.len().min(max);
        let max = u32::try_from(max).unwrap_or(u32::MAX);

        if max == 0 {
            return Ok(0);
        }

        let lease = self.pre_rx(max);

        let count = lease.packets.len();
        debug_assert!(lease.handle.len() == count);

        let packets = lease
            .packets
            .iter_mut()
            .zip(lease.handle.iter_mut())
            .map(|(pkt, hdl)| {
                /*if let Ok(frm) = ethox::wire::ethernet::Frame::new_checked(pkt.payload()) {
                    let pp =
                        ethox::wire::PrettyPrinter::<ethox::wire::ethernet::frame>::print(&frm);
                    eprint!("--> {}\n", pp);
                }; */

                ethox::nic::Packet {
                    payload: pkt,
                    handle: hdl,
                }
            });

        receiver.receivev(packets);
        lease.close();

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
        self.send = Destination::Tx(0);
        Ok(())
    }

    fn info(&self) -> &dyn ethox::nic::Info {
        self
    }
}

impl ethox::nic::Info for Handle {
    fn timestamp(&self) -> ethox::time::Instant {
        let ts_secs = self.shared.ts_seconds.load(Ordering::Relaxed);
        let ts_nanos = self.shared.ts_nanos.load(Ordering::Relaxed);
        let mut instant = ethox::time::Instant::from_secs(ts_secs as i64);
        instant.millis += (ts_nanos / 1_000_000) as i64;
        instant
    }

    fn capabilities(&self) -> ethox::nic::Capabilities {
        ethox::nic::Capabilities::no_support()
    }
}
