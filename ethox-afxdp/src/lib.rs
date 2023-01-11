#![no_std]
extern crate alloc;

mod bpf;
mod buffers;
mod ring;
mod xdp;

use self::buffers::{BufferManagement, OwnedBuf, RxLease, TxLease};

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use alloc::{boxed::Box, sync::Arc, vec::Vec};

use xdpilone::xsk::{
    IfInfo, ReadRx, WriteTx, XskDeviceQueue, XskRxRing, XskSocket, XskSocketConfig, XskTxRing,
    XskUmem, XskUmemConfig, XskUser,
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
    umem: XskUmem,
    /// Is the file descriptor of the `umem` itself used as rx/tx?
    initial_socket: Option<()>,
    /// The memory RAII, only kept alive after the constructor.
    #[allow(dead_code)]
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
pub struct AfXdpBuilderError {
    _inner: Box<dyn core::fmt::Debug + Send + Sync + 'static>,
}

pub struct AfXdp {
    umem: XskUmem,
    #[allow(dead_code)]
    /// The queue's own device handle.
    device_handle: Arc<DeviceHandle>,
    // A buffer of handles we use temporarily to communicate with the sender and receiver.
    handles: Box<[Handle]>,

    tx: Option<XskTxRing>,
    // FIXME: figure out how to handle multiple receive rings.
    rx: Option<XskRxRing>,
    /// The fill/completion queue.
    sock: XskDeviceQueue,

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
    this: Option<ReadRx<'lt>>,
    /// Number of packets that are received.
    lease: RxLease<'lt>,
}

struct PreparedTx<'lt> {
    umem: &'lt mut XskUmem,
    this: Option<WriteTx<'lt>>,
    /// Number of packets that are sent.
    lease: TxLease<'lt>,
}

impl AfXdp {
    /// Accept some buffers from the `afxdp` receive buffer.
    ///
    /// Precondition:
    /// `self.queue_rx` is empty.
    fn pre_rx(&mut self, max: u32) -> PreparedRx<'_> {
        let this = match self.rx.as_mut() {
            None => None,
            Some(rx) => Some(rx.receive(max)),
        };

        let actual = this.as_ref().map_or(0, |rx| rx.capacity());
        let lease = self.buffers.pre_rx(actual);

        PreparedRx { this, lease }
    }

    fn pre_tx(&mut self, max: u32) -> PreparedTx<'_> {
        let this = match self.tx.as_mut() {
            None => None,
            Some(tx) => Some(tx.transmit(max)),
        };

        let actual = this.as_ref().map_or(0, |tx| tx.capacity());
        let lease = self.buffers.pre_tx(actual);
        let umem = &mut self.umem;

        PreparedTx { umem, this, lease }
    }

    /// Handle fill and completion queue actions with the kernel.
    ///
    /// Run this periodically.
    pub fn do_io(&mut self) -> Result<IoReport, AfXdpBuilderError> {
        // Note: acknowledge we may have multiple TX, but then the work might be awkwardly high per
        // iteration. Currently this iterator is an Option.
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

impl AfXdpBuilder {
    /// Create a umem over a custom memory region to use for buffers.
    ///
    /// # Safety
    ///
    /// Guarantee that the memory region that had been used to construct the buffer is not aliased.
    pub unsafe fn new(umem: XskUmem, opt: &XdpBuilderOptions) -> Result<Self, AfXdpBuilderError> {
        Ok(AfXdpBuilder {
            umem,
            initial_socket: Some(()),
            memory: opt.memory.clone(),
            device: Vec::new(),
            rxtx: Vec::new(),
            rx: Vec::new(),
            tx: Vec::new(),
        })
    }

    pub fn from_boxed_slice<P: 'static>(
        memory: Box<[P]>,
        config: XskUmemConfig,
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
        let umem = unsafe { XskUmem::new(config, memory.as_ptr()) }
            .map_err(AfXdpBuilderError::umem_error)?;
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

        let device = self.umem.fq_cq(&socket).map_err(Self::errno_err)?;

        self.device.push(device);
        self.rxtx.push(rxtx);

        Ok(())
    }

    /// Finalize the builder, returning a configured interface.
    pub fn build(mut self) -> Result<AfXdp, AfXdpBuilderError> {
        let sock = match self.device.pop() {
            Some(sock) if !self.device.is_empty() => {
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

        let free = (0..self.umem.len_frames()).map(OwnedBuf).collect();
        let device_handle = Arc::<DeviceHandle>::default();

        let handles = core::iter::repeat_with(|| Handle {
            send: Destination::Free,
            shared: device_handle.clone(),
        })
        .take(2048)
        .collect::<Vec<_>>()
        .into_boxed_slice();

        Ok(AfXdp {
            tx,
            rx,
            sock,
            device_handle,
            handles,
            stats: Box::new(Stats::default()),
            buffers: BufferManagement::new(free),
            umem: self.umem,
        })
    }

    fn errno_err(err: xdpilone::Errno) -> AfXdpBuilderError {
        AfXdpBuilderError {
            _inner: Box::new(err),
        }
    }
}

impl PreparedRx<'_> {
    pub(crate) fn close(self, handles: &[Handle]) {
        let mut rx = match self.this {
            None => return,
            Some(rx) => rx,
        };

        let bufaddr = core::iter::from_fn(|| rx.read());

        for (hdl, addr) in handles.iter().zip(bufaddr) {}
    }
}

impl PreparedTx<'_> {
    pub(crate) fn close(mut self, handles: &[Handle]) {
        let mut tx = match self.this {
            None => return,
            Some(tx) => tx,
        };

        for handle in handles {
            match handle.send {
                Destination::Tx(0) => {}
                _ => {
                    self.lease.skip();
                    continue;
                }
            }

            let sent = self.lease.pop_buf();
            let frame = self.umem.frame(xdpilone::xsk::BufIdx(sent.0)).unwrap();

            let desc = frame.into_xdp(todo!());
            tx.insert(core::iter::once(desc));
        }
    }
}

impl AfXdp {}

impl AfXdpBuilderError {
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
        let max = self.handles.len().min(max);
        let max = u32::try_from(max).unwrap_or(u32::MAX);
        let lease = self.pre_tx(max);

        let (count, packets) = (todo!(), core::iter::empty());
        sender.sendv(packets);
        lease.close(&self.handles);

        Ok(count)
    }

    fn rx(
        &mut self,
        max: usize,
        mut receiver: impl ethox::nic::Recv<Self::Handle, Self::Payload>,
    ) -> ethox::layer::Result<usize> {
        let max = self.handles.len().min(max);
        let max = u32::try_from(max).unwrap_or(u32::MAX);

        if max == 0 {
            return Ok(0);
        }

        let lease = self.pre_rx(max);
        let (count, packets) = (todo!(), core::iter::empty());
        receiver.receivev(packets);
        lease.close(&self.handles);

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
        self.send = Destination::Free;
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
