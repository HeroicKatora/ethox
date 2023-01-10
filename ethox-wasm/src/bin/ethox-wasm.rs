//! Demonstrate how to setup a Umem with linear WASM shared memory.
//!
//! It's important to note that several shared memories could refer to the _same_ Umem and we have
//! page sized access control over the mapping!
//!
//! This all depends on `wasmtime` internals, in particular it's only sound to `remap` **over** the
//! mapping of a `SharedMemory` because of these internals and because it doesn't reallocate any
//! data allocation once it exists. (Well: sound in a very relaxed sense. Nowhere is it promised
//! that this works but it do).
use std::sync::atomic::{AtomicU8, Ordering};
use wasmtime::{Config, Engine, MemoryType, SharedMemory, Store};

fn main() {
    match try_main() {
        Ok(()) => {}
        Err(p) => match p {},
    }
}

fn try_main() -> Result<(), Panic> {
    let mut config = Config::new();
    config.wasm_threads(true);

    let engine = Engine::new(&config)?;
    let store = Store::new(&engine, ());

    let shared_memory = SharedMemory::new(&engine, MemoryType::shared(1, 16))?;
    try_memory(&shared_memory)
}

const PAGE_SZ: usize = 1 << 12;
#[repr(align(4096))]
struct Page([AtomicU8; PAGE_SZ]);

/// Some pages remaped from a shared mapping.
struct PageMmapShared {
    addr: *const Page,
    count: usize,
}

fn try_memory(shared_memory: &SharedMemory) -> Result<(), Panic> {
    shared_memory.grow(1)?;

    let page_count = 16;
    let mmap_result = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            page_count * PAGE_SZ,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    if mmap_result == libc::MAP_FAILED {
        Err(std::io::Error::last_os_error())?;
    }

    let page_mmap = PageMmapShared {
        addr: mmap_result as *const Page,
        count: page_count,
    };

    let remap_result = unsafe {
        libc::mremap(
            mmap_result,
            0,
            PAGE_SZ,
            libc::MREMAP_FIXED | libc::MREMAP_MAYMOVE,
            core::ptr::null_mut::<Page>(),
        )
    };

    if remap_result == libc::MAP_FAILED {
        Err(std::io::Error::last_os_error())?;
    }

    let page_remap = PageMmapShared {
        addr: remap_result as *const Page,
        count: 1,
    };

    let xsk = unsafe {
        xdpilone::xsk::XskUmem::new(
            xdpilone::xsk::XskUmemConfig {
                fill_size: 16,
                complete_size: 16,
                frame_size: PAGE_SZ as u32,
                headroom: 0,
                flags: 0,
            },
            core::ptr::NonNull::new(core::ptr::slice_from_raw_parts_mut(
                mmap_result as *mut u8,
                page_count * PAGE_SZ,
            ))
            .unwrap(),
        )
    }?;

    // Demonstrate these are now duplicate.
    page_mmap[0].0[0].fetch_add(1, Ordering::Relaxed);

    println!(
        "Self Test pure: {}",
        page_remap[0].0[0].load(Ordering::Relaxed) == 1
    );

    assert!(shared_memory.data().len() >= PAGE_SZ);
    let addr = shared_memory.data().as_ptr() as usize;

    let remap_result = unsafe {
        libc::mremap(
            mmap_result,
            0,
            PAGE_SZ,
            libc::MREMAP_FIXED | libc::MREMAP_MAYMOVE,
            addr as *const libc::c_void,
        )
    };

    if remap_result == libc::MAP_FAILED {
        Err(std::io::Error::last_os_error())?;
    }

    // And so is part of the WASM shared memory!
    println!(
        "Self Test wasm: {}",
        unsafe { *shared_memory.data()[0].get() } == 1
    );

    // Preserved beyond growth.
    shared_memory.grow(1)?;
    println!(
        "Self Test grow: {}",
        unsafe { *shared_memory.data()[0].get() } == 1
    );

    Ok(())
}

enum Panic {}

impl<E> From<E> for Panic
where
    E: core::fmt::Debug,
{
    #[track_caller]
    fn from(err: E) -> Self {
        let _loc = std::panic::Location::caller();
        panic!("{:?}", err);
    }
}

impl core::ops::Deref for PageMmapShared {
    type Target = [Page];
    fn deref(&self) -> &[Page] {
        unsafe { core::slice::from_raw_parts(self.addr, self.count) }
    }
}

impl Drop for PageMmapShared {
    fn drop(&mut self) {
        let _ = unsafe { libc::munmap(self.addr as *mut libc::c_void, self.count * PAGE_SZ) };
    }
}
