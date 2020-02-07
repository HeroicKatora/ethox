//! A memory pool used for io-uring operations.
use core::{cell, mem, ops, slice, ptr};
use alloc::rc::Rc;

pub struct Pool {
    /// The entirety of memory.
    /// Inside an `UnsafeCell` since we loan out parts of it via a shared reference.
    memory: Box<cell::UnsafeCell<[u8]>>,

    /// The size of each entry.
    entry_size: usize,

    /// The number of entries.
    entry_count: usize,

    /// All remaining tickets (unused buffers).
    tickets: cell::RefCell<Vec<Ticket>>,
}

/// The non-clonable token granting access to the ith entry's memory.
struct Ticket {
    /// The pointer to the memory itself, which is minimal access time.
    ptr: usize,
}

pub struct Entry {
    /// The pool which we share.
    pool: Rc<Pool>,
    /// We return the ticket, hence do not drop it here.
    ticket: mem::ManuallyDrop<Ticket>,
}

pub struct Entries {
    this: Rc<Pool>,
}

impl Pool {
    pub fn with_size_and_count(size: usize, count: usize) -> Self {
        let total_len = size.checked_mul(count).unwrap();
        let slice = vec![0; total_len].into_boxed_slice();
        let memory = unsafe {
            Box::from_raw(Box::into_raw(slice) as *mut cell::UnsafeCell<[u8]>)
        };

        let pre = Pool {
            memory,
            entry_size: size,
            entry_count: count,
            tickets: cell::RefCell::new(Vec::with_capacity(count)),
        };

        let mut tickets = pre.tickets.borrow_mut();
        for i in 0..count {
            let ticket = Ticket { ptr: pre.iovec_for(i).iov_base as usize };
            tickets.push(ticket);
        }
        drop(tickets);

        pre
    }

    /// An iterator that crates new entries when polled.
    pub fn spawn_entries(this: Rc<Self>) -> Entries {
        Entries { this }
    }

    fn iovec_for(&self, idx: usize) -> libc::iovec {
        assert!(idx <= self.entry_count);
        let offset = idx * self.entry_size;
        let begin = unsafe {
            self.mem_ptr().add(offset)
        };
        libc::iovec {
            iov_base: begin as *mut libc::c_void,
            iov_len: self.entry_size,
        }
    }
    
    fn mem_ptr(&self) -> *mut u8 {
        cell::UnsafeCell::get(&*self.memory) as *mut u8
    }
}

impl Ticket {
    /// Requires: The pool must be the one used to create the ticket.
    pub(crate) unsafe fn get(&self, pool: &Pool) -> &[u8] {
        #[allow(unused_unsafe)]
        unsafe {
            slice::from_raw_parts(self.ptr as *const u8, pool.entry_size)
        }
    }

    /// Requires: The pool must be the one used to create the ticket.
    pub(crate) unsafe fn get_mut(&mut self, pool: &Pool) -> &mut [u8] {
        #[allow(unused_unsafe)]
        unsafe {
            slice::from_raw_parts_mut(self.ptr as *mut u8, pool.entry_size)
        }
    }
}

impl Entry {
    pub fn io_vec(this: &Self) -> libc::iovec {
        libc::iovec {
            iov_base: this.ticket.ptr as *mut libc::c_void,
            iov_len: this.pool.entry_size,
        }
    }
}

impl Iterator for Entries {
    type Item = Entry;

    fn next(&mut self) -> Option<Entry> {
        let ticket = self.this.tickets.borrow_mut().pop()?;
        Some(Entry {
            pool: Rc::clone(&self.this),
            ticket: mem::ManuallyDrop::new(ticket),
        })
    }
}

impl ops::Deref for Entry {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        unsafe { self.ticket.get(&self.pool) }
    }
}

impl ops::DerefMut for Entry {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { self.ticket.get_mut(&self.pool) }
    }
}


impl Drop for Entry {
    fn drop(&mut self) {
        // SAFETY: we forget about our own ticket directly after.
        // Besides, it would be technically Copy from within this module.
        let ticket = unsafe { ptr::read(&*self.ticket) };
        self.pool.tickets.borrow_mut().push(ticket);
    }
}
