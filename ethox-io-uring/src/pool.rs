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
    /// An iterator that crates new entries when polled.
    pub fn spawn_entries(this: Rc<Self>) -> Entries {
        Entries { this }
    }
}

impl Ticket {
    /// Requires: The pool must be the one used to create the ticket.
    unsafe fn get(&self, pool: &Pool) -> &[u8] {
        unsafe {
            slice::from_raw_parts(self.ptr as *const u8, pool.entry_size)
        }
    }

    /// Requires: The pool must be the one used to create the ticket.
    fn get_mut(&mut self, pool: &Pool) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(self.ptr as *mut u8, pool.entry_size)
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
