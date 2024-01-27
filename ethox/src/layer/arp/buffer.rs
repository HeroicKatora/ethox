//! Buffer for ARP neighbor responses which have not been answered immediately or do not originate
//! from an incoming packet. The main concern here is a notion of fairness.
use crate::managed::{Slice, Partial};
use crate::wire::arp;

/// A buffer for outstanding ARP requests against an interface.
pub struct Buffer<'data> {
    storage: Partial<Slice<'data, Option<arp::Repr>>>,
}

impl<'data> Buffer<'data> {
    /// Create a new buffer for outstanding ARP requests against us.
    pub fn new(storage: Slice<'data, Option<arp::Repr>>) -> Self {
        Buffer { storage: Partial::new(storage) }
    }

    /// Inform the buffer of a new ARP request.
    ///
    /// Returns if the request has been added to the buffer. The request can be rejected if the
    /// buffer is full, or if there is an existing request with the same data.
    pub fn offer(&mut self, arp: arp::Repr) -> bool {
        let Some(slot) = self.storage.push() else {
            return false;
        };

        *slot  = Some(arp);
        true
    }

    /// Dequeue one outstanding arp response.
    pub fn pop(&mut self) -> Option<arp::Repr> {
        while let Some(st) = self.storage.pop() {
            if let Some(val) = st.take() {
                return Some(val);
            }

            debug_assert!(false, "Pushed an empty representation");
        }

        None
    }
}

impl<'data> Default for Buffer<'data> {
    fn default() -> Self {
        Buffer {
            storage: Partial::new(Slice::one_default()),
        }
    }
}
