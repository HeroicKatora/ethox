//! Extension traits for payloads.
use core::ops;
use super::{PayloadMut, Reframe, PayloadResult};

/// Describes the resizing that keeps a payload intact.
pub struct ReframePayload {
    /// Total length of the new buffer.
    ///
    /// Must not be smaller than `new_payload.end`.
    pub length: usize,

    /// The position of the payload before reframing.
    ///
    /// Needs to have the same length as `new_payload`.
    pub old_payload: ops::Range<usize>,

    /// The position of the payload after reframing.
    ///
    /// Needs to have the same length as `old_payload`.
    pub new_payload: ops::Range<usize>,
}

/// Extends the mutable payload structures with new reorganization methods.
pub trait PayloadMutExt: PayloadMut {
    /// Reframe but keep the payload.
    ///
    /// The method on the trait protects some arbitrary range of bytes which are in both the source
    /// and target packet. For reusing some packet content it is however necessary to keep the
    /// slice regardless of its position while moving it to some new position. This can be realized
    /// by inserting a move of the packet before or after the reframing operation, depending on its
    /// position.
    ///
    /// ## Example
    ///
    /// ```rust
    /// # #[cfg(feature = "alloc")] {
    /// # use ethox::wire::{PayloadMutExt, ReframePayload};
    /// const PAYLOAD: &[u8] = b"xxxx";
    /// let mut packet = b"******"[..].to_vec();
    /// packet[2..6].copy_from_slice(PAYLOAD);
    ///
    /// packet.reframe_payload(ReframePayload {
    ///     length: 10,
    ///     old_payload: 2..6,
    ///     new_payload: 6..10,
    /// })?;
    ///
    /// assert_eq!(&packet[6..10], PAYLOAD);
    /// # }
    ///
    /// # Ok::<(), ethox::wire::PayloadError>(())
    /// ```
    ///
    /// # Panics
    ///
    /// This methods panics if the reframe is inconsistent, that is:
    ///
    /// * The `old_payload` is not contained in the current frame.
    /// * The `new_payload` is not contained in the wanted frame.
    /// * The paylods differ in length.
    fn reframe_payload(&mut self, frame: ReframePayload) -> PayloadResult<()> {
        assert!(frame.old_payload.len() == frame.new_payload.len());

        let current_len = self.payload().len();
        assert!(current_len >= frame.old_payload.end);
        assert!(frame.length >= frame.new_payload.end);
        assert!(frame.old_payload.start <= frame.old_payload.end);
        assert!(frame.new_payload.start <= frame.new_payload.end);

        if frame.length >= frame.old_payload.end { // We move the payload after reframing.
            // Only reframe if necessary.
            if frame.length != current_len {
                self.reframe(Reframe {
                    length: frame.length,
                    range: frame.old_payload.clone(), // Actually cloning just two ints.
                })?;
            }

            // FIXME: `slice::copy_within` as soon as stable. The following is a specialized
            // variant of its current nightly implementation.
            let slice = self.payload_mut().as_mut_slice();
            assert!(slice.len() == frame.length);
            unsafe {
                core::ptr::copy(
                    slice.get_unchecked(frame.old_payload.start),
                    slice.get_unchecked_mut(frame.new_payload.start),
                    frame.old_payload.len(),
                )
            }
        } else { // Need to move the frame before reframing.
            let slice = self.payload_mut().as_mut_slice();
            assert!(slice.len() == current_len);

            // FIXME: `slice::copy_within`, see above.
            unsafe {
                core::ptr::copy(
                    slice.get_unchecked(frame.old_payload.start),
                    slice.get_unchecked_mut(frame.new_payload.start),
                    frame.old_payload.len(),
                )
            }

            if frame.length != current_len {
                self.reframe(Reframe {
                    length: frame.length,
                    range: frame.new_payload,
                })?;
            }
        }

        Ok(())
    }

    fn memset(&mut self, offset: usize, length: usize, value: u8) {
        let slice = self.payload_mut().as_mut_slice();

        for i in &mut slice[offset..offset + length] {
            *i = value;
        }
    }
}

impl<T: PayloadMut> PayloadMutExt for T { }

#[cfg(test)]
mod tests {
    use super::*;
    use core::cmp::Ordering;

    /// No resizing, just move around.
    #[test]
    fn reframe_move() {
        let mut packet = (0..10).collect::<Vec<_>>();

        // Just moving payload around:
        packet.reframe_payload(ReframePayload {
            length: 10,
            old_payload: 0..5,
            new_payload: 5..10,
        }).expect("Should work fine");
        assert_eq!(packet[5..10].iter().cloned().cmp(0..5), Ordering::Equal);
    }

    /// Overlapping retraction.
    #[test]
    fn reframe_retract() {
        let mut packet = (0..10).collect::<Vec<_>>();
        packet.reframe_payload(ReframePayload {
            length: 7,
            old_payload: 0..5,
            new_payload: 2..7,
        }).expect("Should work fine");
        assert_eq!(packet[2..7].iter().cloned().cmp(0..5), Ordering::Equal);
    }

    /// Reframe extending the packet buffer.
    #[test]
    fn reframe_extend() {
        let mut packet = (0..10).collect::<Vec<_>>();
        packet.reframe_payload(ReframePayload {
            length: 20,
            old_payload: 0..5,
            new_payload: 10..15,
        }).expect("Should work fine");
        assert_eq!(packet[10..15].iter().cloned().cmp(0..5), Ordering::Equal);
    }
}
