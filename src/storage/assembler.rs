use core::{borrow, fmt, ops};

#[derive(Debug, PartialEq, Eq)]
#[repr(transparent)]
#[allow(non_camel_case_types)]
pub struct assembly {
    contigs: [Contig],
}

/// A buffer (re)assembler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Assembler<C> {
    container: C,
}

pub struct AssemblerIter<'a> {
    assembler: &'a assembly,
    index: usize,
    left: u32,
    right:u32 
}

/// A contiguous chunk of absent data, followed by a contiguous chunk of present data.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contig {
    hole_size: u32,
    data_size: u32,
}

impl Contig {
    fn empty() -> Contig {
        Contig { hole_size: 0, data_size: 0 }
    }

    fn hole_and_data(hole_size: u32, data_size: u32) -> Contig {
        Contig { hole_size, data_size }
    }

    fn has_hole(&self) -> bool {
        self.hole_size != 0
    }

    fn has_data(&self) -> bool {
        self.data_size != 0
    }

    fn total_size(&self) -> u32 {
        self.hole_size + self.data_size
    }

    fn is_empty(&self) -> bool {
        self.total_size() == 0
    }
}

impl fmt::Display for Contig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.has_hole() { write!(f, "({})", self.hole_size)?; }
        if self.has_hole() && self.has_data() { write!(f, " ")?; }
        if self.has_data() { write!(f, "{}",   self.data_size)?; }
        Ok(())
    }
}

impl fmt::Display for assembly {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[ ")?;
        for contig in self.contigs.iter() {
            if contig.is_empty() { break }
            write!(f, "{} ", contig)?;
        }
        write!(f, "]")?;
        Ok(())
    }
}

impl assembly {
    /// Create an empty assembly by zeroeing the slice.
    pub fn new(contigs: &mut [Contig]) -> &mut Self {
        contigs.iter_mut().for_each(|v| *v = Contig::empty());
        Self::from_mut_slice_unchecked(contigs)
    }

    /// Convert a slice.
    ///
    /// Only the tail should consist of contigs without data. This is not critical to memory safety
    /// but to correctness.
    pub fn from_slice_unchecked(contigs: &[Contig]) -> &Self {
        assert!(!contigs.is_empty());
        unsafe { &*(contigs as *const [Contig]  as *const assembly) }
    }

    /// Convert a mutable slice.
    ///
    /// Only the tail should consist of contigs without data. This is not critical to memory safety
    /// but to correctness.
    pub fn from_mut_slice_unchecked(contigs: &mut [Contig]) -> &mut Self {
        assert!(!contigs.is_empty());
        unsafe { &mut *(contigs as *mut [Contig]  as *mut assembly) }
    }

    fn back(&self) -> Contig {
        self.contigs[self.contigs.len() - 1]
    }

    /// Return whether the assembler contains no more data.
    pub fn is_empty(&self) -> bool {
        self.contigs.iter().all(|contig| contig.is_empty())
    }

    fn remove_contigs(&mut self, at: usize, len: usize) {
        let range = &mut self.contigs[at..];
        range[..len].iter_mut()
            .for_each(|v| *v = Contig::empty());
        range.rotate_left(len);
    }

    fn add_contig_at(&mut self, at: usize) -> &mut Contig {
        assert!(self.back().is_empty());

        self.contigs[at..].rotate_right(1);
        self.contigs[at] = Contig::empty();

        &mut self.contigs[at]
    }

    /// Remove any leading bytes.
    ///
    /// Can be used to remove leftover bytes after a bounded operation (`bounded_add`) removed only
    /// parts of a fully assembled initial sequence.
    ///
    /// ## Example
    ///
    /// ```
    /// # use ethox::storage::assembler::{Contig, Assembler};
    /// let mut memory: [Contig; 2] = [Contig::default(); 2];
    /// let mut asm = Assembler::new(&mut memory[..]);
    ///
    /// // Add four bytes without removing any start bytes.
    /// assert_eq!(asm.bounded_add(0, 4, 0), Ok(0));
    /// // Pop the 4 bytes in a separate operation.
    /// assert_eq!(asm.reduce_front(), 4);
    /// ```
    pub fn reduce_front(&mut self) -> u32 {
        self.add(0, 0).unwrap()
    }

    /// Add a new contiguous range to the assembler.
    ///
    /// Returns the number of bytes that became assembled from the range.
    ///
    /// ## Example
    ///
    /// ```
    /// # use ethox::storage::assembler::{Contig, Assembler};
    /// let mut memory: [Contig; 2] = [Contig::default(); 2];
    /// let mut asm = Assembler::new(&mut memory[..]);
    ///
    /// // Add four bytes not at the start.
    /// assert_eq!(asm.add(4, 4), Ok(0));
    /// // Add missing four bytes at the start, which assembles the chunk.
    /// assert_eq!(asm.add(0, 4), Ok(8));
    /// ```
    pub fn add(&mut self, start: u32, size: u32) -> Result<u32, ()> {
        self.add_impl(start, size, u32::max_value())
    }

    /// Add a new contiguous range and then pop at most `max` assembled bytes.
    ///
    /// Returns the number of bytes that were assembled in front, or `Err(())` if it was not
    /// possible to store the range. If this operation returns an error then it did not modify the
    /// `Assembler` at all.
    ///
    /// ## Example
    ///
    /// ```
    /// # use ethox::storage::assembler::{Contig, Assembler};
    /// let mut memory: [Contig; 2] = [Contig::default(); 2];
    /// let mut asm = Assembler::new(&mut memory[..]);
    ///
    /// // Add four bytes not at the start.
    /// assert_eq!(asm.add(4, 4), Ok(0));
    /// // Add the four bytes at the start but do not return them all yet.
    /// assert_eq!(asm.bounded_add(0, 4, 4), Ok(4));
    /// // Now pop the 4 remaining bytes.
    /// assert_eq!(asm.reduce_front(), 4);
    /// ```
    pub fn bounded_add(&mut self, start: u32, size: u32, max: u32) -> Result<u32, ()> {
        self.add_impl(start, size, max)
    }

    fn add_impl(&mut self, start: u32, size: u32, max: u32) -> Result<u32, ()> {
        /// A state into which we can absorb existing `Contig` ranges.
        struct Absorber {
            /// End byte relative to start.
            len: u32,
            /// The start relative to iter start.
            start: u32,
            /// End byte relative to current contig.
            rel_end: u32,
            /// Number of absorbed contig ranges.
            absorbed: usize,
            /// If a new range can be inserted.
            available: bool,
        }

        impl Absorber {
            /// Try to absorb a range.
            ///
            /// Returns `true` if the range was fully absorbed or `false` if only its leading empty
            /// part was modified.
            fn absorb(&mut self, rhs: &mut Contig) -> bool {
                if rhs.is_empty() {
                    return false;
                }

                if self.rel_end < rhs.hole_size {
                    if self.would_overflow() {
                        // We must not modify the contig if we can't insert the absorbed bytes.
                        return false;
                    }
                    rhs.hole_size -= self.rel_end;
                    self.rel_end = 0;
                    false
                } else {
                    let rel_start = self.rel_end.saturating_sub(self.len);
                    if rel_start > rhs.hole_size {
                        let new_len = self.start - rhs.hole_size;
                        self.start = rhs.hole_size;
                        self.len += new_len;
                    }

                    let new_end = self.rel_end.max(rhs.total_size());
                    self.len += new_end - self.rel_end;

                    self.rel_end = new_end - rhs.total_size();
                    self.absorbed += 1;
                    true
                }
            }

            fn would_overflow(&self) -> bool {
                // We would overflow if we have not absorbed any existing contig and no empty is
                // available at the end of the assembly.
                self.absorbed == 0 && !self.available
            }
        }

        // Find the containing or adjacent contig range.
        let mut relative = start;
        let mut idx = 0;
        loop {
            if self.contigs[idx].total_size() >= relative {
                break;
            }

            if self.contigs[idx].is_empty() {
                break;
            }

            if idx + 1 == self.contigs.len() {
                return Err(())
            }

            relative -= self.contigs[idx].total_size();
            idx += 1;
        }

        let mut absorber = Absorber {
            len: size,
            start: relative,
            rel_end: relative + size,
            absorbed: 0,
            available: self.back().is_empty(),
        };

        for contig in &mut self.contigs[idx..] {
            if !absorber.absorb(contig) {
                break;
            }
        }

        let removed_bytes;
        if start == 0 {
            if absorber.len <= max {
                debug_assert!(relative == 0);
                // Delete absorbed ranges
                self.remove_contigs(0, absorber.absorbed);
                return Ok(absorber.len);
            }

            // Had more than `max` bytes`. Here we deviate from the options below to provide a
            // forward progress guarantee. Adding bytes at the beginning should *always* succeed
            // with at least the allowed `max` bytes. However, the handling below might require us
            // to reserve a `contig` in case we overflow into a hole at the start of the assembler.
            // This operation may fail (`!absorber.available`). We rather drop *some* data than
            // risk not making any progress when a hole larger than the maximum segment size is
            // introduced.
            //
            // TODO: it may be valuable to *instead* drop one Contig from the end.
            if absorber.would_overflow() {
                // Can't insert all bytes that were added but we can return the start of what would
                // have been inserted instead.
                self.contigs[0].hole_size -= max;
                return Ok(max)
            }

            // We can treat this as a successful merge but deduct the popped bytes.
            removed_bytes = max;
            absorber.len -= max;
        } else {
            removed_bytes = 0;
        }
        
        if absorber.absorbed == 0 {
            if !absorber.available {
                debug_assert_eq!(removed_bytes, 0);
                return Err(())
            }

            let contig = self.add_contig_at(idx);
            *contig = Contig::hole_and_data(absorber.start, absorber.len);
            Ok(removed_bytes)
        } else {
            self.remove_contigs(idx + 1, absorber.absorbed - 1);
            self.contigs[idx] = Contig::hole_and_data(absorber.start, absorber.len);
            Ok(removed_bytes)
        }
    }

    /// Iterate over all of the contiguous data ranges.
    ///
    /// This is used in calculating what data ranges have been received. The offset indicates the
    /// number of bytes of contiguous data received before the beginnings of this Assembler.
    ///
    /// ```text
    ///    Data        Hole        Data
    /// |--- 100 ---|--- 200 ---|--- 100 ---|
    ///
    /// ```
    ///
    /// This would return the ranges: ``(100, 200), (300, 400)``
    pub fn iter_data<'a>(&'a self) -> AssemblerIter<'a> {
        AssemblerIter::new(self)
    }
}

impl<C> Assembler<C> {
    pub fn new(container: C) -> Self
        where C: borrow::BorrowMut<[Contig]>,
    {
        Assembler { container }
    }

    pub fn into_inner(self) -> C {
        self.container
    }
}

impl<'a> AssemblerIter<'a> {
    fn new(assembler: &'a assembly) -> AssemblerIter<'a> {
        AssemblerIter {
            assembler: assembler,
            index: 0,
            left: 0,
            right: 0
        }
    }
}

impl<C: borrow::Borrow<[Contig]>> ops::Deref for Assembler<C> {
    type Target = assembly;

    fn deref(&self) -> &assembly {
        assembly::from_slice_unchecked(self.container.borrow())
    }
}

impl<C: borrow::BorrowMut<[Contig]>> ops::DerefMut for Assembler<C> {
    fn deref_mut(&mut self) -> &mut assembly {
        assembly::from_mut_slice_unchecked(self.container.borrow_mut())
    }
}

impl<'a> Iterator for AssemblerIter<'a> {
    type Item = (u32, u32);

    fn next(&mut self) -> Option<(u32, u32)> {
        let mut data_range = None;
        while data_range.is_none() && self.index < self.assembler.contigs.len() {
            let contig = self.assembler.contigs[self.index];
            self.left = self.left + contig.hole_size;
            self.right = self.left + contig.data_size;
            data_range = if self.left < self.right {
                let data_range = (self.left, self.right);
                self.left = self.right;
                Some(data_range)
            } else {
                None
            };
            self.index += 1;
        }
        data_range
    }
}

#[cfg(test)]
mod test {
    use std::vec::Vec;
    use super::*;

    fn from_values(vec: Vec<(u32, u32)>) -> Assembler<Vec<Contig>> {
        let vec = vec
            .into_iter()
            .map(|(a, b)| Contig::hole_and_data(a, b))
            .collect();
        Assembler::new(vec)
    }

    macro_rules! contigs {
        [$( $x:expr ),*] => ({
            from_values(vec![$( $x ),*])
        })
    }

    #[test]
    fn test_empty_add_full() {
        let mut assr = Assembler::new(vec![Contig::default(); 1]);
        assert_eq!(assr.add(0, 16), Ok(16));
        assert_eq!(assr, contigs![(0, 0)]);
    }

    #[test]
    fn test_empty_add_front() {
        let mut assr = Assembler::new(vec![Contig::default(); 2]);
        assert_eq!(assr.add(0, 4), Ok(4));
        assert_eq!(assr, contigs![(0, 0), (0, 0)]);
    }

    #[test]
    fn test_empty_add_back() {
        let mut assr = contigs![(16, 0)];
        assert_eq!(assr.add(12, 4), Ok(0));
        assert_eq!(assr, contigs![(12, 4)]);
    }

    #[test]
    fn test_empty_add_mid() {
        let mut assr = contigs![(16, 0), (0, 0)];
        assert_eq!(assr.add(4, 8), Ok(0));
        assert_eq!(assr, contigs![(4, 8), (4, 0)]);
    }

    #[test]
    fn test_partial_add_front() {
        let mut assr = contigs![(4, 8), (4, 0)];
        assert_eq!(assr.add(0, 4), Ok(12));
        assert_eq!(assr, contigs![(4, 0), (0, 0)]);
    }

    #[test]
    fn test_partial_add_back() {
        let mut assr = contigs![(4, 8), (4, 0)];
        assert_eq!(assr.add(12, 4), Ok(0));
        assert_eq!(assr, contigs![(4, 12), (0, 0)]);
    }

    #[test]
    fn test_partial_add_front_overlap() {
        let mut assr = contigs![(4, 8), (4, 0)];
        assert_eq!(assr.add(0, 8), Ok(12));
        assert_eq!(assr, contigs![(4, 0), (0, 0)]);
    }

    #[test]
    fn test_partial_add_front_overlap_split() {
        let mut assr = contigs![(4, 8), (4, 0)];
        assert_eq!(assr.add(2, 6), Ok(0));
        assert_eq!(assr, contigs![(2, 10), (4, 0)]);
    }

    #[test]
    fn test_partial_add_back_overlap() {
        let mut assr = contigs![(4, 8), (4, 0)];
        assert_eq!(assr.add(8, 8), Ok(0));
        assert_eq!(assr, contigs![(4, 12), (0, 0)]);
    }

    #[test]
    fn test_partial_add_back_overlap_split() {
        let mut assr = contigs![(4, 8), (4, 0)];
        assert_eq!(assr.add(10, 4), Ok(0));
        assert_eq!(assr, contigs![(4, 10), (2, 0)]);
    }

    #[test]
    fn test_partial_add_both_overlap() {
        let mut assr = contigs![(4, 8), (4, 0)];
        assert_eq!(assr.add(0, 16), Ok(16));
        assert_eq!(assr, contigs![(0, 0), (0, 0)]);
    }

    #[test]
    fn test_partial_add_both_overlap_split() {
        let mut assr = contigs![(4, 8), (4, 0)];
        assert_eq!(assr.add(2, 12), Ok(0));
        assert_eq!(assr, contigs![(2, 12), (2, 0)]);
    }

    #[test]
    fn test_rejected_add_keeps_state() {
        const CONTIG_COUNT: usize = 20;
        let mut assr = Assembler::new(vec![Contig::default(); CONTIG_COUNT]);
        for c in 0..CONTIG_COUNT {
          assert_eq!(assr.add(1 + c as u32*10, 3), Ok(0));
        }
        // Maximum of allowed holes is reached
        let assr_before = assr.clone();
        assert_eq!(assr.add(5, 3), Err(()));
        assert_eq!(assr_before, assr);
    }

    #[test]
    fn test_forward_progress() {
        const CONTIG_COUNT: usize = 20;
        let mut assr = Assembler::new(vec![Contig::default(); CONTIG_COUNT]);
        for c in 0..CONTIG_COUNT {
          assert_eq!(assr.add(2 + c as u32*10, 3), Ok(0));
        }
        assert_eq!(assr.add(0, 1), Ok(1));
    }

    #[test]
    fn test_empty_remove_front() {
        let mut assr = contigs![(12, 0)];
        assert_eq!(assr.reduce_front(), 0);
    }

    #[test]
    fn test_trailing_hole_remove_front() {
        let mut assr = contigs![(0, 4), (8, 0)];
        assert_eq!(assr.reduce_front(), 4);
        assert_eq!(assr, contigs![(8, 0), (0, 0)]);
    }

    #[test]
    fn test_trailing_data_remove_front() {
        let mut assr = contigs![(0, 4), (4, 4)];
        assert_eq!(assr.reduce_front(), 4);
        assert_eq!(assr, contigs![(4, 4), (0, 0)]);

    }

    #[test]
    fn test_iter_empty() {
        let assr = Assembler::new(vec![Contig::default(); 1]);
        let segments: Vec<_> = assr.iter_data().collect();
        assert_eq!(segments, vec![]);
    }

    #[test]
    fn test_iter_full() {
        let assr = contigs![(0, 16)];
        let segments: Vec<_> = assr.iter_data().collect();
        assert_eq!(segments, vec![(0, 16)]);
    }

    #[test]
    fn test_iter_one_front() {
        let assr = contigs![(0, 4)];
        let segments: Vec<_> = assr.iter_data().collect();
        assert_eq!(segments, vec![(0, 4)]);
    }

    #[test]
    fn test_iter_one_back() {
        let assr = contigs![(12, 4)];
        let segments: Vec<_> = assr.iter_data().collect();
        assert_eq!(segments, vec![(12, 16)]);
    }

    #[test]
    fn test_iter_one_mid() {
        let assr = contigs![(4, 8)];
        let segments: Vec<_> = assr.iter_data().collect();
        assert_eq!(segments, vec![(4, 12)]);
    }

    #[test]
    fn test_iter_one_trailing_gap() {
        let assr = contigs![(4, 8), (4, 0)];
        let segments: Vec<_> = assr.iter_data().collect();
        assert_eq!(segments, vec![(4, 12)]);
    }

    #[test]
    fn test_iter_two_split() {
        let assr = contigs![(2, 6), (4, 1), (1, 0)];
        let segments: Vec<_> = assr.iter_data().collect();
        assert_eq!(segments, vec![(2, 8), (12, 13)]);
    }

    #[test]
    fn test_iter_three_split() {
        let assr = contigs![(2, 6), (2, 1), (2, 2), (1, 0)];
        let segments: Vec<_> = assr.iter_data().collect();
        assert_eq!(segments, vec![(2, 8), (10, 11), (13, 15)]);
    }

    #[test]
    fn stored_partial_progress() {
        let mut assr = contigs![(0, 0)];
        // Progress even when no space at all.
        assert_eq!(assr.bounded_add(0, 2, 1), Ok(1));
        assert_eq!(assr, contigs![(0, 1)]);
    }

    #[test]
    fn record_forgotten_partial_progress() {
        let mut assr = contigs![(3, 5)];
        // Progress is reflected in change.
        assert_eq!(assr.bounded_add(0, 2, 1), Ok(1));
        assert_eq!(assr, contigs![(2, 5)]);
    }

    #[test]
    fn always_initial_progress() {
        let mut assr = contigs![(4, 0)];
        assert_eq!(assr.bounded_add(0, 2, 1), Ok(1));
    }

    #[test]
    fn advancing_partial_progress() {
        let mut assr = contigs![(4, 1), (2, 1)];
        assert_eq!(assr.bounded_add(0, 6, 2), Ok(2));
        assert_eq!(assr, contigs![(0, 4), (1, 1)]);
    }

    #[test]
    fn overlapping_partial_progress() {
        let mut assr = contigs![(4, 8), (4, 4)];
        assert_eq!(assr.bounded_add(0, 16, 2), Ok(2));
        assert_eq!(assr, contigs![(0, 18), (0, 0)]);
    }

    #[test]
    fn max_forward_progress() {
        const CONTIG_COUNT: usize = 20;
        let mut assr = Assembler::new(vec![Contig::default(); CONTIG_COUNT]);
        for c in 0..CONTIG_COUNT {
          assert_eq!(assr.add(5 + c as u32*10, 3), Ok(0));
        }
        assert_eq!(assr.bounded_add(0, 2, 1), Ok(1));
    }
}
