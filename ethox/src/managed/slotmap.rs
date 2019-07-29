use super::{List, Slice};

/// Provides links between slots and elements.
///
/// The benefit of separating this struct from the elements is that it is unconditionally `Copy`
/// and `Default`. It also provides better locality for both the indices and the elements which
/// could help with iteration or very large structs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Slot {
    /*
    /// Back link of an element to its slot.
    ///
    /// The `Slot` at index `i` provides the mapping for the element at index `i` and its
    /// `index_to_slot` is the index of the slot owning that element. This makes it possible for
    /// the `SlotMap` to swap elements within their containing slice while updating the index
    /// structure in constant time. This in turn keeps the element list organized as a pure stack
    /// even in the face of element removal.
    index_to_slot: usize,
    */

    /// The id of this slot.
    ///
    /// If the given out index mismatches the `generation_id` then the element was removed already
    /// and we can return `None` on lookup.
    ///
    /// If the slot is currently unused we will instead provide the index to the previous slot in
    /// the slot-free-list.
    generation_id: GenerationOrFreelink,
}

/// Provides a slotmap based on external memory.
///
/// A slotmap provides a `Vec`-like interface where each entry is associated with a stable
/// index-like key. Lookup with the key will detect if an entry has been removed but does not
/// require and lifetime relation.
///
/// ## Usage
///
/// The important aspect is that the slotmap does not create the storage of its own elements, it
/// merely manages one given to it at construction time.
///
/// ```
/// # use ethox::managed::{Slice, SlotMap, Slot};
///
/// let mut elements = [0usize; 1024];
/// let mut slots = [Slot::default(); 1024];
///
/// let mut map = SlotMap::new(
///     Slice::Borrowed(&mut elements[..]),
///     Slice::Borrowed(&mut slots[..]));
/// let index = map.insert(42).unwrap();
/// assert_eq!(map.get(index).cloned(), Some(42));
/// ```
pub struct SlotMap<'a, T> {
    elements: Slice<'a, T>,
    slots: List<'a, Slot>,
    generation: Generation,
    free_top: usize,
    indices: IndexComputer,
}

/// An index into a slotmap.
///
/// The index remains valid until the entry is removed. If accessing the slotmap with the index
/// again after the entry was removed will fail, even if the index where the element was previously
/// stored has been reused for another element.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Key {
    idx: usize,
    generation: Generation,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
struct GenerationOrFreelink(isize);

/// Newtype wrapper around the index of a free slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
struct FreeIndex(usize);

/// The generation counter.
/// 
/// Has strictly positive values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Generation(isize);

/// Offset of a freelist entry to the next entry.
///
/// The base for the offset is the *next* element for two reasons:
/// * Offset of `0` points to the natural successor.
/// * Offset of `len` would point to the element itself and should not occur.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Offset(isize);

/// Links FreeIndex and Offset.
struct IndexComputer(usize);

impl<T> SlotMap<'_, T> {
    /// Get a mutable reference to the element that would be pushed next.
    pub fn init(&mut self) -> Option<&mut T> {
        let index = self.free()?;
        Some(&mut self.elements[index.0])
    }

    /// Retrieve a value by index.
    pub fn get(&self, index: Key) -> Option<&T> {
        let slot_generation = self.slots
            .get(index.idx)?
            .generation_id
            .generation().ok()?;

        if slot_generation != index.generation {
            return None;
        }

        self.elements.get(index.idx)
    }

    /// Retrieve a mutable value by index.
    pub fn get_mut(&mut self, index: Key) -> Option<&mut T> {
        let slot_generation = self.slots
            .get(index.idx)?
            .generation_id
            .generation().ok()?;

        if slot_generation != index.generation {
            return None;
        }

        self.elements.get_mut(index.idx)
    }

    /// Reserve a new entry.
    pub fn reserve(&mut self) -> Option<(Key, &mut T)> {
        let index = self.free()?;
        let slot = &mut self.slots[index.0];
        let element = &mut self.elements[index.0];

        let offset = slot.generation_id
            .free_link()
            .expect("Free link should be free");
        slot.generation_id = self.generation.into();
        let key = Key {
            idx: index.0,
            generation: self.generation,
        };

        self.free_top = self.indices.free_list_next(index, offset);
        self.generation.advance();
        Some((key, element))
    }

    /// Sugar wrapper around `reserve` for inserting values.
    ///
    /// Note that on success, an old value stored in the backing slice will be overwritten.
    pub fn insert(&mut self, value: T) -> Option<Key> {
        // Insertion must work but we don't care about the value.
        let (index, element) = self.reserve()?;
        *element = value;
        Some(index)
    }

    /// Remove an element.
    ///
    /// If successful, return a mutable reference to the removed element. Returns `None` if the
    /// provided index did not refer to an element that could be freed.
    pub fn remove(&mut self, index: Key) -> Option<&mut T> {
        if self.get(index).is_none() {
            return None
        }

        // The slot can be freed.
        let free = FreeIndex(index.idx);
        let slot = &mut self.slots[index.idx];
        assert!(slot.generation_id.generation().is_ok());

        let offset = self.indices.free_list_offset(free, self.free_top);
        slot.generation_id = offset.into();
        self.free_top = index.idx;

        Some(&mut self.elements[index.idx])
    }

    /// Get the next free slot.
    fn free(&mut self) -> Option<FreeIndex> {
        // If free_top is one-past-the-end marker one of those is going to fail. Note that this
        // also means extracting one of these statements out of the function may change the
        // semantics if `elements.len() != slots.len()`.

        // Ensure the index refers to an element within the slice or try to allocate a new slot
        // wherein we can fit the element.
        let free = match self.slots.get_mut(self.free_top) {
            Some(_) => {
                // Ensure that there is also a real element there.
                let _= self.elements.get_mut(self.free_top)?;
                FreeIndex(self.free_top)
            },
            None => { // Try to get the next one
                // Will not actually wrap if pushing is successful.
                let new_index = self.slots.len();
                // Ensure there is an element where we want to push to.
                let _ = self.elements.get_mut(new_index)?;

                let free_slot = self.slots.push()?;
                let free_index = FreeIndex(new_index);
                let new_top = new_index.checked_add(1).unwrap();

                let offset = self.indices.free_list_offset(free_index, new_top);
                free_slot.generation_id = offset.into();
                self.free_top = free_index.0;

                free_index
            }
        };


        // index refers to elements within the slices
        Some(free)
    }
}

impl<'a, T> SlotMap<'a, T> {
    pub fn new(elements: Slice<'a, T>, slots: Slice<'a, Slot>) -> Self {
        let capacity = elements.len().min(slots.len());
        SlotMap {
            elements,
            slots: List::new(slots),
            generation: Generation::default(),
            free_top: 0,
            indices: IndexComputer::from_capacity(capacity),
        }
    }
}

impl GenerationOrFreelink {
    pub fn free_link(self) -> Result<Offset, Generation> {
        if self.0 > 0 {
            Err(Generation(self.0))
        } else {
            Ok(Offset(self.0))
        }
    }

    pub fn generation(self) -> Result<Generation, Offset> {
        if self.0 > 0 {
            Ok(Generation(self.0))
        } else {
            Err(Offset(self.0))
        }
    }
}

impl IndexComputer {
    pub fn from_capacity(capacity: usize) -> Self {
        assert!(capacity < isize::max_value() as usize);
        IndexComputer(capacity)
    }

    /// Get the next free list entry.
    fn free_list_next(&self, FreeIndex(base): FreeIndex, offset: Offset)
        -> usize
    {
        let length = self.0;
        let offset = offset.int_offset();

        assert!(base < length);
        assert!(offset <= length);
        let base = base + 1;

        if length - offset <= base {
            offset + base // Fine within the range
        } else {
            // Wrap once, mod (length + 1), result again in range
            offset
                .wrapping_add(base)
                .wrapping_sub(length)
                // Still > 0
                .wrapping_sub(1)
        }
    }

    fn free_list_offset(&self, FreeIndex(base): FreeIndex, to: usize)
        -> Offset
    {
        let length = self.0;

        assert!(base != to, "Cant offset element to itself");
        assert!(base < length, "Should never have to offset the end-of-list marker");
        assert!(to <= length, "Can only offset to the end-of-list marker");
        let base = base + 1;

        Offset::from_int_offset(if base <= to {
            to - base
        } else {
            // Wrap once, mod (length + 1), result again in range
            to
                .wrapping_add(length)
                .wrapping_add(1)
                .wrapping_sub(base)
        })
    }
}

impl Generation {
    pub fn advance(&mut self) {
        assert!(self.0 > 0);
        self.0 = self.0.wrapping_add(1).max(1)
    }
}

impl Offset {
    pub fn from_int_offset(offset: usize) -> Self {
        assert!(offset < isize::max_value() as usize);
        Offset((offset as isize).checked_neg().unwrap())
    }

    pub fn int_offset(self) -> usize {
        self.0.checked_neg().unwrap() as usize
    }
}

impl Default for Generation {
    fn default() -> Self {
        Generation(1)
    }
}

impl From<Generation> for GenerationOrFreelink {
    fn from(gen: Generation) -> GenerationOrFreelink {
        GenerationOrFreelink(gen.0)
    }
}

impl From<Offset> for GenerationOrFreelink {
    fn from(offset: Offset) -> GenerationOrFreelink {
        GenerationOrFreelink(offset.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::Slice;

    #[test]
    fn simple() {
        let mut elements = [0u32; 2];
        let mut slots = [Slot::default(); 2];

        let mut map = SlotMap::new(
            Slice::Borrowed(&mut elements[..]),
            Slice::Borrowed(&mut slots[..]));
        let key42 = map.insert(42).unwrap();
        let keylo = map.insert('K' as _).unwrap();

        assert_eq!(map.insert(0x9999), None);
        assert_eq!(map.get(key42).cloned(), Some(42));
        assert_eq!(map.get(keylo).cloned(), Some('K' as _));
    }

    #[test]
    fn retained() {
        let mut elements = [0u32; 1];
        let mut slots = [Slot::default(); 1];

        let mut map = SlotMap::new(
            Slice::Borrowed(&mut elements[..]),
            Slice::Borrowed(&mut slots[..]));
        let key = map.insert(0xde).unwrap();
        map.remove(key).unwrap();
        assert_eq!(map.get(key), None);

        let new_key = map.insert(0xad).unwrap();

        assert_eq!(map.get(key), None);
        assert_eq!(map.get(new_key).cloned(), Some(0xad));

        assert_eq!(map.remove(key), None);
        map.remove(new_key).unwrap();

        assert_eq!(map.get(key), None);
        assert_eq!(map.get(new_key), None);
    }
}
