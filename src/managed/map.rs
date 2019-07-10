use super::List;
use crate::alloc::collections::btree_map;

/// A map on owned or non-owned data.
///
///
pub enum Map<'a, K: Ord, V> {
    /// The primitive option for a map, a list of pairs.
    ///
    /// Only use this for very small maps where it should be expected that simple traversal is
    /// faster or about as fast as binary search (e.g. `len=4`).
    Pairs(List<'a, (K, V)>),

    /// An owned btree map.
    ///
    /// Note that this refers to a phantom data structure from this crate (that can no be
    /// constructed) when the feature `std` is not enabled. Since this struct is not provided by
    /// this enum but by its user this is no problem. Quite the opposite, it allows structs which
    /// contain a `Map` and thus must match on its (public) variants to be written without
    /// `#[cfg(..)]` tricks to toggle match arms.
    Btree(btree_map::BTreeMap<K, V>),
}

/// An entry of the map.
///
/// Can be inspected, filled, or removed depending on its state variant.
pub enum Entry<'map, 'a, K: Ord, V> {
    Occupied(OccupiedEntry<'map, 'a, K, V>),
    Vacant(VacantEntry<'map, 'a, K, V>),
    Full,
}

pub struct OccupiedEntry<'map, 'a, K: Ord, V> {
    inner: Occupied<'map, 'a, K, V>,
}

enum Occupied<'map, 'a, K, V> {
    Pairs {
        list: &'map mut List<'a, (K, V)>,
        index: usize,
        key: K,
    },
    Btree(btree_map::OccupiedEntry<'map, K, V>),
}

pub struct VacantEntry<'map, 'a, K: Ord, V> {
    inner: Vacant<'map, 'a, K, V>,
}

enum Vacant<'map, 'a, K, V> {
    Pairs {
        list: &'map mut List<'a, (K, V)>,
        key: K,
    },
    Btree(btree_map::VacantEntry<'map, K, V>),
}


impl<K: Ord, V> Map<'_, K, V> {
    pub fn get(&self, key: &K) -> Option<&V> {
        match self {
            Map::Pairs(list) => list
                .as_slice()
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, val)| val),
            Map::Btree(tree) => tree.get(key),
        }
    }
}

impl<'a, K: Ord, V> Map<'a, K, V> {
    pub fn entry(&mut self, key: K) -> Entry<'_, 'a, K, V> {
        match self {
            Map::Pairs(list) => {
                let index = list
                    .as_slice()
                    .iter()
                    .position(|(k, _)| k == &key);
                match index {
                    Some(index) => Entry::Occupied(OccupiedEntry {
                        inner: Occupied::Pairs {
                            list,
                            index,
                            key,
                        },
                    }),
                    None if list.len() == list.capacity() => Entry::Full,
                    None => Entry::Vacant(VacantEntry {
                        inner: Vacant::Pairs {
                            list,
                            key,
                        },
                    }),
                }
            },
            Map::Btree(tree) => tree.entry(key).into(),
        }
    }
}

impl<'map, K: Ord, V> OccupiedEntry<'map, '_, K, V> {
    pub fn get_mut(&mut self) -> &mut V {
        match &mut self.inner {
            Occupied::Pairs { list, index, .. } => &mut list[*index].1,
            Occupied::Btree(btree) => btree.get_mut(),
        }
    }

    pub fn into_mut(self) -> &'map mut V {
        match self.inner {
            Occupied::Pairs { list, index, .. } => &mut list[index].1,
            Occupied::Btree(btree) => btree.into_mut(),
        }
    }

    /// Delete the entry.
    ///
    /// Contrary to `BtreeMap` the element is *not* always returned as it can not be guaranteed to
    /// yield an owned version. Instead, Clone or `mem::swap` the entry if you require it and use
    /// `remove_key` if you require the key.
    pub fn remove(self) {
        match self.inner {
            Occupied::Pairs { list, index, .. } => { list.remove_at(index).expect("Element was present"); },
            Occupied::Btree(btree) => { btree.remove_entry(); },
        }
    }

    /// Delete the entry but return the key.
    ///
    /// Contrary to `BtreeMap` the element is *not* always returned as it can not be guaranteed to
    /// be possible. Instead, Clone or `mem::swap` the entry if you require it.
    pub fn remove_key(self) -> K {
        match self.inner {
            Occupied::Pairs { list, index, key } => { list.remove_at(index).expect("Element was present"); key },
            Occupied::Btree(btree) => btree.remove_entry().0,
        }
    }
}

impl<'map, K: Ord, V> VacantEntry<'map, '_, K, V> {
    pub fn into_key(self) -> K {
        match self.inner {
            Vacant::Pairs { key, .. } => key,
            Vacant::Btree(btree) => btree.into_key(),
        }
    }

    pub fn insert(self, value: V) -> &'map mut V {
        match self.inner {
            Vacant::Pairs { list, key } => {
                let empty = list.push()
                    .expect("List was not full");
                *empty = (key, value);
                &mut empty.1
            },
            Vacant::Btree(btree) => btree.insert(value),
        }
    }
}

impl<'a, K: Ord, V>
    From<btree_map::Entry<'a, K, V>>
for Entry<'a, '_, K, V> {
    fn from(entry: btree_map::Entry<'a, K, V>) -> Self {
       match entry {
           btree_map::Entry::Occupied(occ) => Entry::Occupied(OccupiedEntry {
               inner: Occupied::Btree(occ),
           }),
           btree_map::Entry::Vacant(vac) => Entry::Vacant(VacantEntry {
               inner: Vacant::Btree(vac),
           }),
       }
    }
}
