use super::Ordered;

/// A map on owned or non-owned data.
///
///
pub enum Map<'a, K: Ord, V> {
    Pairs(Ordered<'a, (K, V)>),

    /// An owned btree map.
    ///
    /// Note that this refers to a phantom data structure from this crate (that can no be
    /// constructed) when the feature `std` is not enabled. Since this struct is not provided by
    /// this enum but by its user this is no problem. Quite the opposite, it allows structs which
    /// contain a `Map` and thus must match on its (public) variants to be written without
    /// `#[cfg(..)]` tricks to toggle match arms.
    Btree(crate::BTreeMap<K, V>),
}

