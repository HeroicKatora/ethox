//! An assortment of non-owning containers.
//!
//! All of these containers have some option to construct them from one (or more) slices of the
//! underlying types instead of allocating resources dynamically.
mod map;
mod ordered;
mod partial;
mod phantom_vec;
mod phantom_btree;
mod slice;
pub mod slotmap;

pub use self::map::Map;
pub use self::ordered::Ordered;
pub use self::partial::Partial;
pub use self::slice::Slice;
pub use self::slotmap::{SlotMap, Slot};

/// A sort of `Vec` on initialized data.
pub type List<'a, T> = Partial<Slice<'a, T>>;

/// A 'drop-in' replacement for the interface of `alloc`, excluding instantiation.
///
/// Most processing tasks require some memory. But a strict `no_std` crate can not allocate on its
/// own, so it needs to calling code to pass the memory to it. This is easy when the interface can
/// use a generic slice or uninitialized memory. However, when a specific container is expected
/// (e.g. a map or vector) then the type must actually exist in the type system.
///
/// The rust standard library declares its containers in the `alloc` crate but using it conflicts
/// with struct `no_std`, since linking it will require an allocator already. The replacements
/// declarations here offer an *interface* similar to the standard containers but are uninhabited,
/// they can't be instantiated.
///
/// This allows writing methods that look as if they utilize a borrowed `::alloc::Vec` without
/// depending on `alloc` which greatly reduces the number of feature dependent `#[cfg]` switches
/// present in the code.
#[cfg(all(
    not(feature = "std"),
    not(test)))]
pub mod alloc {
    pub mod collections {
        pub use crate::managed::phantom_btree::BTreeMap;

        pub mod btree_map {
            pub use crate::managed::phantom_btree::*;
        }
    }

    pub mod vec {
        pub use crate::managed::phantom_vec::Vec;
    }
}
