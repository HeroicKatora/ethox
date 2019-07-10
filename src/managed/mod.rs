mod map;
mod ordered;
mod partial;
mod phantom_vec;
mod phantom_btree;
mod slice;
mod slotmap;

pub use self::map::Map;
pub use self::ordered::Ordered;
pub use self::partial::Partial;
pub use self::slice::Slice;
pub use self::slotmap::SlotMap;

pub type List<'a, T> = Partial<Slice<'a, T>>;

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
