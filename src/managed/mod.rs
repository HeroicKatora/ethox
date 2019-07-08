mod map;
mod ordered;
mod partial;
mod phantom_vec;
mod phantom_btree;
mod slice;

pub use self::map::Map;
pub use self::slice::Slice;
pub use self::ordered::Ordered;
pub use self::partial::Partial;

pub type List<'a, T> = Partial<Slice<'a, T>>;

#[cfg(all(
    not(feature = "std"),
    not(test)))]
pub(crate) mod alloc {
    pub use managed::phantom_vec::Vec;

    pub(crate) mod collections {
        pub use managed::phantom_btree::BTreeMap;

        pub(crate) mod btree_map {
            pub use managed::phantom_btree::*;
        }
    }
}

#[cfg(any(
    feature = "std",
    test))]
pub(crate) use ::alloc;
