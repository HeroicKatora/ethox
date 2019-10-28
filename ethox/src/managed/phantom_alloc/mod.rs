mod phantom_vec;
mod phantom_btree;

pub mod collections {
    pub use super::phantom_btree::BTreeMap;

    pub mod btree_map {
        pub use super::super::phantom_btree::*;
    }
}

pub mod vec {
    pub use super::phantom_vec::Vec;
}
