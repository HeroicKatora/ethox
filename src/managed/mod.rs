mod ordered;
mod partial;
mod phantom_vec;
mod slice;

pub use self::slice::Slice;
pub use self::ordered::Ordered;
pub use self::partial::Partial;

pub type List<'a, T> = Partial<Slice<'a, T>>;

#[cfg(all(
    not(feature = "std"),
    not(test)))]
pub(crate) use self::phantom_vec::Vec;
