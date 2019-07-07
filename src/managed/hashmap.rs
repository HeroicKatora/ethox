//! An implementation of a hashmap with external buffer.
//!
//! ## Design
//!
//! There is not internal way to re-allocate the map and we have a fixed bucket count. That is, the
//! map may report a full storage and for guaranteeing a near-constant time lookup and insertion
//! the full state is not necessarily reached when all buckets are exhausted.
//!
//! There is a question of how the user can provide storage to the hashmap. That depends on the
//! internal structure, of course. Some possible layouts:
//!
//! * `[(hash, key, value), ..]`: Here one needs to preallocate an array of such tuples. Since we
//!   need random access into the array it needs to be fully initialized. For non-`Copy` keys or
//!   values the initialization is complicated; array syntax—`[..; 1024]`—does not work. The
//!   alternatives are transmuting bytes (i.e. wrapped in a macro) or taking *temporary* ownership
//!   of a byte array–which requires there to be no padding within `(hash, key, value)` so that we
//!   do not expose unitialized bytes after the borrow has ended.
//!
//! * `[idx, ..] [(hash, key, value), ..]`: This design (Python 3.7) requires two allocated
//!   regions but  maintains insertion order. This makes iteration much faster. It also permits
//!   in-place modification of the key since rehashing does not require a full reinsertion. It is
//!   thus similar to a slotmap.
//!
//!   There is a slightly hidden advantage. When `key` or `value` is not `Copy` then it is obscure
//!   (and potentially requires `unsafe`) to create a very length array of buckets. However, if the
//!   underlying buckets storage is a list structure (`StaticVec`) instead we can use a byte array
//!   underneat and emplace the initialized bucket contents one-at-a-time. The vec permits a safe
//!   wrapper to correctly track the initialization state but padding within a bucket still has the
//!   same problem with unitialized bytes as above. Also, requiring an internal type as the
//!   underlying storage will in turn make it harder to construct a hashmap where allocation is
//!   possible and the above workaround can be fully avoided.
//!
//! Since padding makes safe borrowing of byte regions impossible in both cases, we'll have to
//! produce owned values for arrays of buckets. Until `const`-generics are stabilized we can sadly
//! also not go the route of providing a `const` constructor for arbitrary sized storages and the
//! `Default` implementation also only reaches until `n=32`.
//!
//! Avoiding the `StaticVec` there remain two possible ways, where `Vec` and `Box` is not
//! available. These are not exclusive.
//!
//! * An `unsafe` constructor from a byte slice with the promise that never is a reference
//!   constructed to its contents, such that we can use it as uninitialized storage. The `unsafe`
//!   portion can be hidden inside a macro that creates an instance of an `UnsafeCell` which can
//!   never be referenced. Then its contents are hidden.
//! * A `Bucket` with an `Empty` state and a macro to construct arbitrarily large arrays of that
//!   type. The only way I found of making the macro `const` enabled depends on
//!   `core::mem::{zeroed, transmute}` being const functions of their own. However, the non-`const`
//!   version can be implemented more safely by correctly initializing each variant instead of
//!   relying on compiler internal representation of a bucket.
//!
//! Note that in the case of allocation or external crates (`Vec`, `SmallVec`, ..) an ergonomic
//! solution should also be applicable to providing the storage from those types.
use core::num::NonZeroU64;

pub struct Bucket<Key, Value> {
    inner: InnerBucket<Key, Value>,
}

enum InnerBucket<Key, Value> {
    None,
    Some {
        hash: NonZeroU64,
        key: Key,
        value: Value,
    },
}

impl<K, V> Default for Bucket<K, V> {
    fn default() -> Self {
        Bucket { inner: InnerBucket::None, }
    }
}

macro_rules! buckets {
    (Bucket::<$Key:ty, $Val:ty>::None; $len:expr) => {{
        const BUCKET_SIZE: usize = core::mem::size_of::<Bucket<$Key, $Val>>();

        let mut storage = [[0u8; BUCKET_SIZE]; $len];

        storage
            .iter_mut()
            .for_each(|bucket| *bucket = unsafe {
                core::mem::transmute(Bucket::<$Key, $Val>::default())
            });

        unsafe {
            core::mem::transmute::<[_; $len], _>(storage)
        }
    }}
}

#[cfg(test)]
#[test]
fn bucket_macro() {
    assert_eq!(core::mem::size_of::<Bucket<u32, u32>>(), 16);
    let buckets: [Bucket<u32, u32>; 5] = buckets![Bucket::<u32, u32>::None; 5];
//     let buckets: [Bucket<u32, u32>; 5] = buckets![None; 5];
    buckets
        .iter()
        .for_each(|bucket| match bucket.inner {
            InnerBucket::None => (),
            _ => panic!("Wrongly initialized bucket"),
        });
}
