/// Define an enumeration with known variants and an unknown representation.
///
/// Most network protocols define fields where not all bit-patterns are standardized values. In
/// some cases these are invalid while others allocate them through some registrar (such as IANA).
/// This macro makes it more ergonomic to define a representation for such fields by providing
/// converters to and from an underlying representation derived from the definition.
///
/// # Example
///
/// ```
/// # use ethox::enum_with_unknown;
/// # fn main() { }
/// enum_with_unknown! {
///     #[derive(Copy, Clone)]
///     pub enum IpVersion(u8) {
///         IpV4 = 4,
///         IpV6 = 6,
///     }
/// }
/// ```
// Copyright (C) 2016 whitequark@whitequark.org
macro_rules! enum_with_unknown {
    (
        $( #[$enum_attr:meta] )*
        pub enum $name:ident($ty:ty) {
            $( $variant:ident = $value:expr ),+ $(,)*
        }
    ) => {
        enum_with_unknown! {
            $( #[$enum_attr] )*
            pub doc enum $name($ty) {
                $( #[doc(shown)] $variant = $value ),+
            }
        }
    };
    (
        $( #[$enum_attr:meta] )*
        pub doc enum $name:ident($ty:ty) {
            $(
              $( #[$variant_attr:meta] )+
              $variant:ident = $value:expr $(,)*
            ),+
        }
    ) => {
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
        $( #[$enum_attr] )*
        pub enum $name {
            $(
              $( #[$variant_attr] )*
              $variant
            ),*,
            /// A value whose interpretation was not determined.
            ///
            /// There are two common cases where this is necessary: To represent a parsed valued
            /// from an unknown source which might be faulty or from an unsupported standard
            /// version; Or to encode an arbitrary user supplied value in such fields to allow
            /// extensions that are not supported in `ethox` itself.
            Unknown($ty)
        }

        impl ::core::convert::From<$ty> for $name {
            fn from(value: $ty) -> Self {
                match value {
                    $( $value => $name::$variant ),*,
                    other => $name::Unknown(other)
                }
            }
        }

        impl ::core::convert::From<$name> for $ty {
            fn from(value: $name) -> Self {
                match value {
                    $( $name::$variant => $value ),*,
                    $name::Unknown(other) => other
                }
            }
        }
    }
}

/// Declare a dynamically sized byte wrapper.
///
/// Use this to create byte slices with inner invariants. This macro performs two basic actions:
/// * Define a type with the indicated structure, documentation, attributes. The type can not have
///   any generic arguments and can only wrap a simple byte slice.
/// * Define two new private methods for conversion from a byte slice:
///   - `fn __from_macro_new_unchecked(&[u8]) -> &Self`
///   - `fn __from_macro_new_unchecked_mut(&mut [u8]) -> &mut Self`
///
/// ## Usage
///
/// You can currently only use a tuple type with a single member, a `[u8]`.
///
/// ```
/// # use ethox::byte_wrapper;
/// byte_wrapper! {
///     /// A udp packet.
///     pub struct udp([u8]);
/// }
///
/// impl udp {
///     pub fn from_slice(slice: &[u8]) -> &Self {
///         Self::__from_macro_new_unchecked(slice)
///     }
/// }
///
/// let data = [0x20, 0x00, 0x00, 0x20, 0x00, 0x00, 0x08, 0x00];
/// let _= udp::from_slice(&data);
/// ```
#[macro_export]
macro_rules! byte_wrapper {
    (
        pub struct $name:ident([u8])$(;)*
    ) => {
        byte_wrapper! {
            @pub struct $name([u8])
        }
    };
    (
        $( #[$attr:meta] )*
        pub struct $name:ident([u8])$(;)*
    ) => {
        byte_wrapper! {
            @$( #[$attr] )*
            pub struct $name([u8])
        }
    };
    (
        @$( #[$attr:meta] )*
        pub struct $name:ident([u8])
    ) => {
        #[allow(non_camel_case_types)]
        #[repr(transparent)]
        $( #[$attr] )*
        pub struct $name([u8]);

        impl $name {
            #[allow(dead_code)]
            fn __from_macro_new_unchecked(data: &[u8]) -> &Self {
                // SAFETY: this is safe due to repr(transparent)
                unsafe { &*(data as *const _ as *const Self) }
            }

            #[allow(dead_code)]
            fn __from_macro_new_unchecked_mut(data: &mut [u8]) -> &mut Self {
                // SAFETY: this is safe due to repr(transparent)
                unsafe { &mut *(data as *mut _ as *mut Self) }
            }
        }
    }
}

#[cfg(all(feature = "log", DISABLED))]
#[macro_use]
mod log {
    macro_rules! net_log {
        (trace, $($arg:expr),*) => { trace!($($arg),*); };
        (debug, $($arg:expr),*) => { debug!($($arg),*); };
    }
}

#[cfg(not(all(feature = "log", DISABLED)))]
#[macro_use]
mod log {
    macro_rules! net_log {
        ($level:ident, $($arg:expr),*) => { $( let _ = $arg; )* }
    }
}

#[macro_export]
macro_rules! net_trace {
    ($($arg:expr),*) => (net_log!(trace, $($arg),*));
}

#[macro_export]
macro_rules! net_debug {
    ($($arg:expr),*) => (net_log!(debug, $($arg),*));
}
