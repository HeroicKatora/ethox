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

macro_rules! byte_wrapper {
    ($name:ident) => {
        #[allow(non_camel_case_types)]
        #[repr(transparent)]
        #[derive(Debug, PartialEq, Eq, PartialOrd)]
        pub struct $name([u8]);

        impl $name {
            fn __from_macro_new_unchecked(data: &[u8]) -> &Self {
                // SAFETY: this is safe due to repr(transparent)
                unsafe { &*(data as *const _ as *const Self) }
            }

            fn __from_macro_new_unchecked_mut(data: &mut [u8]) -> &mut Self {
                // SAFETY: this is safe due to repr(transparent)
                unsafe { &mut *(data as *mut _ as *mut Self) }
            }
        }
    }
}

#[cfg(feature = "log")]
#[macro_use]
mod log {
    macro_rules! net_log {
        (trace, $($arg:expr),*) => { trace!($($arg),*); };
        (debug, $($arg:expr),*) => { debug!($($arg),*); };
    }
}

#[cfg(not(feature = "log"))]
#[macro_use]
mod log {
    macro_rules! net_log {
        ($level:ident, $($arg:expr),*) => { $( let _ = $arg; )* }
    }
}

macro_rules! net_trace {
    ($($arg:expr),*) => (net_log!(trace, $($arg),*));
}

macro_rules! net_debug {
    ($($arg:expr),*) => (net_log!(debug, $($arg),*));
}
