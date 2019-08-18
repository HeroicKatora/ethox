use core::fmt;

/// The error type for parsing of the network stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// An incoming packet could not be parsed because it was shorter than assumed.
    ///
    /// The packet may be shorter than the minimum length specified, a size longer than the actual
    /// payload. For variable length packets, this may be because some of its fields were out of
    /// bounds of the received data.
    Truncated,

    /// An incoming packet had an incorrect checksum and was dropped.
    ///
    /// A checksum is data that is redundant if perfect packet delivery is ensured. Additionally,
    /// checksum checks should have a switch to disable them to enable fuzzing. For error
    /// correcting checksums this indicates that error correction has also failed.
    WrongChecksum,

    /// An incoming packet could not be recognized and was dropped.
    ///
    /// E.g. an Ethernet packet with an unknown EtherType. This may be due to an outdated
    /// implementation of the standard or registry which defines identifiers in packets. In most
    /// settings, this is not fatal as well-crafted standards consider interoperability to older
    /// revisions of their protocols or even explicitely allow ignoring unknown extensions.
    Unrecognized,

    /// An incoming packet was recognized but was self-contradictory.
    ///
    /// Examples: a TCP packet with both SYN and FIN flags set; a UDP packet claiming to contain
    /// less than 8 bytes of data.
    Malformed,

    /// Parsing depends on information derived from a non-implemented features.
    ///
    /// Similar to `Unrecognized` but in contrast we know that our implementation is incomplete. An
    /// example is a ethernet jumbo frame where the semantics depend not only on the recognition
    /// but also correct handling of the contained data. Other examples would be optional options
    /// that are however mandatory to support if requested by the communicating party.
    Unsupported,

    #[doc(hidden)]
    __Nonexhaustive(Private),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Private { private: () }

/// The result type for the networking stack.
pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Truncated     => write!(f, "truncated packet"),
            Error::WrongChecksum => write!(f, "checksum error"),
            Error::Unrecognized  => write!(f, "unrecognized packet"),
            Error::Unsupported   => write!(f, "unsupported option"),
            Error::Malformed     => write!(f, "malformed packet"),
            Error::__Nonexhaustive(_) => unreachable!()
        }
    }
}
