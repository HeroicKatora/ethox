//! Useful base types for implementing a nic.
use crate::layer::{Error, Result};
use crate::time::Instant;

use super::{Capabilities, Handle, Info};

/// A handle representation allowing to set a flag for queueing a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnqueueFlag {
    flag: FlagState,
    info: PacketInfo,
}

/// A static representation of packet/network interface metadata.
///
/// This implements [`Info`] and can be used for interface implementations where that information is
/// not dynamic.
///
/// [`Info`]: ../trait.Info.html
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketInfo {
    /// The associated timestamp of the packet.
    pub timestamp: Instant,
    /// The capabilities offered for a packet buffer.
    pub capabilities: Capabilities,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlagState {
    NotPossible,
    SetTrue(bool),
}

impl EnqueueFlag {
    /// Create a flag signalling that the buffer can not be queued.
    pub fn not_possible(info: PacketInfo) -> Self {
        EnqueueFlag {
            flag: FlagState::NotPossible,
            info,
        }
    }

    /// Create a flag that can be set to queue a buffer.
    pub fn set_true(info: PacketInfo) -> Self {
        EnqueueFlag {
            flag: FlagState::SetTrue(false),
            info,
        }
    }

    /// Query if the flag has been set to queue a buffer.
    ///
    /// This can only return `true` if the flag was created with `set_true`.
    pub fn was_sent(&self) -> bool {
        self.flag.was_sent()
    }
}

impl FlagState {
    pub(crate) fn was_sent(&self) -> bool {
        match self {
            FlagState::NotPossible => false,
            FlagState::SetTrue(b) => *b,
        }
    }

    fn queue(&mut self) -> Result<()> {
        match self {
            FlagState::NotPossible => Err(Error::Illegal),
            FlagState::SetTrue(b) => Ok(*b = true),
        }
    }
}

impl Handle for EnqueueFlag {
    fn queue(&mut self) -> Result<()> {
        self.flag.queue()
    }

    fn info(&self) -> &dyn Info {
        &self.info
    }
}

impl Info for PacketInfo {
    fn timestamp(&self) -> Instant {
        self.timestamp
    }

    fn capabilities(&self) -> Capabilities {
        self.capabilities
    }
}
