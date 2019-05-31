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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketInfo {
    pub timestamp: Instant,
    pub capabilities: Capabilities,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlagState {
    NotPossible,
    SetTrue(bool),
}

impl EnqueueFlag {
    pub fn not_possible(info: PacketInfo) -> Self {
        EnqueueFlag {
            flag: FlagState::NotPossible,
            info,
        }
    }

    pub fn set_true(info: PacketInfo) -> Self {
        EnqueueFlag {
            flag: FlagState::SetTrue(false),
            info,
        }
    }

    pub fn was_sent(&self) -> bool {
        self.flag.was_sent()
    }
}

impl FlagState {
    pub fn was_sent(&self) -> bool {
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

    fn info(&self) -> &Info {
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
