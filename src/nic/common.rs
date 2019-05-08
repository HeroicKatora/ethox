//! Useful base types for implementing a nic.
use super::{Error, Handle, Result};

/// A handle representation allowing to set a flag for queueing a packet.
pub enum EnqueueFlag {
    NotPossible,
    SetTrue(bool),
}

impl EnqueueFlag {
    pub fn was_sent(&self) -> bool {
        match self {
            EnqueueFlag::NotPossible => false,
            EnqueueFlag::SetTrue(b) => *b,
        }
    }
}

impl Handle for EnqueueFlag {
    fn queue(&mut self) -> Result<()> {
        match self {
            EnqueueFlag::NotPossible => Err(Error::Illegal),
            EnqueueFlag::SetTrue(b) => Ok(*b = true),
        }
    }
}
