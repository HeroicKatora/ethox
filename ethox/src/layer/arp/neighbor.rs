// Heads up! Before working on this file you should read, at least,
// the parts of RFC 1122 that discuss ARP.
use core::slice;
use core::ops::Deref;

use crate::managed::Ordered;
use crate::time::{Duration, Expiration, Instant};
use crate::wire::{ethernet, ip};

/// A cached neighbor.
///
/// A neighbor mapping translates from a protocol address (IPv4 and IPv6) to a hardware address,
/// and contains the timestamp past which the mapping should be considered invalid. It also
/// contains a timestamp at which we should try to update the neighbor mapping by sending out
/// solicitation requests.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Neighbor {
    protocol_addr: ip::Address,
    hardware_addr: Mapping,
    expires_at:    Expiration,
}

/// An answer to a neighbor cache lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// The neighbor address is in the cache and not expired.
    Found(ethernet::Address),
    /// The neighbor address is not in the cache, or has expired.
    NotFound,
    /// The neighbor address is not in the cache, or has expired,
    /// and a lookup has been made recently.
    RateLimited,
}

/// One mapped value of an entry in the neighbor cache.
///
/// A valid physical address is only one possible variant. To ensure that an outgoing probe can
/// receive an answer, we reserve a slot while the outstanding request has not timed out. And since
/// we might not have a packet buffer when a request should be sent, or due to rate limiting, there
/// also exists a state for requests that have not yet been sent but which are necessary for upper
/// layer progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mapping {
    /// An address is present.
    Address(ethernet::Address),

    /// We don't have a mapping but want to have one.
    LookingFor,

    /// We are currently sending a request.
    Requesting,
}

impl Default for Mapping {
    fn default() -> Self {
        Mapping::LookingFor
    }
}

/// Errors that can occur when adding a new ARP result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// There as no space to add the entry.
    ///
    /// Entries that do no expire will never be deleted or the storage is completely empty.
    NoSpace,

    /// All other entries that could be evicted live longer.
    ExpiresTooSoon,

    /// Entry could not be found in the storage
    EntryNotFound,
}

/// A neighbor cache backed by a map.
///
/// # Examples
///
/// On systems with heap, this cache can be created with:
///
/// ```rust
/// # #[cfg(feature = "std")] {
/// // Only available with feature = "std"
/// use ethox::layer::arp::{Neighbor, NeighborCache};
///
/// let mut entry_set = vec![Neighbor::default(); 10];
/// let mut neighbor_cache = NeighborCache::new(entry_set);
/// # }
/// ```
///
/// On systems without heap, use:
///
/// ```rust
/// use ethox::layer::arp::{Neighbor, NeighborCache};
///
/// let mut neighbor_cache_storage = [Neighbor::default(); 10];
/// let mut neighbor_cache = NeighborCache::new(&mut neighbor_cache_storage[..]);
/// ```
///
/// ## Details
///
/// The map in the background is an ordered slice, optimized for use in small local networks. This
/// makes insertion and deletion potentially costly but it is bounded by the size of the slice
/// which is chosen by the user. If your use case requires a different performance characteristic,
/// feel free to change the code (and upstream your improvement if possible).
#[derive(Debug)]
pub struct Cache<'a> {
    storage: Ordered<'a, Neighbor>,
    silent_until: Instant,
}

/// Iterator over missing entries.
pub struct Missing<'a> {
    inner: slice::Iter<'a, Neighbor>,
}

/// A part of the neighbor table.
///
/// For lookup purposes only. Even without the additional metadata within the cache itself we can
/// still use the slice of data to perform lookup, as its ordering guarantees are upheld. (We could
/// also do strictly replacing updates which do not influence the table length but doing so is more
/// intricate).
///
/// The advantage of this type is its lifetime bound of `'static`. Meanwhile, `Cache` is bound by
/// its lifetime parameter from the encapsulated reference on the storage. This is a direct
/// reference to the storage and skips the outer reference and thus lifetime layer. In total, this
/// keeps the number of necessary lifetime bounds in check (hopefully).
#[derive(Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Table([Neighbor]);

impl<'a> Cache<'a> {
    /// Neighbor entry lifetime, in milliseconds.
    pub(crate) const ENTRY_LIFETIME: Duration = Duration::from_millis(60_000);

    /// Create a cache.
    ///
    /// The backing storage is created logically empty.
    pub fn new<T>(storage: T) -> Cache<'a>
        where T: Into<Ordered<'a, Neighbor>>
    {
        Self::import(storage.into())
    }

    /// Create a cache from pre-filled neighbor data.
    ///
    /// The backing storage is not cleared and can be arbitrarily pre-filled. Be careful as having
    /// duplicate entries for the same protocol address may make some functions panic. This is
    /// currently not checked beforehand!
    // TODO: remove duplicate entires, e.g. `slice::partition_dedup_by_key` once stable.
    pub fn import(storage: Ordered<'a, Neighbor>) -> Self {
        Cache {
            storage,
            // We will not respond to neighbors requesting, unless we can respond in the same frame.
            silent_until: Instant::from_millis(0),
        }
    }

    /// Add a lookup entry.
    ///
    /// Provide the current timestamp or `None` to disable expiration.
    pub fn fill_looking(
        &mut self,
        protocol_addr: ip::Address,
        timestamp: Option<Instant>,
    ) -> Result<(), Error> {
        self.update_or_insert(protocol_addr, Mapping::LookingFor, timestamp)
    }

    /// Indicate an entry is currently being requested.
    ///
    /// This blocks updates to `LookingFor` from occurring until the timeout.
    pub fn requesting(
        &mut self,
        protocol_addr: ip::Address,
        timestamp: Instant,
    ) -> Result<(), Error> {
        self.update_or_insert(protocol_addr, Mapping::Requesting, Some(timestamp))
    }

    /// Add an entry containing a MAC address.
    ///
    /// Provide the current timestamp or `None` to disable expiration.
    pub fn fill(
        &mut self,
        protocol_addr: ip::Address,
        hardware_addr: ethernet::Address,
        timestamp: Option<Instant>,
    ) -> Result<(), Error> {
        self.update_or_insert(protocol_addr, Mapping::Address(hardware_addr), timestamp)
    }

    /// Add an entry.
    ///
    /// Provide the current timestamp or `None` to disable expiration.
    fn update_or_insert(
        &mut self,
        protocol_addr: ip::Address,
        hardware_addr: Mapping,
        timestamp: Option<Instant>,
    ) -> Result<(), Error> {
        debug_assert!(protocol_addr.is_unicast());
        if let Mapping::Address(hw_addr) = hardware_addr {
            debug_assert!(hw_addr.is_unicast());
        }

        let new_neighbor = Neighbor {
            protocol_addr,
            hardware_addr,
            expires_at: timestamp.map(|ts| ts + Self::ENTRY_LIFETIME).into(),
        };

        // Is this already mapped?
        let exists = self.storage.ordered_slice()
            .binary_search_by_key(&protocol_addr, |neighbor| neighbor.protocol_addr);
        if let Ok(index) = exists {
            let old = self.storage[index];
            assert_eq!(old.protocol_addr, new_neighbor.protocol_addr);

            if let (Mapping::Requesting, Mapping::LookingFor) = (old.hardware_addr, new_neighbor.hardware_addr) {
                if old.expires_at >= Expiration::from(timestamp) {
                    // A not-yet expired request is currently running. Simply do nothing.
                    return Ok(())
                }
            }

            let _old = self.storage.replace_at(index, new_neighbor)
                .expect("Sorting didn't change since we only have one entry per protocol addr");
            return Ok(());
        }

        // Not mapped, need to free an entry.
        let free = match self.storage.init() {
            Some(entry) => {
                entry
            },
            None => {
                // find the oldest entry.
                let (idx, oldest) = self.storage.ordered_slice()
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, neighbor)| neighbor.expires_at)
                    .ok_or(Error::NoSpace)?;
                if oldest.expires_at > new_neighbor.expires_at {
                    return Err(Error::ExpiresTooSoon)
                }
                self.storage.pop(idx)
                    .expect("Entry we just found is valid.");
                self.storage.init()
                    .expect("At least one entry is now free")
            },
        };

        debug_assert!(new_neighbor.hardware_addr != Mapping::Requesting);

        *free = new_neighbor;
        self.storage.push()
            .expect("There was one to insert");
        Ok(())
    }
}

impl Table {
    /// Create a table.
    ///
    /// The data should be ordered and have at most one entry per protocol address, according to
    /// the internal invariants of the neighbor Cache.
    fn from_slice(data: &[Neighbor]) -> &Self {
        unsafe { &*(data as *const [Neighbor] as *const Self) }
    }

    /// Perform one IpAddress to EthernetAddress translation.
    ///
    /// This will ignore any existing mapping other than a valid address. Use it in case it is not
    /// required to know if the protocol address is currently being queried or the request is
    /// currently rate limited. If this *is* required, use `lookup` instead.
    pub fn lookup_pure(
        &self,
        protocol_addr: ip::Address,
        timestamp: Instant
    ) -> Option<ethernet::Address> {
        match self.lookup(protocol_addr, timestamp) {
            Some(Mapping::Address(addr)) => Some(addr),
            _ => None,
        }
    }

    /// Resolve one protocol address to the state reserved for it.
    ///
    /// The variants of the returned enum allows one to deduce if the protocol address is currently
    /// being queried and ifaa request has been sent or is currently rate limited. If only address
    /// information is desired, use `lookup_pure` instead.
    pub fn lookup(
        &self,
        protocol_addr: ip::Address,
        timestamp: Instant
    ) -> Option<Mapping> {
        if protocol_addr.is_broadcast() {
            return Some(Mapping::Address(ethernet::Address::BROADCAST))
        }

        let existing = self
            .binary_search_by_key(&protocol_addr, |neighbor| neighbor.protocol_addr)
            .ok()?;

        let entry = &self[existing];
        if Expiration::When(timestamp) >= entry.expires_at {
            return None;
        }
        
        Some(entry.hardware_addr)
    }

    /// An iterator over entries with no response yet.
    pub fn missing(&self) -> Missing {
        Missing {
            inner: self.0.iter(),
        }
    }
}

impl Neighbor {
    /// Get the protocol address stored in this entry.
    pub fn protocol_addr(&self) -> ip::Address {
        self.protocol_addr
    }

    /// Get the physical address this protocol address is mapped to.
    pub fn hardware_addr(&self) -> Option<ethernet::Address> {
        match self.hardware_addr {
            Mapping::Address(addr) => Some(addr),
            Mapping::LookingFor => None,
            Mapping::Requesting => None,
        }
    }

    /// Check if the entry should still be considered valid.
    ///
    /// This is the negation of `is_expired`.
    pub fn is_alive(&self, ts: Instant) -> bool {
        Expiration::When(ts) <= self.expires_at
    }

    /// Check if the entry expired.
    ///
    /// This is the negation of `is_alive`.
    pub fn is_expired(&self, ts: Instant) -> bool {
        !self.is_alive(ts)
    }

    /// If this address mapping is unknown and should be requested.
    pub fn looking_for(&self) -> bool {
        self.hardware_addr == Mapping::LookingFor
    }
}

impl Deref for Cache<'_> {
    type Target = Table;

    fn deref(&self) -> &Table {
        Table::from_slice(self.storage.ordered_slice())
    }
}

impl Deref for Table {
    type Target = [Neighbor];

    fn deref(&self) -> &[Neighbor] {
        &self.0
    }
}

impl Iterator for Missing<'_> {
    type Item = Neighbor;

    fn next(&mut self) -> Option<Neighbor> {
        self.inner.by_ref()
            .filter(|entry| entry.hardware_addr().is_none())
            .next()
            .copied()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    pub(crate) const MOCK_IP_ADDR_1: ip::Address = ip::Address::Ipv6(ip::v6::Address(
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
    pub(crate) const MOCK_IP_ADDR_2: ip::Address = ip::Address::Ipv6(ip::v6::Address(
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]));
    pub(crate) const MOCK_IP_ADDR_3: ip::Address = ip::Address::Ipv6(ip::v6::Address(
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]));
    pub(crate) const MOCK_IP_ADDR_4: ip::Address = ip::Address::Ipv6(ip::v6::Address(
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4]));

    const HADDR_A: ethernet::Address = ethernet::Address([0, 0, 0, 0, 0, 1]);
    const HADDR_B: ethernet::Address = ethernet::Address([0, 0, 0, 0, 0, 2]);
    const HADDR_C: ethernet::Address = ethernet::Address([0, 0, 0, 0, 0, 3]);
    const HADDR_D: ethernet::Address = ethernet::Address([0, 0, 0, 0, 0, 4]);

    #[test]
    fn fill() {
        let mut cache_storage = [Default::default(); 3];
        let mut cache = Cache::new(&mut cache_storage[..]);

        assert_eq!(cache.lookup_pure(MOCK_IP_ADDR_1, Instant::from_millis(0)), None);
        assert_eq!(cache.lookup_pure(MOCK_IP_ADDR_2, Instant::from_millis(0)), None);

        cache.fill(MOCK_IP_ADDR_1, HADDR_A, Some(Instant::from_millis(0)))
            .unwrap();
        assert_eq!(cache.lookup_pure(MOCK_IP_ADDR_1, Instant::from_millis(0)), Some(HADDR_A));
        assert_eq!(cache.lookup_pure(MOCK_IP_ADDR_2, Instant::from_millis(0)), None);
        assert_eq!(cache.lookup_pure(MOCK_IP_ADDR_1, Instant::from_millis(0) + Cache::ENTRY_LIFETIME * 2),
                   None);

        cache.fill(MOCK_IP_ADDR_1, HADDR_A, Some(Instant::from_millis(0)))
            .unwrap();
        assert_eq!(cache.lookup_pure(MOCK_IP_ADDR_2, Instant::from_millis(0)), None);
    }

    #[test]
    fn expire() {
        let mut cache_storage = [Default::default(); 3];
        let mut cache = Cache::new(&mut cache_storage[..]);

        cache.fill(MOCK_IP_ADDR_1, HADDR_A, Some(Instant::from_millis(0)))
            .unwrap();
        assert_eq!(cache.lookup_pure(MOCK_IP_ADDR_1, Instant::from_millis(0)), Some(HADDR_A));
        assert_eq!(cache.lookup_pure(MOCK_IP_ADDR_1, Instant::from_millis(0) + Cache::ENTRY_LIFETIME * 2),
                   None);
    }

    #[test]
    fn replace() {
        let mut cache_storage = [Default::default(); 3];
        let mut cache = Cache::new(&mut cache_storage[..]);

        cache.fill(MOCK_IP_ADDR_1, HADDR_A, Some(Instant::from_millis(0)))
            .unwrap();
        assert_eq!(cache.lookup_pure(MOCK_IP_ADDR_1, Instant::from_millis(0)), Some(HADDR_A));
        cache.fill(MOCK_IP_ADDR_1, HADDR_B, Some(Instant::from_millis(0)))
            .unwrap();
        assert_eq!(cache.lookup_pure(MOCK_IP_ADDR_1, Instant::from_millis(0)), Some(HADDR_B));

        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn evict() {
        let mut cache_storage = [Default::default(); 3];
        let mut cache = Cache::new(&mut cache_storage[..]);

        cache.fill(MOCK_IP_ADDR_1, HADDR_A, Some(Instant::from_millis(100)))
            .unwrap();
        cache.fill(MOCK_IP_ADDR_2, HADDR_B, Some(Instant::from_millis(50)))
            .unwrap();
        cache.fill(MOCK_IP_ADDR_3, HADDR_C, Some(Instant::from_millis(200)))
            .unwrap();
        assert_eq!(cache.lookup_pure(MOCK_IP_ADDR_2, Instant::from_millis(1000)), Some(HADDR_B));
        assert_eq!(cache.lookup_pure(MOCK_IP_ADDR_4, Instant::from_millis(1000)), None);

        cache.fill(MOCK_IP_ADDR_4, HADDR_D, Some(Instant::from_millis(300)))
            .unwrap();
        assert_eq!(cache.lookup_pure(MOCK_IP_ADDR_2, Instant::from_millis(1000)), None);
        assert_eq!(cache.lookup_pure(MOCK_IP_ADDR_4, Instant::from_millis(1000)), Some(HADDR_D));
    }

    #[test]
    fn full() {
        let mut cache_storage = [Default::default(); 1];
        let mut cache = Cache::new(&mut cache_storage[..]);

        assert!(cache.fill(MOCK_IP_ADDR_1, HADDR_A, None).is_ok());
        assert!(cache.fill(MOCK_IP_ADDR_2, HADDR_A, Some(Instant::from_millis(0))).is_err());

        // Can still overwrite the entry itself though.
        assert!(cache.fill(MOCK_IP_ADDR_1, HADDR_B, None).is_ok());
        assert!(cache.fill(MOCK_IP_ADDR_2, HADDR_A, None).is_ok());
    }
}
