//! CIDR, relevant rfc1519, rfc4632.
//!
use crate::layer::{Error, Result};
use crate::managed::{List, Slice};
use crate::time::{Expiration, Instant};
use crate::wire::{IpAddress, IpCidr, IpSubnet};
use crate::wire::Ipv4Address;
use crate::wire::Ipv6Address;

/// A prefix of addresses that should be routed via a router
#[derive(Debug, Clone, Copy)]
pub struct Route {
    /// The network routed through this route.
    ///
    /// Better only set actual networks here. Although host identifiers (where not all bits outside
    /// the subnet mask are zero) and broadcast (where these bits are all ones) are accepted, they
    /// may lead to unexpected routing decisions.
    pub net: IpSubnet,

    /// Next hop for this network.
    pub next_hop: IpAddress,

    /// Expired routes are never considered.
    pub expires_at: Expiration,
}

impl Route {
    /// A route without specified target.
    ///
    /// May be used as a placeholder for storage where the address is not assigned yet and where
    /// the more specific placeholders `ipv4_invalid` and `ipv6_invalid` are less precise.
    pub fn unspecified() -> Self {
        Route {
            net: IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0).subnet(),
            next_hop: IpAddress::Unspecified,
            expires_at: Expiration::Never,
        }
    }

    /// Establishes a routing `0.0.0.0/0` to `0.0.0.0`.
    ///
    /// You can freely use this as an initializer for a slice of routes. Network addresses within
    /// `0.0.0.0/8` are only valid as source addresses.
    pub fn ipv4_invalid() -> Self {
        Route {
            net: IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0).subnet(),
            next_hop: IpAddress::v4(0, 0, 0, 0).into(),
            expires_at: Expiration::Never,
        }
    }

    /// A route `::/0` to the reserved, 'unspecified' `::/128` address.
    pub fn ipv6_invalid() -> Self {
        Route {
            net: IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 0), 0).subnet(),
            next_hop: IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 0).into(),
            expires_at: Expiration::Never,
        }
    }

    /// Returns a route match `0.0.0.0/0` via the `gateway`, with no expiry.
    ///
    /// This route is a worst match for all addresses so that it can be used as a sink, for
    /// example.
    pub fn new_ipv4_gateway(gateway: Ipv4Address) -> Route {
        Route {
            net: IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0).subnet(),
            next_hop: gateway.into(),
            expires_at: Expiration::Never,
        }
    }

    /// Returns a route match `::/0` via the `gateway`, with no expiry.
    ///
    /// This route is a worst match for all addresses so that it can be used as a sink, for
    /// example.
    pub fn new_ipv6_gateway(gateway: Ipv6Address) -> Route {
        Route {
            net: IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 0), 0).subnet(),
            next_hop: gateway.into(),
            expires_at: Expiration::Never,
        }
    }
}

/// A routing table.
///
/// # Examples
///
/// On systems with heap, this table can be created with:
///
/// ```rust
/// # #[cfg(feature = "std")] {
/// use ethox::layer::ip::{Route, Routes};
/// use ethox::managed::List;
/// 
/// let mut routes_storage = vec![Route::unspecified(); 10];
/// let mut routes = Routes::new(routes_storage);
/// # }
/// ```
///
/// On systems without heap, use:
///
/// ```rust
/// use ethox::layer::ip::{Route, Routes};
///
/// let mut routes_storage = [Route::unspecified(); 10];
/// let mut routes = Routes::new(&mut routes_storage[..]);
/// ```
#[derive(Debug)]
pub struct Routes<'a> {
    storage: List<'a, Route>,
}

impl<'a> Routes<'a> {
    /// Creates an empty routing tables.
    ///
    /// The storage is not touched but no element within it is used for route searching by default.
    /// See `import` for creating routes from a pre-filled list.
    pub fn new<T>(storage: T) -> Self
        where T: Into<Slice<'a, Route>>
    {
        Routes::import(List::new(storage.into()))
    }

    /// Creates a routing tables. The backing storage is **not** cleared
    /// upon creation.
    pub fn import(storage: List<'a, Route>) -> Self {
        Routes { storage }
    }

    /// Update the routes of this node.
    pub fn update<F: FnOnce(&mut [Route])>(&mut self, f: F) {
        f(&mut self.storage);
    }

    /// Add a default ipv6 gateway (ie. "ip -6 route add ::/0 via `gateway`").
    ///
    /// On success, returns the previous default route, if any.
    pub fn add_route(&mut self, route: Route) -> Result<()> {
        match self.storage.push() {
            Some(place) => Ok(*place = route),
            None => Err(Error::Exhausted),
        }
    }

    pub fn lookup(&self, addr: IpAddress, timestamp: Instant)
        -> Option<IpAddress>
    {
        assert!(addr.is_unicast());

        // The rules say to find the subnet with longest prefix.
        let mut best_match = None;
        for route in self.storage.iter() {
            // Ignored expired routes.
            if Expiration::When(timestamp) > route.expires_at {
                continue;
            }

            // Ignored routes with mismatching net.
            if !route.net.contains(addr) {
                continue;
            }

            let best = best_match.get_or_insert(route);
            // Prefer shortest route.
            if best.net.prefix_len() < route.net.prefix_len() {
                *best = route;
            }
        }
        best_match.map(|route| route.next_hop)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    mod mock {
        use super::super::*;
        use crate::wire::Ipv6Cidr;

        pub const ADDR_1A: Ipv6Address = Ipv6Address(
                [0xfe, 0x80, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1]);
        pub const ADDR_1B: Ipv6Address = Ipv6Address(
                [0xfe, 0x80, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 13]);
        pub const ADDR_1C: Ipv6Address = Ipv6Address(
                [0xfe, 0x80, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 42]);
        pub fn cidr_1() -> Ipv6Cidr {
            Ipv6Cidr::new(Ipv6Address(
                    [0xfe, 0x80, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]), 64)
        }

        pub const ADDR_2A: Ipv6Address = Ipv6Address(
                [0xfe, 0x80, 0, 0, 0, 0, 51, 100, 0, 0, 0, 0, 0, 0, 0, 1]);
        pub const ADDR_2B: Ipv6Address = Ipv6Address(
                [0xfe, 0x80, 0, 0, 0, 0, 51, 100, 0, 0, 0, 0, 0, 0, 0, 21]);
        pub fn cidr_2() -> Ipv6Cidr {
            Ipv6Cidr::new(Ipv6Address(
                    [0xfe, 0x80, 0, 0, 0, 0, 51, 100, 0, 0, 0, 0, 0, 0, 0, 0]), 64)
        }
    }

    use self::mock::*;

    #[test]
    fn test_fill() {
        let routes_storage = vec![Route::ipv4_invalid(); 3];
        let mut routes = Routes::new(routes_storage);

        assert_eq!(routes.lookup(ADDR_1A.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(ADDR_1B.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(ADDR_1C.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(ADDR_2A.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(ADDR_2B.into(), Instant::from_millis(0)), None);

        let route = Route {
            net: cidr_1().subnet().into(),
            next_hop: ADDR_1A.into(),
            expires_at: Expiration::Never,
        };

        routes.add_route(route)
            .expect("Can add single route");

        assert_eq!(routes.lookup(ADDR_1A.into(), Instant::from_millis(0)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(ADDR_1B.into(), Instant::from_millis(0)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(ADDR_1C.into(), Instant::from_millis(0)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(ADDR_2A.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(ADDR_2B.into(), Instant::from_millis(0)), None);

        let route2 = Route {
            net: cidr_2().subnet().into(),
            next_hop: ADDR_2A.into(),
            expires_at: Expiration::When(Instant::from_millis(10)),
        };

        routes.add_route(route2)
            .expect("Can add second route");

        assert_eq!(routes.lookup(ADDR_1A.into(), Instant::from_millis(0)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(ADDR_1B.into(), Instant::from_millis(0)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(ADDR_1C.into(), Instant::from_millis(0)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(ADDR_2A.into(), Instant::from_millis(0)), Some(ADDR_2A.into()));
        assert_eq!(routes.lookup(ADDR_2B.into(), Instant::from_millis(0)), Some(ADDR_2A.into()));

        assert_eq!(routes.lookup(ADDR_1A.into(), Instant::from_millis(10)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(ADDR_1B.into(), Instant::from_millis(10)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(ADDR_1C.into(), Instant::from_millis(10)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(ADDR_2A.into(), Instant::from_millis(10)), Some(ADDR_2A.into()));
        assert_eq!(routes.lookup(ADDR_2B.into(), Instant::from_millis(10)), Some(ADDR_2A.into()));
    }
}
