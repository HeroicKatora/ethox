# Ethox

**Ethox** is a standalone library for user-space networking and unikernel
systems with a focus on *speeed* and stability. There exist basic structures
for compiling its features into a complete network stack. It is also possibly
useful for bare-metal microcontrollers but it is not engineered towards that
primary goal.

As part of the consistent performance promises, **Ethox** restricts itself to
never perform internal allocation. However, the user may choose to do so where
deemed nessary. It targets `stable` and `nightly` Rust only, and does not aim
to be compatible to previous stable releases.

## Overview and Features

The initial feature set will be `eth+(ipv4|ipv6)+(udp+tcp)`. Also `arp` and
`icmp` are supported. See the more complete feature list [below](#Details).

<!--[![crates.io](https://img.shields.io/crates/v/image.svg)](https://crates.io/crates/image) -->
[![CI Status](https://api.cirrus-ci.com/github/HeroicKatora/ethox.svg)](https://cirrus-ci.com/github/HeroicKatora/ethox)
[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](COPYING)
[![Scc lines of code](https://sloc.xyz/github/HeroicKatora/ethox?category=code)](#Ethox)
[![Scc comments](https://sloc.xyz/github/HeroicKatora/ethox?category=comments)](#Ethox)

## Usage

```
# Cargo.toml
# Pin the version to a specific commit with `rev = "…"`.
ethox = { git = "https://github.com/HeroicKatora/ethox" }
```

The main interface of **Ethox** is built around zero-copy, for as long as
possible. It is *not* socket oriented but based on a dynamically built tree of
trait implementors which offer callbacks for layer specific functionality and
packet receiving and transmission. The packet buffer is never *owned* within
these callbacks but a mutable, unique reference to a network device specific
structure that can be resized and reused at will. Batching of packets for both
ingress and egress is enabled at the NIC level. Batching is **not** provided in
the layers above that.

## License

**Ethox** is distributed under the GPLv3. Code contributions are only accepted
under waiver of copyright, at the moment, to allow freely choosing other
licensing options further down the road. These conditions may be opened up a
bit in the future.

A significant but shrinking portion of the original network code comes from
`smoltcp`, copyright `whitequark@whitequark.org`, and reproduced and modified
here under the terms allowed by its 0-clause BSD license. It may have changed a
lot by the time you read this.

## Details

More details about each layer, with supported, unsupported and work-in-progress
features. Keep in mind that this may still evolve rapidly and is maybe not
up-to-date. This also documents possible future additions.

### Ethernet

Ethernet is the only supported medium/link layer.

* Regular Ethernet II frames are supported.
* Unicast and broadcast packets (**not** multicast) are supported.
* 802.3 frames and 802.1Q are **not** supported.
* Jumbo frames are **not** supported.

### IPv4

* IPv4 header checksum is generated and validated. May be ignored.
* CIDR tables are supported.
* QoS and TTL per route are **not** supported.
* Link local routing is supported.
* Broadcast and Network addressing is supported.
* Prefix 31 and 32 networks are supported.
* IGMP is **not** supported.
* IPv4 fragmentation is **not** supported.
* IPv4 options are **not** supported and silently discarded.

#### IPv4 — Icmpv4

* Icmpv4 echo replies are generated.
* Icmpv4 header checksums are supported.
* Messages (including unreachable errors) may be passed to custom receiver logic.
* Icmpv4 errors are **not** generated.

#### IPv4 — Arp

* ARP packets (requests and queries) are automatically performed supported.
* ARP entries are revalidated periodically (1 minute).
* Gratuitous requests and replies are **not** supported and ignored.
* Auto-configuration and collision detection is **not** supported.

### IPv6

* IPv6 options are **not** supported.
* IPv6 fragmentation is **not** supported.

#### IPv6 — Icmpv6

Is **not** supported yet.

#### IPv6 — NDISC

Neighbor discovery is **not** supported.

### Tcp

* Header checksums are generated and validated. May be ignored.
* Zero-copy receiving and sending of messages, all buffers under user control.
* Adheres to maximum segment size.
* Windows scaling is negotiated and utilized. May be configured.
* Predefined structures for arbitrary length reassembly are available.
* Bytes-in-flight are not limited by segment sizes.
* Initial sequence number is generated according to rfc6528 (keyed siphash-2-4).
* Exponential backoff is **not** supported.
* Selective acknowledgment is **ignored**.
* Congestion control is **not** implemented.
* Round-trip-time estimation is **not** implemented.
* MTU discovery is **not** implemented.
* Delayed acknowledgments are **not** implemented.
* Silly window syndrome avoidance is **not** implemented.
* Nagle's algorithm is **not** implemented.
* Timestamping is **not** supported.
* Urgent pointer is **ignored**.
* Probing Zero Windows is **not** implemented.

### Udp

* Header checksum is generated, validated, can be elided, may be ignored.
* Zero-copy receiving and sending of messages
