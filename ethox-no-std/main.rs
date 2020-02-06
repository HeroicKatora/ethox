//! Example for raw usage without `std` or `alloc`.
//!
//! Note that this is not as ergonomic for argument parsing, so we set up a stack answering only
//! icmpv4 pings (and arp) without any routes.
#![no_std]
#![no_main]

use ethox::managed::Slice;
use ethox::nic::{Device, sys::TapInterface};
use ethox::layer::{arp, eth, ip, icmp};
use ethox::wire::{ip::v4, ethernet};

#[no_mangle]
// The main function, with its input arguments ignored, and an exit status is returned
pub extern fn main(_nargs: i32, _args: *const *const u8) -> i32 {
    let name = "tap0";
    let host = v4::Cidr::new(v4::Address([10, 0, 0, 1]), 24);
    let hostmac = ethernet::Address([0xab,0xff,0xff,0xff,0xff,0xff]);

    let mut eth = eth::Endpoint::new(hostmac);

    let mut neighbors = [arp::Neighbor::default(); 10];
    let mut ip = ip::Endpoint::new(Slice::One(host.into()),
        // No routes at all
        ip::Routes::new(Slice::empty()), 
        // But do automatic arp
        arp::NeighborCache::new(&mut neighbors[..]));

    let mut icmp = icmp::Endpoint::new();

    let mut buffer = [0; 1 << 14];
    let mut interface = TapInterface::new(&name, &mut buffer[..])
        .expect("Couldn't initialize interface");

    loop {
        // Receive the next packet.
        let rx_ok = interface.rx(1, eth.recv(ip.recv(icmp.answer())));
        // Give some chance for outgoing maintenance such as arp.
        let tx_ok = interface.tx(1, eth.send(ip.layer_internal()));

        let result = rx_ok.and_then(|x| tx_ok.map(|y| x + y));

        if result.is_err() {
            break;
        }
    }

    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // We abort on panic.
    loop { }
}
