//! Debugs all packets coming in on a tap.
use std::{env, process};

use ethox::nic::{Device, sys::TapInterface};
use ethox::wire::pretty_print::Formatter;

fn main() {
    let name = env::args().nth(1)
        .unwrap_or_else(usage_and_exit);

    let mut interface = TapInterface::new(&name, vec![0; 1 << 14])
        .expect("Couldn't initialize interface");
    loop {
        // Receive the next packet.
        let result = interface.rx(1, Formatter::default());

        result.unwrap_or_else(|err| {
            panic!("Error during receive {:?} {:?}", err, interface.last_err());
        });
    }
}

fn usage_and_exit<T>() -> T {
    eprintln!("Usage: debug_tap <ifname>");
    process::exit(1);
}
