# Ethox

**Ethox** is a standalone network stack for user-space networking and unikernel
systems with a focus on *speeed* and stability. Less so but also possibly
useful for bare-metal microcontrollers. 

As part of the consistent performance promises, **Ethox** restricts itself to
not perform internal allocation but integrate well enough to allow the user to
choose to perform them nonetheless. It targets `stable` and `nightly` Rust
only, and does not aim to be backwards compatible to previous stable releases.

## Features

The initial feature set will be `eth+(ipv4|ipv6)+udp`, targetting tcp as a
stretch goal. `arp` and `icmp` will also be adopted, in some form along the
way.

## License

**Ethox** is distributed under the GPLv3. Code contributions are only accepted
under waiver of copyright, at the moment, to allow freely choosing other
licensing options further down the road. These conditions may be opened up a
bit in the future.

A significant portion of the original network code comes from `smoltcp`,
copyright `whitequark@whitequark.org`, and reproduced and modified here under
the terms allowed by its 0-clause BSD license. It may have changed a lot by the
time you read this.
