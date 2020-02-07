use core::slice;
use ethox_io_uring::RawRing;
use ethox::{layer::eth, nic::Device, wire};

#[test]
fn ping_self() {
    const ADDR_A: wire::ethernet::Address = wire::ethernet::Address([0xaa, 0, 0, 0, 0, 0x1]);
    const ADDR_B: wire::ethernet::Address = wire::ethernet::Address([0xaa, 0, 0, 0, 0, 0x2]);

    let [sock_a, sock_b] = sockets();

    let mut ring_a = create_ring(sock_a);
    let mut ring_b = create_ring(sock_b);

    let mut eth_a = eth::Endpoint::new(ADDR_A);
    let mut eth_b = eth::Endpoint::new(ADDR_B);

    assert_eq!(ring_a.tx(10, eth_a.send(Dummy(ADDR_B))), Ok(10));
    assert_eq!(ring_b.rx(10, eth_b.recv(Dummy(ADDR_A))), Ok(10));
}

fn sockets() -> [libc::c_int; 2] {
    let mut pair = [0, 0];
    let result = unsafe {
        // Yes, this is not a true raw socket. But we test uring and sendmsg so it is the same.
        libc::socketpair(
            libc::PF_LOCAL,
            libc::SOCK_DGRAM,
            0,
            pair.as_mut_ptr())
    };
    assert_eq!(result, 0, "Opening sockets failed");
    pair
}

fn create_ring(sock: libc::c_int) -> RawRing {
    RawRing::from_fd(sock).expect("Failed to initiate io uring")
}

struct Dummy(wire::ethernet::Address);

impl<P: wire::PayloadMut> eth::Send<P> for Dummy {
    fn send(&mut self, _: eth::RawPacket<P>) {
    }
}

impl<P: wire::PayloadMut> eth::Recv<P> for Dummy {
    fn receive(&mut self, _: eth::InPacket<P>) {
    }
}
