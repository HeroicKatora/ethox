use ethox_io_uring::RawRing;
use ethox::{layer::eth, nic::Device, wire};
use ethox::wire::{Payload, PayloadMut};

#[test]
fn ping_self() {
    const ADDR_A: wire::ethernet::Address = wire::ethernet::Address([0xaa, 0, 0, 0, 0, 0x1]);
    const ADDR_B: wire::ethernet::Address = wire::ethernet::Address([0xaa, 0, 0, 0, 0, 0x2]);

    let [sock_a, sock_b] = sockets();
    println!("Sockets created");

    let mut ring_a = create_ring(sock_a);
    let mut ring_b = create_ring(sock_b);
    println!("Rings created");

    let mut eth_a = eth::Endpoint::new(ADDR_A);
    let mut eth_b = eth::Endpoint::new(ADDR_B);
    println!("Starting sending");

    println!("Starting receives");
    const PACKET_COUNT: usize = 1000;
    let mut to_send = PACKET_COUNT;
    let mut to_recv = PACKET_COUNT;
    while to_recv != 0 {
        to_send -= ring_a.tx(to_send, eth_a.send(Dummy(ADDR_B))).expect("Sending failed");
        ring_a.flush_and_reap().expect("Sending failed");
        to_recv -= ring_b.rx(to_recv, eth_b.recv(Dummy(ADDR_A))).expect("Receiving failed");
        println!("{} {}", to_send, to_recv);
    }
    
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

const HELLO: &[u8] = b"Hello, world";

impl<P: wire::PayloadMut> eth::Send<P> for Dummy {
    fn send(&mut self, raw: eth::RawPacket<P>) {
        let mut out = raw.prepare(eth::Init {
            dst_addr: self.0,
            src_addr: self.0,
            ethertype: wire::ethernet::EtherType::Ipv4,
            payload: HELLO.len(),
        }).expect("Initialization failed");

        out
            .payload_mut()
            .as_mut_slice()
            .copy_from_slice(HELLO);

        out.send().expect("Sending failed");
    }
}

impl<P: wire::PayloadMut> eth::Recv<P> for Dummy {
    fn receive(&mut self, packet: eth::InPacket<P>) {
        assert_eq!(packet.frame.payload().as_slice(), HELLO);
    }
}
