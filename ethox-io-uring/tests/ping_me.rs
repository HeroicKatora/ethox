use ethox_io_uring::RawRing;

#[test]
fn ping_self() {
    let [sock_a, sock_b] = sockets();
    let mut ring_a = create_ring(sock_a);
    let mut ring_b = create_ring(sock_b);
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
    let ring = io_uring::Builder::default()
        .setup_iopoll()
        .build(32)
        .expect("Failed to initiate io uring");
    RawRing::from_ring(ring, sock)
}
