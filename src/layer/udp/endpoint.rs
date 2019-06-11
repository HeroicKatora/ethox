use crate::managed::Ordered;

pub struct Endpoint<'a> {
    /// List of accepted ports for lookup.
    ports: Ordered<'a, u16>,
}

/// An endpoint borrowed for receiving.
pub struct Receiver<'a, 'e, H> {
    endpoint: UdpEndpoint<'a, 'e>,

    /// The upper protocol receiver.
    handler: H,
}

/// An endpoint borrowed for sending.
pub struct Sender<'a, 'e, H> {
    endpoint: UdpEndpoint<'a, 'e>,

    /// The upper protocol sender.
    handler: H,
}

struct UdpEndpoint<'a, 'e> {
    inner: &'a Endpoint<'e>,
}


