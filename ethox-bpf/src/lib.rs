use std::{fmt, mem, ptr};
use std::boxed::Box;
use std::error::Error;

use ethox::nic;
use bpfjit_sys::{BpfJit, Opcode};

/// A bpf module using NetBSD bpfjit/sljit implementations.
#[derive(Clone)]
pub struct Bpf {
    bpf_vm: BpfJit,
}

/// A filtered receiver.
///
/// All packets are checked against the configured program and only matching packets are forwarded
/// to the inner receiver.
pub struct Filtered<'a, I> {
    bpf: &'a Bpf,
    inner: I,
}

#[derive(Debug)]
enum AsmError {
    InvalidLength,
}

impl Bpf {
    pub fn from_binary(program: &[u8]) -> Result<Self, Box<dyn Error>> {
        let opcodes = Self::load_binary(program)?;
        Self::from_opcodes(opcodes)
    }

    fn from_opcodes(opcodes: Vec<Opcode>) -> Result<Self, Box<dyn Error>> {
        let bpf_vm = BpfJit::raw(&opcodes)?;
        Ok(Bpf { bpf_vm })
    }

    pub fn filter<I>(&self, inner: I) -> Filtered<'_, I> {
        Filtered { bpf: self, inner }
    }

    fn load_binary(program: &[u8]) -> Result<Vec<Opcode>, Box<dyn Error>>  {
        #[repr(C)]
        struct InnerOpcode(u16, u8, u8, u32);
        const OPCODE_SIZE: usize = mem::size_of::<InnerOpcode>();

        if program.len() % OPCODE_SIZE != 0 {
            return Err(AsmError::InvalidLength.into());
        }

        // The program is assumed to be a native endian array of (u16, u8, u8, u32) as defined by
        // C-style struct, possibly incorrectly aligned.
        let nr_opcodes = program.len() / OPCODE_SIZE;
        let mut opcodes = Vec::with_capacity(nr_opcodes);

        for opcode in program.chunks_exact(OPCODE_SIZE) {
            let InnerOpcode(a, b, c, d) = unsafe {
                ptr::read_unaligned(opcode.as_ptr() as *const InnerOpcode)
            };
            opcodes.push(Opcode(a, b, c, d));
        }

        Ok(opcodes)
    }
}

impl<H, P, I> nic::Recv<H, P> for Filtered<'_, I>
where
    H: nic::Handle + ?Sized,
    P: ethox::wire::Payload + ?Sized,
    I: nic::Recv<H, P>,
{
    fn receive(&mut self, packet: nic::Packet<H, P>) {
        let bytes = packet.payload.payload();

        if self.bpf.bpf_vm.matches(bytes.into()) {
            self.inner.receive(packet)
        }
    }
}

impl Error for AsmError { }

impl fmt::Display for AsmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AsmError::InvalidLength => write!(f, "The byte length of a valid opcode array must be divisible by 8"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::Bpf;
    use ethox::nic::{self, Device, external::External};

    struct Counter(u64);

    impl<H, P> nic::Recv<H, P> for Counter 
    where
        H: nic::Handle + ?Sized,
        P: ethox::wire::Payload + ?Sized,
    {
        fn receive(&mut self, _: nic::Packet<H, P>) {
            self.0 += 1;
        }
    }

    /// Load a comma-separated program.
    ///
    /// TODO: this should be exported in Bpf in some variant but the exact interface is still TBD.
    fn from_str(program: &str) -> Result<Bpf, Box<dyn std::error::Error>> {
        let opcodes = program.split(",")
            .map(|code| code.parse())
            .collect::<Result<Vec<_>, _>>()?;
        Bpf::from_opcodes(opcodes)
    }

    #[test]
    fn check_filter_count() {
        let mut nic = External::new_recv(vec![
            // This is an arp for 192.168.178.31 from 192.168.178.1
            // MAC addresses have been replaced with spoofed ones
            &b"\xac\xff\xff\xff\xff\xff\xac\xff\xff\x0f\xff\xff\x08\x06
            \x00\x01\x08\x00\x06\x04\x00\x01\xac\xff\xff\x0f\xff\xff\xc0\xa8\
            \xb2\x01\x00\x00\x00\x00\x00\x00\xc0\xa8\xb2\x27\x00\x00\x00\x00\
            \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"[..],
            // This is a dummy ipv4 icmp packet.
            &b"\xac\xff\xff\xff\xff\xff\xac\xff\xff\x0f\xff\xff\x08\x00\
            \x45\x00\x00\x18\x00\x00\x40\x00\x40\x01\xd2\x79\x11\x12\x13\x14\
            \x21\x22\x23\x24\xaa\x00\x00\xff"[..],
        ]);

        let mut counter = Counter(0);
        // This is an ARP packet filter from the Linux kernel documentation.
        // ** ARP packets:
        // ldh [12]
        // jne #0x806, drop
        // ret #-1
        // drop: ret #0

        let bpf = from_str("40 0 0 12,21 0 1 2054,6 0 0 4294967295,6 0 0 0").unwrap();

        let mut received = 0;
        loop {
            match nic.rx(2, bpf.filter(&mut counter)) {
                Ok(0) => break,
                Ok(n) => received += n,
                err => panic!("Receiving is should not fail {:?}", err),
            }
        }

        // Received two packets in total ...
        assert_eq!(received, 2);
        // ... but only one reached the counter.
        assert_eq!(counter.0, 1);
    }
}
