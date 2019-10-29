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
