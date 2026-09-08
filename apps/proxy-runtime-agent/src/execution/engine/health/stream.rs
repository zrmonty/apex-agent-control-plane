//! Docker's eight-byte multiplex framing, independent of HTTP fragmentation.
use super::ERROR;
use zeroize::Zeroizing;

const STDOUT: usize = 16385;
const STDERR: usize = 1024;
pub(super) struct Multiplex {
    stdout: Zeroizing<Vec<u8>>,
    header: [u8; 8],
    header_used: usize,
    remaining: usize,
}
impl Multiplex {
    pub(super) fn new() -> Self {
        Self {
            stdout: Zeroizing::new(Vec::with_capacity(STDOUT)),
            header: [0; 8],
            header_used: 0,
            remaining: 0,
        }
    }
    pub(super) fn push(&mut self, mut bytes: &[u8]) -> Result<(), &'static str> {
        while !bytes.is_empty() {
            if self.remaining != 0 {
                let n = self.remaining.min(bytes.len());
                self.stdout.extend_from_slice(&bytes[..n]);
                self.remaining -= n;
                bytes = &bytes[n..];
                continue;
            }
            let n = (8 - self.header_used).min(bytes.len());
            self.header[self.header_used..self.header_used + n].copy_from_slice(&bytes[..n]);
            self.header_used += n;
            bytes = &bytes[n..];
            if self.header_used != 8 {
                continue;
            }
            self.header_used = 0;
            if self.header[1..4] != [0, 0, 0] {
                return Err(ERROR);
            }
            let length = u32::from_be_bytes(self.header[4..8].try_into().map_err(|_| ERROR)?);
            let length = usize::try_from(length).map_err(|_| ERROR)?;
            match self.header[0] {
                1 if length <= STDOUT - self.stdout.len() => self.remaining = length,
                // Reject stderr before allocating or reading its content. Even
                // a bounded diagnostic is a refusal and must never escape.
                2 if length <= STDERR => return Err(ERROR),
                _ => return Err(ERROR),
            }
        }
        Ok(())
    }
    pub(super) fn finish(self) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        if self.header_used != 0 || self.remaining != 0 {
            return Err(ERROR);
        }
        Ok(self.stdout)
    }
}
