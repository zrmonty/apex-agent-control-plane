use super::ERROR;
use std::net::Ipv4Addr;
#[derive(Clone, Copy)]
pub(super) struct Cidr {
    pub base: u32,
    pub prefix: u8,
}
pub(super) fn ip(text: &str) -> Result<Ipv4Addr, &'static str> {
    let ip: Ipv4Addr = text.parse().map_err(|_| ERROR)?;
    if ip.to_string() != text {
        return Err(ERROR);
    }
    Ok(ip)
}
impl Cidr {
    pub(super) fn parse(text: &str) -> Result<Self, &'static str> {
        let (host, prefix) = text.split_once('/').ok_or(ERROR)?;
        let prefix: u8 = prefix.parse().map_err(|_| ERROR)?;
        if prefix > 32 {
            return Err(ERROR);
        }
        let base = u32::from(ip(host)?);
        let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
        if base & mask != base || format!("{}/{prefix}", Ipv4Addr::from(base)) != text {
            return Err(ERROR);
        }
        Ok(Self { base, prefix })
    }
    fn last(self) -> u32 {
        self.base | u32::MAX.checked_shr(u32::from(self.prefix)).unwrap_or(0)
    }
    pub(super) fn size(self) -> u32 {
        self.last().saturating_sub(self.base).saturating_add(1)
    }
    pub(super) fn overlaps(self, other: Self) -> bool {
        self.base <= other.last() && other.base <= self.last()
    }
    pub(super) fn private(self) -> bool {
        [(0x0a000000, 8), (0xac100000, 12), (0xc0a80000, 16)]
            .into_iter()
            .any(|(base, prefix)| {
                self.base >= base && self.last() <= (Self { base, prefix }).last()
            })
    }
    pub(super) fn reserved(self) -> bool {
        [(0, 8), (0x7f000000, 8), (0xa9fe0000, 16), (0xe0000000, 3)]
            .into_iter()
            .any(|(base, prefix)| self.overlaps(Self { base, prefix }))
    }
}
