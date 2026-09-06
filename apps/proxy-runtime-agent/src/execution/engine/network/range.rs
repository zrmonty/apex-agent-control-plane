use super::ERROR;
use std::net::IpAddr;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Range {
    pub v6: bool,
    pub first: u128,
    pub last: u128,
}
impl Range {
    pub fn parse(text: &str, network: bool) -> Result<Self, &'static str> {
        let (s, p) = text.split_once('/').ok_or(ERROR)?;
        let ip: IpAddr = s.parse().map_err(|_| ERROR)?;
        let prefix: u32 = p.parse().map_err(|_| ERROR)?;
        let (v6, value, bits) = match ip {
            IpAddr::V4(a) => (false, u128::from(u32::from(a)), 32),
            IpAddr::V6(a) => (true, u128::from(a), 128),
        };
        if prefix > bits || format!("{ip}/{prefix}") != text {
            return Err(ERROR);
        }
        let host = u128::MAX.checked_shr(128 - (bits - prefix)).unwrap_or(0);
        let first = value & !host;
        if network && value != first {
            return Err(ERROR);
        }
        Ok(if network {
            Self {
                v6,
                first,
                last: value | host,
            }
        } else {
            Self {
                v6,
                first: value,
                last: value,
            }
        })
    }
    pub fn overlaps(self, other: Self) -> bool {
        self.v6 == other.v6 && self.first <= other.last && other.first <= self.last
    }
    pub fn contains(self, other: Self) -> bool {
        self.v6 == other.v6 && self.first <= other.first && other.last <= self.last
    }
    pub fn address(text: &str) -> Result<Self, &'static str> {
        let ip: IpAddr = text.parse().map_err(|_| ERROR)?;
        Self::parse(
            &format!("{text}/{}", if ip.is_ipv4() { 32 } else { 128 }),
            false,
        )
    }
}
