//! Validate declared grant metadata without DNS, connections, or host authority.
//! The agent still intersects grants with its host policy and denies other proxy
//! networks; the compiler has neither that inventory nor deployment privileges.

use std::{collections::BTreeSet, net::IpAddr};

use super::{
    invalid, require,
    validation::{https_url, identifier},
};
use crate::{
    proto::RuntimeNetworkGrant,
    proxy::{EgressDestination, PrivateDestinationAllowance, ProxyError},
};

pub(super) fn validate(
    destinations: &[EgressDestination],
    grants: &[RuntimeNetworkGrant],
) -> Result<(), ProxyError> {
    require(!grants.is_empty() && grants.len() <= 64 && grants.len() == destinations.len())?;
    let mut declared = BTreeSet::new();
    for EgressDestination::Https { host, port, .. } in destinations {
        require(declared.insert((host.as_str(), u32::from(*port))))?;
    }
    let mut ids = BTreeSet::new();
    let mut bound = BTreeSet::new();
    for grant in grants {
        require(
            identifier(&grant.grant_id)
                && ids.insert(&grant.grant_id)
                && bound.insert((grant.host.as_str(), grant.port))
                && declared.contains(&(grant.host.as_str(), grant.port))
                && grant.approved_cidrs.len() <= 64,
        )?;
        let destination = destinations
            .iter()
            .find(|destination| match destination {
                EgressDestination::Https { host, port, .. } => {
                    host == &grant.host && u32::from(*port) == grant.port
                }
            })
            .ok_or_else(invalid)?;
        require(
            grant.private_destination
                == (destination.private_allowance() == PrivateDestinationAllowance::Allowed),
        )?;
        // Reject alternative numeric IP spellings and other URL normalization
        // that could disguise a denied destination as an ordinary DNS name.
        let endpoint = https_url(&format!("https://{}:{}/", grant.host, grant.port))?;
        require(endpoint.host_str() == Some(grant.host.as_str()))?;
        let host = grant.host.trim_matches(['[', ']']).to_ascii_lowercase();
        require(
            !matches!(
                host.as_str(),
                "localhost"
                    | "host.docker.internal"
                    | "gateway.docker.internal"
                    | "metadata.google.internal"
                    | "instance-data.ec2.internal"
            ) && !host.ends_with(".localhost"),
        )?;
        require(!grant.private_destination || !grant.approved_cidrs.is_empty())?;
        require(!destination.requires_private_allowance() || grant.private_destination)?;
        let mut cidrs = BTreeSet::new();
        let mut ranges = Vec::with_capacity(grant.approved_cidrs.len());
        for cidr in &grant.approved_cidrs {
            require(cidrs.insert(cidr))?;
            let range = Cidr::parse(cidr)?;
            require(range.permitted(grant.private_destination))?;
            ranges.push(range);
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            let literal = Cidr::single(ip);
            require(
                literal.permitted(grant.private_destination)
                    && (ranges.is_empty() || ranges.iter().any(|range| range.contains(literal))),
            )?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Cidr {
    start: u128,
    end: u128,
    v4: bool,
}

impl Cidr {
    fn parse(value: &str) -> Result<Self, ProxyError> {
        require(value.len() <= 64)?;
        let (address, prefix) = value.split_once('/').ok_or_else(invalid)?;
        let ip: IpAddr = address.parse().map_err(|_| invalid())?;
        let width = if ip.is_ipv4() { 32 } else { 128 };
        let bits: u32 = prefix.parse().map_err(|_| invalid())?;
        require(bits > 0 && bits <= width && bits.to_string() == prefix)?;
        let literal = Self::single(ip);
        // The checked bounds above and the /128 branch avoid invalid shifts.
        let host_mask = if bits == width {
            0
        } else if literal.v4 {
            u128::from(u32::MAX >> bits)
        } else {
            u128::MAX >> bits
        };
        require(literal.start & host_mask == 0)?;
        Ok(Self {
            end: literal.start | host_mask,
            ..literal
        })
    }

    fn single(ip: IpAddr) -> Self {
        let start = match ip {
            IpAddr::V4(ip) => u128::from(u32::from(ip)),
            IpAddr::V6(ip) => u128::from(ip),
        };
        Self {
            start,
            end: start,
            v4: ip.is_ipv4(),
        }
    }

    fn contains(self, other: Self) -> bool {
        self.v4 == other.v4 && self.start <= other.start && self.end >= other.end
    }

    fn overlaps(self, start: u128, end: u128) -> bool {
        self.start <= end && start <= self.end
    }

    fn permitted(self, private: bool) -> bool {
        if self.v4 {
            let private_ranges = [
                (0x0a00_0000, 0x0aff_ffff),
                (0xac10_0000, 0xac1f_ffff),
                (0xc0a8_0000, 0xc0a8_ffff),
            ];
            if private {
                return private_ranges
                    .iter()
                    .any(|&(start, end)| self.start >= start && self.end <= end);
            }
            let reserved = [
                (0x0000_0000, 0x00ff_ffff),
                (0x6440_0000, 0x647f_ffff),
                (0x7f00_0000, 0x7fff_ffff),
                (0xa9fe_0000, 0xa9fe_ffff),
                (0xc000_0000, 0xc000_00ff),
                (0xc000_0200, 0xc000_02ff),
                (0xc058_6300, 0xc058_63ff),
                (0xc612_0000, 0xc613_ffff),
                (0xc633_6400, 0xc633_64ff),
                (0xcb00_7100, 0xcb00_71ff),
                (0xe000_0000, 0xffff_ffff),
            ];
            !private_ranges
                .iter()
                .chain(&reserved)
                .any(|&(start, end)| self.overlaps(start, end))
        } else if private {
            self.start >= (0xfc00_u128 << 112) && self.end < (0xfe00_u128 << 112)
        } else {
            // Only native global unicast. Special-use, mapped IPv4, translation,
            // transition and documentation ranges remain unsupported.
            self.start >= (0x2000_u128 << 112)
                && self.end < (0x4000_u128 << 112)
                && !self.overlaps(0x2001_u128 << 112, (0x2001_0200_u128 << 96) - 1)
                && !self.overlaps(0x2001_0db8_u128 << 96, (0x2001_0db9_u128 << 96) - 1)
                && !self.overlaps(0x2002_u128 << 112, (0x2003_u128 << 112) - 1)
                && !self.overlaps(0x3fff_u128 << 112, (0x3fff_1000_u128 << 96) - 1)
        }
    }
}
