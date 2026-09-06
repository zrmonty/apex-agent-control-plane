use super::ERROR;
use std::net::Ipv4Addr;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Range {
    pub start: u32,
    pub end: u32,
}
impl Range {
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        if text.len() > 18 {
            return Err(ERROR);
        }
        let (ip, bits) = text.split_once('/').ok_or(ERROR)?;
        let ip: Ipv4Addr = ip.parse().map_err(|_| ERROR)?;
        let prefix: u32 = bits.parse().map_err(|_| ERROR)?;
        if !(1..=32).contains(&prefix) || prefix.to_string() != bits {
            return Err(ERROR);
        }
        let start = u32::from(ip);
        let mask = u32::MAX.checked_shr(prefix).unwrap_or(0);
        if start & mask != 0 {
            return Err(ERROR);
        }
        Ok(Self {
            start,
            end: start | mask,
        })
    }
    fn overlaps(self, other: Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}
pub(super) fn parse(values: &[String], max: usize) -> Result<Vec<Range>, &'static str> {
    if values.len() > max {
        return Err(ERROR);
    }
    let mut distinct = std::collections::BTreeSet::new();
    let ranges = values
        .iter()
        .map(|s| {
            if !distinct.insert(s) {
                return Err(ERROR);
            }
            Range::parse(s)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(reduce(ranges))
}
pub(super) fn reduce(mut ranges: Vec<Range>) -> Vec<Range> {
    ranges.sort_unstable();
    let mut result: Vec<Range> = Vec::new();
    for r in ranges {
        if let Some(last) = result.last_mut()
            && r.start <= last.end.saturating_add(1)
        {
            last.end = last.end.max(r.end);
        } else {
            result.push(r);
        }
    }
    result
}
// Inputs are reduced disjoint ordered intervals; at most n+m outputs, no product.
pub(super) fn intersection(a: &[Range], b: &[Range]) -> Vec<Range> {
    let (mut i, mut j) = (0, 0);
    let mut result = Vec::new();
    while i < a.len() && j < b.len() {
        let x = a[i];
        let y = b[j];
        if x.overlaps(y) {
            result.push(Range {
                start: x.start.max(y.start),
                end: x.end.min(y.end),
            });
        }
        if x.end < y.end {
            i += 1;
        } else {
            j += 1;
        }
    }
    reduce(result)
}
// Exact IPv4 policy from the unchanged TS runtime-config/network.ts permitted().
pub(super) fn classify(ranges: &[Range], excluded: &[Range]) -> Result<bool, &'static str> {
    const PRIVATE: [Range; 3] = [
        Range {
            start: 0x0a000000,
            end: 0x0affffff,
        },
        Range {
            start: 0xac100000,
            end: 0xac1fffff,
        },
        Range {
            start: 0xc0a80000,
            end: 0xc0a8ffff,
        },
    ];
    const RESERVED: [(u32, u32); 11] = [
        (0, 0x00ffffff),
        (0x64400000, 0x647fffff),
        (0x7f000000, 0x7fffffff),
        (0xa9fe0000, 0xa9feffff),
        (0xc0000000, 0xc00000ff),
        (0xc0000200, 0xc00002ff),
        (0xc0586300, 0xc05863ff),
        (0xc6120000, 0xc613ffff),
        (0xc6336400, 0xc63364ff),
        (0xcb007100, 0xcb0071ff),
        (0xe0000000, 0xffffffff),
    ];
    if ranges.is_empty() {
        return Err(ERROR);
    }
    let mut classification = None;
    for &r in ranges {
        if excluded.iter().any(|&p| p.overlaps(r)) {
            return Err(ERROR);
        }
        let private = PRIVATE.iter().any(|p| p.start <= r.start && p.end >= r.end);
        if !private
            && (PRIVATE.iter().any(|&p| p.overlaps(r))
                || RESERVED
                    .iter()
                    .any(|&(start, end)| r.overlaps(Range { start, end })))
            || classification.is_some_and(|v| v != private)
        {
            return Err(ERROR);
        }
        classification = Some(private);
    }
    classification.ok_or(ERROR)
}
pub(super) fn strings(ranges: &[Range], max: usize) -> Result<Vec<String>, &'static str> {
    let mut result = Vec::new();
    for r in ranges {
        let mut start = u64::from(r.start);
        let end = u64::from(r.end);
        while start <= end {
            if result.len() >= max {
                return Err(ERROR);
            }
            let bits = start
                .trailing_zeros()
                .min((end - start + 1).ilog2())
                .min(31);
            result.push(format!(
                "{}/{}",
                Ipv4Addr::from(u32::try_from(start).map_err(|_| ERROR)?),
                32 - bits
            ));
            start += 1u64 << bits;
        }
    }
    Ok(result)
}
