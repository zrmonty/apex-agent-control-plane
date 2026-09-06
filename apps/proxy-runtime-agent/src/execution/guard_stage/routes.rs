use super::ERROR;
use crate::{
    network_catalog::{NetworkCatalog, Profile},
    proto::RuntimeNetworkGrant,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
mod range;
use range::{Range, classify, intersection, parse, reduce, strings};

#[derive(Serialize)]
pub(super) struct Route {
    host: String,
    port: u16,
    private_destination: bool,
    declared_cidrs: Vec<String>,
    protected_cidrs: Vec<String>,
}
pub(super) fn derive(
    published: &[RuntimeNetworkGrant],
    authority: &Value,
    profile: &Profile,
    catalog: &NetworkCatalog,
) -> Result<Vec<Route>, &'static str> {
    if published.is_empty() || published.len() > 64 {
        return Err(ERROR);
    }
    let excluded = [
        Range::parse(catalog.internal_pool())?,
        Range::parse(catalog.outer().subnet())?,
    ];
    let protected = |purpose: &str, host: &str, port: u16| -> Result<Vec<Range>, &'static str> {
        let g = profile
            .grants()
            .find(|g| g.purpose() == purpose && g.host() == host && g.port() == port)
            .ok_or(ERROR)?;
        parse(g.cidrs(), 32)
    };
    let mut routes: BTreeMap<(String, u16), (bool, Vec<Range>)> = BTreeMap::new();
    let mut selectors = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for g in published {
        let port = u16::try_from(g.port).map_err(|_| ERROR)?;
        host(&g.host, g.private_destination)?;
        if port == 0 || !selectors.insert((&g.host, port)) || !ids.insert(&g.grant_id) {
            return Err(ERROR);
        }
        let upper = protected("upstream", &g.host, port)?;
        let declared = parse(&g.approved_cidrs, 64)?;
        if g.private_destination && declared.is_empty() {
            return Err(ERROR);
        }
        let effective = if declared.is_empty() {
            upper
        } else {
            intersection(&upper, &declared)
        };
        if classify(&effective, &excluded)? != g.private_destination {
            return Err(ERROR);
        }
        add(&mut routes, &g.host, port, effective, &excluded)?;
    }
    for purpose in ["governance", "evidence"] {
        let endpoint = authority[purpose]["endpoint"].as_str().ok_or(ERROR)?;
        if endpoint.len() > 2048 {
            return Err(ERROR);
        }
        let u = url::Url::parse(endpoint).map_err(|_| ERROR)?;
        if u.scheme() != "https"
            || !u.username().is_empty()
            || u.password().is_some()
            || u.query().is_some()
            || u.fragment().is_some()
            || u.path() != "/"
        {
            return Err(ERROR);
        }
        let name = u.host_str().ok_or(ERROR)?;
        let port = u.port_or_known_default().ok_or(ERROR)?;
        let effective = protected(purpose, name, port)?;
        add(&mut routes, name, port, effective, &excluded)?;
    }
    routes
        .into_iter()
        .map(|((host, port), (private_destination, ranges))| {
            let cidrs = strings(&ranges, 32)?;
            Ok(Route {
                host,
                port,
                private_destination,
                declared_cidrs: cidrs.clone(),
                protected_cidrs: cidrs,
            })
        })
        .collect()
}
fn add(
    routes: &mut BTreeMap<(String, u16), (bool, Vec<Range>)>,
    name: &str,
    port: u16,
    effective: Vec<Range>,
    excluded: &[Range],
) -> Result<(), &'static str> {
    let private = classify(&effective, excluded)?;
    host(name, private)?;
    let key = (name.into(), port);
    if let Some((previous, ranges)) = routes.get_mut(&key) {
        if *previous != private {
            return Err(ERROR);
        }
        *ranges = intersection(ranges, &effective);
        classify(ranges, excluded)?;
    } else {
        routes.insert(key, (private, reduce(effective)));
    }
    Ok(())
}
fn host(name: &str, private: bool) -> Result<(), &'static str> {
    if name.is_empty()
        || name.len() > 253
        || !name.split('.').all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && !s.starts_with('-')
                && !s.ends_with('-')
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        || name.split('.').all(|s| {
            s.bytes().all(|b| b.is_ascii_digit())
                || s.strip_prefix("0x")
                    .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit()))
        })
        || matches!(
            name,
            "localhost"
                | "host.docker.internal"
                | "gateway.docker.internal"
                | "metadata.google.internal"
                | "instance-data.ec2.internal"
        )
        || name.ends_with(".localhost")
        || (!private && (name.ends_with(".internal") || name.ends_with(".local")))
    {
        return Err(ERROR);
    }
    let u = url::Url::parse(&format!("https://{name}/")).map_err(|_| ERROR)?;
    if u.host_str() != Some(name) || !matches!(u.host(), Some(url::Host::Domain(_))) {
        return Err(ERROR);
    }
    Ok(())
}
