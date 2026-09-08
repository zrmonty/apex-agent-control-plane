//! Cross-observe exact active endpoints before applying the unchanged empty-fabric grammar.
use super::*;
use serde_json::{Value, json};
impl Inventory {
    pub(in crate::execution::engine) fn outer_candidate(
        &self,
        t: &Topology,
    ) -> Result<String, &'static str> {
        let c = t.catalog()?;
        let candidates: Vec<_> = self
            .networks
            .iter()
            .filter(|n| n.id == c.outer().network_id())
            .collect();
        let [n] = candidates.as_slice() else {
            return Err(ERROR);
        };
        if self
            .networks
            .iter()
            .filter(|other| other.name == n.name)
            .count()
            != 1
        {
            return Err(ERROR);
        }
        Ok(n.name.clone())
    }
    pub(in crate::execution::engine) fn without_running(
        &self,
        observed: &[Value],
    ) -> Result<Self, &'static str> {
        let mut values: BTreeMap<_, _> = self
            .networks
            .iter()
            .map(|n| (n.id.clone(), n.value.clone()))
            .collect();
        for container in observed {
            let id = container["Id"].as_str().ok_or(ERROR)?;
            let name = container["Name"]
                .as_str()
                .and_then(|s| s.strip_prefix('/'))
                .ok_or(ERROR)?;
            for endpoint in container["NetworkSettings"]["Networks"]
                .as_object()
                .ok_or(ERROR)?
                .values()
            {
                let network_id = endpoint["NetworkID"].as_str().ok_or(ERROR)?;
                let n = values.get_mut(network_id).ok_or(ERROR)?;
                let member = &n["Containers"][id];
                if member["Name"] != name
                    || member["EndpointID"] != endpoint["EndpointID"]
                    || member["MacAddress"] != endpoint["MacAddress"]
                    || member["IPv4Address"]
                        != format!(
                            "{}/{}",
                            endpoint["IPAddress"].as_str().ok_or(ERROR)?,
                            endpoint["IPPrefixLen"].as_u64().ok_or(ERROR)?
                        )
                    || member["IPv6Address"] != ""
                {
                    return Err(ERROR);
                }
                n["Containers"]
                    .as_object_mut()
                    .ok_or(ERROR)?
                    .remove(id)
                    .ok_or(ERROR)?;
            }
        }
        let networks = values
            .into_values()
            .map(|v| Inspected::parse(&serde_json::to_vec(&json!([v])).map_err(|_| ERROR)?))
            .collect::<Result<_, _>>()?;
        Ok(Self { networks })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Inventory, Value) {
        let id = "a".repeat(64);
        let network_id = "b".repeat(64);
        let endpoint = "c".repeat(64);
        let n = json!([{"Name":"internal", "Id":network_id, "Scope":"local", "Driver":"bridge",
            "IPAM":{"Driver":"default","Options":{},"Config":[{"Subnet":"10.246.0.0/29","Gateway":"10.246.0.1"}]},
            "Containers":{&id:{"Name":"guard","EndpointID":endpoint,"MacAddress":"02:42:0a:f6:00:03","IPv4Address":"10.246.0.3/29","IPv6Address":""}}}]);
        let inventory = Inventory {
            networks: vec![Inspected::parse(&serde_json::to_vec(&n).unwrap()).unwrap()],
        };
        let container = json!({"Id":id,"Name":"/guard","NetworkSettings":{"Networks":{"internal":{
            "NetworkID":network_id,"EndpointID":endpoint,"MacAddress":"02:42:0a:f6:00:03","IPAddress":"10.246.0.3","IPPrefixLen":29}}}});
        (inventory, container)
    }
    #[test]
    fn task4z_active_network_join_requires_independent_endpoint_agreement() {
        let (inventory, container) = fixture();
        let projected = inventory
            .without_running(std::slice::from_ref(&container))
            .unwrap();
        assert_eq!(projected.networks[0].value["Containers"], json!({}));
        for (field, bad) in [
            ("EndpointID", json!("d".repeat(64))),
            ("MacAddress", json!("02:42:0a:f6:00:04")),
            ("IPAddress", json!("10.246.0.4")),
            ("NetworkID", json!("f".repeat(64))),
            ("IPPrefixLen", json!(24)),
        ] {
            let mut changed = container.clone();
            changed["NetworkSettings"]["Networks"]["internal"][field] = bad;
            assert!(inventory.without_running(&[changed]).is_err(), "{field}");
        }
        let mut foreign = container.clone();
        foreign["Id"] = json!("d".repeat(64));
        assert!(inventory.without_running(&[foreign]).is_err());
        assert!(
            inventory
                .without_running(&[container.clone(), container])
                .is_err()
        );
    }
    #[test]
    fn task4z_active_network_join_never_discards_unproven_members() {
        let (mut inventory, container) = fixture();
        inventory.networks[0].value["Containers"]["d".repeat(64)] = json!({
            "Name":"foreign","EndpointID":"e".repeat(64),"MacAddress":"02:42:0a:f6:00:04","IPv4Address":"10.246.0.4/29","IPv6Address":""});
        let projected = inventory.without_running(&[container]).unwrap();
        assert_eq!(
            projected.networks[0].value["Containers"]
                .as_object()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            projected.networks[0].value["Containers"]["d".repeat(64)]["Name"],
            "foreign"
        );
    }
}
