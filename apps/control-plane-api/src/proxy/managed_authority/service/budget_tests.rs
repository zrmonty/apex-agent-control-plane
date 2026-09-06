use super::*;
use tonic::metadata::MetadataMap;

#[test]
fn grpc_timeout_units_are_bounded_and_ambiguous_or_zero_values_refuse() {
    assert_eq!(
        budget(&MetadataMap::new()).unwrap(),
        Duration::from_secs(10)
    );
    for (value, nanos) in [
        ("1n", 1),
        ("1u", 1_000),
        ("1m", 1_000_000),
        ("1S", 1_000_000_000),
        ("1M", 10_000_000_000),
        ("99999999H", 10_000_000_000),
    ] {
        let mut metadata = MetadataMap::new();
        metadata.insert("grpc-timeout", value.parse().unwrap());
        assert_eq!(
            budget(&metadata).unwrap(),
            Duration::from_nanos(nanos),
            "{value}"
        );
    }
    for value in ["0n", "1", "1s", "-1S", "100000000n", "1.0S", "S1", " 1S"] {
        let mut metadata = MetadataMap::new();
        metadata.insert("grpc-timeout", value.parse().unwrap());
        assert!(budget(&metadata).is_err(), "{value}");
    }
    let mut metadata = MetadataMap::new();
    metadata.append("grpc-timeout", "1S".parse().unwrap());
    metadata.append("grpc-timeout", "1S".parse().unwrap());
    assert!(budget(&metadata).is_err());
}
