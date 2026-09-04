// Startup tests for network.

#[test]
fn bind_address_defaults_to_loopback_and_refuses_silent_exposure() {
    assert_eq!(
        resolve_bind_addr_value(None, None).unwrap().to_string(),
        DEFAULT_BIND_ADDR
    );
    assert_eq!(
        resolve_bind_addr_value(Some(""), None).unwrap().to_string(),
        DEFAULT_BIND_ADDR
    );
    // Loopback needs no acknowledgement, in either address family.
    assert!(resolve_bind_addr_value(Some("127.0.0.1:9443"), None).is_ok());
    assert!(resolve_bind_addr_value(Some("[::1]:9443"), None).is_ok());

    // Anything else does, even though the listener now terminates mTLS.
    assert!(resolve_bind_addr_value(Some("0.0.0.0:9443"), None).is_err());
    assert!(resolve_bind_addr_value(Some("[::]:9443"), None).is_err());
    assert!(resolve_bind_addr_value(Some("10.0.0.5:9443"), None).is_err());
    assert!(resolve_bind_addr_value(Some("0.0.0.0:9443"), Some("true")).is_ok());
}

#[test]
fn nonlocal_bind_acknowledgement_is_exact_and_fails_closed() {
    // A near-miss must never be read as consent to expose the control
    // channel. Only the literal "true" acknowledges.
    for near_miss in ["TRUE", "True", "1", "yes", "on", " true", "true ", ""] {
        assert!(
            resolve_bind_addr_value(Some("0.0.0.0:9443"), Some(near_miss)).is_err(),
            "{near_miss:?} must not acknowledge a non-loopback bind"
        );
    }
    assert!(resolve_bind_addr_value(Some("0.0.0.0:9443"), Some("false")).is_err());
}

#[test]
fn bind_address_rejects_values_that_are_not_socket_addresses() {
    for bad in [
        "9443",
        "127.0.0.1",
        "not-an-address",
        "localhost:9443",
        "::1:9443",
    ] {
        assert!(
            resolve_bind_addr_value(Some(bad), Some("true")).is_err(),
            "{bad:?} must not parse as a bind address"
        );
    }
}

#[test]
fn metrics_endpoint_is_optional_and_loopback_only() {
    assert_eq!(metrics_bind_addr_value(None).unwrap(), None);
    assert_eq!(
        metrics_bind_addr_value(Some("127.0.0.1:9943"))
            .unwrap()
            .unwrap()
            .to_string(),
        "127.0.0.1:9943"
    );
    assert!(metrics_bind_addr_value(Some("0.0.0.0:9943")).is_err());
    assert!(metrics_bind_addr_value(Some("not-an-address")).is_err());
}
