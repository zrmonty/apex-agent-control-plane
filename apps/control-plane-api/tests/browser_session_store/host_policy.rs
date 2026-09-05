use super::browser_session_store_support::is_loopback_config;

// These tests only parse documentation addresses; none opens a socket.
#[test]
fn fixture_rejects_documentation_ipv4_hostaddr_behind_loopback_host() {
    let config = "host=127.0.0.1 hostaddr=192.0.2.123".parse().unwrap();
    assert!(!is_loopback_config(&config));
}

#[test]
fn fixture_rejects_documentation_ipv6_hostaddr_behind_loopback_host() {
    let config = "host=::1 hostaddr=2001:db8::123".parse().unwrap();
    assert!(!is_loopback_config(&config));
}

#[test]
fn fixture_rejects_mixed_loopback_and_remote_hostaddrs() {
    let config = "host=127.0.0.1,127.0.0.2 hostaddr=127.0.0.1,198.51.100.23"
        .parse()
        .unwrap();
    assert!(!is_loopback_config(&config));
}

#[test]
fn fixture_accepts_only_explicit_loopback_destinations() {
    for value in [
        "host=127.0.0.1",
        "host=::1",
        "host=127.0.0.1 hostaddr=127.0.0.2",
        "host=::1 hostaddr=::1",
        "host=127.0.0.1,::1 hostaddr=127.0.0.2,::1",
    ] {
        assert!(is_loopback_config(&value.parse().unwrap()));
    }
    for value in [
        "",
        "host=localhost",
        "host=192.0.2.123",
        "hostaddr=127.0.0.1",
    ] {
        assert!(!is_loopback_config(&value.parse().unwrap()));
    }
}
