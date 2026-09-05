use super::*;

#[test]
fn real_clock_window_check_is_not_peer_authentication() {
    let policy = parse(&document()).unwrap();
    let before = checked_clock(SystemTime::now().duration_since(UNIX_EPOCH).ok()).unwrap();
    let observed = policy.check_current().expect("current explicit document");
    let after = checked_clock(SystemTime::now().duration_since(UNIX_EPOCH).ok()).unwrap();
    assert!(before <= observed && observed <= after);
    assert_eq!(
        policy
            .authorize(
                &tonic::Request::new(()),
                RuntimePeerRole::Controller,
                INSTALL_A,
                "work",
                "ns"
            )
            .unwrap_err(),
        RuntimePeerError::Unauthenticated
    );
}

#[test]
fn real_clock_window_check_refuses_expired_and_future_documents() {
    for (from, until) in [("1", "2"), ("18446744073709551614", "18446744073709551615")] {
        let mut input = document();
        input["validFromUnixUs"] = from.into();
        input["expiresAtUnixUs"] = until.into();
        assert_eq!(
            parse(&input).unwrap().check_current(),
            Err(RuntimePeerError::PolicyNotCurrent)
        );
    }
}
