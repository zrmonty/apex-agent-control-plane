//! Existing bounded real transport, never an unbounded synchronous socket.
pub(super) fn connect(url: &str) -> apex_durability::PostgresConnection {
    apex_durability::connect_postgres_for_worker(url)
        .expect("required bounded observer PostgreSQL connection")
}

#[cfg(feature = "test-support")]
pub(super) async fn counts(
    witness: &apex_control_plane_api::RuntimeAuthorityObservations,
    index: usize,
    minimum: u64,
) -> [u64; 4] {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let actual = witness.counts();
        if actual[index] >= minimum {
            // The acquired completion/admission observation is the fence. Sample
            // again AFTER it; earlier fields in `actual` may precede completion.
            return witness.counts();
        }
        assert!(
            std::time::Instant::now() < until,
            "real executor witness not reached"
        );
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
}
