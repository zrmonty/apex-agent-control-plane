use super::*;
use apex_durability::InMemoryOutbox;

#[test]
fn busy_single_outbox_is_refused_without_waiting_or_running_the_callback() {
    let backend = ControlOutboxBackend::new(Box::new(InMemoryOutbox::new(10).unwrap()));
    let BackendInner::Single(inner) = &backend.inner else {
        unreachable!()
    };
    let _held = inner.lock().unwrap();
    assert!(
        backend
            .try_with_lock(|_| panic!("busy backend called the callback"))
            .is_err()
    );
}

#[test]
fn relay_tries_other_pool_slots_without_queueing_behind_a_busy_connection() {
    let backend = ControlOutboxBackend::new_pool(vec![
        Box::new(InMemoryOutbox::new(10).unwrap()),
        Box::new(InMemoryOutbox::new(10).unwrap()),
    ])
    .unwrap();
    let BackendInner::Pool { connections, .. } = &backend.inner else {
        unreachable!()
    };
    let _first = connections[0].lock().unwrap();
    assert_eq!(backend.try_with_lock(|_| 7).unwrap(), 7);
    let _second = connections[1].lock().unwrap();
    assert!(
        backend
            .try_with_lock(|_| panic!("busy pool called the callback"))
            .is_err()
    );
}
