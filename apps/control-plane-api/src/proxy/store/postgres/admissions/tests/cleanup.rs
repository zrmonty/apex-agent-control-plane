use super::super::super::serving::Withdrawal;
use super::*;

#[test]
fn exact_completion_survives_closed_state_and_never_refunds() {
    let f = Fixture::new();
    serving(&f);
    let input = request(&f);
    let first = f
        .store
        .reserve_managed_call_checked(&input, &|| Ok(()))
        .unwrap();
    f.store
        .withdraw_deployment_checked(
            &f.lease,
            &input.binding,
            Withdrawal::Replacement,
            &|| Ok(()),
        )
        .unwrap();
    assert!(
        f.store
            .reserve_managed_call_checked(&request(&f), &|| Ok(()))
            .is_err()
    );
    assert!(
        f.store
            .complete_managed_call_checked(
                &input.binding,
                Uuid::now_v7(),
                input.call_id,
                &|| Ok(())
            )
            .is_err()
    );
    assert!(
        f.store
            .complete_managed_call_checked(
                &input.binding,
                first.admission_id,
                Uuid::now_v7(),
                &|| Ok(())
            )
            .is_err()
    );
    let mut wrong = input.binding.clone();
    wrong.launch_context_hash = "c".repeat(64);
    assert!(
        f.store
            .complete_managed_call_checked(&wrong, first.admission_id, input.call_id, &|| Ok(()))
            .is_err()
    );
    assert_eq!(counters(&f), (1, 1, 1, 1));
    complete(&f, &input, &first);
    complete(&f, &input, &first);
    assert_eq!(counters(&f), (1, 1, 0, 1));
}

#[test]
fn only_persisted_exact_termination_releases_uncertain_capacity() {
    let f = Fixture::new();
    serving(&f);
    let input = request(&f);
    let first = f
        .store
        .reserve_managed_call_checked(&input, &|| Ok(()))
        .unwrap();
    f.store
        .reserve_managed_call_checked(&request(&f), &|| Ok(()))
        .unwrap();
    assert!(
        f.store
            .release_terminated_admissions_checked(&input.binding, &|| Ok(()))
            .is_err()
    );
    assert_eq!(counters(&f), (2, 2, 2, 2));
    f.store
        .record_deployment_termination_checked(&f.lease, &input.binding, &|| Ok(()))
        .unwrap();
    assert_eq!(
        f.store
            .release_terminated_admissions_checked(&input.binding, &|| Ok(()))
            .unwrap(),
        2
    );
    assert_eq!(
        f.store
            .release_terminated_admissions_checked(&input.binding, &|| Ok(()))
            .unwrap(),
        0
    );
    complete(&f, &input, &first);
    assert_eq!(counters(&f), (2, 2, 0, 2));
}
