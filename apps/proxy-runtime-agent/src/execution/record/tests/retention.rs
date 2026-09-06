use super::*;
fn copy(r: &Record) -> Record {
    serde_json::from_slice(&serde_json::to_vec(r).unwrap()).unwrap()
}
#[test]
fn more_than_64_commands_restart_and_current_cleanup_do_not_exhaust_lifetime_capacity() {
    let first = claims();
    let install = uuid::Uuid::now_v7().to_string();
    let mut r = Record::select(&install, &first, None).unwrap();
    let instance = r.instance.clone();
    for _ in 0..130 {
        let mut next = first.clone();
        next.command_id = uuid::Uuid::now_v7().to_string();
        r = Record::select(&install, &next, Some(copy(&r)))
            .expect("current retry cannot exhaust lifetime capacity");
        assert!(r.commands.len() <= 64);
        assert_eq!(r.instance, instance);
        assert_eq!(r.original, first);
    }
    assert!(
        Record::select(&install, &first, Some(copy(&r))).is_err(),
        "evicted ID is a tombstone, not forgotten permission"
    );
    let retained = r.claims.command_id.clone();
    let mut pause = r.claims.clone();
    pause.operation_id = uuid::Uuid::now_v7().to_string();
    pause.command_id = uuid::Uuid::now_v7().to_string();
    pause.target.as_mut().unwrap().generation += 1;
    pause.target.as_mut().unwrap().fencing_token += 1;
    r = copy(&r)
        .advance(&pause, false)
        .expect("fresh pause after full retention");
    assert_eq!(r.instance, instance);
    for id in [first.command_id.clone(), retained] {
        let mut conflict = pause.clone();
        conflict.command_id = id;
        assert!(Record::select(&install, &conflict, Some(copy(&r))).is_err());
    }
    let mut retire = pause.clone();
    retire.operation_id = uuid::Uuid::now_v7().to_string();
    retire.command_id = uuid::Uuid::now_v7().to_string();
    retire.target.as_mut().unwrap().generation += 1;
    retire.target.as_mut().unwrap().fencing_token += 1;
    r = copy(&r)
        .advance(&retire, false)
        .expect("fresh retire after full retention");
    assert_eq!(r.original, first);
    assert!(Record::select(&install, &pause, Some(copy(&r))).is_err());
    let mut stale = retire;
    stale.command_id = uuid::Uuid::now_v7().to_string();
    stale.target.as_mut().unwrap().fencing_token -= 1;
    assert!(Record::select(&install, &stale, Some(copy(&r))).is_err());
}
