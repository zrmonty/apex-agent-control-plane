//! Sealed paired identity is registerable before start, never self-admitting.
use super::*;
use sha2::{Digest, Sha256};
use std::cell::RefCell;

fn installed() -> Storage {
    let mut s = Storage::new();
    prepared(&mut s);
    let p = s
        .record
        .installed
        .as_mut()
        .unwrap()
        .paired_containers
        .as_mut()
        .unwrap();
    p.phase = Phase::Verified;
    p.gateway_id = "d".repeat(64);
    p.guard_id = "e".repeat(64);
    s.journal.save(&s.record).unwrap();
    s
}

#[test]
fn paired_registration_uses_only_the_sealed_gateway_identity_before_start() {
    let s = installed();
    let i = s.record.installed.as_ref().unwrap();
    let before = serde_json::to_vec(i).unwrap();
    let a = i
        .attestation(INSTALL)
        .expect("sealed verified pair must attest")
        .unwrap();
    let g = i.gateway_stage.as_ref().unwrap();
    assert_eq!(a.instance_proof_sha256, g.files["instance-proof"]);
    assert_eq!(
        a.image_id,
        i.paired_containers.as_ref().unwrap().gateway_image_id
    );
    assert_eq!(
        a.staged_manifest_sha256,
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&g.files).unwrap())
        )
    );
    assert_eq!(a.launch.as_ref().unwrap().target, i.original.target);
    assert_eq!(a.launch.as_ref().unwrap().process_instance_id, i.instance);
    assert_eq!(serde_json::to_vec(i).unwrap(), before);
    assert!(i.paired_containers.as_ref().unwrap().start.is_none());
}

#[test]
fn paired_registration_recovery_keeps_original_binding_after_current_fence_advances() {
    let mut s = installed();
    let a = s
        .record
        .installed
        .as_ref()
        .unwrap()
        .attestation(INSTALL)
        .unwrap()
        .unwrap();
    let mut claims = s.record.claims.clone();
    claims.command_id = uuid::Uuid::now_v7().to_string();
    claims.target.as_mut().unwrap().fencing_token += 1;
    s.record = Record::select(INSTALL, &claims, Some(s.record)).unwrap();
    s.journal.save(&s.record).unwrap();
    s.reload();
    assert_eq!(
        s.record
            .installed
            .as_ref()
            .unwrap()
            .attestation(INSTALL)
            .unwrap(),
        Some(a)
    );
}

#[test]
fn paired_registration_refuses_partial_or_rebound_pair_without_legacy_fallback() {
    let s = installed();
    let original = s.record.installed.as_ref().unwrap();
    assert!(original.attestation(INSTALL).unwrap().is_some());
    for field in ["phase", "binding", "proof", "stage", "pair", "legacy"] {
        let mut i = original.clone();
        match field {
            "phase" => i.paired_containers.as_mut().unwrap().phase = Phase::ConnectIntent,
            "binding" => i.paired_containers.as_mut().unwrap().binding_hash = "f".repeat(64),
            "proof" => {
                i.gateway_stage
                    .as_mut()
                    .unwrap()
                    .files
                    .remove("instance-proof");
            }
            "stage" => i.gateway_stage = None,
            "pair" => i.paired_containers = None,
            "legacy" => i.instance_proof_version = None,
            _ => unreachable!(),
        }
        assert!(i.attestation(INSTALL).is_err(), "{field}");
    }
}

#[test]
fn paired_registration_prestart_rechecks_around_the_actual_callback() {
    let s = installed();
    let i = s.record.installed.as_ref().unwrap();
    let events = RefCell::new(Vec::new());
    crate::execution::paired::registration::before_start(
        INSTALL,
        i,
        true,
        &mut || {
            events.borrow_mut().push("check");
            Ok(())
        },
        &mut |a| {
            assert_eq!(Some(a.clone()), i.attestation(INSTALL).unwrap());
            events.borrow_mut().push("register");
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(*events.borrow(), ["check", "register", "check"]);
}

#[test]
fn paired_registration_prestart_refusal_cannot_reach_start() {
    let s = installed();
    let i = s.record.installed.as_ref().unwrap();
    for fail in ["mode", "before", "callback", "after"] {
        let events = RefCell::new(Vec::new());
        let mut checks = 0;
        let result = crate::execution::paired::registration::before_start(
            INSTALL,
            i,
            fail != "mode",
            &mut || {
                checks += 1;
                events.borrow_mut().push("check");
                if (fail == "before" && checks == 1) || (fail == "after" && checks == 2) {
                    Err("RUNTIME_CANCELLED")
                } else {
                    Ok(())
                }
            },
            &mut |_| {
                events.borrow_mut().push("register");
                if fail == "callback" {
                    Err("RUNTIME_REGISTRATION_REFUSED")
                } else {
                    Ok(())
                }
            },
        );
        if result.is_ok() {
            events.borrow_mut().push("start");
        }
        assert!(result.is_err(), "{fail}: start must remain unreachable");
        let expected = match fail {
            "mode" => vec![],
            "before" => vec!["check"],
            "callback" => vec!["check", "register"],
            "after" => vec!["check", "register", "check"],
            _ => unreachable!(),
        };
        assert_eq!(*events.borrow(), expected, "{fail}");
    }
}
