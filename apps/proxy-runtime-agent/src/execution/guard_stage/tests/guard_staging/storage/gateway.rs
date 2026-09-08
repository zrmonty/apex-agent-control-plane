//! Paired producer/journal/real Linux storage acceptance. No signature proof.
use super::*;
use crate::execution::gateway_staging;
mod containers;
mod current_bindings;
mod currentness;
mod descriptor_races;
mod recovery;
mod validation;

fn paired(
    s: &mut Storage,
    check: &mut impl FnMut() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    s.stage()?;
    let f = &s.fixture;
    let signing = f
        .catalogs
        .images
        .select(f.launch.image_catalog_id(), &f.launch.context().image_ref)
        .unwrap();
    let fresh = gateway_staging::GatewayStage::new(
        INSTALL,
        s.record.installed.as_ref().unwrap(),
        signing,
        crate::execution::network::hash(&(f.launch.materials(), &f.selected.tools)).unwrap(),
        s.staging.guard_root().unwrap(),
    )?;
    gateway_staging::stage(
        &s.journal,
        &s.staging,
        &mut s.record,
        fresh,
        &f.launch,
        &f.selected,
        check,
    )
}
fn materials(s: &Storage) {
    for n in 1..=13 {
        let path = s.root.join("material").join(format!("m{n}"));
        fs::write(
            &path,
            if n == 1 {
                &b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"[..]
            } else {
                &b"task4x-fixture-material-canary"[..]
            },
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    }
    for t in &s.fixture.selected.tools {
        let path = s.root.join("material").join(&t.source_name);
        fs::write(&path, b"task4x-fixture-tool-canary").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    }
}

#[test]
fn task4x_paired_gateway_is_sealed_while_remaining_not_serving() {
    let mut s = Storage::new();
    materials(&s);
    assert_eq!(
        paired(&mut s, &mut || Ok(())),
        Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
    );
    s.reload();
    let installed = serde_json::to_value(&s.record.installed).unwrap();
    assert_eq!(installed["guard_stage"]["phase"], "Sealed");
    assert_eq!(
        installed["gateway_stage"]["phase"], "Sealed",
        "managed paired boundary must seal the gateway after the existing guard"
    );
    assert_eq!(installed["phase"], "Intent");
    assert_eq!(installed["container_id"], "");
    assert_eq!(installed["image_id"], "");
    assert_eq!(installed["files"], json!({}));
    let directory = s
        .root
        .join("staging")
        .join(format!("apex-runtime-{INSTANCE}"));
    for name in [
        "runtime-revision.json",
        "launch-context.json",
        "authority-profile.json",
        "tool-bindings.json",
        "instance-proof",
    ] {
        let stat = fs::metadata(directory.join(name)).unwrap();
        assert_eq!(
            (stat.uid(), stat.gid(), stat.mode() & 0o7777, stat.nlink()),
            (10001, 10001, 0o400, 1)
        );
    }
    assert_eq!(
        fs::metadata(directory.join("instance-proof"))
            .unwrap()
            .len(),
        32
    );
}

#[test]
fn task4x_byte_identical_source_rotation_refuses_after_reopen() {
    let mut s = Storage::new();
    materials(&s);
    assert_eq!(
        paired(&mut s, &mut || Ok(())),
        Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
    );
    let path = s.root.join("material/m2");
    fs::rename(&path, s.root.join("original-source")).unwrap();
    fs::copy(s.root.join("original-source"), &path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    s.reload();
    assert_eq!(
        paired(&mut s, &mut || Ok(())),
        Err("RUNTIME_GATEWAY_STAGE_QUARANTINED"),
        "source identity rotation cannot reuse a paired instance even with identical bytes"
    );
}
