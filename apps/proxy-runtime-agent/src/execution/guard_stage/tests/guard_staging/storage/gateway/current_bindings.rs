//! Fresh, internally valid bindings must not replace an instance's original binding.
use super::*;

#[test]
fn task4x_valid_current_signer_catalog_and_source_bindings_do_not_rebind_instance() {
    let mut s = Storage::new();
    materials(&s);
    assert_eq!(
        paired(&mut s, &mut || Ok(())),
        Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
    );
    let before = serde_json::to_value(&s.record).unwrap();
    let directory = s
        .root
        .join("staging")
        .join(format!("apex-runtime-{INSTANCE}"));
    let original_files = recovery::hashes(&directory);
    let selected = s
        .fixture
        .catalogs
        .images
        .select(
            s.fixture.launch.image_catalog_id(),
            &s.fixture.launch.context().image_ref,
        )
        .unwrap();
    let pristine = json!({
        "schema_version": 1,
        "images": [{
            "id": selected.catalog_id,
            "image_ref": selected.image_ref,
            "signing": {
                "certificate_identity": selected.certificate_identity,
                "certificate_oidc_issuer": selected.certificate_oidc_issuer
            }
        }]
    });
    for changed in ["unchanged", "identity", "issuer", "catalog", "source"] {
        let mut catalog = pristine.clone();
        match changed {
            "identity" => {
                catalog["images"][0]["signing"]["certificate_identity"] =
                    json!("https://example.test/new-signer")
            }
            "issuer" => {
                catalog["images"][0]["signing"]["certificate_oidc_issuer"] =
                    json!("https://new-issuer.example.test")
            }
            "catalog" => catalog["images"][0]["id"] = json!("new-gateway-catalog"),
            "source" | "unchanged" => {}
            _ => unreachable!(),
        }
        let parsed =
            crate::image_catalog::ImageCatalog::parse(&serde_json::to_vec(&catalog).unwrap())
                .unwrap();
        let image = parsed
            .select(
                catalog["images"][0]["id"].as_str().unwrap(),
                &s.fixture.launch.context().image_ref,
            )
            .unwrap();
        let source_hash = if changed == "source" {
            "f".repeat(64)
        } else {
            crate::execution::network::hash(&(
                s.fixture.launch.materials(),
                &s.fixture.selected.tools,
            ))
            .unwrap()
        };
        let fresh = gateway_staging::GatewayStage::new(
            INSTALL,
            s.record.installed.as_ref().unwrap(),
            image,
            source_hash,
            s.staging.guard_root().unwrap(),
        )
        .unwrap();
        // All candidates pass their own validation and preserve the original
        // launch/image. Only their current-vs-installed binding differs.
        fresh
            .validate(INSTALL, s.record.installed.as_ref().unwrap())
            .unwrap();
        assert_eq!(
            fresh.binding_hash == before["installed"]["gateway_stage"]["binding_hash"],
            changed == "unchanged",
            "{changed}"
        );
        assert_eq!(
            gateway_staging::stage(
                &s.journal,
                &s.staging,
                &mut s.record,
                fresh,
                &s.fixture.launch,
                &s.fixture.selected,
                &mut || Ok(()),
            ),
            Err(if changed == "unchanged" {
                "RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE"
            } else {
                "RUNTIME_GATEWAY_STAGE_QUARANTINED"
            }),
            "{changed}"
        );
        s.reload();
        assert_eq!(
            serde_json::to_value(&s.record).unwrap(),
            before,
            "{changed}"
        );
        assert_eq!(recovery::hashes(&directory), original_files, "{changed}");
    }
}
