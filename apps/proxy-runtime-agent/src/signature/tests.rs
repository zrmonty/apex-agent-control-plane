use super::*;
use serde_json::json;
mod filesystem;

const IMAGE: &str = "ghcr.io/sigstore/cosign/cosign@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8";
fn catalog(identity: &str) -> ImageCatalog {
    ImageCatalog::parse(
        &serde_json::to_vec(&json!({"schema_version":1,"images":[{
            "id":"cosign-fixture","image_ref":IMAGE,"signing":{
                "certificate_oidc_issuer":"https://accounts.google.com",
                "certificate_identity":identity
            }
        }]}))
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn invalid_executable_and_cache_are_refused() {
    for (exe, cache) in [
        ("relative", "/"),
        ("/does-not-exist", "/"),
        ("/bin/sh", "/tmp"),
    ] {
        assert!(matches!(
            SignatureVerifier::open(Path::new(exe), Path::new(cache)),
            Err(SignatureError::InvalidConfiguration)
        ));
    }
}

#[test]
#[ignore = "explicit CI acceptance runs as dedicated nonroot UID 1001"]
fn dedicated_agent_uid_can_open_its_protected_cache() {
    assert_eq!(rustix::process::geteuid().as_raw(), 1001);
    SignatureVerifier::open(
        Path::new("/usr/local/bin/apex-test-cosign"),
        Path::new("/signature-user-cache"),
    )
    .expect("agent UID is not the container UID");
}

#[test]
#[ignore = "network acceptance: run explicitly in the protected Cosign fixture container"]
fn live_cosign_accepts_exact_signer_and_rejects_wrong_identity() {
    let verifier = SignatureVerifier::open(
        Path::new("/usr/local/bin/apex-test-cosign"),
        Path::new("/cosign-test-cache"),
    )
    .expect("protected real Cosign");
    let identity = "keyless@projectsigstore.iam.gserviceaccount.com";
    let verified = verifier
        .verify(
            &catalog(identity),
            "cosign-fixture",
            IMAGE,
            Duration::from_secs(30),
            &AtomicBool::new(false),
        )
        .expect("real signature must verify");
    assert_eq!(verified.image_ref(), IMAGE);
    assert_eq!(
        verifier
            .verify(
                &catalog("https://invalid.example/attacker"),
                "cosign-fixture",
                IMAGE,
                Duration::from_secs(30),
                &AtomicBool::new(false)
            )
            .unwrap_err(),
        SignatureError::Verification
    );
}
