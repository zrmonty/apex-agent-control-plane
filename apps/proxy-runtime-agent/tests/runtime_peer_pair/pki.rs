//! Existing test PKI only, following runtime_peer_mtls/support.rs without edits.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::{io::Read, path::PathBuf};
use tonic::transport::Identity;

pub const AGENT: &str = "agent-workload-client";
pub const CONTROLLER: &str = "control-operator-client";
pub const OTHER: &str = "ingest-http-client";

pub struct Pki(PathBuf);

impl Pki {
    pub fn require() -> Self {
        let root = std::env::var_os("APEX_BROWSER_TEST_PKI_DIR")
            .filter(|value| !value.is_empty())
            .expect("runtime_peer_pair requires existing APEX_BROWSER_TEST_PKI_DIR; no skip");
        let pki = Self(
            PathBuf::from(root)
                .canonicalize()
                .expect("existing PKI root required"),
        );
        assert!(pki.0.is_dir(), "existing PKI root must be a directory");
        assert_ne!(
            pki.read("trusted-host", "ca.pem"),
            pki.read("untrusted-host", "ca.pem")
        );
        for name in [AGENT, CONTROLLER, OTHER, "control-plane-server"] {
            for extension in ["pem", "key"] {
                pki.file("trusted-host", &format!("{name}.{extension}"));
            }
        }
        for extension in ["pem", "key"] {
            pki.file("untrusted-host", &format!("{CONTROLLER}.{extension}"));
        }
        assert_ne!(pki.pin(AGENT), pki.pin(CONTROLLER));
        assert_ne!(pki.pin(AGENT), pki.pin(OTHER));
        assert_ne!(pki.pin(CONTROLLER), pki.pin(OTHER));
        pki
    }

    fn file(&self, tree: &str, name: &str) -> std::fs::File {
        let file = std::fs::File::open(self.0.join(tree).join(name))
            .expect("required existing PKI fixture unavailable; never generate or overwrite");
        let metadata = file.metadata().expect("PKI fixture metadata unavailable");
        assert!(metadata.is_file() && (1..=1_048_576).contains(&metadata.len()));
        file
    }

    pub fn read(&self, tree: &str, name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.file(tree, name)
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .expect("cannot read existing PKI fixture");
        assert!(
            (1..=1_048_576).contains(&bytes.len()),
            "PKI fixture changed size"
        );
        bytes
    }

    pub fn pin(&self, leaf: &str) -> [u8; 32] {
        let pem = self.read("trusted-host", &format!("{leaf}.pem"));
        let text = std::str::from_utf8(&pem).expect("test certificate must be PEM");
        assert_eq!(text.matches("-----BEGIN CERTIFICATE-----").count(), 1);
        assert_eq!(text.matches("-----END CERTIFICATE-----").count(), 1);
        let encoded: String = text
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let der = STANDARD
            .decode(encoded)
            .expect("test certificate must contain DER");
        Sha256::digest(der).into()
    }

    pub fn identity(&self, tree: &str, leaf: &str) -> Identity {
        Identity::from_pem(
            self.read(tree, &format!("{leaf}.pem")),
            self.read(tree, &format!("{leaf}.key")),
        )
    }
}

pub fn hex(pin: &[u8; 32]) -> String {
    pin.iter().map(|byte| format!("{byte:02x}")).collect()
}
