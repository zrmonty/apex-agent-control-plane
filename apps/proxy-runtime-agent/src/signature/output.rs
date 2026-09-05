use super::SignatureError;

pub(super) fn check(bytes: &[u8], image: &str) -> Result<(), SignatureError> {
    let denied = || SignatureError::Verification;
    if bytes.is_empty() || bytes.len() > 262_144 {
        return Err(denied());
    }
    // This is output of the protected verifier after successful cryptographic
    // verification, never caller-supplied evidence or a substitute for Cosign.
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| denied())?;
    let entries = value
        .as_array()
        .filter(|items| !items.is_empty() && items.len() <= 64)
        .ok_or_else(denied)?;
    let (_, digest) = image.split_once('@').ok_or_else(denied)?;
    for entry in entries {
        let critical = entry
            .get("critical")
            .and_then(|value| value.as_object())
            .ok_or_else(denied)?;
        if critical
            .get("image")
            .and_then(|value| value.get("docker-manifest-digest"))
            .and_then(|value| value.as_str())
            != Some(digest)
            || !matches!(
                critical.get("type").and_then(|value| value.as_str()),
                Some("cosign container image signature" | "https://sigstore.dev/cosign/sign/v1")
            )
        {
            return Err(denied());
        }
    }
    Ok(())
}
