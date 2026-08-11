use std::path::Path;

/// Returns whether a private key is restricted to non-broad Windows ACLs.
///
/// Gated on `cfg(test)` ONLY -- not the `test-support` Cargo feature.
/// `test-support` is a normal (non-dev-only) feature that can be compiled
/// into a release binary or an integration-test build (`tests/*.rs`, which
/// link the library *without* `cfg(test)`). If this stub were reachable via
/// `feature = "test-support"` alone, an unconditional-pass permission check
/// could ship in a build that a build script or CI job believes is
/// hardened. Only `cargo test`'s unit-test compilation (which always sets
/// `cfg(test)`) gets the stub; every other configuration -- including
/// `--features test-support` on its own -- compiles the real ACL probe
/// below.
#[cfg(test)]
pub fn private_key_permissions_restricted(path: &Path) -> bool {
    // Unit fixtures inherit the desktop ACL and cannot safely mutate it
    // without changing the developer's profile.
    let _ = path;
    true
}

#[cfg(not(test))]
pub fn private_key_permissions_restricted(path: &Path) -> bool {
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    let Some(system_root) = env::var_os("SystemRoot") else {
        return false;
    };
    let powershell = PathBuf::from(system_root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    let output = Command::new(powershell)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            r#"
$acl = Get-Acl -LiteralPath $env:APEX_ACL_PATH
if ($null -eq $acl.Owner -or $null -eq $acl.Sddl -or $acl.Sddl -notmatch '(^|;)o:' -or $acl.Sddl -notmatch '(^|;)d:') { exit 2 }
try { $ownerSid = (New-Object System.Security.Principal.NTAccount($acl.Owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { exit 2 }
$allowed = @($ownerSid, 'S-1-5-18', 'S-1-5-32-544')
if ($acl.Access.Count -eq 0) { exit 2 }
foreach ($ace in $acl.Access) {
  if ($ace.IsInherited -or $ace.AccessControlType -ne 'Allow' -or $ace.InheritanceFlags -ne 'None' -or $ace.PropagationFlags -ne 'None') { exit 2 }
  try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { exit 2 }
  if ($allowed -notcontains $sid) { exit 2 }
}
Write-Output 'SAFE'
            "#,
        ])
        .env("APEX_ACL_PATH", path)
        .output();
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    String::from_utf8_lossy(&output.stdout).trim() == "SAFE"
}
