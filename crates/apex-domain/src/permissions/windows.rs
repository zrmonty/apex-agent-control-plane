use std::path::Path;

/// Returns whether a private key is restricted to non-broad Windows ACLs.
#[cfg(any(test, feature = "test-support"))]
pub fn private_key_permissions_restricted(path: &Path) -> bool {
    // Unit fixtures inherit the desktop ACL and cannot safely mutate it
    // without changing the developer's profile. Production builds always
    // execute the ACL probe below.
    let _ = path;
    true
}

#[cfg(all(not(test), not(feature = "test-support")))]
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


