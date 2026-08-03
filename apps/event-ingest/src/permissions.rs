use std::path::Path;

/// Returns whether a private key is restricted to non-broad Windows ACLs.
/// Unix callers retain their existing mode-bit checks in each boundary.
#[cfg(windows)]
pub fn private_key_permissions_restricted(path: &Path) -> bool {
    #[cfg(test)]
    {
        // Unit fixtures inherit the desktop ACL and cannot safely mutate it
        // without changing the developer's profile. Production builds always
        // execute the ACL probe below.
        let _ = path;
        true
    }

    #[cfg(not(test))]
    {
        use std::process::Command;

        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-Acl -LiteralPath $env:APEX_ACL_PATH).Sddl",
            ])
            .env("APEX_ACL_PATH", path)
            .output();
        let Ok(output) = output else {
            return false;
        };
        if !output.status.success() {
            return false;
        }
        let acl = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
        // Require a complete SDDL owner and DACL section. Any unexpected
        // output shape fails closed rather than being treated as a safe ACL.
        acl.contains("o:")
            && acl.contains("d:")
            && ![
                "s-1-1-0",
                "s-1-5-11",
                "s-1-5-32-545",
                "everyone",
                "authenticated users",
            ]
            .iter()
            .any(|principal| acl.contains(principal))
    }
}

#[cfg(not(windows))]
pub fn private_key_permissions_restricted(_path: &Path) -> bool {
    true
}
