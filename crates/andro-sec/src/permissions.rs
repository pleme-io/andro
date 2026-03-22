use serde::{Deserialize, Serialize};

/// Permission risk classification.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum PermissionRisk {
    Normal,
    Dangerous,
    Signature,
    Critical,
}

/// Result of permission audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionAudit {
    pub permissions: Vec<PermissionEntry>,
    pub dangerous_count: usize,
    pub critical_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionEntry {
    pub name: String,
    pub risk: PermissionRisk,
    pub description: String,
}

impl PermissionAudit {
    /// Classify a list of Android permission strings.
    pub fn audit(permissions: &[String]) -> Self {
        let mut entries = Vec::new();
        let mut dangerous_count = 0;
        let mut critical_count = 0;

        for perm in permissions {
            let (risk, desc) = classify_permission(perm);
            if risk == PermissionRisk::Dangerous {
                dangerous_count += 1;
            }
            if risk == PermissionRisk::Critical {
                critical_count += 1;
            }
            entries.push(PermissionEntry {
                name: perm.clone(),
                risk,
                description: desc,
            });
        }

        entries.sort_by(|a, b| b.risk.cmp(&a.risk));

        Self {
            permissions: entries,
            dangerous_count,
            critical_count,
        }
    }
}

fn classify_permission(perm: &str) -> (PermissionRisk, String) {
    match perm {
        // Critical
        "android.permission.READ_SMS" | "android.permission.RECEIVE_SMS" | "android.permission.SEND_SMS" =>
            (PermissionRisk::Critical, "SMS access — can read, send, or intercept text messages".into()),
        "android.permission.READ_CALL_LOG" | "android.permission.WRITE_CALL_LOG" =>
            (PermissionRisk::Critical, "Call log access — can read or modify call history".into()),
        "android.permission.READ_CONTACTS" | "android.permission.WRITE_CONTACTS" =>
            (PermissionRisk::Critical, "Contacts access — can read or modify contact data".into()),
        "android.permission.ACCESS_FINE_LOCATION" =>
            (PermissionRisk::Critical, "Fine location — GPS-level location tracking".into()),
        "android.permission.CAMERA" =>
            (PermissionRisk::Critical, "Camera access — can take photos and record video".into()),
        "android.permission.RECORD_AUDIO" =>
            (PermissionRisk::Critical, "Microphone access — can record audio".into()),

        // Dangerous
        "android.permission.READ_EXTERNAL_STORAGE" | "android.permission.WRITE_EXTERNAL_STORAGE" =>
            (PermissionRisk::Dangerous, "Storage access — can read or write files on device".into()),
        "android.permission.ACCESS_COARSE_LOCATION" =>
            (PermissionRisk::Dangerous, "Coarse location — approximate location via network".into()),
        "android.permission.READ_PHONE_STATE" =>
            (PermissionRisk::Dangerous, "Phone state — can read device identifiers and call state".into()),
        "android.permission.CALL_PHONE" =>
            (PermissionRisk::Dangerous, "Phone calls — can initiate calls without user interaction".into()),

        // Normal
        "android.permission.INTERNET" =>
            (PermissionRisk::Normal, "Internet access — standard for network-connected apps".into()),
        "android.permission.ACCESS_NETWORK_STATE" =>
            (PermissionRisk::Normal, "Network state — check connectivity status".into()),
        "android.permission.VIBRATE" =>
            (PermissionRisk::Normal, "Vibration — control device vibration".into()),
        "android.permission.WAKE_LOCK" =>
            (PermissionRisk::Normal, "Wake lock — prevent device from sleeping".into()),

        _ => (PermissionRisk::Normal, format!("Unknown permission: {perm}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_classifies_permissions() {
        let perms = vec![
            "android.permission.INTERNET".into(),
            "android.permission.CAMERA".into(),
            "android.permission.READ_SMS".into(),
        ];
        let audit = PermissionAudit::audit(&perms);
        assert_eq!(audit.critical_count, 2); // CAMERA + READ_SMS
        assert_eq!(audit.dangerous_count, 0);
        assert_eq!(audit.permissions.len(), 3);
        // First should be critical (sorted by risk)
        assert_eq!(audit.permissions[0].risk, PermissionRisk::Critical);
    }
}
