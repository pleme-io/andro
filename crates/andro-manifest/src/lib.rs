//! AndroidManifest.xml lint rules — detect security misconfigurations
//! and best-practice violations in parsed binary XML manifests.
//!
//! Uses the `AxmlParser` trait from andro-core for manifest parsing,
//! then applies a set of lint rules that inspect the resulting XML tree.

use andro_core::traits::AxmlParser;
use andro_core::types::{XmlDocument, XmlElement};
use serde::{Deserialize, Serialize};

/// Severity level for a lint finding.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// A single lint finding from manifest analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintFinding {
    pub rule: String,
    pub severity: Severity,
    pub message: String,
    pub element: Option<String>,
}

/// Lint the parsed manifest and return all findings.
///
/// # Rules
///
/// 1. **exported-no-permission** (Error): Components (activity, service, receiver,
///    provider) with `exported=true` but no `permission` attribute.
/// 2. **debuggable** (Critical): `application` has `debuggable=true`.
/// 3. **allow-backup** (Warning): `application` has `allowBackup=true`.
/// 4. **cleartext-traffic** (Error): `application` has `usesCleartextTraffic=true`.
/// 5. **no-network-security-config** (Warning): `application` missing
///    `networkSecurityConfig` when targeting SDK >= 28.
/// 6. **target-sdk-too-low** (Error): `targetSdkVersion` below 28.
pub struct ManifestLinter;

impl ManifestLinter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Run all lint rules against binary XML data.
    ///
    /// Parses the data using the provided `AxmlParser`, then inspects the
    /// resulting document tree.
    pub fn lint(
        &self,
        data: &[u8],
        parser: &dyn AxmlParser,
    ) -> andro_core::Result<Vec<LintFinding>> {
        let doc = parser.parse(data)?;
        let target_sdk = parser.target_sdk(&doc);
        let mut findings = Vec::new();

        for element in &doc.elements {
            Self::lint_element(element, target_sdk, &mut findings);
        }

        Ok(findings)
    }

    /// Run all lint rules against an already-parsed `XmlDocument`.
    #[must_use]
    pub fn lint_document(
        &self,
        doc: &XmlDocument,
        target_sdk: Option<u32>,
    ) -> Vec<LintFinding> {
        let mut findings = Vec::new();
        for element in &doc.elements {
            Self::lint_element(element, target_sdk, &mut findings);
        }
        findings
    }

    fn lint_element(
        element: &XmlElement,
        target_sdk: Option<u32>,
        findings: &mut Vec<LintFinding>,
    ) {
        match element.name.as_str() {
            "application" => Self::lint_application(element, target_sdk, findings),
            "activity" | "service" | "receiver" | "provider" => {
                Self::lint_component(element, findings);
            }
            _ => {}
        }

        // Recurse into children.
        for child in &element.children {
            Self::lint_element(child, target_sdk, findings);
        }
    }

    fn lint_application(
        element: &XmlElement,
        target_sdk: Option<u32>,
        findings: &mut Vec<LintFinding>,
    ) {
        // Rule: debuggable=true
        if Self::attr_eq(element, "debuggable", "true") {
            findings.push(LintFinding {
                rule: "debuggable".to_string(),
                severity: Severity::Critical,
                message: "Application is debuggable — must be false for release builds"
                    .to_string(),
                element: Some("application".to_string()),
            });
        }

        // Rule: allowBackup=true
        if Self::attr_eq(element, "allowBackup", "true") {
            findings.push(LintFinding {
                rule: "allow-backup".to_string(),
                severity: Severity::Warning,
                message: "allowBackup=true permits data extraction via adb backup".to_string(),
                element: Some("application".to_string()),
            });
        }

        // Rule: usesCleartextTraffic=true
        if Self::attr_eq(element, "usesCleartextTraffic", "true") {
            findings.push(LintFinding {
                rule: "cleartext-traffic".to_string(),
                severity: Severity::Error,
                message: "Cleartext HTTP traffic is enabled — use HTTPS".to_string(),
                element: Some("application".to_string()),
            });
        }

        // Rule: no networkSecurityConfig when target SDK >= 28
        if let Some(sdk) = target_sdk {
            if sdk >= 28 && !Self::has_attr(element, "networkSecurityConfig") {
                findings.push(LintFinding {
                    rule: "no-network-security-config".to_string(),
                    severity: Severity::Warning,
                    message: "Missing networkSecurityConfig for SDK >= 28".to_string(),
                    element: Some("application".to_string()),
                });
            }
        }

        // Rule: target SDK too low
        if let Some(sdk) = target_sdk {
            if sdk < 28 {
                findings.push(LintFinding {
                    rule: "target-sdk-too-low".to_string(),
                    severity: Severity::Error,
                    message: format!("targetSdkVersion {sdk} is below minimum 28"),
                    element: Some("manifest".to_string()),
                });
            }
        }
    }

    fn lint_component(element: &XmlElement, findings: &mut Vec<LintFinding>) {
        // Rule: exported component without permission
        let exported = Self::attr_eq(element, "exported", "true");
        let has_intent_filter = element
            .children
            .iter()
            .any(|c| c.name == "intent-filter");

        // Components with intent-filters are implicitly exported.
        let is_exported = exported || has_intent_filter;

        if is_exported && !Self::has_attr(element, "permission") {
            let component_name = Self::attr_value(element, "name")
                .unwrap_or_else(|| element.name.clone());
            findings.push(LintFinding {
                rule: "exported-no-permission".to_string(),
                severity: Severity::Error,
                message: format!(
                    "Exported {0} '{component_name}' has no permission guard",
                    element.name
                ),
                element: Some(element.name.clone()),
            });
        }
    }

    fn attr_eq(element: &XmlElement, name: &str, value: &str) -> bool {
        element
            .attributes
            .iter()
            .any(|a| a.name == name && a.value == value)
    }

    fn has_attr(element: &XmlElement, name: &str) -> bool {
        element.attributes.iter().any(|a| a.name == name)
    }

    fn attr_value(element: &XmlElement, name: &str) -> Option<String> {
        element
            .attributes
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.value.clone())
    }
}

impl Default for ManifestLinter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use andro_core::types::XmlAttribute;

    fn make_app_element(attrs: Vec<(&str, &str)>, children: Vec<XmlElement>) -> XmlElement {
        XmlElement {
            namespace: None,
            name: "application".to_string(),
            attributes: attrs
                .into_iter()
                .map(|(n, v)| XmlAttribute {
                    namespace: None,
                    name: n.to_string(),
                    value: v.to_string(),
                    resource_id: None,
                })
                .collect(),
            children,
        }
    }

    fn make_component(
        kind: &str,
        name: &str,
        attrs: Vec<(&str, &str)>,
        children: Vec<XmlElement>,
    ) -> XmlElement {
        let mut all_attrs: Vec<XmlAttribute> = vec![XmlAttribute {
            namespace: None,
            name: "name".to_string(),
            value: name.to_string(),
            resource_id: None,
        }];
        for (n, v) in attrs {
            all_attrs.push(XmlAttribute {
                namespace: None,
                name: n.to_string(),
                value: v.to_string(),
                resource_id: None,
            });
        }
        XmlElement {
            namespace: None,
            name: kind.to_string(),
            attributes: all_attrs,
            children,
        }
    }

    fn make_doc(elements: Vec<XmlElement>) -> XmlDocument {
        XmlDocument {
            string_pool: Vec::new(),
            resource_map: Vec::new(),
            elements,
        }
    }

    #[test]
    fn debuggable_finding() {
        let doc = make_doc(vec![make_app_element(vec![("debuggable", "true")], vec![])]);
        let linter = ManifestLinter::new();
        let findings = linter.lint_document(&doc, Some(34));
        assert!(findings.iter().any(|f| f.rule == "debuggable"));
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn allow_backup_finding() {
        let doc = make_doc(vec![make_app_element(
            vec![("allowBackup", "true")],
            vec![],
        )]);
        let linter = ManifestLinter::new();
        let findings = linter.lint_document(&doc, Some(34));
        assert!(findings.iter().any(|f| f.rule == "allow-backup"));
    }

    #[test]
    fn cleartext_traffic_finding() {
        let doc = make_doc(vec![make_app_element(
            vec![("usesCleartextTraffic", "true")],
            vec![],
        )]);
        let linter = ManifestLinter::new();
        let findings = linter.lint_document(&doc, Some(34));
        assert!(findings.iter().any(|f| f.rule == "cleartext-traffic"));
    }

    #[test]
    fn missing_network_security_config() {
        let doc = make_doc(vec![make_app_element(vec![], vec![])]);
        let linter = ManifestLinter::new();
        let findings = linter.lint_document(&doc, Some(34));
        assert!(findings
            .iter()
            .any(|f| f.rule == "no-network-security-config"));
    }

    #[test]
    fn target_sdk_too_low() {
        let doc = make_doc(vec![make_app_element(vec![], vec![])]);
        let linter = ManifestLinter::new();
        let findings = linter.lint_document(&doc, Some(24));
        assert!(findings.iter().any(|f| f.rule == "target-sdk-too-low"));
    }

    #[test]
    fn exported_no_permission() {
        let activity = make_component(
            "activity",
            ".MainActivity",
            vec![("exported", "true")],
            vec![],
        );
        let doc = make_doc(vec![make_app_element(vec![], vec![activity])]);
        let linter = ManifestLinter::new();
        let findings = linter.lint_document(&doc, Some(34));
        assert!(findings
            .iter()
            .any(|f| f.rule == "exported-no-permission"));
    }

    #[test]
    fn exported_with_permission_is_clean() {
        let activity = make_component(
            "activity",
            ".MainActivity",
            vec![("exported", "true"), ("permission", "com.example.MY_PERM")],
            vec![],
        );
        let doc = make_doc(vec![make_app_element(vec![], vec![activity])]);
        let linter = ManifestLinter::new();
        let findings = linter.lint_document(&doc, Some(34));
        assert!(!findings
            .iter()
            .any(|f| f.rule == "exported-no-permission"));
    }

    #[test]
    fn implicit_export_via_intent_filter() {
        let intent_filter = XmlElement {
            namespace: None,
            name: "intent-filter".to_string(),
            attributes: Vec::new(),
            children: Vec::new(),
        };
        let service = make_component("service", ".MyService", vec![], vec![intent_filter]);
        let doc = make_doc(vec![make_app_element(vec![], vec![service])]);
        let linter = ManifestLinter::new();
        let findings = linter.lint_document(&doc, Some(34));
        assert!(findings
            .iter()
            .any(|f| f.rule == "exported-no-permission"));
    }

    #[test]
    fn clean_manifest() {
        let activity = make_component(
            "activity",
            ".MainActivity",
            vec![("exported", "false")],
            vec![],
        );
        let doc = make_doc(vec![make_app_element(
            vec![("networkSecurityConfig", "@xml/network")],
            vec![activity],
        )]);
        let linter = ManifestLinter::new();
        let findings = linter.lint_document(&doc, Some(34));
        assert!(findings.is_empty(), "expected no findings: {findings:?}");
    }
}
