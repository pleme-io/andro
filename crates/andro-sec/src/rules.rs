use crate::scanner::{ScanFinding, Severity};
use regex::Regex;

/// A security scanning rule.
pub struct SecurityRule {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub pattern: Regex,
}

impl SecurityRule {
    /// Default built-in security rules.
    pub fn default_rules() -> Vec<Self> {
        vec![
            Self {
                id: "HARDCODED_SECRET".into(),
                severity: Severity::High,
                title: "Hardcoded secret or API key".into(),
                description: "Potential hardcoded API key, secret, or token found in application files.".into(),
                pattern: Regex::new(r#"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[=:]\s*["'][A-Za-z0-9+/=_\-]{16,}"#).unwrap(),
            },
            Self {
                id: "AWS_KEY".into(),
                severity: Severity::Critical,
                title: "AWS access key".into(),
                description: "AWS access key ID found in application files.".into(),
                pattern: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            },
            Self {
                id: "PRIVATE_KEY".into(),
                severity: Severity::Critical,
                title: "Private key material".into(),
                description: "Private key (RSA, DSA, EC) found in application files.".into(),
                pattern: Regex::new(r"-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----").unwrap(),
            },
            Self {
                id: "HTTP_URL".into(),
                severity: Severity::Medium,
                title: "Insecure HTTP URL".into(),
                description: "HTTP (not HTTPS) URL found. Data transmitted in cleartext.".into(),
                pattern: Regex::new(r#"http://[a-zA-Z0-9]"#).unwrap(),
            },
            Self {
                id: "DEBUG_FLAG".into(),
                severity: Severity::Medium,
                title: "Debug flag enabled".into(),
                description: "Debug mode appears to be enabled in configuration.".into(),
                pattern: Regex::new(r#"(?i)(debuggable|debug)\s*[=:]\s*["']?true"#).unwrap(),
            },
            Self {
                id: "LOG_SENSITIVE".into(),
                severity: Severity::Low,
                title: "Logging potentially sensitive data".into(),
                description: "Log statement may contain sensitive information (password, token, secret).".into(),
                pattern: Regex::new(r#"(?i)Log\.[dievw]\(.*?(password|token|secret|credential)"#).unwrap(),
            },
            Self {
                id: "FIREBASE_URL".into(),
                severity: Severity::Low,
                title: "Firebase URL exposed".into(),
                description: "Firebase database URL found. Verify security rules are configured.".into(),
                pattern: Regex::new(r"https://[a-z0-9-]+\.firebaseio\.com").unwrap(),
            },
            Self {
                id: "GOOGLE_API_KEY".into(),
                severity: Severity::Medium,
                title: "Google API key".into(),
                description: "Google API key found. Ensure key restrictions are configured.".into(),
                pattern: Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap(),
            },
        ]
    }

    /// Check a file's content against this rule.
    pub fn check(&self, filename: &str, content: &str) -> Option<ScanFinding> {
        self.pattern.find(content).map(|m| ScanFinding {
            rule_id: self.id.clone(),
            severity: self.severity,
            title: self.title.clone(),
            description: self.description.clone(),
            file: Some(filename.to_string()),
            line: None,
            evidence: Some(m.as_str().chars().take(100).collect()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_aws_key() {
        let rules = SecurityRule::default_rules();
        let aws_rule = rules.iter().find(|r| r.id == "AWS_KEY").unwrap();
        let finding = aws_rule.check("config.xml", "aws_key=AKIAIOSFODNN7EXAMPLE");
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn detect_private_key() {
        let rules = SecurityRule::default_rules();
        let rule = rules.iter().find(|r| r.id == "PRIVATE_KEY").unwrap();
        let finding = rule.check("cert.pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
        assert!(finding.is_some());
    }

    #[test]
    fn no_false_positive_https() {
        let rules = SecurityRule::default_rules();
        let rule = rules.iter().find(|r| r.id == "HTTP_URL").unwrap();
        let finding = rule.check("config.xml", "url=https://api.example.com");
        assert!(finding.is_none());
    }

    #[test]
    fn detect_http_url() {
        let rules = SecurityRule::default_rules();
        let rule = rules.iter().find(|r| r.id == "HTTP_URL").unwrap();
        let finding = rule.check("config.xml", "url=http://api.example.com");
        assert!(finding.is_some());
    }
}
