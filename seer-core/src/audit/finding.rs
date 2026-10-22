//! The audit's unit of output: one problem, where it is, how bad, how to fix.
//!
//! A passing check produces no finding — only a [`CheckRun`] saying it ran —
//! so the scorer can tell "passed" from "never ran". `id` is a stable
//! contract (`<category>.<check>.<condition>`): drift and suppression key on
//! it, so renaming one is a breaking change.

use serde::Serialize;

/// The layer a finding belongs to. Declaration order is display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Email,
    Web,
    Tls,
    Dns,
    Takeover,
    Registration,
}

impl Category {
    /// Every category, in display order.
    pub const ALL: [Category; 6] = [
        Category::Email,
        Category::Web,
        Category::Tls,
        Category::Dns,
        Category::Takeover,
        Category::Registration,
    ];

    /// Share of the overall score (the weights sum to 100).
    pub fn weight(self) -> u32 {
        match self {
            Category::Email | Category::Web | Category::Tls => 20,
            Category::Dns | Category::Takeover => 15,
            Category::Registration => 10,
        }
    }

    /// The serde name.
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Email => "email",
            Category::Web => "web",
            Category::Tls => "tls",
            Category::Dns => "dns",
            Category::Takeover => "takeover",
            Category::Registration => "registration",
        }
    }

    /// Display label.
    pub fn label(self) -> &'static str {
        match self {
            Category::Email => "Email",
            Category::Web => "Web",
            Category::Tls => "TLS",
            Category::Dns => "DNS",
            Category::Takeover => "Takeover",
            Category::Registration => "Registration",
        }
    }
}

/// How bad a finding is. Declared least to most severe, so `Ord` ranks
/// `Critical` highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Points this finding takes off its category's 100.
    pub fn deduction(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 3,
            Severity::Medium => 10,
            Severity::High => 25,
            Severity::Critical => 60,
        }
    }

    /// The serde name.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// One problem found by the audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Stable slug, `<category>.<check>.<condition>`.
    pub id: &'static str,
    pub category: Category,
    pub severity: Severity,
    /// The host or domain it applies to.
    pub host: String,
    /// Seer's own wording.
    pub title: String,
    /// What was observed — may be remote text; sanitize before display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// How to fix it (Seer's own wording).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl Finding {
    pub(crate) fn new(
        id: &'static str,
        category: Category,
        severity: Severity,
        host: &str,
        title: impl Into<String>,
    ) -> Self {
        Self {
            id,
            category,
            severity,
            host: host.to_string(),
            title: title.into(),
            evidence: None,
            remediation: None,
        }
    }

    pub(crate) fn evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }

    pub(crate) fn fix(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }
}

/// Whether a check produced a result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum CheckStatus {
    /// The check ran; its findings (if any) are in the report.
    Ran,
    /// The check could not finish (lookup failed, deadline) — unknown, not a fail.
    Incomplete { reason: String },
    /// The check does not apply (e.g. no MX, so no MTA-STS).
    NotApplicable { reason: String },
}

/// One check's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckRun {
    pub check: &'static str,
    pub category: Category,
    #[serde(flatten)]
    pub status: CheckStatus,
}
