//! Human (colored) renderers for the security/intelligence report types:
//! drift, email posture, standalone CAA, confusables, and classified
//! subdomains.

use super::sanitize_display;
use super::HumanFormatter;
use crate::caa::CaaPolicy;
use crate::confusables::ConfusableReport;
use crate::drift::DriftReport;
use crate::posture::{EmailPosture, PostureVerdict};
use crate::subdomains::{SubdomainClassification, SubdomainStatus};

impl HumanFormatter {
    /// Colors a posture verdict token.
    fn posture_verdict(&self, verdict: PostureVerdict) -> String {
        match verdict {
            PostureVerdict::Strict => self.success("strict"),
            PostureVerdict::Moderate => self.warning("moderate"),
            PostureVerdict::Weak => self.warning("weak"),
            PostureVerdict::Present => self.value("present"),
            PostureVerdict::Absent => self.error("absent"),
        }
    }

    pub(super) fn format_drift(&self, report: &DriftReport) -> String {
        let mut out = vec![self.header(&format!("Drift: {}", sanitize_display(&report.domain)))];
        if report.changes.is_empty() {
            out.push(self.success("No changes since the previous snapshot"));
        } else {
            for c in &report.changes {
                let old = c.old.as_deref().unwrap_or("(none)");
                let new = c.new.as_deref().unwrap_or("(none)");
                out.push(format!(
                    "{}: {} {} {}",
                    self.label(&c.field),
                    self.dim(&sanitize_display(old)),
                    self.warning("→"),
                    self.value(&sanitize_display(new)),
                ));
            }
        }
        out.join("\n")
    }

    pub(super) fn format_posture(&self, posture: &EmailPosture) -> String {
        let mut out = vec![self.header(&format!(
            "Email posture: {}",
            sanitize_display(&posture.domain)
        ))];

        let line = |name: &str, verdict: PostureVerdict, detail: Option<&str>| {
            let base = format!("{}: {}", self.label(name), self.posture_verdict(verdict));
            match detail {
                Some(d) if !d.is_empty() => format!("{base} {}", self.dim(&sanitize_display(d))),
                _ => base,
            }
        };

        out.push(line(
            "SPF",
            posture.spf.verdict,
            posture
                .spf
                .all_qualifier
                .as_ref()
                .map(|q| format!("{q}all"))
                .as_deref(),
        ));
        out.push(line(
            "DMARC",
            posture.dmarc.verdict,
            posture
                .dmarc
                .policy
                .as_deref()
                .map(|p| format!("p={p}"))
                .as_deref(),
        ));
        out.push(line("MTA-STS", posture.mta_sts.verdict, None));
        out.push(line("BIMI", posture.bimi.verdict, None));
        out.push(line(
            "DANE",
            posture.dane.verdict,
            Some(&format!("{} TLSA record(s)", posture.dane.records.len())),
        ));

        if !posture.notes.is_empty() {
            out.push(String::new());
            out.push(self.label("Advisories:"));
            for note in &posture.notes {
                out.push(format!(
                    "  {} {}",
                    self.warning("•"),
                    sanitize_display(note)
                ));
            }
        }
        out.join("\n")
    }

    pub(super) fn format_caa(&self, policy: &CaaPolicy) -> String {
        let mut out = vec![self.header("CAA Policy")];
        out.extend(self.render_caa_block(policy, ""));
        if !policy.iodef.is_empty() {
            out.push(format!(
                "  {}: {}",
                self.label("iodef (incident reporting)"),
                self.value(&sanitize_display(&policy.iodef.join(", ")))
            ));
        }
        if let Some(note) = &policy.wildcard_note {
            out.push(format!(
                "  {}: {}",
                self.label("Wildcard"),
                self.warning(&sanitize_display(note))
            ));
        }
        self.push_caa_note_footer(&mut out, policy);
        out.join("\n")
    }

    pub(super) fn format_confusables(&self, report: &ConfusableReport) -> String {
        let mut out = vec![self.header(&format!(
            "Look-alikes: {}",
            sanitize_display(&report.domain)
        ))];
        out.push(format!(
            "{} candidates generated, {} registered",
            self.value(&report.candidates_generated.to_string()),
            self.value(&report.registered.len().to_string()),
        ));
        if report.registered.is_empty() {
            out.push(self.success("No registered look-alikes found"));
        } else {
            out.push(String::new());
            for r in &report.registered {
                let created = r
                    .creation_date
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let registrar = r.registrar.as_deref().unwrap_or("-");
                out.push(format!(
                    "{}  [{}]  registered {}  via {}",
                    self.warning(&sanitize_display(&r.domain)),
                    self.dim(&r.technique),
                    self.value(&created),
                    self.dim(&sanitize_display(registrar)),
                ));
            }
        }
        out.join("\n")
    }

    pub(super) fn format_subdomain_classification(
        &self,
        result: &SubdomainClassification,
    ) -> String {
        let mut out =
            vec![self.header(&format!("Subdomains: {}", sanitize_display(&result.domain)))];
        if result.wildcard_detected {
            out.push(
                self.warning(
                    "Wildcard DNS detected — some \"live\" verdicts may be zone wildcards",
                ),
            );
        }
        let live = result
            .subdomains
            .iter()
            .filter(|s| s.status == SubdomainStatus::Live)
            .count();
        out.push(format!(
            "{} names — {} live, {} takeover-risk",
            self.value(&result.subdomains.len().to_string()),
            self.value(&live.to_string()),
            self.value(
                &result
                    .subdomains
                    .iter()
                    .filter(|s| s.takeover_risk.is_some())
                    .count()
                    .to_string()
            ),
        ));
        if result.names_skipped > 0 {
            out.push(self.warning(&format!(
                "{} more names exceeded the classification cap and were not resolved",
                result.names_skipped
            )));
        }
        out.push(String::new());
        for s in &result.subdomains {
            let status = match s.status {
                SubdomainStatus::Live => self.success("live"),
                SubdomainStatus::Dead => self.dim("dead"),
                SubdomainStatus::Wildcard => self.warning("wildcard"),
            };
            let mut line = format!("{}  [{}]", self.value(&sanitize_display(&s.name)), status);
            if let Some(risk) = &s.takeover_risk {
                line.push_str(&format!(
                    "  {}",
                    self.error(&format!("takeover risk: {}", sanitize_display(risk)))
                ));
            }
            out.push(line);
        }
        out.join("\n")
    }
}
