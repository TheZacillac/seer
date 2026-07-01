//! Markdown renderers for the security/intelligence report types.

use std::fmt::Write as _;

use super::{MarkdownFormatter, MdSafe};
use crate::caa::CaaPolicy;
use crate::confusables::ConfusableReport;
use crate::drift::DriftReport;
use crate::posture::EmailPosture;
use crate::subdomains::SubdomainClassification;

impl MarkdownFormatter {
    pub(super) fn format_drift(&self, report: &DriftReport) -> String {
        let mut out = format!("## Drift: {}\n\n", MdSafe(&report.domain));
        if report.changes.is_empty() {
            out.push_str("_No changes since the previous snapshot._\n");
            return out;
        }
        out.push_str("| Field | Old | New |\n|---|---|---|\n");
        for c in &report.changes {
            let _ = writeln!(
                out,
                "| {} | {} | {} |",
                MdSafe(&c.field),
                MdSafe(c.old.as_deref().unwrap_or("—")),
                MdSafe(c.new.as_deref().unwrap_or("—")),
            );
        }
        out
    }

    pub(super) fn format_posture(&self, posture: &EmailPosture) -> String {
        let mut out = format!("## Email posture: {}\n\n", MdSafe(&posture.domain));
        out.push_str("| Mechanism | Verdict | Detail |\n|---|---|---|\n");
        let spf_detail = posture
            .spf
            .all_qualifier
            .as_ref()
            .map(|q| format!("{q}all"))
            .unwrap_or_default();
        let dmarc_detail = posture
            .dmarc
            .policy
            .as_deref()
            .map(|p| format!("p={p}"))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "| SPF | {:?} | {} |",
            posture.spf.verdict,
            MdSafe(&spf_detail)
        );
        let _ = writeln!(
            out,
            "| DMARC | {:?} | {} |",
            posture.dmarc.verdict,
            MdSafe(&dmarc_detail)
        );
        let _ = writeln!(out, "| MTA-STS | {:?} |  |", posture.mta_sts.verdict);
        let _ = writeln!(out, "| BIMI | {:?} |  |", posture.bimi.verdict);
        let _ = writeln!(
            out,
            "| DANE | {:?} | {} TLSA |",
            posture.dane.verdict,
            posture.dane.records.len()
        );
        if !posture.notes.is_empty() {
            out.push_str("\n### Advisories\n\n");
            for note in &posture.notes {
                let _ = writeln!(out, "- {}", MdSafe(note));
            }
        }
        out
    }

    pub(super) fn format_caa(&self, policy: &CaaPolicy) -> String {
        let mut out = String::from("## CAA Policy\n\n");
        if !policy.has_policy {
            out.push_str("_No CAA records (any CA may issue)._\n\n");
        } else {
            if let Some(eff) = &policy.effective_domain {
                let _ = writeln!(out, "**Found at:** {}\n", MdSafe(eff));
            }
            out.push_str("| Flags | Tag | Value |\n|---|---|---|\n");
            for r in &policy.records {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} |",
                    r.flags,
                    MdSafe(&r.tag),
                    MdSafe(&r.value)
                );
            }
            if !policy.iodef.is_empty() {
                let _ = writeln!(
                    out,
                    "\n**iodef (incident reporting):** {}",
                    MdSafe(&policy.iodef.join(", "))
                );
            }
            if let Some(note) = &policy.wildcard_note {
                let _ = writeln!(out, "\n**Wildcard:** {}", MdSafe(note));
            }
        }
        let _ = writeln!(out, "\n> {}", MdSafe(&policy.note));
        out
    }

    pub(super) fn format_confusables(&self, report: &ConfusableReport) -> String {
        let mut out = format!("## Look-alikes: {}\n\n", MdSafe(&report.domain));
        let _ = writeln!(
            out,
            "{} candidates generated, {} registered.\n",
            report.candidates_generated,
            report.registered.len()
        );
        if report.registered.is_empty() {
            out.push_str("_No registered look-alikes found._\n");
            return out;
        }
        out.push_str("| Domain | Technique | Registered | Registrar |\n|---|---|---|---|\n");
        for r in &report.registered {
            let created = r
                .creation_date
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "—".to_string());
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} |",
                MdSafe(&r.domain),
                MdSafe(&r.technique),
                created,
                MdSafe(r.registrar.as_deref().unwrap_or("—")),
            );
        }
        out
    }

    pub(super) fn format_subdomain_classification(
        &self,
        result: &SubdomainClassification,
    ) -> String {
        let mut out = format!("## Subdomains: {}\n\n", MdSafe(&result.domain));
        if result.wildcard_detected {
            out.push_str(
                "> ⚠️ Wildcard DNS detected — some \"live\" verdicts may be zone wildcards.\n\n",
            );
        }
        out.push_str("| Name | Status | CNAME | Takeover risk |\n|---|---|---|---|\n");
        for s in &result.subdomains {
            let _ = writeln!(
                out,
                "| {} | {:?} | {} | {} |",
                MdSafe(&s.name),
                s.status,
                MdSafe(s.cname.as_deref().unwrap_or("—")),
                MdSafe(s.takeover_risk.as_deref().unwrap_or("—")),
            );
        }
        out
    }
}
