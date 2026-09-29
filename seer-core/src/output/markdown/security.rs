//! Markdown renderers for the security/intelligence report types: drift,
//! subdomain baseline diffs, email posture, HTTP headers, takeover, CAA,
//! confusables, and classified subdomains.

use super::{caa_body, Bullets, MarkdownFormatter, MdCode, MdSafe};
use crate::caa::CaaPolicy;
use crate::confusables::ConfusableReport;
use crate::drift::DriftReport;
use crate::headers::HeaderReport;
use crate::output::{subdomain_status_label, takeover_label};
use crate::posture::{EmailPosture, PostureVerdict};
use crate::subdomains::{SubdomainBaselineDiff, SubdomainClassification, SubdomainStatus};
use crate::takeover::{TakeoverReport, TakeoverVerdict};

/// `## title` and the blank line after it.
fn heading(title: String) -> Vec<String> {
    vec![title, String::new()]
}

/// Appends a table header row and its delimiter row.
fn table_header(out: &mut Vec<String>, columns: &[&str]) {
    out.push(format!("| {} |", columns.join(" | ")));
    out.push(format!("|{}", " --- |".repeat(columns.len())));
}

/// Appends a `### title` section of one text bullet per remote item;
/// nothing when there are none.
fn bullet_section(out: &mut Vec<String>, title: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    out.extend([String::new(), format!("### {title}"), String::new()]);
    out.extend(items.iter().map(|item| format!("- {}", MdSafe(item))));
}

/// Remote text for a table cell, or `—` when absent.
fn or_dash(value: Option<&str>) -> String {
    value.map_or_else(|| "—".to_string(), |v| MdSafe(v).to_string())
}

impl MarkdownFormatter {
    pub(super) fn format_drift(&self, report: &DriftReport) -> String {
        let mut out = heading(format!("## Drift: {}", MdSafe(&report.domain)));
        if let Some(reason) = &report.inconclusive {
            out.push(format!("_Not compared: {}._", MdSafe(reason)));
        } else if report.changes.is_empty() {
            out.push("_No changes since the previous snapshot._".to_string());
        } else {
            table_header(&mut out, &["Field", "Old", "New"]);
            for c in &report.changes {
                out.push(format!(
                    "| {} | {} | {} |",
                    MdSafe(&c.field),
                    or_dash(c.old.as_deref()),
                    or_dash(c.new.as_deref()),
                ));
            }
        }
        out.join("\n")
    }

    pub(super) fn format_subdomain_baseline_diff(&self, report: &SubdomainBaselineDiff) -> String {
        let mut out = heading(format!("## Subdomain diff: {}", MdSafe(&report.domain)));

        if report.baseline_missing {
            // Neutral phrasing: the CLI/REPL note carries the actionable
            // "--record" hint (it knows whether a baseline was just recorded).
            out.push("_No stored baseline to compare against (first run)._".to_string());
            return out.join("\n");
        }

        if let Some(at) = report.baseline_recorded_at {
            Bullets(&mut out).raw("Baseline recorded", at.format("%Y-%m-%d %H:%M UTC"));
            out.push(String::new());
        }
        if report.baseline_truncated {
            out.extend([
                "_Baseline came from truncated enumerations — added names may be \
                 long-standing (not counted as new until a complete run is recorded)._"
                    .to_string(),
                String::new(),
            ]);
        }
        out.push(format!(
            "{} added, {} removed, {} unchanged.",
            report.added.len(),
            report.removed.len(),
            report.unchanged_count
        ));

        if report.added.is_empty() && report.removed.is_empty() {
            out.extend([
                String::new(),
                "_No changes since the baseline._".to_string(),
            ]);
            return out.join("\n");
        }

        let names = |out: &mut Vec<String>, title: &str, names: &[String]| {
            if !names.is_empty() {
                out.extend([String::new(), format!("### {title}"), String::new()]);
                out.extend(names.iter().map(|name| format!("- `{}`", MdCode(name))));
            }
        };
        names(&mut out, "Added", &report.added);
        // Removals are informational: CT logs are append-mostly, so a
        // vanished name usually means source flakiness (see baseline.rs).
        names(
            &mut out,
            "Removed (informational — often CT source flakiness)",
            &report.removed,
        );
        out.join("\n")
    }

    pub(super) fn format_posture(&self, posture: &EmailPosture) -> String {
        let mut out = heading(format!("## Email posture: {}", MdSafe(&posture.domain)));
        table_header(&mut out, &["Mechanism", "Verdict", "Detail"]);
        let spf = posture
            .spf
            .all_qualifier
            .as_ref()
            .map(|q| format!("{q}all"));
        let dmarc = posture.dmarc.policy.as_deref().map(|p| format!("p={p}"));
        let dane = format!("{} TLSA", posture.dane.records.len());
        for (name, verdict, detail) in [
            ("SPF", posture.spf.verdict, spf.as_deref()),
            ("DMARC", posture.dmarc.verdict, dmarc.as_deref()),
            ("MTA-STS", posture.mta_sts.verdict, None),
            ("BIMI", posture.bimi.verdict, None),
            ("DANE", posture.dane.verdict, Some(dane.as_str())),
        ] {
            // A failed lookup says so instead of its (empty) detail.
            let detail = match verdict {
                PostureVerdict::Unknown => "lookup failed".to_string(),
                _ => MdSafe(detail.unwrap_or("")).to_string(),
            };
            out.push(format!("| {name} | {} | {detail} |", verdict.as_str()));
        }
        bullet_section(&mut out, "Advisories", &posture.notes);
        out.join("\n")
    }

    pub(super) fn format_headers(&self, report: &HeaderReport) -> String {
        let mut out = heading(format!(
            "## HTTP security headers: {}",
            MdSafe(&report.domain)
        ));
        let mut b = Bullets(&mut out);
        b.raw(
            "Grade",
            format_args!("**{}** ({}/100)", MdSafe(&report.grade), report.score),
        );
        b.raw(
            "URL",
            format_args!("`{}` (HTTP {})", MdCode(&report.url), report.status),
        );
        if report.redirects > 0 {
            b.raw("Redirects followed", report.redirects);
        }

        out.push(String::new());
        table_header(&mut out, &["Header", "Verdict", "Value"]);
        for f in &report.headers {
            out.push(format!(
                "| {} | {} | {} |",
                MdSafe(&f.header),
                f.verdict.as_str(),
                MdSafe(f.value.as_deref().unwrap_or(""))
            ));
        }

        if !report.cookies.is_empty() {
            out.extend([String::new(), "### Cookies".to_string(), String::new()]);
            table_header(
                &mut out,
                &["Cookie", "Verdict", "Secure", "HttpOnly", "SameSite"],
            );
            for c in &report.cookies {
                out.push(format!(
                    "| {} | {} | {} | {} | {} |",
                    MdSafe(&c.name),
                    c.verdict.as_str(),
                    c.secure,
                    c.http_only,
                    or_dash(c.same_site.as_deref())
                ));
            }
        }

        if !report.disclosures.is_empty() {
            out.extend([
                String::new(),
                "### Disclosed software".to_string(),
                String::new(),
            ]);
            for d in &report.disclosures {
                out.push(format!(
                    "- `{}`: {}{}",
                    MdCode(&d.header),
                    MdSafe(&d.value),
                    if d.versioned { " (versioned)" } else { "" }
                ));
            }
        }

        bullet_section(&mut out, "Advisories", &report.notes);
        out.join("\n")
    }

    pub(super) fn format_takeover(&self, report: &TakeoverReport) -> String {
        let mut out = heading(format!("## Takeover scan: {}", MdSafe(&report.domain)));
        out.push(format!(
            "{} host(s) checked — **{} vulnerable**, {} potential",
            report.hosts_checked, report.vulnerable, report.potential
        ));
        if report.inconclusive > 0 {
            out.extend([
                String::new(),
                format!("_{} host(s) could not be checked._", report.inconclusive),
            ]);
        }
        if report.hosts_skipped > 0 {
            out.extend([
                String::new(),
                format!(
                    "_{} more host(s) exceeded the scan cap and were not examined._",
                    report.hosts_skipped
                ),
            ]);
        }

        out.push(String::new());
        if report.findings.is_empty() {
            out.push("_No takeover signals found._".to_string());
        } else {
            // `Note` carries the probe note — why a host is only "potential"
            // or "inconclusive" (does not resolve, probe failed, …).
            table_header(
                &mut out,
                &["Host", "Verdict", "Provider", "CNAME", "Evidence", "Note"],
            );
            for f in &report.findings {
                let label = takeover_label(f.verdict);
                let verdict = match f.verdict {
                    TakeoverVerdict::Vulnerable => format!("**{label}**"),
                    _ => label.to_string(),
                };
                out.push(format!(
                    "| {} | {verdict} | {} | {} | {} | {} |",
                    MdSafe(&f.host),
                    or_dash(f.provider.as_deref()),
                    or_dash(f.cname.as_deref()),
                    or_dash(f.evidence.as_deref()),
                    or_dash(f.probe_note.as_deref())
                ));
            }
        }

        bullet_section(&mut out, "Advisories", &report.notes);
        out.join("\n")
    }

    pub(super) fn format_caa(&self, policy: &CaaPolicy) -> String {
        let mut out = heading("## CAA Policy".to_string());
        caa_body(&mut out, policy);
        if policy.has_policy && (!policy.iodef.is_empty() || policy.wildcard_note.is_some()) {
            out.push(String::new());
            let mut b = Bullets(&mut out);
            if !policy.iodef.is_empty() {
                b.text("iodef (incident reporting)", &policy.iodef.join(", "));
            }
            b.opt("Wildcard", &policy.wildcard_note);
        }
        out.extend([String::new(), format!("> **Note:** {}", policy.note)]);
        out.join("\n")
    }

    pub(super) fn format_confusables(&self, report: &ConfusableReport) -> String {
        let mut out = heading(format!("## Look-alikes: {}", MdSafe(&report.domain)));
        out.push(format!(
            "{} candidates generated, {} registered.",
            report.candidates_generated,
            report.registered.len()
        ));
        out.push(String::new());
        if report.registered.is_empty() {
            out.push("_No registered look-alikes found._".to_string());
            return out.join("\n");
        }
        table_header(
            &mut out,
            &["Domain", "Technique", "Registered", "Registrar"],
        );
        for r in &report.registered {
            let created = r
                .creation_date
                .map_or_else(|| "—".to_string(), |d| d.format("%Y-%m-%d").to_string());
            out.push(format!(
                "| {} | {} | {created} | {} |",
                MdSafe(&r.domain),
                MdSafe(&r.technique),
                or_dash(r.registrar.as_deref()),
            ));
        }
        out.join("\n")
    }

    pub(super) fn format_subdomain_classification(
        &self,
        result: &SubdomainClassification,
    ) -> String {
        let mut out = heading(format!("## Subdomains: {}", MdSafe(&result.domain)));
        if result.wildcard_detected {
            out.push(
                "> ⚠️ Wildcard DNS detected — some \"live\" verdicts may be zone wildcards."
                    .to_string(),
            );
            out.push(String::new());
        }
        let live = result
            .subdomains
            .iter()
            .filter(|s| s.status == SubdomainStatus::Live)
            .count();
        let at_risk = result
            .subdomains
            .iter()
            .filter(|s| s.takeover_risk.is_some())
            .count();
        out.push(format!(
            "{} names — {live} live, {at_risk} takeover-risk.",
            result.subdomains.len()
        ));
        out.push(String::new());
        if result.names_skipped > 0 {
            out.push(format!(
                "> ⚠️ {} more names exceeded the classification cap and were not resolved.",
                result.names_skipped
            ));
            out.push(String::new());
        }
        table_header(&mut out, &["Name", "Status", "CNAME", "Takeover risk"]);
        for s in &result.subdomains {
            out.push(format!(
                "| {} | {} | {} | {} |",
                MdSafe(&s.name),
                subdomain_status_label(s.status),
                or_dash(s.cname.as_deref()),
                or_dash(s.takeover_risk.as_deref()),
            ));
        }
        out.join("\n")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::takeover::TakeoverFinding;

    #[test]
    fn takeover_table_includes_probe_note() {
        // The probe note is the reason a finding is only "potential"; the
        // human formatter prints it, markdown dropped it.
        let report = TakeoverReport {
            domain: "example.com".to_string(),
            hosts_checked: 1,
            hosts_skipped: 0,
            vulnerable: 0,
            potential: 1,
            inconclusive: 0,
            findings: vec![TakeoverFinding {
                host: "docs.example.com".to_string(),
                verdict: TakeoverVerdict::Potential,
                provider: Some("GitHub Pages".to_string()),
                cname: Some("example.github.io".to_string()),
                addresses: Vec::new(),
                evidence: None,
                http_status: None,
                probe_note: Some("HTTP probe failed: connection|refused".to_string()),
            }],
            notes: Vec::new(),
        };
        let out = MarkdownFormatter::new().format_takeover(&report);
        assert!(
            out.contains("| Host | Verdict | Provider | CNAME | Evidence | Note |"),
            "got:\n{out}"
        );
        assert!(
            out.contains(
                "| docs.example.com | potential | GitHub Pages | example.github.io | — \
                 | HTTP probe failed: connection\\|refused |"
            ),
            "probe note must render (MdSafe-escaped):\n{out}"
        );
    }
}
