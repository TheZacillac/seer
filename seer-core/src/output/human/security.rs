//! Human (colored) renderers for the security/intelligence report types:
//! drift, email posture, standalone CAA, confusables, and classified
//! subdomains.

use super::{sanitize_line, HumanFormatter};
use crate::caa::CaaPolicy;
use crate::confusables::ConfusableReport;
use crate::drift::DriftReport;
use crate::headers::HeaderReport;
use crate::output::{subdomain_status_label, takeover_label};
use crate::posture::{EmailPosture, PostureVerdict};
use crate::subdomains::{SubdomainBaselineDiff, SubdomainClassification, SubdomainStatus};
use crate::takeover::{TakeoverReport, TakeoverVerdict};

impl HumanFormatter {
    /// Colors a posture/header verdict token by strength, so both security
    /// reports read identically.
    fn verdict(&self, verdict: PostureVerdict) -> String {
        let label = verdict.as_str();
        match verdict {
            PostureVerdict::Strict => self.success(label),
            PostureVerdict::Moderate | PostureVerdict::Weak => self.warning(label),
            PostureVerdict::Present => self.value(label),
            PostureVerdict::Absent => self.error(label),
        }
    }

    pub(super) fn format_drift(&self, report: &DriftReport) -> String {
        let mut out = vec![self.header(&format!("Drift: {}", sanitize_line(&report.domain)))];
        if let Some(reason) = &report.inconclusive {
            out.push(self.warning(&format!("Not compared: {}", sanitize_line(reason))));
        } else if report.changes.is_empty() {
            out.push(self.success("No changes since the previous snapshot"));
        } else {
            for c in &report.changes {
                let old = c.old.as_deref().unwrap_or("(none)");
                let new = c.new.as_deref().unwrap_or("(none)");
                out.push(format!(
                    "{}: {} {} {}",
                    self.label(&sanitize_line(&c.field)),
                    self.dim(&sanitize_line(old)),
                    self.warning("→"),
                    self.value(&sanitize_line(new)),
                ));
            }
        }
        out.join("\n")
    }

    pub(super) fn format_subdomain_baseline_diff(&self, report: &SubdomainBaselineDiff) -> String {
        let mut out = vec![self.header(&format!(
            "Subdomain diff: {}",
            sanitize_line(&report.domain)
        ))];

        if report.baseline_missing {
            // Neutral phrasing: the CLI/REPL note carries the actionable
            // "--record" hint (it knows whether a baseline was just recorded).
            out.push(self.warning("No stored baseline to compare against (first run)"));
            return out.join("\n");
        }

        if let Some(at) = report.baseline_recorded_at {
            let at = self.value(&at.format("%Y-%m-%d %H:%M UTC").to_string());
            self.rows(&mut out, "").kv("Baseline recorded", at);
        }
        out.push(format!(
            "{} added, {} removed, {} unchanged",
            self.value(&report.added.len().to_string()),
            self.value(&report.removed.len().to_string()),
            self.value(&report.unchanged_count.to_string()),
        ));

        if report.added.is_empty() && report.removed.is_empty() {
            out.push(self.success("No changes since the baseline"));
            return out.join("\n");
        }

        if !report.added.is_empty() {
            out.push(String::new());
            out.push(self.label("Added:"));
            for name in &report.added {
                out.push(format!(
                    "  {} {}",
                    self.warning("+"),
                    self.value(&sanitize_line(name))
                ));
            }
        }
        if !report.removed.is_empty() {
            out.push(String::new());
            // Removals are informational: CT logs are append-mostly, so a
            // vanished name usually means source flakiness (see baseline.rs).
            out.push(self.label("Removed (informational — often CT source flakiness):"));
            for name in &report.removed {
                out.push(format!(
                    "  {} {}",
                    self.dim("-"),
                    self.dim(&sanitize_line(name))
                ));
            }
        }
        out.join("\n")
    }

    pub(super) fn format_posture(&self, posture: &EmailPosture) -> String {
        let mut out = vec![self.header(&format!(
            "Email posture: {}",
            sanitize_line(&posture.domain)
        ))];

        let line = |name: &str, verdict: PostureVerdict, detail: Option<&str>| {
            let base = format!("{}: {}", self.label(name), self.verdict(verdict));
            match detail {
                Some(d) if !d.is_empty() => format!("{base} {}", self.dim(&sanitize_line(d))),
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
                out.push(format!("  {} {}", self.warning("•"), sanitize_line(note)));
            }
        }
        out.join("\n")
    }

    pub(super) fn format_headers(&self, report: &HeaderReport) -> String {
        let mut out = vec![self.header(&format!(
            "HTTP security headers: {}",
            sanitize_line(&report.domain)
        ))];

        // Color the grade by band so the headline verdict is readable at a
        // glance: A/A+ passing, B–C partial, D and below failing.
        let grade = match report.grade.as_str() {
            "A+" | "A" => self.success(&report.grade),
            "B" | "C" => self.warning(&report.grade),
            _ => self.error(&report.grade),
        };
        let score = self.value(&report.score.to_string());
        let url = self.value(&sanitize_line(&report.url));
        let status = self.dim(&format!("[HTTP {}]", report.status));
        let mut rows = self.rows(&mut out, "");
        rows.kv("Grade", format!("{grade} ({score}/100)"));
        rows.kv("URL", format!("{url} {status}"));
        if report.redirects > 0 {
            rows.kv(
                "Redirects followed",
                self.value(&report.redirects.to_string()),
            );
        }

        out.push(String::new());
        for finding in &report.headers {
            let mut line = format!(
                "{}: {}",
                self.label(&sanitize_line(&finding.header)),
                self.verdict(finding.verdict),
            );
            if let Some(value) = &finding.value {
                line.push_str(&format!(" {}", self.dim(&sanitize_line(value))));
            }
            out.push(line);
        }

        if !report.cookies.is_empty() {
            out.push(String::new());
            out.push(self.label("Cookies:"));
            for cookie in &report.cookies {
                let flags = [
                    ("Secure", cookie.secure),
                    ("HttpOnly", cookie.http_only),
                    ("SameSite", cookie.same_site.is_some()),
                ]
                .iter()
                .map(|(name, set)| {
                    if *set {
                        self.success(name)
                    } else {
                        self.error(&format!("no {name}"))
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
                out.push(format!(
                    "  {} [{}] {}",
                    self.value(&sanitize_line(&cookie.name)),
                    self.verdict(cookie.verdict),
                    self.dim(&flags),
                ));
            }
        }

        if !report.disclosures.is_empty() {
            out.push(String::new());
            out.push(self.label("Disclosed software:"));
            for d in &report.disclosures {
                let value = sanitize_line(&d.value);
                out.push(format!(
                    "  {}: {}",
                    self.dim(&sanitize_line(&d.header)),
                    if d.versioned {
                        self.warning(&value)
                    } else {
                        self.value(&value)
                    },
                ));
            }
        }

        if !report.notes.is_empty() {
            out.push(String::new());
            out.push(self.label("Advisories:"));
            for note in &report.notes {
                out.push(format!("  {} {}", self.warning("•"), sanitize_line(note)));
            }
        }
        out.join("\n")
    }

    pub(super) fn format_takeover(&self, report: &TakeoverReport) -> String {
        let mut out =
            vec![self.header(&format!("Takeover scan: {}", sanitize_line(&report.domain)))];

        out.push(format!(
            "{} host(s) checked — {} vulnerable, {} potential",
            self.value(&report.hosts_checked.to_string()),
            if report.vulnerable > 0 {
                self.error(&report.vulnerable.to_string())
            } else {
                self.success("0")
            },
            if report.potential > 0 {
                self.warning(&report.potential.to_string())
            } else {
                self.success("0")
            },
        ));
        if report.hosts_skipped > 0 {
            out.push(self.warning(&format!(
                "{} more host(s) exceeded the scan cap and were not examined",
                report.hosts_skipped
            )));
        }

        if !report.findings.is_empty() {
            out.push(String::new());
            for f in &report.findings {
                let label = takeover_label(f.verdict);
                let verdict = match f.verdict {
                    TakeoverVerdict::Vulnerable => self.error(label),
                    TakeoverVerdict::Potential => self.warning(label),
                    TakeoverVerdict::Safe => self.success(label),
                };
                let mut line = format!("{}  [{}]", self.value(&sanitize_line(&f.host)), verdict);
                if let Some(provider) = &f.provider {
                    line.push_str(&format!("  {}", self.dim(&sanitize_line(provider))));
                }
                out.push(line);
                if let Some(cname) = &f.cname {
                    out.push(format!(
                        "    {} {}",
                        self.label("CNAME →"),
                        self.dim(&sanitize_line(cname)),
                    ));
                }
                // The matched fingerprint is the evidence for a VULNERABLE
                // claim — always show it so the finding can be verified.
                if let Some(evidence) = &f.evidence {
                    out.push(format!(
                        "    {} {}",
                        self.label("Evidence:"),
                        self.error(&sanitize_line(evidence)),
                    ));
                }
                if let Some(note) = &f.probe_note {
                    out.push(format!("    {}", self.dim(&sanitize_line(note))));
                }
            }
        }

        if !report.notes.is_empty() {
            out.push(String::new());
            for note in &report.notes {
                out.push(format!("{} {}", self.warning("•"), sanitize_line(note)));
            }
        }
        out.join("\n")
    }

    pub(super) fn format_caa(&self, policy: &CaaPolicy) -> String {
        let mut out = vec![self.header("CAA Policy")];
        out.extend(self.render_caa_block(policy, ""));
        let mut rows = self.rows(&mut out, "  ");
        if !policy.iodef.is_empty() {
            rows.text("iodef (incident reporting)", &policy.iodef.join(", "));
        }
        if let Some(note) = &policy.wildcard_note {
            rows.kv("Wildcard", self.warning(&sanitize_line(note)));
        }
        self.push_caa_note_footer(&mut out, policy);
        out.join("\n")
    }

    pub(super) fn format_confusables(&self, report: &ConfusableReport) -> String {
        let mut out = vec![self.header(&format!("Look-alikes: {}", sanitize_line(&report.domain)))];
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
                    self.warning(&sanitize_line(&r.domain)),
                    self.dim(&sanitize_line(&r.technique)),
                    self.value(&created),
                    self.dim(&sanitize_line(registrar)),
                ));
            }
        }
        out.join("\n")
    }

    pub(super) fn format_subdomain_classification(
        &self,
        result: &SubdomainClassification,
    ) -> String {
        let mut out = vec![self.header(&format!("Subdomains: {}", sanitize_line(&result.domain)))];
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
            let label = subdomain_status_label(s.status);
            let status = match s.status {
                SubdomainStatus::Live => self.success(label),
                SubdomainStatus::Dead => self.dim(label),
                SubdomainStatus::Wildcard | SubdomainStatus::Unknown => self.warning(label),
            };
            let mut line = format!("{}  [{}]", self.value(&sanitize_line(&s.name)), status);
            if let Some(cname) = &s.cname {
                line.push_str(&format!(
                    "  {} {}",
                    self.label("CNAME →"),
                    self.dim(&sanitize_line(cname))
                ));
            }
            if let Some(risk) = &s.takeover_risk {
                line.push_str(&format!(
                    "  {}",
                    self.error(&format!("takeover risk: {}", sanitize_line(risk)))
                ));
            }
            out.push(line);
        }
        out.join("\n")
    }
}
