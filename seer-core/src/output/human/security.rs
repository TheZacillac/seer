//! Human (colored) renderers for the security/intelligence report types:
//! drift, email posture, standalone CAA, confusables, and classified
//! subdomains.

use super::sanitize_display;
use super::HumanFormatter;
use crate::caa::CaaPolicy;
use crate::confusables::ConfusableReport;
use crate::drift::DriftReport;
use crate::headers::{HeaderReport, HeaderVerdict};
use crate::posture::{EmailPosture, PostureVerdict};
use crate::subdomains::{SubdomainBaselineDiff, SubdomainClassification, SubdomainStatus};
use crate::takeover::{TakeoverReport, TakeoverVerdict};

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

    /// Colors a header verdict token. Mirrors [`Self::posture_verdict`] so the
    /// two security reports read identically.
    fn header_verdict(&self, verdict: HeaderVerdict) -> String {
        match verdict {
            HeaderVerdict::Strict => self.success("strict"),
            HeaderVerdict::Moderate => self.warning("moderate"),
            HeaderVerdict::Weak => self.warning("weak"),
            HeaderVerdict::Present => self.value("present"),
            HeaderVerdict::Absent => self.error("absent"),
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

    pub(super) fn format_subdomain_baseline_diff(&self, report: &SubdomainBaselineDiff) -> String {
        let mut out = vec![self.header(&format!(
            "Subdomain diff: {}",
            sanitize_display(&report.domain)
        ))];

        if report.baseline_missing {
            // Neutral phrasing: the CLI/REPL note carries the actionable
            // "--record" hint (it knows whether a baseline was just recorded).
            out.push(self.warning("No stored baseline to compare against (first run)"));
            return out.join("\n");
        }

        if let Some(at) = report.baseline_recorded_at {
            out.push(format!(
                "{}: {}",
                self.label("Baseline recorded"),
                self.value(&at.format("%Y-%m-%d %H:%M UTC").to_string()),
            ));
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
                    self.value(&sanitize_display(name))
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
                    self.dim(&sanitize_display(name))
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

    pub(super) fn format_headers(&self, report: &HeaderReport) -> String {
        let mut out = vec![self.header(&format!(
            "HTTP security headers: {}",
            sanitize_display(&report.domain)
        ))];

        // Color the grade by band so the headline verdict is readable at a
        // glance: A/A+ passing, B–C partial, D and below failing.
        let grade = match report.grade.as_str() {
            "A+" | "A" => self.success(&report.grade),
            "B" | "C" => self.warning(&report.grade),
            _ => self.error(&report.grade),
        };
        out.push(format!(
            "{}: {} ({}/100)",
            self.label("Grade"),
            grade,
            self.value(&report.score.to_string()),
        ));
        out.push(format!(
            "{}: {} {}",
            self.label("URL"),
            self.value(&sanitize_display(&report.url)),
            self.dim(&format!("[HTTP {}]", report.status)),
        ));
        if report.redirects > 0 {
            out.push(format!(
                "{}: {}",
                self.label("Redirects followed"),
                self.value(&report.redirects.to_string()),
            ));
        }

        out.push(String::new());
        for finding in &report.headers {
            let mut line = format!(
                "{}: {}",
                self.label(&finding.header),
                self.header_verdict(finding.verdict),
            );
            if let Some(value) = &finding.value {
                line.push_str(&format!(" {}", self.dim(&sanitize_display(value))));
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
                    self.value(&sanitize_display(&cookie.name)),
                    self.header_verdict(cookie.verdict),
                    self.dim(&flags),
                ));
            }
        }

        if !report.disclosures.is_empty() {
            out.push(String::new());
            out.push(self.label("Disclosed software:"));
            for d in &report.disclosures {
                let value = sanitize_display(&d.value);
                out.push(format!(
                    "  {}: {}",
                    self.dim(&d.header),
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
                out.push(format!(
                    "  {} {}",
                    self.warning("•"),
                    sanitize_display(note)
                ));
            }
        }
        out.join("\n")
    }

    pub(super) fn format_takeover(&self, report: &TakeoverReport) -> String {
        let mut out = vec![self.header(&format!(
            "Takeover scan: {}",
            sanitize_display(&report.domain)
        ))];

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
                let verdict = match f.verdict {
                    TakeoverVerdict::Vulnerable => self.error("VULNERABLE"),
                    TakeoverVerdict::Potential => self.warning("potential"),
                    TakeoverVerdict::Safe => self.success("safe"),
                };
                let mut line = format!("{}  [{}]", self.value(&sanitize_display(&f.host)), verdict);
                if let Some(provider) = &f.provider {
                    line.push_str(&format!("  {}", self.dim(&sanitize_display(provider))));
                }
                out.push(line);
                if let Some(cname) = &f.cname {
                    out.push(format!(
                        "    {} {}",
                        self.label("CNAME →"),
                        self.dim(&sanitize_display(cname)),
                    ));
                }
                // The matched fingerprint is the evidence for a VULNERABLE
                // claim — always show it so the finding can be verified.
                if let Some(evidence) = &f.evidence {
                    out.push(format!(
                        "    {} {}",
                        self.label("Evidence:"),
                        self.error(&sanitize_display(evidence)),
                    ));
                }
                if let Some(note) = &f.probe_note {
                    out.push(format!("    {}", self.dim(&sanitize_display(note))));
                }
            }
        }

        if !report.notes.is_empty() {
            out.push(String::new());
            for note in &report.notes {
                out.push(format!("{} {}", self.warning("•"), sanitize_display(note)));
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
