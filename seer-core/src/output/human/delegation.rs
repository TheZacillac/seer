//! Human (colored) renderer for the NS delegation health report.

use super::sanitize_display;
use super::HumanFormatter;
use crate::dns::DelegationReport;

impl HumanFormatter {
    pub(super) fn format_delegation(&self, report: &DelegationReport) -> String {
        let mut out = Vec::new();

        out.push(format!(
            "Delegation Report for {}",
            self.success(&sanitize_display(&report.domain))
        ));
        out.push(String::new());

        out.push(format!(
            "  {}: {}",
            self.label("Parent zone"),
            self.value(&sanitize_display(&report.parent_zone))
        ));
        let servers = if report.parent_server_queried.is_empty() {
            self.warning("(none)")
        } else {
            self.value(&sanitize_display(&report.parent_server_queried.join(", ")))
        };
        out.push(format!(
            "  {}: {}",
            self.label("Parent servers queried"),
            servers
        ));
        let verdict = if report.in_sync {
            self.success("in sync")
        } else {
            self.error("out of sync")
        };
        out.push(format!("  {}: {}", self.label("Delegation"), verdict));

        // Marks derive from the report's own diff fields so the lists always
        // agree with missing_from_zone / missing_from_parent.
        out.push(String::new());
        out.push(format!("  {}:", self.label("Delegated NS (parent view)")));
        if report.delegated_ns.is_empty() {
            out.push(format!(
                "    {}",
                self.warning("(none — parent returned no delegation)")
            ));
        }
        for ns in &report.delegated_ns {
            let mark = if report.missing_from_zone.contains(ns) {
                self.error("\u{2717}")
            } else {
                self.success("\u{2713}")
            };
            out.push(format!(
                "    {} {}",
                mark,
                self.value(&sanitize_display(ns))
            ));
        }

        out.push(format!("  {}:", self.label("Zone NS (authoritative view)")));
        if report.zone_ns.is_empty() {
            out.push(format!(
                "    {}",
                self.warning("(none — no authoritative NS answer obtained)")
            ));
        }
        for ns in &report.zone_ns {
            let mark = if report.missing_from_parent.contains(ns) {
                self.error("\u{2717}")
            } else {
                self.success("\u{2713}")
            };
            out.push(format!(
                "    {} {}",
                mark,
                self.value(&sanitize_display(ns))
            ));
        }

        if !report.missing_from_zone.is_empty() {
            out.push(String::new());
            out.push(format!(
                "  {}:",
                self.label("Listed at parent but missing from zone")
            ));
            for ns in &report.missing_from_zone {
                out.push(format!(
                    "    {} {}",
                    self.error("\u{2717}"),
                    self.value(&sanitize_display(ns))
                ));
            }
        }
        if !report.missing_from_parent.is_empty() {
            out.push(String::new());
            out.push(format!(
                "  {}:",
                self.label("Listed in zone but missing from parent")
            ));
            for ns in &report.missing_from_parent {
                out.push(format!(
                    "    {} {}",
                    self.error("\u{2717}"),
                    self.value(&sanitize_display(ns))
                ));
            }
        }

        if !report.lame.is_empty() {
            out.push(String::new());
            out.push(format!("  {}:", self.label("Lame servers")));
            for lame in &report.lame {
                out.push(format!(
                    "    {} {} — {}",
                    self.error("\u{2717}"),
                    self.value(&sanitize_display(&lame.host)),
                    self.error(&sanitize_display(&lame.reason))
                ));
            }
        }

        if !report.warnings.is_empty() {
            out.push(String::new());
            out.push(format!("  {}:", self.label("Warnings")));
            for warning in &report.warnings {
                out.push(format!(
                    "    {} {}",
                    self.warning("\u{2022}"),
                    sanitize_display(warning)
                ));
            }
        }

        out.join("\n")
    }
}
