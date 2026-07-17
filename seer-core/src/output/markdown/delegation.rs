//! Markdown renderer for the NS delegation health report.

use std::collections::BTreeSet;

use super::{MarkdownFormatter, MdSafe};
use crate::dns::DelegationReport;

impl MarkdownFormatter {
    pub(super) fn format_delegation(&self, report: &DelegationReport) -> String {
        let mut out = Vec::new();

        out.push(format!("## Delegation: {}", MdSafe(&report.domain)));
        out.push(String::new());
        out.push(format!(
            "- **Parent zone**: `{}`",
            MdSafe(&report.parent_zone)
        ));
        let servers = if report.parent_server_queried.is_empty() {
            "none".to_string()
        } else {
            report
                .parent_server_queried
                .iter()
                .map(|server| format!("`{}`", MdSafe(server)))
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push(format!("- **Parent servers queried**: {}", servers));
        out.push(format!(
            "- **In sync**: {}",
            if report.in_sync { "yes" } else { "no" }
        ));

        // One row per NS name in either view, so mismatches read directly
        // off the table.
        let union: BTreeSet<&String> = report
            .delegated_ns
            .iter()
            .chain(report.zone_ns.iter())
            .collect();
        if !union.is_empty() {
            out.push(String::new());
            out.push("| Nameserver | Parent | Zone |".to_string());
            out.push("| --- | --- | --- |".to_string());
            for ns in union {
                out.push(format!(
                    "| `{}` | {} | {} |",
                    MdSafe(ns),
                    if report.delegated_ns.contains(ns) {
                        "yes"
                    } else {
                        "no"
                    },
                    if report.zone_ns.contains(ns) {
                        "yes"
                    } else {
                        "no"
                    },
                ));
            }
        }

        if !report.lame.is_empty() {
            out.push(String::new());
            out.push("### Lame servers".to_string());
            out.push(String::new());
            for lame in &report.lame {
                out.push(format!(
                    "- `{}` — {}",
                    MdSafe(&lame.host),
                    MdSafe(&lame.reason)
                ));
            }
        }

        if !report.warnings.is_empty() {
            out.push(String::new());
            out.push("### Warnings".to_string());
            out.push(String::new());
            for warning in &report.warnings {
                out.push(format!("- {}", MdSafe(warning)));
            }
        }

        out.join("\n")
    }
}
