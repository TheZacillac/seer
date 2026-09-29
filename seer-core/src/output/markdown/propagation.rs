use super::*;
use crate::dns::{PropagationVerdict, ServerVerdict};

impl MarkdownFormatter {
    pub(super) fn format_propagation(&self, result: &PropagationResult) -> String {
        let mut output = Vec::new();

        output.push(format!(
            "## Propagation: {} {}",
            MdSafe(&result.domain),
            result.record_type
        ));
        output.push(String::new());

        let verdict = result.verdict();
        let (agree, responding) = (result.servers_agreeing(), result.servers_responding);
        let detail = match verdict {
            PropagationVerdict::NoAnswer => {
                format!("none of the {} servers answered", result.servers_checked)
            }
            PropagationVerdict::Full => format!("all {responding} responding servers agree"),
            _ => format!("{agree} of {responding} responding servers agree"),
        };
        output.push(format!("**{}** — {detail}", verdict.label()));
        output.push(String::new());

        let ns_details = result.nameserver_details.as_ref();
        let mut bullets = Bullets(&mut output);
        if responding > 0 {
            if let Some(label) = result.empty_consensus_label() {
                bullets.raw("Consensus", format!("no records ({label})"));
            } else {
                let multi_type = result
                    .consensus_values
                    .iter()
                    .any(|v| v.record_type != result.record_type);
                let values: Vec<String> = result
                    .consensus_values
                    .iter()
                    .map(|v| {
                        let mut text = format!("`{}`", MdSafe(&v.value));
                        if let Some(ips) = ns_details
                            .and_then(|d| d.consensus.get(&v.value.to_ascii_lowercase()))
                            .filter(|ips| !ips.is_empty())
                        {
                            text = format!("{text} ({})", code_list(ips));
                        }
                        if multi_type {
                            text = format!("{} {text}", v.record_type);
                        }
                        text
                    })
                    .collect();
                bullets.raw("Consensus", values.join(", "));
            }
        }
        let silent = result.servers_checked - responding;
        if silent > 0 && responding > 0 {
            bullets.raw(
                "No answer",
                format!("{silent} of {} servers", result.servers_checked),
            );
        }

        // Per-vantage nameserver-IP disagreements (glue-update lag), grouped
        // by NS hostname. Only present for NS-record lookups.
        if let Some(details) = ns_details.filter(|d| !d.inconsistencies.is_empty()) {
            output.push(String::new());
            output.push("### Nameserver IP inconsistencies".to_string());
            output.push(String::new());
            render_grouped(
                &mut output,
                &details.inconsistencies,
                |inc| inc.nameserver.clone(),
                |out, hdr| {
                    out.push(format!("**{}**", MdSafe(hdr)));
                    out.push(String::new());
                },
                |out, inc, _nested| out.push(format!("- {}", MdSafe(&inc.to_string()))),
            );
        }

        // One row per server: whether it agrees, and only for the rest what
        // it answered instead or why it did not.
        output.push(String::new());
        output.push("### Results".to_string());
        output.push(String::new());
        output.push("| | Server | Region | IP | Answer | Time |".to_string());
        output.push("| --- | --- | --- | --- | --- | --- |".to_string());
        for sr in &result.results {
            let (mark, answer, time) = match result.server_verdict(sr) {
                ServerVerdict::Agrees => (
                    "✓",
                    "matches consensus".to_string(),
                    format!("{} ms", sr.response_time_ms),
                ),
                ServerVerdict::Differs(inc) => (
                    "≠",
                    format!(
                        "`{}`",
                        MdSafe(&propagation_difference(inc, sr.empty_answer_label()))
                    ),
                    format!("{} ms", sr.response_time_ms),
                ),
                ServerVerdict::NoAnswer(reason) => ("✗", MdSafe(reason).to_string(), "—".into()),
            };
            output.push(format!(
                "| {mark} | {} | {} | `{}` | {answer} | {time} |",
                MdSafe(&sr.server.name),
                MdSafe(&sr.server.location),
                MdSafe(&sr.server.ip),
            ));
        }

        if result.looks_location_dependent() {
            output.push(String::new());
            output.push(format!("> {GEO_NOTE}."));
        }
        if !result.dnssec_validated {
            output.push(String::new());
            output.push(format!("> {DNSSEC_NOTE}."));
        }

        output.join("\n")
    }
}
