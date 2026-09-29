//! The local-state commands — `watch`, `history` and `config` — for the CLI
//! and the REPL. Each produces a [`Listing`]: the prose a human reads plus
//! the data behind it, so `--format json|yaml` (and `-q`/`--fields` in the
//! CLI) get a structured document instead of the prose.

use seer_core::colors::CatppuccinExt;
use seer_core::output::OutputFormat;
use serde::Serialize;

use crate::ops::{load_history, load_watchlist, state_io};

/// A local-state command's result: `text` for human (and markdown) output,
/// `data` for the structured formats.
pub struct Listing {
    pub text: String,
    pub data: serde_json::Value,
}

impl Listing {
    fn new<T: Serialize>(text: String, data: &T) -> Self {
        Self {
            text,
            // Serializing plain data structs cannot fail.
            data: serde_json::to_value(data).unwrap_or_default(),
        }
    }

    /// The listing in `format`: the data for JSON/YAML, the prose otherwise.
    pub fn render(&self, format: OutputFormat) -> String {
        crate::payload::structured(&self.data, format).unwrap_or_else(|| self.text.clone())
    }
}

/// One `watch add|remove` change, as the structured formats report it.
#[derive(Debug, Serialize, PartialEq, Eq)]
struct WatchChange {
    action: &'static str,
    domain: String,
    /// False when the domain was already (add) or not (remove) watched.
    changed: bool,
}

/// Runs `watch add|remove <domain>...` or `watch list`. `cmd` is how the user
/// invokes watch on this surface (`seer watch` in the CLI, `watch` in the
/// REPL), for the usage errors and the empty-list hint. Every domain is
/// validated before anything is saved, so one bad name changes nothing.
pub async fn watch_edit(action: &str, domains: &[String], cmd: &str) -> Result<Listing, String> {
    let adding = match action {
        "list" => {
            if let Some(extra) = domains.first() {
                return Err(format!("Unexpected argument: {extra}\nUsage: {cmd} list"));
            }
            return Ok(watchlist_listing(&load_watchlist().await?, cmd));
        }
        "add" => true,
        "remove" => false,
        other => {
            return Err(format!(
                "Unknown watch action: {}. Use: add, remove, list",
                other
            ))
        }
    };
    if domains.is_empty() {
        return Err(format!("Usage: {} {} <domain>...", cmd, action));
    }

    let mut watchlist = load_watchlist().await?;
    let mut changes = Vec::with_capacity(domains.len());
    for domain in domains {
        let changed = if adding {
            watchlist
                .add(domain)
                .map_err(|e| format!("Invalid domain: {}", e))?
        } else {
            watchlist.remove(domain)
        };
        changes.push(WatchChange {
            action: if adding { "add" } else { "remove" },
            domain: domain.clone(),
            changed,
        });
    }
    if changes.iter().any(|c| c.changed) {
        state_io("save watchlist", move || watchlist.save()).await?;
    }
    let text = changes
        .iter()
        .map(|change| match (adding, change.changed) {
            (true, true) => format!("Added {} to watchlist", change.domain.ctp_green()),
            (true, false) => format!("{} is already in the watchlist", change.domain),
            (false, true) => format!("Removed {} from watchlist", change.domain.ctp_green()),
            (false, false) => format!("{} was not in the watchlist", change.domain),
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Listing::new(text, &changes))
}

/// The `watch list` listing, or the empty-watchlist hint (see [`watch_edit`]
/// for `cmd`); its data is the watchlist itself.
pub fn watchlist_listing(watchlist: &seer_core::Watchlist, cmd: &str) -> Listing {
    let text = if watchlist.domains.is_empty() {
        format!(
            "Watchlist is empty. Use '{} add <domain>' to add domains.",
            cmd
        )
    } else {
        let mut out = format!("Watchlist ({} domains):", watchlist.domains.len());
        for domain in &watchlist.domains {
            out.push_str(&format!("\n  - {}", domain));
        }
        out
    };
    Listing::new(text, watchlist)
}

/// What the check-all `watch` found.
pub enum WatchCheck {
    /// Nothing is watched: the empty-watchlist listing.
    Empty(Listing),
    Report(Box<seer_core::WatchReport>),
}

/// The check-all `watch`: every watched domain's expiry and health, with a
/// spinner while it runs.
pub async fn watch_check(config: &seer_core::SeerConfig, cmd: &str) -> Result<WatchCheck, String> {
    let watchlist = load_watchlist().await?;
    if watchlist.domains.is_empty() {
        return Ok(WatchCheck::Empty(watchlist_listing(&watchlist, cmd)));
    }
    let spinner =
        crate::display::Spinner::new(&format!("Checking {} domains", watchlist.domains.len()));
    let report = seer_core::check_watchlist_with_config(&watchlist.domains, config).await;
    spinner.finish();
    Ok(WatchCheck::Report(Box::new(report)))
}

/// Runs `history [domain]` or `history --clear` (which empties all history,
/// so it takes no domain). `lookup_cmd` (`seer lookup` / `lookup`) names the
/// command in the empty-history hint. The data is the entries shown, as
/// [`crate::payload::Payload::History`].
pub async fn history(
    domain: Option<&str>,
    clear: bool,
    lookup_cmd: &str,
) -> Result<Listing, String> {
    if clear {
        if let Some(domain) = domain {
            return Err(format!(
                "--clear empties all lookup history, so it takes no domain (got '{domain}')"
            ));
        }
        crate::ops::clear_history().await?;
        return Ok(Listing::new(
            "Lookup history cleared".to_string(),
            &serde_json::json!({ "cleared": true }),
        ));
    }
    let history = load_history().await?;
    Ok(history_listing(&history, domain, lookup_cmd))
}

/// The `history` listing: one domain's lookups, or a per-domain summary
/// (see [`history`] for `lookup_cmd`).
pub fn history_listing(
    history: &seer_core::LookupHistory,
    domain: Option<&str>,
    lookup_cmd: &str,
) -> Listing {
    let entries: Vec<seer_core::HistoryEntry> = match domain {
        Some(domain) => history.get(domain).into_iter().cloned().collect(),
        None => history.entries.values().flatten().cloned().collect(),
    };
    let data = crate::payload::Payload::History(entries);

    let Some(domain) = domain else {
        let total: usize = history.entries.values().map(Vec::len).sum();
        if total == 0 {
            let text = format!(
                "No lookup history. Run '{} <domain>' to build history.",
                lookup_cmd
            );
            return Listing::new(text, &data);
        }
        let mut out = format!(
            "Lookup history ({} entries across {} domains):",
            total,
            history.entries.len()
        );
        for (domain, entries) in &history.entries {
            out.push_str(&format!("\n  {} ({} entries)", domain, entries.len()));
        }
        return Listing::new(out, &data);
    };

    let entries = history.get(domain);
    if entries.is_empty() {
        return Listing::new(format!("No history for {}", domain), &data);
    }
    let mut out = format!(
        "History for {} ({} entries):",
        domain.ctp_green(),
        entries.len()
    );
    for entry in entries {
        out.push_str(&format!(
            "\n  [{}] via {} - registrar: {}",
            entry.timestamp.format("%Y-%m-%d %H:%M"),
            crate::ops::lookup_source(&entry.result).unwrap_or("availability"),
            entry.result.registrar().unwrap_or_else(|| "—".to_string())
        ));
    }
    Listing::new(out, &data)
}

/// `seer config`: the effective configuration (as pretty JSON for humans,
/// as before).
pub fn config_show(config: &seer_core::SeerConfig) -> Listing {
    let text = serde_json::to_string_pretty(config).unwrap_or_default();
    Listing::new(text, config)
}

/// `seer config --init`: writes the default config file, refusing to
/// overwrite an existing one.
pub fn config_init() -> Result<Listing, String> {
    let path = seer_core::SeerConfig::config_path()
        .ok_or_else(|| "Could not determine home directory".to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Could not create {}: {}", parent.display(), e))?;
    }
    // `create_new` refuses an existing file atomically — no check-then-write
    // window in which a concurrent init could be overwritten.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => {
                format!("Config file already exists at: {}", path.display())
            }
            _ => format!("Could not write {}: {}", path.display(), e),
        })?;
    std::io::Write::write_all(&mut file, seer_core::SeerConfig::default_toml().as_bytes())
        .map_err(|e| format!("Could not write {}: {}", path.display(), e))?;
    let shown = path.display().to_string();
    Ok(Listing::new(
        format!("Created config file at: {}", shown.ctp_green()),
        &serde_json::json!({ "created": shown }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn watch_edit_rejects_bad_actions_and_arity_before_io() {
        let err = watch_edit("bogus", &["a.com".into()], "watch")
            .await
            .err()
            .expect("bad action");
        assert!(err.starts_with("Unknown watch action: bogus"), "got: {err}");
        let err = watch_edit("add", &[], "seer watch")
            .await
            .err()
            .expect("no domain");
        assert_eq!(err, "Usage: seer watch add <domain>...");
        let err = watch_edit("remove", &[], "watch")
            .await
            .err()
            .expect("no domain");
        assert_eq!(err, "Usage: watch remove <domain>...");
        // `list` takes no domain; it used to be silently ignored.
        let err = watch_edit("list", &["a.com".into()], "watch")
            .await
            .err()
            .expect("extra argument");
        assert!(err.starts_with("Unexpected argument: a.com"), "got: {err}");
    }

    #[test]
    fn watchlist_listing_names_the_surface_command_when_empty() {
        let mut watchlist = seer_core::Watchlist::default();
        let listing = watchlist_listing(&watchlist, "seer watch");
        assert_eq!(
            listing.text,
            "Watchlist is empty. Use 'seer watch add <domain>' to add domains."
        );
        assert_eq!(
            listing.render(OutputFormat::Json),
            "{\n  \"domains\": []\n}"
        );
        watchlist.domains = vec!["a.com".into(), "b.com".into()];
        let listing = watchlist_listing(&watchlist, "watch");
        assert_eq!(listing.text, "Watchlist (2 domains):\n  - a.com\n  - b.com");
        assert_eq!(listing.render(OutputFormat::Human), listing.text);
        assert_eq!(listing.data["domains"][1], "b.com");
    }

    fn available(domain: &str) -> seer_core::LookupResult {
        seer_core::LookupResult::Available {
            data: Box::new(seer_core::AvailabilityResult {
                domain: domain.into(),
                available: true,
                confidence: "high".into(),
                method: "rdap".into(),
                details: None,
            }),
            rdap_error: "404".into(),
            whois_error: "no match".into(),
            whois_data: None,
        }
    }

    #[test]
    fn history_listing_covers_empty_summary_and_per_domain_views() {
        let mut history = seer_core::LookupHistory::default();
        assert_eq!(
            history_listing(&history, None, "lookup").text,
            "No lookup history. Run 'lookup <domain>' to build history."
        );
        assert_eq!(
            history_listing(&history, Some("a.com"), "lookup").text,
            "No history for a.com"
        );

        history.record("a.com", available("a.com"));
        assert_eq!(
            history_listing(&history, None, "seer lookup").text,
            "Lookup history (1 entries across 1 domains):\n  a.com (1 entries)"
        );
        let listing = history_listing(&history, Some("a.com"), "lookup").text;
        assert!(listing.contains("(1 entries):"), "got: {listing}");
        assert!(
            listing.ends_with("via availability - registrar: —"),
            "got: {listing}"
        );
    }

    /// `seer --format json history` printed the prose listing; the
    /// structured formats now carry the entries themselves.
    #[test]
    fn history_listing_data_is_the_entries_shown() {
        let mut history = seer_core::LookupHistory::default();
        history.record("a.com", available("a.com"));
        history.record("b.com", available("b.com"));

        let all = history_listing(&history, None, "lookup");
        let domains: Vec<&str> = all
            .data
            .as_array()
            .expect("an array of entries")
            .iter()
            .map(|entry| entry["domain"].as_str().expect("domain"))
            .collect();
        assert_eq!(domains, vec!["a.com", "b.com"]);

        let one = history_listing(&history, Some("b.com"), "lookup");
        let json: serde_json::Value =
            serde_json::from_str(&one.render(OutputFormat::Json)).expect("valid JSON");
        assert_eq!(json.as_array().map(Vec::len), Some(1));
        assert_eq!(json[0]["domain"], "b.com");
        assert!(one.render(OutputFormat::Yaml).contains("b.com"));
    }

    /// `history example.com --clear` used to clear ALL history, ignoring the
    /// domain; the combination is now an error, before any I/O.
    #[tokio::test]
    async fn history_clear_takes_no_domain() {
        let err = history(Some("example.com"), true, "lookup")
            .await
            .err()
            .expect("must be rejected");
        assert!(err.contains("takes no domain"), "got: {err}");
    }

    #[test]
    fn config_show_keeps_pretty_json_for_humans_and_yaml_for_yaml() {
        let config = seer_core::SeerConfig::default();
        let listing = config_show(&config);
        assert_eq!(listing.render(OutputFormat::Human), listing.text);
        assert!(listing.text.trim_start().starts_with('{'));
        let yaml = listing.render(OutputFormat::Yaml);
        assert!(
            !yaml.trim_start().starts_with('{'),
            "YAML, not JSON: {yaml}"
        );
        assert!(yaml.contains("output_format"), "{yaml}");
    }
}
