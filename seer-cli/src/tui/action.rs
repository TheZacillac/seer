//! Intent (`Action`) and message (`Msg`) types plus per-lens data/state.

use crossterm::event::Event;
use seer_core::RecordType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Focus {
    #[default]
    Nav,
    Pane,
}
impl Focus {
    pub fn toggled(self) -> Self {
        match self {
            Focus::Nav => Focus::Pane,
            Focus::Pane => Focus::Nav,
        }
    }
}

/// Which text field an `InputMode::Field` is editing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditTarget {
    Target,
    DiffB,
    FollowInterval,
    FollowCount,
    BulkPath,
    BulkDomains,
    WatchAdd,
    TldFilter,
    /// Live `/`-filter for a table lens (subdomains/history/propagation).
    LensFilter,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum InputMode {
    #[default]
    Normal,
    Command(crate::tui::line_editor::LineEditor),
    Field {
        target: EditTarget,
        buf: crate::tui::line_editor::LineEditor,
    },
}

/// A parameterized lookup request. The single source of truth for what
/// `data::fetch` runs and which lens key owns the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchReq {
    Overview(String),
    Whois(String),
    RdapDomain(String),
    RdapIp(String),
    RdapAsn(u32),
    Dns {
        domain: String,
        record_type: RecordType,
        nameserver: Option<String>,
    },
    Dnssec(String),
    Compare {
        domain: String,
        record_type: RecordType,
        a: String,
        b: String,
    },
    Ssl(String),
    Status(String),
    Prop(String),
    Reverse(String),
    Avail(String),
    Tld(String),
    Diff {
        a: String,
        b: String,
    },
    Watch,
    History,
    Subdomains(String),
    Headers(String),
    Takeover(String),
}

impl FetchReq {
    /// The registry lens key this request's result belongs to.
    pub fn lens_key(&self) -> &'static str {
        match self {
            FetchReq::Overview(_) => "overview",
            FetchReq::Whois(_) => "whois",
            FetchReq::RdapDomain(_) | FetchReq::RdapIp(_) | FetchReq::RdapAsn(_) => "rdap",
            FetchReq::Dns { .. } => "dns",
            FetchReq::Dnssec(_) | FetchReq::Compare { .. } => "dns",
            FetchReq::Ssl(_) => "ssl",
            FetchReq::Status(_) => "status",
            FetchReq::Prop(_) => "propagation",
            FetchReq::Reverse(_) => "reverse",
            FetchReq::Avail(_) => "avail",
            FetchReq::Tld(_) => "tld",
            FetchReq::Diff { .. } => "diff",
            FetchReq::Watch => "watch",
            FetchReq::History => "history",
            FetchReq::Subdomains(_) => "subdomains",
            FetchReq::Headers(_) => "headers",
            FetchReq::Takeover(_) => "takeover",
        }
    }

    /// The sub-tab of its lens this request's result renders under. Lens
    /// state is cached per lens (not per tab), so `App` compares this against
    /// the active tab to tell whether a cached result still belongs on screen.
    pub fn tab(&self) -> usize {
        match self {
            FetchReq::RdapIp(_) | FetchReq::Dnssec(_) => 1,
            FetchReq::RdapAsn(_) | FetchReq::Compare { .. } => 2,
            _ => 0,
        }
    }

    /// Human label for what this request queries (loading indicator text).
    pub fn target(&self) -> String {
        match self {
            FetchReq::Overview(d)
            | FetchReq::Whois(d)
            | FetchReq::RdapDomain(d)
            | FetchReq::RdapIp(d)
            | FetchReq::Dnssec(d)
            | FetchReq::Ssl(d)
            | FetchReq::Status(d)
            | FetchReq::Prop(d)
            | FetchReq::Reverse(d)
            | FetchReq::Avail(d)
            | FetchReq::Tld(d)
            | FetchReq::Subdomains(d)
            | FetchReq::Headers(d)
            | FetchReq::Takeover(d) => d.clone(),
            FetchReq::RdapAsn(n) => format!("AS{n}"),
            FetchReq::Dns { domain, .. } | FetchReq::Compare { domain, .. } => domain.clone(),
            FetchReq::Diff { a, b } => format!("{a} ⇄ {b}"),
            FetchReq::Watch => "watchlist".to_string(),
            FetchReq::History => "history".to_string(),
        }
    }
}

/// Parameters for a streaming Follow run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FollowParams {
    pub domain: String,
    pub iterations: usize,
    pub interval_secs: u64,
    /// Generation tag — stale callbacks from a superseded run are dropped.
    pub gen: u64,
}

/// Parameters for a streaming Bulk run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkParams {
    pub op: String, // "lookup" | "status" | "dig" | "avail" | "info"
    pub domains: Vec<String>,
    /// Generation tag — stale callbacks from a superseded run are dropped.
    pub gen: u64,
}

/// Side-effecting intents returned by `App`/components for the loop to perform.
#[derive(Debug, Clone)]
pub enum Action {
    Quit,
    /// Parameterized lookup with a generation tag for stale-result detection.
    Fetch {
        req: FetchReq,
        gen: u64,
    },
    Copy {
        text: String,
        label: String,
    },
    StartFollow(FollowParams),
    /// Cancel the in-flight live-follow run (its background DNS loop), if any.
    StopFollow,
    StartBulk(BulkParams),
    /// Cancel the in-flight bulk run (aborts its background task), if any.
    StopBulk,
    /// Trigger a bulk run from a newline-separated domain file (read off-thread in mod.rs).
    StartBulkFromFile {
        op: String,
        path: String,
        gen: u64,
    },
    WriteCsv {
        path: String,
        contents: String,
    },
    /// Add or remove a domain from the watchlist. Handled in `mod.rs`.
    /// `gen` is the watch lens's current fetch generation so the post-mutation
    /// refresh `Msg::Data` is not dropped by the staleness guard.
    WatchMutate {
        add: Option<String>,
        remove: Option<String>,
        gen: u64,
    },
    /// Clear all lookup history. Handled in `mod.rs`. `gen` is the history
    /// lens's current fetch generation (see `WatchMutate`).
    HistoryClear {
        gen: u64,
    },
}

/// Per-lens payload — the shared `Payload` enum under its TUI-local name.
pub use crate::payload::Payload as LensData;

#[derive(Debug, Clone, Default)]
pub enum LensState {
    #[default]
    Idle,
    Loading,
    Loaded(LensData),
    Error(String),
}

#[derive(Debug)]
pub enum Msg {
    Input(Event),
    Tick,
    Data {
        lens: String,
        gen: u64,
        result: Result<LensData, String>,
    },
    CopyResult {
        ok: bool,
        label: String,
    },
    /// A status-bar notice from a side effect that is not a clipboard copy
    /// (CSV export, bulk file load, watchlist edit). `tone` uses the shared
    /// `Theme::tone` vocabulary ("ok" | "info" | "warn" | "fail").
    Toast {
        tone: &'static str,
        msg: String,
    },
    FollowStep {
        gen: u64,
        it: Box<seer_core::dns::FollowIteration>,
    },
    FollowDone {
        gen: u64,
    },
    BulkStep {
        gen: u64,
        result: Box<seer_core::bulk::BulkResult>,
    },
    BulkDone {
        gen: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_req_lens_keys() {
        assert_eq!(FetchReq::RdapIp("1.2.3.4".into()).lens_key(), "rdap");
        assert_eq!(FetchReq::Dnssec("x".into()).lens_key(), "dns");
        assert_eq!(
            FetchReq::Compare {
                domain: "x".into(),
                record_type: RecordType::A,
                a: "8.8.8.8".into(),
                b: "1.1.1.1".into()
            }
            .lens_key(),
            "dns"
        );
        assert_eq!(FetchReq::Tld(".com".into()).lens_key(), "tld");
        assert_eq!(FetchReq::Headers("x".into()).lens_key(), "headers");
        assert_eq!(FetchReq::Takeover("x".into()).lens_key(), "takeover");
    }

    #[test]
    fn fetch_req_tabs_match_the_lens_sub_tabs() {
        assert_eq!(FetchReq::RdapDomain("x".into()).tab(), 0);
        assert_eq!(FetchReq::RdapIp("1.2.3.4".into()).tab(), 1);
        assert_eq!(FetchReq::RdapAsn(15169).tab(), 2);
        assert_eq!(FetchReq::Dnssec("x".into()).tab(), 1);
        assert_eq!(FetchReq::Whois("x".into()).tab(), 0);
        assert_eq!(FetchReq::RdapAsn(15169).target(), "AS15169");
    }

    #[test]
    fn input_mode_default_and_focus() {
        assert_eq!(InputMode::Normal, InputMode::default());
        assert_eq!(Focus::Nav.toggled(), Focus::Pane);
    }
}
