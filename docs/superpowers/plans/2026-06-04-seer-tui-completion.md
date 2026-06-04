# Seer TUI Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the remaining 9 lenses + 4 sub-tabs + custom-nameserver field of the Seer TUI, with full in-pane inputs and live `seer-core` data.

**Architecture:** Parameterized fetch requests (`FetchReq`) drive a single `data::fetch`; interactive lenses are self-contained components under `panes/` that own `(state, handle_key, render)` and are delegated pane-focused keys by `App`; a generalized `InputMode::Field` handles editable text inputs; Follow/Bulk stream incremental `Msg` steps over the existing channel.

**Tech Stack:** Rust 2021, ratatui 0.29, crossterm 0.28, tokio, `seer-core`. Builds on the merged first pass (`seer-cli/src/tui/`).

---

## Verified seer-core API reference (use exactly)

```text
seer_core::lookup_tld(tld:&str).await -> TldInfo            // async, INFALLIBLE (no Result)
  TldInfo { tld:String, whois_server:Option<String>, rdap_url:Option<String>, registry_url:Option<String>, tld_type:String }
seer_core::DnssecChecker::new().check(domain:&str).await -> Result<DnssecReport>
  DnssecReport { domain, enabled:bool, has_ds_records:bool, has_dnskey_records:bool, ds_records:Vec<DsInfo>, dnskey_records:Vec<DnskeyInfo>, issues:Vec<String>, status:String, chain_valid:bool }
  DsInfo { key_tag:u16, algorithm:u8, digest_type:u8, digest:String, algorithm_name:String, digest_type_name:String, matched_key:bool, digest_verified:bool }
  DnskeyInfo { flags:u16, protocol:u8, algorithm:u8, key_tag:u16, is_ksk:bool, is_zsk:bool, algorithm_name:String }
seer_core::dns::DnsComparator::new().compare(domain:&str, rt:RecordType, server_a:&str, server_b:&str).await -> Result<DnsComparison>
  DnsComparison { domain, record_type:RecordType, server_a:CmpServerResult, server_b:CmpServerResult, matches:bool, only_in_a:Vec<String>, only_in_b:Vec<String>, common:Vec<String> }
  // compare.rs ServerResult (NOT propagation's): { nameserver:String, records:Vec<DnsRecord>, error:Option<String> }
seer_core::DomainDiffer::new().diff(a:&str, b:&str).await -> Result<DomainDiff>
  DomainDiff { domain_a:String, domain_b:String, registration:RegistrationDiff, dns:DnsDiff, ssl:SslDiff }
  RegistrationDiff { registrar:(Option<String>,Option<String>), organization:(..), created:(..), expires:(..) }
  DnsDiff { a_records:(Vec<String>,Vec<String>), nameservers:(Vec<String>,Vec<String>), resolves:(bool,bool) }
  SslDiff { issuer:(Option<String>,Option<String>), valid_until:(..), days_remaining:(Option<i64>,Option<i64>), is_valid:(Option<bool>,Option<bool>) }
seer_core::DnsFollower::new().follow(domain:&str, rt:RecordType, ns:Option<&str>, config:FollowConfig, cb:Option<FollowProgressCallback>, cancel:Option<tokio::sync::watch::Receiver<bool>>).await -> Result<FollowResult>
  FollowConfig::new(iterations:usize, interval_minutes:f64) -> Result<FollowConfig>;  .with_changes_only(bool)
  FollowConfig { iterations:usize, interval_secs:u64, changes_only:bool }
  FollowIteration { iteration:usize, total_iterations:usize, timestamp:DateTime<Utc>, records:Vec<DnsRecord>, changed:bool, added:Vec<String>, removed:Vec<String>, error:Option<String> }
  seer_core::dns::FollowProgressCallback = Arc<dyn Fn(&FollowIteration)+Send+Sync>
seer_core::BulkExecutor::new()  // execute_lookup/status/avail/info/whois/rdap/ssl(domains:Vec<String>).await -> Vec<BulkResult>; execute_dns(domains,rt)
  seer_core::bulk::parse_domains_from_file(content:&str) -> Vec<String>
  BulkResult { operation:BulkOperation, success:bool, data:Option<BulkResultData>, error:Option<String>, duration_ms:u64 }
  BulkOperation::{Whois{domain},Rdap{domain},Dns{domain,record_type},Lookup{domain},Status{domain},Avail{domain},Info{domain},Ssl{domain}}  // .domain() helper does NOT exist — match it
seer_core::Watchlist::load() -> Watchlist { domains:Vec<String> };  .add(&mut,&str)->Result<bool>; .remove(&mut,&str)->bool; .save()->Result<()>
seer_core::check_watchlist(domains:&[String]).await -> WatchReport
  WatchResult { domain, ssl_days_remaining:Option<i64>, domain_days_remaining:Option<i64>, registrar:Option<String>, http_status:Option<u16>, issues:Vec<String> }
  WatchReport { checked_at, results:Vec<WatchResult>, total:usize, warnings:usize, critical:usize }
seer_core::LookupHistory::load() -> LookupHistory { entries:BTreeMap<String,Vec<HistoryEntry>> };  .get(&str)->Vec<&HistoryEntry>; .clear(&mut); .save()->Result<()>
  HistoryEntry { domain:String, timestamp:DateTime<Utc>, result:LookupResult }
seer_core::AvailabilityChecker::new().check(domain:&str).await -> Result<AvailabilityResult>
  AvailabilityResult { domain, available:bool, confidence:String, method:String, details:Option<String> };  .verdict()->&'static str
seer_core::RdapClient::new().lookup_ip(ip:&str).await -> Result<RdapResponse>;  .lookup_asn(asn:u32).await -> Result<RdapResponse>
seer_core::DnsResolver::new().resolve(domain:&str, rt:RecordType, ns:Option<&str>).await -> Result<Vec<DnsRecord>>   // PTR for reverse
```

All `format_*` raw methods exist on `seer_core::output::OutputFormatter`: `format_dnssec, format_tld, format_dns_comparison, format_diff, format_availability, format_watch` (+ the pass-1 ones).

---

## File structure

```
seer-cli/src/tui/action.rs   MODIFY  FetchReq, EditTarget, InputMode::Field, new LensData + Msg variants, new Action variants
seer-cli/src/tui/data.rs     MODIFY  fetch(FetchReq) — all new seer-core calls
seer-cli/src/tui/command.rs  MODIFY  parse new commands (reverse/tld/compare/diff/follow/bulk)
seer-cli/src/tui/app.rs      MODIFY  FetchReq migration; Panes field; Field routing; stream Msg routing; pane-key delegation
seer-cli/src/tui/render.rs   MODIFY  RDAP/DNS sub-tab routing; dispatch new lenses; render active pane component
seer-cli/src/tui/raw.rs      MODIFY  serialize arms for new LensData variants
seer-cli/src/tui/mod.rs      MODIFY  handle_action: spawn FetchReq + Follow/Bulk streams
seer-cli/src/tui/panes/mod.rs        CREATE  Panes struct + PaneOutcome + routing helpers
seer-cli/src/tui/panes/{tld,dns,compare,diff,follow,bulk,watch,history}.rs  CREATE  components
seer-cli/src/tui/lenses/{reverse,avail,tld,dnssec,compare,diff,follow,bulk,watch,history}.rs  MODIFY (replace placeholders) render fns
seer-cli/src/tui/lenses/rdap.rs MODIFY  IP/ASN tab rendering
seer-cli/src/tui/lenses/dns.rs  MODIFY  DNSSEC/Compare tab + nameserver chips
```

---

# Phase 1 — Foundation refactor

## Task 1: `FetchReq`, `EditTarget`, `InputMode::Field`, new `LensData`/`Msg`/`Action` variants

**Files:** Modify `seer-cli/src/tui/action.rs`

- [ ] **Step 1: Replace `action.rs` with the extended types**

```rust
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
    WatchAdd,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum InputMode {
    #[default]
    Normal,
    Command(String),
    Field {
        target: EditTarget,
        buf: String,
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
        }
    }
}

/// Parameters for a streaming Follow run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FollowParams {
    pub domain: String,
    pub iterations: usize,
    pub interval_secs: u64,
}

/// Parameters for a streaming Bulk run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkParams {
    pub op: String, // "lookup" | "status" | "dig" | "avail" | "info"
    pub domains: Vec<String>,
}

/// Side-effecting intents returned by `App`/components for the loop to perform.
#[derive(Debug, Clone)]
pub enum Action {
    Quit,
    Fetch(FetchReq),
    Copy { text: String, label: String },
    StartFollow(FollowParams),
    StartBulk(BulkParams),
    WriteCsv { path: String, contents: String },
}

#[derive(Debug, Clone)]
pub enum LensData {
    Overview(Box<seer_core::LookupResult>),
    Whois(Box<seer_core::WhoisResponse>),
    Rdap(Box<seer_core::RdapResponse>),
    Dns(Vec<seer_core::DnsRecord>),
    Ssl(Box<seer_core::SslReport>),
    Status(Box<seer_core::StatusResponse>),
    Prop(Box<seer_core::PropagationResult>),
    Reverse(Vec<seer_core::DnsRecord>),
    Avail(Box<seer_core::AvailabilityResult>),
    Tld(Box<seer_core::TldInfo>),
    Dnssec(Box<seer_core::DnssecReport>),
    Compare(Box<seer_core::DnsComparison>),
    Diff(Box<seer_core::DomainDiff>),
    Watch(Box<seer_core::WatchReport>),
    History(Vec<seer_core::HistoryEntry>),
}

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
        result: Result<LensData, String>,
    },
    CopyResult {
        ok: bool,
        label: String,
    },
    FollowStep(Box<seer_core::dns::FollowIteration>),
    FollowDone,
    BulkStep(Box<seer_core::bulk::BulkResult>),
    BulkDone,
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
    }

    #[test]
    fn input_mode_default_and_focus() {
        assert_eq!(InputMode::Normal, InputMode::default());
        assert_eq!(Focus::Nav.toggled(), Focus::Pane);
    }
}
```

NOTE: `Msg::Data` now keys by `lens: String` (was `lens: usize`). This ripples into `app.rs` and `mod.rs::handle_action` — both updated in Task 3 (Steps 3 and 4b). `seer_core::TldInfo`, `DnssecReport`, `DnsComparison`, `DomainDiff`, `WatchReport`, `HistoryEntry`, `dns::FollowIteration`, `bulk::BulkResult` are all re-exported (verified).

- [ ] **Step 2: Verify it compiles in isolation**

Run: `cargo build -p seer-cli 2>&1 | tail -20`
Expected: `action.rs` itself compiles; errors will appear in `app.rs`/`data.rs`/`mod.rs`/`raw.rs` referencing the old `Action::Fetch { lens, domain }`, old `Msg::Data { lens: usize }`, and `InputMode::EditDomain`. Those are fixed in Tasks 2–7. Do NOT try to make the whole crate build yet.

Run: `cargo test -p seer-cli action:: 2>&1 | tail -6`
Expected: the two `action::tests` pass (the test target also needs the crate to compile — if it doesn't yet because of the other modules, proceed to Tasks 2–7 and run this again after Task 7).

- [ ] **Step 3: Commit**

```bash
git add seer-cli/src/tui/action.rs
git commit -m "feat(tui): add FetchReq, InputMode::Field, and lens-data/msg variants"
```

---

## Task 2: `data::fetch(FetchReq)`

**Files:** Modify `seer-cli/src/tui/data.rs`

- [ ] **Step 1: Replace `data.rs`**

```rust
//! Async data layer: run a parameterized `FetchReq` against seer-core.
//! The only module coupled to seer-core's network clients.

use seer_core::RecordType;

use crate::tui::action::{FetchReq, LensData};

fn e(e: seer_core::SeerError) -> String {
    e.to_string()
}

pub async fn fetch(req: FetchReq) -> Result<LensData, String> {
    match req {
        FetchReq::Overview(d) => seer_core::SmartLookup::new()
            .lookup(&d)
            .await
            .map(|r| LensData::Overview(Box::new(r)))
            .map_err(e),
        FetchReq::Whois(d) => seer_core::WhoisClient::new()
            .lookup(&d)
            .await
            .map(|r| LensData::Whois(Box::new(r)))
            .map_err(e),
        FetchReq::RdapDomain(d) => seer_core::RdapClient::new()
            .lookup_domain(&d)
            .await
            .map(|r| LensData::Rdap(Box::new(r)))
            .map_err(e),
        FetchReq::RdapIp(ip) => seer_core::RdapClient::new()
            .lookup_ip(&ip)
            .await
            .map(|r| LensData::Rdap(Box::new(r)))
            .map_err(e),
        FetchReq::RdapAsn(asn) => seer_core::RdapClient::new()
            .lookup_asn(asn)
            .await
            .map(|r| LensData::Rdap(Box::new(r)))
            .map_err(e),
        FetchReq::Dns {
            domain,
            record_type,
            nameserver,
        } => seer_core::DnsResolver::new()
            .resolve(&domain, record_type, nameserver.as_deref())
            .await
            .map(LensData::Dns)
            .map_err(e),
        FetchReq::Dnssec(d) => seer_core::DnssecChecker::new()
            .check(&d)
            .await
            .map(|r| LensData::Dnssec(Box::new(r)))
            .map_err(e),
        FetchReq::Compare {
            domain,
            record_type,
            a,
            b,
        } => seer_core::dns::DnsComparator::new()
            .compare(&domain, record_type, &a, &b)
            .await
            .map(|r| LensData::Compare(Box::new(r)))
            .map_err(e),
        FetchReq::Ssl(d) => seer_core::SslChecker::new()
            .check(&d)
            .await
            .map(|r| LensData::Ssl(Box::new(r)))
            .map_err(e),
        FetchReq::Status(d) => seer_core::StatusClient::new()
            .check(&d)
            .await
            .map(|r| LensData::Status(Box::new(r)))
            .map_err(e),
        FetchReq::Prop(d) => seer_core::dns::PropagationChecker::new()
            .check(&d, RecordType::A)
            .await
            .map(|r| LensData::Prop(Box::new(r)))
            .map_err(e),
        FetchReq::Reverse(ip) => seer_core::DnsResolver::new()
            .resolve(&ip, RecordType::PTR, None)
            .await
            .map(LensData::Reverse)
            .map_err(e),
        FetchReq::Avail(d) => seer_core::AvailabilityChecker::new()
            .check(&d)
            .await
            .map(|r| LensData::Avail(Box::new(r)))
            .map_err(e),
        // lookup_tld is async + infallible.
        FetchReq::Tld(t) => Ok(LensData::Tld(Box::new(seer_core::lookup_tld(&t).await))),
        FetchReq::Diff { a, b } => seer_core::DomainDiffer::new()
            .diff(&a, &b)
            .await
            .map(|r| LensData::Diff(Box::new(r)))
            .map_err(e),
        FetchReq::Watch => {
            let wl = seer_core::Watchlist::load();
            Ok(LensData::Watch(Box::new(
                seer_core::check_watchlist(&wl.domains).await,
            )))
        }
        FetchReq::History => {
            let h = tokio::task::spawn_blocking(seer_core::LookupHistory::load)
                .await
                .map_err(|err| err.to_string())?;
            let mut flat: Vec<seer_core::HistoryEntry> =
                h.entries.into_values().flatten().collect();
            flat.sort_by(|x, y| y.timestamp.cmp(&x.timestamp));
            Ok(LensData::History(flat))
        }
    }
}
```

- [ ] **Step 2: Verify**

Run: `cargo build -p seer-cli 2>&1 | grep -E "error" | grep "data.rs" | head`
Expected: NO errors originating in `data.rs` (other modules still error until Tasks 3–7). If `data.rs` reports a signature mismatch, fix it against the API reference above and report what differed.

- [ ] **Step 3: Commit**

```bash
git add seer-cli/src/tui/data.rs
git commit -m "feat(tui): data::fetch handles all FetchReq variants"
```

---

## Task 3: Migrate `app.rs` to `FetchReq`, add `Panes`, `Field` routing, stream + pane-key delegation

**Files:** Modify `seer-cli/src/tui/app.rs`

This is the largest task. It (a) replaces `Action::Fetch { lens, domain }` construction with `FetchReq`, (b) keys `states`/`Msg::Data` by `String`, (c) replaces `InputMode::EditDomain` handling with `InputMode::Field { target, buf }`, (d) adds a `panes: Panes` field and delegates pane-focused keys to the active component when a lens is interactive, and (e) routes streaming `Msg`s to the Follow/Bulk components.

- [ ] **Step 1: Update the test module first (TDD — these encode the new contract)**

Replace the `#[cfg(test)] mod tests` block in `app.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

    fn key(app: &mut App, code: KeyCode) -> Vec<Action> {
        app.update(Msg::Input(Event::Key(KeyEvent::new(code, KeyModifiers::NONE))))
    }

    #[test]
    fn new_starts_on_overview_nav_focus() {
        let app = App::new(None);
        assert_eq!(app.lens, 0);
        assert_eq!(app.focus, Focus::Nav);
        assert!(!app.should_quit);
    }

    #[test]
    fn startup_with_domain_emits_overview_fetch() {
        let mut app = App::new(Some("example.com".into()));
        let actions = app.take_startup_actions();
        assert!(matches!(
            actions.as_slice(),
            [Action::Fetch(FetchReq::Overview(_))]
        ));
    }

    #[test]
    fn number_jump_to_whois_fetches_whois() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let actions = key(&mut app, KeyCode::Char('2'));
        assert_eq!(app.lens, 1);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Fetch(FetchReq::Whois(_)))));
    }

    #[test]
    fn editing_target_field_enter_fetches() {
        let mut app = App::new(None);
        key(&mut app, KeyCode::Char('/'));
        assert!(matches!(
            app.input_mode,
            InputMode::Field { target: EditTarget::Target, .. }
        ));
        for c in "acme.io".chars() {
            key(&mut app, KeyCode::Char(c));
        }
        let actions = key(&mut app, KeyCode::Enter);
        assert_eq!(app.domain.as_deref(), Some("acme.io"));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Fetch(FetchReq::Overview(_)))));
    }

    #[test]
    fn data_message_keyed_by_lens_string_stores_state() {
        let mut app = App::new(None);
        app.update(Msg::Data {
            lens: "dns".into(),
            result: Ok(LensData::Dns(vec![])),
        });
        let dns_idx = crate::tui::lenses::find_by_cmd_or_key("dns").unwrap();
        assert!(matches!(app.state_of(dns_idx), LensState::Loaded(_)));
    }

    #[test]
    fn r_toggles_raw_format() {
        let mut app = App::new(None);
        assert_eq!(app.format, seer_core::output::OutputFormat::Human);
        key(&mut app, KeyCode::Char('r'));
        assert_eq!(app.format, seer_core::output::OutputFormat::Json);
    }

    #[test]
    fn tick_clears_expired_toast() {
        let mut app = App::new(None);
        app.set_toast("ok", "hi");
        for _ in 0..40 {
            app.update(Msg::Tick);
        }
        assert!(app.toast.is_none());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p seer-cli app:: 2>&1 | head`
Expected: compile errors (old `Action::Fetch { lens, domain }`, `Msg::Data { lens: usize }`, `EditDomain`).

- [ ] **Step 3: Apply the implementation changes**

Apply these precise edits to the non-test part of `app.rs`:

**(a)** Update imports: change the action import to
`use crate::tui::action::{Action, EditTarget, FetchReq, Focus, InputMode, LensData, LensState, Msg};`
and add `use crate::tui::panes::{PaneOutcome, Panes};` and `use seer_core::RecordType;`.

**(b)** Add a `panes: Panes` field to `struct App` (after `toast`), and initialize `panes: Panes::default(),` in `App::new`. Keep `states: HashMap<&'static str, LensState>` keyed by the lens `key`.

**(c)** Replace `fetch_current` so it returns `Option<Action>` built from a `FetchReq` for the current lens, using the current domain. Map each implemented lens key to its default `FetchReq`:

```rust
    fn fetch_current(&mut self) -> Option<Action> {
        let lens = self.current_lens();
        let (key, implemented) = (lens.key, lens.implemented);
        if !implemented {
            return None;
        }
        if matches!(
            self.states.get(key),
            Some(LensState::Loaded(_) | LensState::Loading)
        ) {
            return None; // cached for this domain
        }
        let domain = self.domain.clone()?;
        let req = self.default_req(key, &domain)?;
        self.states.insert(key, LensState::Loading);
        Some(Action::Fetch(req))
    }

    /// Default fetch request for a lens at `domain` (used by nav/number-jump).
    /// Interactive lenses with no single-domain default return None.
    fn default_req(&self, key: &str, domain: &str) -> Option<FetchReq> {
        let d = domain.to_string();
        Some(match key {
            "overview" => FetchReq::Overview(d),
            "whois" => FetchReq::Whois(d),
            "rdap" => match self.panes.rdap_tab {
                0 => FetchReq::RdapDomain(d),
                1 => FetchReq::RdapIp(self.panes.dns.resolved_ip.clone().unwrap_or(d)),
                _ => return None, // ASN needs explicit :rdap AS…
            },
            "dns" => match self.tab {
                1 => FetchReq::Dnssec(d),
                2 => FetchReq::Compare {
                    domain: d,
                    record_type: RecordType::A,
                    a: self.panes.compare.a.clone(),
                    b: self.panes.compare.b.clone(),
                },
                _ => FetchReq::Dns {
                    domain: d,
                    record_type: RecordType::A,
                    nameserver: self.panes.dns.nameserver(),
                },
            },
            "ssl" => FetchReq::Ssl(d),
            "status" => FetchReq::Status(d),
            "propagation" => FetchReq::Prop(d),
            "reverse" => FetchReq::Reverse(d),
            "avail" => FetchReq::Avail(d),
            "tld" => FetchReq::Tld(self.panes.tld.current()),
            "diff" => return None, // needs a second domain (DiffB field)
            "watch" => FetchReq::Watch,
            "history" => FetchReq::History,
            "follow" | "bulk" => return None, // streaming — started explicitly
            _ => return None,
        })
    }
```

NOTE: `self.panes.dns.resolved_ip`, `self.panes.dns.nameserver()`, `self.panes.compare.a/b`, `self.panes.tld.current()`, and `self.panes.rdap_tab` are defined by the pane components (Tasks 9, 14, 15) and `Panes` (Task 8). Since this task lands before those, **stub `Panes` minimally now** (Step 3f) and flesh it out in Task 8.

**(d)** Replace `set_domain_and_fetch` to clear cached states on domain change (as in the first pass) and call `fetch_current`. Replace every other site that built `Action::Fetch { lens, domain }` with the `fetch_current()`/`default_req` path. The `Msg::Data` arm keys by string:

```rust
            Msg::Data { lens, result } => {
                let key = crate::tui::lenses::lenses()
                    .iter()
                    .position(|l| l.key == lens)
                    .map(|_| lens.clone());
                if let Some(k) = key {
                    // map String -> &'static str via the registry
                    if let Some(reg) = crate::tui::lenses::lenses().iter().find(|l| l.key == k) {
                        self.states.insert(reg.key, match result {
                            Ok(data) => LensState::Loaded(data),
                            Err(e) => LensState::Error(e),
                        });
                    }
                }
                vec![]
            }
```

**(e)** Replace `InputMode::EditDomain` handling with `InputMode::Field`. The `/` key (KeyAction::EditDomain) enters `InputMode::Field { target: EditTarget::Target, buf: <current domain> }`. Generalize `on_edit_key` to `on_field_key(key, target, buf)` that, on `Enter`, routes by `target`:

```rust
    fn on_field_key(&mut self, key: KeyEvent, target: EditTarget, mut buf: String) -> Vec<Action> {
        match key.code {
            KeyCode::Esc => vec![],
            KeyCode::Enter => self.apply_field(target, buf.trim().to_string()),
            KeyCode::Backspace => {
                buf.pop();
                self.input_mode = InputMode::Field { target, buf };
                vec![]
            }
            KeyCode::Char(c) => {
                buf.push(c);
                self.input_mode = InputMode::Field { target, buf };
                vec![]
            }
            _ => {
                self.input_mode = InputMode::Field { target, buf };
                vec![]
            }
        }
    }

    fn apply_field(&mut self, target: EditTarget, value: String) -> Vec<Action> {
        match target {
            EditTarget::Target => {
                if value.is_empty() {
                    return vec![];
                }
                self.lens = 0;
                self.focus = Focus::Nav;
                self.set_domain_and_fetch(&value).into_iter().collect()
            }
            EditTarget::DiffB => {
                self.panes.diff.b = value.to_lowercase();
                match self.domain.clone() {
                    Some(a) if !self.panes.diff.b.is_empty() => {
                        self.states.remove("diff");
                        vec![Action::Fetch(FetchReq::Diff { a, b: self.panes.diff.b.clone() })]
                    }
                    _ => vec![],
                }
            }
            EditTarget::FollowInterval | EditTarget::FollowCount | EditTarget::BulkPath
            | EditTarget::WatchAdd => self.panes.apply_field(target, value, self.domain.clone()),
        }
    }
```

**(f)** In `on_normal_action`, when `focus == Pane` and the current lens is interactive, delegate to the component BEFORE the generic row-nav handling:

```rust
            // (top of on_normal_action, after computing n_lenses)
            // delegate to interactive pane component if applicable
            // (handled in handle_pane_key below; see Step 3g)
```

Add a `handle_pane_key` helper and call it from `on_key` when `focus == Pane` and `self.current_lens()` is one of the interactive keys (tld, dns, compare, diff, follow, bulk, watch, history):

```rust
    fn handle_pane_key(&mut self, key: KeyEvent) -> Option<Vec<Action>> {
        if self.focus != Focus::Pane {
            return None;
        }
        let lens_key = self.current_lens().key;
        let domain = self.domain.clone();
        let outcome = self.panes.handle_key(lens_key, self.tab, key, domain.as_deref())?;
        Some(self.apply_pane_outcome(outcome))
    }

    fn apply_pane_outcome(&mut self, outcome: PaneOutcome) -> Vec<Action> {
        match outcome {
            PaneOutcome::None => vec![],
            PaneOutcome::Fetch(req) => {
                self.states.remove(req.lens_key());
                vec![Action::Fetch(req)]
            }
            PaneOutcome::Action(a) => vec![a],
            PaneOutcome::EditField(target) => {
                let cur = self.panes.field_value(target);
                self.input_mode = InputMode::Field { target, buf: cur };
                vec![]
            }
        }
    }
```

In `on_key`, after the input-mode/help checks and before `event::map`, insert:
`if let Some(actions) = self.handle_pane_key(key) { return actions; }`
— but only when in `Focus::Pane`; nav-focused keys keep the existing behavior. (Place it after the `InputMode`/`help` guards, before `let Some(ka) = event::map(key)`.)

**(g)** Add the streaming Msg arms to `update`:

```rust
            Msg::FollowStep(it) => {
                self.panes.follow.push(*it);
                vec![]
            }
            Msg::FollowDone => {
                self.panes.follow.running = false;
                vec![]
            }
            Msg::BulkStep(r) => {
                self.panes.bulk.push(*r);
                vec![]
            }
            Msg::BulkDone => {
                self.panes.bulk.running = false;
                vec![]
            }
```

- [ ] **Step 4: Add a minimal `Panes` stub so this task compiles**

Create `seer-cli/src/tui/panes/mod.rs` with a minimal stub (fleshed out in Task 8). Add `mod panes;` to `seer-cli/src/tui/mod.rs` module list.

```rust
//! Interactive lens components (stub — completed in Task 8+).
use crossterm::event::KeyEvent;

use crate::tui::action::{Action, EditTarget, FetchReq};

#[derive(Default)]
pub struct Panes {
    pub rdap_tab: usize,
    pub tld: TldState,
    pub dns: DnsState,
    pub compare: CompareState,
    pub diff: DiffState,
    pub follow: FollowState,
    pub bulk: BulkState,
}

pub enum PaneOutcome {
    None,
    Fetch(FetchReq),
    Action(Action),
    EditField(EditTarget),
}

impl Panes {
    pub fn handle_key(
        &mut self,
        _lens_key: &str,
        _tab: usize,
        _key: KeyEvent,
        _domain: Option<&str>,
    ) -> Option<PaneOutcome> {
        None
    }
    pub fn apply_field(
        &mut self,
        _t: EditTarget,
        _v: String,
        _domain: Option<String>,
    ) -> Vec<Action> {
        vec![]
    }
    pub fn field_value(&self, _t: EditTarget) -> String {
        String::new()
    }
}

#[derive(Default)]
pub struct TldState {
    pub idx: usize,
}
impl TldState {
    pub fn current(&self) -> String {
        ".com".to_string()
    }
}
#[derive(Default)]
pub struct DnsState {
    pub ns_idx: usize,
    pub resolved_ip: Option<String>,
}
impl DnsState {
    pub fn nameserver(&self) -> Option<String> {
        None
    }
}
#[derive(Default)]
pub struct CompareState {
    pub a: String,
    pub b: String,
}
#[derive(Default)]
pub struct DiffState {
    pub b: String,
}
#[derive(Default)]
pub struct FollowState {
    pub running: bool,
    pub log: Vec<seer_core::dns::FollowIteration>,
}
impl FollowState {
    pub fn push(&mut self, it: seer_core::dns::FollowIteration) {
        self.log.insert(0, it);
    }
}
#[derive(Default)]
pub struct BulkState {
    pub running: bool,
    pub rows: Vec<seer_core::bulk::BulkResult>,
}
impl BulkState {
    pub fn push(&mut self, r: seer_core::bulk::BulkResult) {
        self.rows.push(r);
    }
}
```

NOTE: `CompareState::a/b` should default to `"8.8.8.8"`/`"1.1.1.1"` — implement `Default` manually in Task 15; the derive gives empty strings for now (Compare just won't auto-fetch until then). This keeps Task 3 compiling.

- [ ] **Step 4b: Migrate `mod.rs::handle_action` to the new `Action`/`Msg` shapes**

In `seer-cli/src/tui/mod.rs`, `Msg::Data` no longer carries `domain` and is keyed by `lens: String`; `Action::Fetch` now wraps a `FetchReq`. Replace `handle_action`:

```rust
fn handle_action(action: Action, tx: &tokio::sync::mpsc::UnboundedSender<Msg>) {
    match action {
        Action::Quit => {}
        Action::Fetch(req) => {
            let tx = tx.clone();
            let lens = req.lens_key().to_string();
            tokio::spawn(async move {
                let result = data::fetch(req).await;
                let _ = tx.send(Msg::Data { lens, result });
            });
        }
        Action::Copy { text, label } => {
            let ok = clipboard::copy(&text).is_ok();
            let _ = tx.send(Msg::CopyResult { ok, label });
        }
        // StartFollow / StartBulk / WriteCsv / WatchMutate / HistoryClear are
        // wired in Tasks 17–20; until then they fall through.
        _ => {}
    }
}
```

The startup loop and main loop already call `handle_action(action, &tx)` (the `_app` param was dropped in the first pass) — no other `mod.rs` change is needed here.

- [ ] **Step 5: Verify**

After Tasks 4–6 also land, run `cargo test -p seer-cli app:: 2>&1 | tail -10` → the 7 app tests pass. For now: `cargo build -p seer-cli 2>&1 | tail -20` and fix any `app.rs`/`panes`/`mod.rs` compile errors. The crate won't fully build until Tasks 4–6 migrate `command.rs`/`raw.rs`/`render.rs` too.

- [ ] **Step 6: Commit**

```bash
git add seer-cli/src/tui/app.rs seer-cli/src/tui/panes/mod.rs seer-cli/src/tui/mod.rs
git commit -m "feat(tui): migrate App to FetchReq, add Panes + field/stream routing"
```

---

## Task 4: Extend the command parser

**Files:** Modify `seer-cli/src/tui/command.rs`

- [ ] **Step 1: Add failing tests** (append to `command.rs` test module)

```rust
    #[test]
    fn parses_new_lens_commands() {
        assert_eq!(parse("reverse 8.8.8.8"),
            CmdOutcome::Lens { lens: "reverse".into(), target: Some("8.8.8.8".into()) });
        assert_eq!(parse("tld .com"),
            CmdOutcome::Lens { lens: "tld".into(), target: Some(".com".into()) });
        assert_eq!(parse("diff a.com b.com"),
            CmdOutcome::Diff { a: "a.com".into(), b: "b.com".into() });
        assert_eq!(parse("compare ex.com 8.8.8.8 1.1.1.1"),
            CmdOutcome::Compare { domain: "ex.com".into(), a: "8.8.8.8".into(), b: "1.1.1.1".into() });
    }
```

- [ ] **Step 2: Run → fails.** `cargo test -p seer-cli command:: 2>&1 | head`

- [ ] **Step 3: Implement.** Add `Diff { a, b }` and `Compare { domain, a, b }` variants to `CmdOutcome`. In `parse`, before the generic lens match, handle `diff` and `compare` with their multi-arg forms:

```rust
        if head == "diff" {
            return match (parts.get(1), parts.get(2)) {
                (Some(a), Some(b)) => CmdOutcome::Diff { a: a.to_string(), b: b.to_string() },
                _ => CmdOutcome::Unknown(line.to_string()),
            };
        }
        if head == "compare" {
            return match (parts.get(1), parts.get(2), parts.get(3)) {
                (Some(d), Some(a), Some(b)) => CmdOutcome::Compare {
                    domain: d.to_string(),
                    a: a.to_string(),
                    b: b.to_string(),
                },
                _ => CmdOutcome::Unknown(line.to_string()),
            };
        }
```

`reverse`/`tld`/`follow`/`bulk` already resolve via the generic `find_by_cmd_or_key` path (they're registry `cmd`s) → `CmdOutcome::Lens { lens, target }`, which the App routes to the lens + seeds its pane. (Follow/Bulk specifics handled by their components.)

- [ ] **Step 4: Run → passes.** Wire `CmdOutcome::Diff`/`Compare` handling in `app.rs::exec_command` (set lens, seed `panes.diff.b` / `panes.compare.a/b`, emit the `FetchReq`).

- [ ] **Step 5: Commit** `git commit -am "feat(tui): parse diff/compare/reverse/tld commands"`

---

## Task 5: `raw.rs` serialize arms for new variants

**Files:** Modify `seer-cli/src/tui/raw.rs`

- [ ] **Step 1: Add arms** to the `serialize` match (these formatter methods exist on `OutputFormatter`):

```rust
        LensData::Reverse(records) => fmt.format_dns(records),
        LensData::Avail(a) => fmt.format_availability(a),
        LensData::Tld(t) => fmt.format_tld(t),
        LensData::Dnssec(r) => fmt.format_dnssec(r),
        LensData::Compare(c) => fmt.format_dns_comparison(c),
        LensData::Diff(d) => fmt.format_diff(d),
        LensData::Watch(w) => fmt.format_watch(w),
        LensData::History(_) => "history (raw view not applicable)".to_string(),
```

- [ ] **Step 2: Verify** `cargo build -p seer-cli 2>&1 | grep raw.rs` → no errors. **Commit** `git commit -am "feat(tui): raw serialize for new lens data"`.

---

## Task 6: `render.rs` — sub-tab routing + dispatch

**Files:** Modify `seer-cli/src/tui/render.rs`, `seer-cli/src/tui/lenses/mod.rs`

- [ ] **Step 1:** In `lenses/mod.rs::render` dispatch, route the new keys to their renderers (signatures defined in Phases 2–4):

```rust
        "reverse" => reverse::render(f, area, theme, data),
        "avail" => avail::render(f, area, theme, data),
        "tld" => tld::render(f, area, theme, &/*panes.tld*/ ..),  // see note
        "diff" => diff::render(f, area, theme, data),
        "follow" => follow::render(f, area, theme, &/*panes.follow*/ ..),
        "bulk" => bulk::render(f, area, theme, &/*panes.bulk*/ ..),
        "watch" => watch::render(f, area, theme, data, focused, sel),
        "history" => history::render(f, area, theme, data, focused, sel),
```

NOTE: renderers needing component state (tld switcher, follow log, bulk rows, dns nameserver chips, compare resolvers) receive it from `&App`/`&Panes`. To keep the dispatch signature simple, **pass `&Panes` into `lenses::render`** (add a `panes: &Panes` param) and let each renderer pull what it needs. Update `render.rs::main_pane` to pass `&app.panes`. Non-interactive renderers ignore it.

- [ ] **Step 2:** In `render.rs`, the DNS lens already shows a sub-tab bar; ensure `rdap` also shows its tab bar (it has `tabs`). The `main_pane` Loaded dispatch already calls `lenses::render(...)`; extend it to pass `&app.panes` and `app.tab`. RDAP IP/ASN: when the rdap tab changes, the App should `Fetch` the tab's `FetchReq` (wire in Task 9).

- [ ] **Step 3:** Build + the existing render smoke test must still pass. **Commit** `git commit -am "feat(tui): route sub-tabs and dispatch new lens renderers"`.

---

# Phase 2 — Static lens renderers (fetch-and-render)

Each task: replace the placeholder `render` in the named file, following the structural pattern of the cited pass-1 lens file (same `panel::block` + `kv::render`/`Table` + `dot`/`gauge` helpers), using the exact fields below; add a `TestBackend` buffer test asserting a known field renders; build; commit. Renderer signature matches the dispatch (`fn render(f:&mut Frame, area:Rect, theme:&Theme, data:&LensData)` unless it needs focus/sel/panes).

## Task 7: Reverse DNS renderer
**File:** `seer-cli/src/tui/lenses/reverse.rs` (template: `lenses/dns.rs`)
- Match `LensData::Reverse(records)`. Title `"Reverse DNS · PTR"`, accent `theme.sapphire`. Table cols `IP / PTR`: for each `DnsRecord` show `r.name` (the in-addr.arpa query name) and `r.format_short()` (the PTR target). If `records` is empty, render a dim "no PTR records".
- Test: build a `LensData::Reverse(vec![DnsRecord{ name:"8.8.8.8".into(), record_type:RecordType::PTR, ttl:300, data:RecordData::PTR{ target:"dns.google".into() } }])`; assert buffer contains `"dns.google"`.
- Commit `feat(tui): reverse DNS lens`.

## Task 8: Flesh out `panes/mod.rs` + Availability renderer
**Files:** `seer-cli/src/tui/panes/mod.rs` (real routing), `seer-cli/src/tui/lenses/avail.rs` (template: `lenses/overview.rs`)
- `panes/mod.rs`: implement `Panes::handle_key` to dispatch by `lens_key` to the per-component `handle_key` (added in later tasks; for now route tld/dns/compare/diff/follow/bulk and return `None` for others), `apply_field`, `field_value`. Keep it a thin router; component logic lives in the component files.
- Availability renderer: match `LensData::Avail(a)`. Big state header (`a.verdict()` → "AVAILABLE"/"REGISTERED"/… colored green when available else peach) + a `kv::render` of `[("domain",a.domain),("available",a.available),("confidence",a.confidence),("method",a.method),("details",a.details.unwrap_or("—"))]`.
- Test: `AvailabilityResult{ domain:"x.com".into(), available:true, confidence:"high".into(), method:"rdap".into(), details:None }` → buffer contains `"available"`.
- Commit `feat(tui): availability lens + panes router`.

## Task 9: RDAP IP/ASN tab rendering
**File:** `seer-cli/src/tui/lenses/rdap.rs`
- Currently tab 0 renders the domain object and tab≠0 shows a placeholder. Replace tab 1 (IP) and tab 2 (ASN) to render from `LensData::Rdap(r)` (same data type; IP/ASN responses populate IP/ASN fields on `RdapResponse`): IP → `kv` of `handle, name, start_address, end_address, ip_version, country, parent_handle, status.join(", ")`; ASN → `kv` of `handle, name, start_autnum, end_autnum, country, status`. When the RDAP tab changes (`[`/`]`), the App emits `FetchReq::RdapIp(<target's resolved A>)` / requires `:rdap AS…` for ASN — wire `panes.rdap_tab` to mirror `app.tab` and trigger the tab's `default_req` on tab change.
- Test: construct a minimal `RdapResponse` with `handle=Some("AS15169")`, `name=Some("GOOGLE")`, render tab 2 → buffer contains `"GOOGLE"`. (Build the struct with `..Default::default()` only if `RdapResponse: Default`; otherwise construct via `serde_json::from_value(json!({...}))` since all fields are `#[serde(default)]`.)
- Commit `feat(tui): RDAP IP and ASN tabs`.

## Task 10: DNSSEC tab renderer
**File:** `seer-cli/src/tui/lenses/dnssec.rs` (new) + route from `dns.rs` tab 1 (template: `lenses/ssl.rs`)
- Move DNS tab-1 rendering to `dnssec::render(f, area, theme, data)`. Match `LensData::Dnssec(r)`. State header from `r.status` (green if `r.chain_valid`/`status=="signed"` else yellow/red) + `kv` `[("enabled",r.enabled),("status",r.status),("chain valid",r.chain_valid),("DS records",r.ds_records.len()),("DNSKEY",r.dnskey_records.len())]` + a chips/line of `r.issues`. Optionally a table of `ds_records` (`key_tag`, `algorithm_name`, `digest_type_name`, matched via `dot` tone ok/fail from `matched_key`).
- Test: `DnssecReport{ domain:"x".into(), enabled:true, has_ds_records:true, has_dnskey_records:true, ds_records:vec![], dnskey_records:vec![], issues:vec![], status:"signed".into(), chain_valid:true }` → buffer contains `"signed"`.
- `dns.rs` tab 1 calls `dnssec::render`. Commit `feat(tui): DNSSEC tab`.

## Task 11: Diff renderer (data side)
**File:** `seer-cli/src/tui/lenses/diff.rs` (template: `lenses/status.rs`)
- Match `LensData::Diff(d)`. Header `A · {d.domain_a}  ⇄  B · {d.domain_b}`. Then `kv`-style rows comparing each field, coloring the value yellow when the pair differs: registrar/organization/created/expires from `d.registration` (each is `(Option<String>,Option<String>)`), A-record + nameservers + resolves from `d.dns`, issuer/valid_until/days_remaining/is_valid from `d.ssl`. Render as a 3-column table `FIELD | A | B` with a same/diff `dot`.
- Test: build a `DomainDiff` with `domain_a:"a.com"`, `domain_b:"b.com"` and trivial sub-structs (all fields present per the API reference) → buffer contains `"a.com"` and `"b.com"`.
- Commit `feat(tui): diff lens render`.

## Task 12: TLD renderer (data side)
**File:** `seer-cli/src/tui/lenses/tld.rs` (template: `lenses/whois.rs`)
- Receives `&Panes` (for the switcher chips — rendered in Task 14) and `data`. Match `LensData::Tld(t)`: `kv` `[("tld",t.tld),("type",t.tld_type),("whois",t.whois_server.unwrap_or("—")),("rdap",t.rdap_url.unwrap_or("—")),("registry",t.registry_url.unwrap_or("—"))]`.
- Test: `TldInfo{ tld:".com".into(), whois_server:Some("whois.verisign-grs.com".into()), rdap_url:None, registry_url:None, tld_type:"gTLD".into() }` → buffer contains `"whois.verisign-grs.com"`.
- Commit `feat(tui): TLD info lens render`.

## Task 13: Watchlist + History renderers (view)
**Files:** `seer-cli/src/tui/lenses/watch.rs`, `seer-cli/src/tui/lenses/history.rs` (template: `lenses/propagation.rs` table)
- Watch: match `LensData::Watch(w)`; table cols `DOMAIN | EXPIRES(d) | SSL(d) | HTTP | ⚑` over `w.results`, coloring days red/yellow by threshold; hint `"a add · d remove · ↵ open"`. Selectable rows (`focused`, `sel`).
- History: match `LensData::History(entries)`; table cols `WHEN | DOMAIN | SOURCE | RESULT` over `entries` (`e.timestamp` formatted, `e.domain`, `e.result.is_rdap()?"RDAP":e.result.is_whois()?"WHOIS":"—"`, `e.result.registrar().unwrap_or("—")`); hint `"↵ replay · c clear"`. Selectable rows.
- `row_count()` in `app.rs`: add `LensData::Watch`/`History`/`Reverse` arms returning their lengths.
- Tests: Watch with one `WatchResult{domain:"x.com",..}` → buffer `"x.com"`; History view: empty list renders without panic.
- Commit `feat(tui): watchlist and history list views`.

---

# Phase 3 — Interactive components

## Task 14: TLD switcher component
**Files:** `seer-cli/src/tui/panes/tld.rs`, wire into `panes/mod.rs` + `lenses/tld.rs`
- `TldState { idx: usize }` over a const list `[".com",".net",".org",".io",".dev",".app",".co"]`. `current()` returns the selected. `handle_key`: `j`/`k`/`h`/`l`/`[`/`]` cycle `idx` and return `PaneOutcome::Fetch(FetchReq::Tld(current()))`. Render switcher chips above the KV (selected chip uses `theme.mauve`/on-style).
- Tests: cycling `idx` wraps; `handle_key('l')` returns `Fetch(Tld(...))`.
- Commit `feat(tui): TLD switcher`.

## Task 15: DNS nameserver chips + custom NS + Compare resolver pickers
**Files:** `seer-cli/src/tui/panes/dns.rs`, `seer-cli/src/tui/panes/compare.rs`, `lenses/dns.rs`, `lenses/compare.rs`
- `DnsState { ns_idx, resolved_ip }`: `nameserver()` maps `ns_idx` over `[None("system"), Some("8.8.8.8"), Some("1.1.1.1")]`; `handle_key` on the Records tab cycles `ns_idx` and returns `Fetch(FetchReq::Dns{ domain, A, nameserver })`. Render the chips (`system | 8.8.8.8 | 1.1.1.1`) above the records table (the pass-1 mock had these).
- `CompareState`: manual `Default` → `a:"8.8.8.8"`, `b:"1.1.1.1"`. `compare.rs` renderer: match `LensData::Compare(c)`; header `A · {c.server_a.nameserver} vs B · {c.server_b.nameserver}` + diff summary (`c.matches`/`only_in_a`/`only_in_b`); table of records with match/differ `dot`. `handle_key` cycles A/B among common resolvers and returns `Fetch(Compare{...})`.
- Tests: `DnsState::nameserver()` mapping; `CompareState` default resolvers; compare render shows a resolver IP.
- Commit `feat(tui): DNS nameserver chips and compare resolver pickers`.

## Task 16: Diff second-domain field
**Files:** `seer-cli/src/tui/panes/diff.rs`, `lenses/diff.rs`
- `DiffState { b: String }`. In `diff.rs` render, when no diff data yet, show an editable B-field prompt; pressing `e`/`i` (or `↵`) enters `InputMode::Field { target: DiffB }` (component returns `PaneOutcome::EditField(EditTarget::DiffB)`). `Panes::field_value(DiffB)` returns `self.diff.b`; `apply_field(DiffB,..)` is handled in `app.rs::apply_field` (Task 3e) which emits the `Diff` fetch.
- Test: `handle_key('e')` on diff returns `EditField(DiffB)`.
- Commit `feat(tui): diff second-domain input`.

## Task 17: Watchlist actions (add/remove/open)
**Files:** `seer-cli/src/tui/panes/watch.rs`, wire `lenses/watch.rs` + `app.rs`
- `handle_key` on watch (pane-focused): `a` → `PaneOutcome::EditField(EditTarget::WatchAdd)`; `d` → `PaneOutcome::Action` that removes `selected` domain (`Watchlist::load().remove(&d).save()`), then re-`Fetch(Watch)`; `↵` → load selected domain into Overview (`PaneOutcome::Action` setting target — model as `FetchReq::Overview(domain)` + the App switches to lens 0). `apply_field(WatchAdd, value)`: `Watchlist::load().add(&value)?.save()` then `Fetch(Watch)`. Persisting uses `Watchlist::save()` (blocking — wrap in `spawn_blocking` inside the data layer, OR perform synchronously in `apply_field` since it's local file I/O; prefer a small `Action::WatchMutate` handled in `mod.rs` to keep `App` pure of I/O). Implement as `Action::WatchMutate { add: Option<String>, remove: Option<String> }` handled in `mod.rs::handle_action` (spawn_blocking the load/mutate/save, then send `Msg::Data` for "watch").
- Tests: `handle_key('a')` → `EditField(WatchAdd)`; `handle_key('d')` with a selection → an `Action` mutating the watchlist.
- Commit `feat(tui): watchlist add/remove/open`.

## Task 18: History actions (replay/clear)
**Files:** `seer-cli/src/tui/panes/history.rs`, wire `lenses/history.rs` + `app.rs`/`mod.rs`
- `handle_key` on history: `↵` → load selected entry's domain into Overview; `c` → `Action::HistoryClear` handled in `mod.rs` (spawn_blocking `LookupHistory::load().clear()/save()`), then re-`Fetch(History)`.
- Test: `handle_key('c')` → `Action::HistoryClear`.
- Commit `feat(tui): history replay/clear`.

---

# Phase 4 — Streaming subsystems

## Task 19: Follow component + streaming + render
**Files:** `seer-cli/src/tui/panes/follow.rs`, `lenses/follow.rs`, `mod.rs::handle_action`, `app.rs`
- `FollowState { interval_secs:u64=30, count:usize=20, running:bool, log:Vec<FollowIteration>, total:usize }`. `handle_key`: `s`/`↵` → `PaneOutcome::Action(Action::StartFollow(FollowParams{ domain, iterations:count, interval_secs }))` (resets log, sets running); `i` → `EditField(FollowInterval)`; `n` → `EditField(FollowCount)`; `x` → stop (a cancel — for v1, simply set `running=false`; full cancel via the `watch::Receiver` is optional).
- `mod.rs::handle_action` for `Action::StartFollow(p)`: build `FollowConfig::new(p.iterations, p.interval_secs as f64 / 60.0)?.with_changes_only(false)`; spawn `DnsFollower::new().follow(&p.domain, RecordType::A, None, config, Some(cb), None)` where `cb = Arc::new(move |it| { let _ = tx.send(Msg::FollowStep(Box::new(it.clone()))); })`; on completion `tx.send(Msg::FollowDone)`.
- `lenses/follow.rs render(f, area, theme, &panes.follow)`: top panel with a `gauge` (`log.len()/count`) + interval/count + running spinner; bottom panel a newest-first table of `log` (`#`, `timestamp`, `records.first().format_short()`, changed→`dot` warn "CHANGED" else ok "no change").
- Tests: `FollowState::push` prepends; `handle_key('s')` returns `StartFollow` with the configured count; render with a couple of injected iterations shows a record.
- Commit `feat(tui): follow live-monitor lens (streaming)`.

## Task 20: Bulk component + streaming + render + CSV export
**Files:** `seer-cli/src/tui/panes/bulk.rs`, `lenses/bulk.rs`, `mod.rs::handle_action`, `app.rs`
- `BulkState { source:String, op:String="lookup", path:String, domains:Vec<String>, rows:Vec<BulkResult>, running:bool, note:Option<String> }` + built-in sample lists (a small const map like the mock). `handle_key`: cycle `op` among `[lookup,status,dig,avail,info]`; `f` → `EditField(BulkPath)`; switch source among samples; `↵`/`r` → start (build `domains` from the chosen source/sample) → `Action::StartBulk(BulkParams{ op, domains })`; `e` → `Action::WriteCsv{ path:"seer-bulk-<op>.csv", contents:<csv built from rows> }`.
- `apply_field(BulkPath, value)`: read the file (`std::fs::read_to_string`), `parse_domains_from_file`, set `domains`, auto-start.
- `mod.rs::handle_action` for `Action::StartBulk(p)`: pick `execute_lookup/status/avail/info` (and `execute_dns(_, A)` for "dig"); since these return the whole `Vec<BulkResult>` (not per-row streaming), spawn a task that calls it and sends one `Msg::BulkStep` per result then `Msg::BulkDone`. (The convenience methods don't expose a per-row callback; the lower-level `execute(ops, Some(progress))` does, but for v1 the post-hoc per-row emit is sufficient and simpler.) For `Action::WriteCsv`, `std::fs::write` in `spawn_blocking`, then a toast via `Msg::CopyResult`-style note.
- `lenses/bulk.rs render(f, area, theme, &panes.bulk)`: source/op switcher row + path field + `gauge` (`rows.len()/domains.len()`) + a results table (per-op columns) + the note.
- Tests: `op` cycles; `handle_key('e')` returns `WriteCsv`; CSV builder produces a header + one line per row; render with injected rows shows a domain.
- Commit `feat(tui): bulk lens with streaming results + CSV export`.

---

# Phase 5 — Finish

## Task 21: Full verification, lint, docs, PR
**Files:** Modify `README.md`, `CLAUDE.md`

- [ ] **Step 1:** `cargo test --workspace` (all green), `cargo clippy --workspace -- -D warnings` (clean — resolve any new dead_code by wiring or `#[allow]` with rationale), `cargo fmt --all`.
- [ ] **Step 2:** Update `README.md` (the lens list in the Interactive TUI section: drop "with more on the way" → list all 16; note Follow/Bulk/Diff usage) and `CLAUDE.md` (note `panes/` + that all 16 lenses are wired; FetchReq architecture).
- [ ] **Step 3:** `cargo build --release -p seer-cli`.
- [ ] **Step 4:** Commit `docs(tui): document completed lenses`. Push `git push -u origin claude/seer-tui-completion`; open PR against `main`; monitor CI.

---

## Notes for the executor
- **Compile ordering:** Tasks 1–7 are a connected refactor; the crate won't fully build until Task 6/7 land. Build per-file and rely on `cargo build` after Task 7 for the first green. Tasks 8–20 each keep the crate green (they fill placeholders the dispatch already tolerates).
- **`Msg::Data` is keyed by `String`** now; always resolve to the registry `&'static str` before inserting into `states`.
- **No `unwrap()`/`expect()` in non-test code** (workspace clippy lints). Local file I/O (Watchlist/History/CSV) goes through `spawn_blocking` in `mod.rs`, never in the pure `App`.
- **`RdapResponse`/large structs in tests:** construct via `serde_json::from_value(serde_json::json!({...}))` (all fields are `#[serde(default)]`) when a literal is unwieldy.
- **CI command is `cargo clippy --workspace -- -D warnings`** (no `--all-targets`) — test-only `unwrap()` is not linted; match the existing test style.
- **`tokio::sync::watch`** is available via the `tokio` dep (`sync` feature already enabled in the workspace).
