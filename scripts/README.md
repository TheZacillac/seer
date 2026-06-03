# scripts

Maintenance utilities that are **not** part of the build or CI.

## `tld_availability_audit.py`

Audits seer's WHOIS availability detection across every TLD in
`seer-core/src/whois/servers.rs`. For each unique WHOIS server it probes an
unregistered domain and replays `is_available()` (parsing the live
`AVAILABILITY_PATTERNS` out of `parser.rs`), then cross-references the IANA
RDAP bootstrap so RDAP-covered TLDs (handled by the RDAP-404 path) are
separated from no-RDAP gaps where a new WHOIS pattern would help.

Network-heavy (~1,100 one-off WHOIS queries); run occasionally when registries
change their responses. Standard library only.

```sh
python3 scripts/tld_availability_audit.py                 # full run, summary to stdout
python3 scripts/tld_availability_audit.py --out audit.tsv # also dump per-server detail
python3 scripts/tld_availability_audit.py --limit 25      # quick smoke run
```

Candidate "not found" wordings it surfaces should only be added to
`AVAILABILITY_PATTERNS` after confirming they're unique to not-found bodies
(there's a guard test in `parser.rs`).
