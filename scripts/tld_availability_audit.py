#!/usr/bin/env python3
"""Audit seer's WHOIS availability detection across every TLD it knows.

For each unique WHOIS server in ``seer-core/src/whois/servers.rs`` this probes
a guaranteed-unregistered domain and replays seer's ``is_available()`` logic.
The ``AVAILABILITY_PATTERNS`` list is parsed straight out of
``seer-core/src/whois/parser.rs``, so the audit always reflects the patterns
the code actually ships — it can't silently drift.

Each server is bucketed as:

* **OK**   - the registry's "available" wording is recognized (high-confidence
  WHOIS detection).
* **MISS** - the server responded but no pattern matched. These fall back to
  the medium-confidence DNS-NXDOMAIN net today; a new pattern would upgrade
  them to high-confidence WHOIS.
* **ERR**  - the WHOIS server was unreachable/blocked (the DNS net is the only
  path for these).

Results are cross-referenced against the IANA RDAP bootstrap: an RDAP-enabled
TLD is already covered by seer's authoritative RDAP-404 path, so the
actionable gaps are the **no-RDAP** TLDs that show up as MISS.

This is a network-heavy, occasional maintenance audit (one WHOIS query each to
~1,100 distinct registry servers) and is intentionally **not** part of CI. Run
it when registries change their WHOIS responses to find new "not found"
wordings worth adding to ``AVAILABILITY_PATTERNS`` (verify any candidate is
unique to not-found bodies — there's a guard test in ``parser.rs``).

Usage::

    python3 scripts/tld_availability_audit.py [--workers N] [--timeout S]
                                              [--probe-label LABEL]
                                              [--out FILE] [--limit N]

Standard library only; no third-party dependencies.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import re
import socket
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PARSER_RS = REPO_ROOT / "seer-core" / "src" / "whois" / "parser.rs"
SERVERS_RS = REPO_ROOT / "seer-core" / "src" / "whois" / "servers.rs"
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"


def parse_availability_patterns(parser_rs: Path) -> list[str]:
    """Extract the AVAILABILITY_PATTERNS string literals from parser.rs so the
    audit replays the exact patterns the code ships.

    The array is interspersed with ``//`` comments that themselves quote
    example wordings (e.g. ``"not available"``), so each line's trailing
    comment is stripped before the string literal is read — otherwise the
    comment text would pollute the pattern list.
    """
    text = parser_rs.read_text(encoding="utf-8")
    m = re.search(r"AVAILABILITY_PATTERNS[^=]*=\s*&\[(.*?)\];", text, re.DOTALL)
    if not m:
        sys.exit(f"could not find AVAILABILITY_PATTERNS in {parser_rs}")
    patterns: list[str] = []
    for line in m.group(1).splitlines():
        code = re.sub(r"//.*$", "", line)  # drop trailing line comment
        patterns.extend(re.findall(r'"((?:[^"\\]|\\.)*)"', code))
    return patterns


def parse_whois_servers(servers_rs: Path) -> dict[str, str]:
    """Extract the tld -> whois-server map from servers.rs."""
    text = servers_rs.read_text(encoding="utf-8")
    return dict(re.findall(r'm\.insert\("([^"]+)",\s*"([^"]+)"\)', text))


def load_rdap_tlds() -> set[str] | None:
    """Set of TLDs with an RDAP server per the IANA bootstrap, or None if the
    bootstrap can't be fetched (the audit still runs, just without the
    RDAP-coverage cross-reference)."""
    try:
        with urllib.request.urlopen(RDAP_BOOTSTRAP_URL, timeout=20) as resp:
            data = json.load(resp)
    except Exception as exc:  # noqa: BLE001 - best-effort enrichment
        print(f"WARN: could not load RDAP bootstrap ({exc}); "
              "RDAP coverage will show as 'unknown'", file=sys.stderr)
        return None
    tlds: set[str] = set()
    for service in data.get("services", []):
        if service and isinstance(service[0], list):
            tlds.update(t.lower() for t in service[0])
    return tlds


def seer_detects(raw: str, patterns: list[str]) -> str | None:
    """Replicate WhoisResponse::is_available(): skip blank/#/% lines,
    lowercase and collapse internal whitespace, then substring-match the
    pattern list. Returns the matched pattern, or None."""
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "%")):
            continue
        norm = " ".join(stripped.lower().split())
        for pat in patterns:
            if pat in norm:
                return pat
    return None


def first_lines(raw: str, n: int = 2) -> str:
    out = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith(("%", "#")):
            out.append(stripped[:88])
            if len(out) >= n:
                break
    return " | ".join(out)


def whois_query(server: str, query: str, timeout: float) -> str:
    sock = socket.create_connection((server, 43), timeout=timeout)
    try:
        sock.sendall((query + "\r\n").encode())
        data = b""
        while len(data) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data.decode("utf-8", "replace")
    finally:
        sock.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workers", type=int, default=60, help="concurrent probes (default 60)")
    ap.add_argument("--timeout", type=float, default=6.0, help="per-server timeout seconds (default 6)")
    ap.add_argument("--probe-label", default="seerprobe-x7q2z9k4",
                    help="second-level label of the unregistered probe domain")
    ap.add_argument("--out", type=Path, default=None,
                    help="write the full per-server TSV to this path")
    ap.add_argument("--limit", type=int, default=None,
                    help="only probe the first N servers (for a quick smoke run)")
    args = ap.parse_args()

    patterns = parse_availability_patterns(PARSER_RS)
    tld_server = parse_whois_servers(SERVERS_RS)
    server_tlds: dict[str, list[str]] = collections.defaultdict(list)
    for tld, server in tld_server.items():
        server_tlds[server].append(tld)
    rdap_tlds = load_rdap_tlds()

    servers = list(server_tlds.keys())
    if args.limit:
        servers = servers[: args.limit]

    print(f"AVAILABILITY_PATTERNS parsed from parser.rs: {len(patterns)}")
    print(f"TLDs in WHOIS_SERVERS: {len(tld_server)} | unique servers: {len(server_tlds)}"
          f"{f' (probing {len(servers)})' if args.limit else ''} | "
          f"RDAP-enabled TLDs: {len(rdap_tlds) if rdap_tlds is not None else 'unknown'}")

    def no_rdap_count(server: str) -> int | None:
        if rdap_tlds is None:
            return None
        return sum(1 for t in server_tlds[server] if t not in rdap_tlds)

    def probe(server: str) -> dict:
        tld = min(server_tlds[server], key=len)  # short representative TLD
        domain = f"{args.probe_label}.{tld}"
        try:
            raw = whois_query(server, domain, args.timeout)
        except Exception as exc:  # noqa: BLE001 - record, don't crash the sweep
            return dict(server=server, tld=tld, status="ERR", detail=type(exc).__name__, line="")
        matched = seer_detects(raw, patterns)
        return dict(server=server, tld=tld,
                    status="OK" if matched else "MISS",
                    detail=matched or "", line=first_lines(raw))

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        rows = list(pool.map(probe, servers))

    ok = [r for r in rows if r["status"] == "OK"]
    miss = [r for r in rows if r["status"] == "MISS"]
    err = [r for r in rows if r["status"] == "ERR"]
    tld_total = lambda rs: sum(len(server_tlds[r["server"]]) for r in rs)  # noqa: E731

    print("\n=== SERVER RESULTS ===")
    print(f"  OK   (wording recognized)  : {len(ok):4} servers ({tld_total(ok)} TLDs)")
    print(f"  MISS (not recognized)      : {len(miss):4} servers ({tld_total(miss)} TLDs)")
    print(f"  ERR  (blocked/unreachable) : {len(err):4} servers ({tld_total(err)} TLDs)")

    def priority(r: dict) -> int:
        n = no_rdap_count(r["server"])
        return -(n if n is not None else len(server_tlds[r["server"]]))

    print("\n=== TOP 'MISS' SERVERS BY NO-RDAP TLDs AFFECTED (high priority) ===")
    print(f"{'server':34} {'#tld':>4} {'#noRDAP':>7}  first-lines")
    for r in sorted(miss, key=priority)[:40]:
        print(f'{r["server"]:34} {len(server_tlds[r["server"]]):4} '
              f'{str(no_rdap_count(r["server"])):>7}  {r["line"][:78]}')

    print("\n=== 'MISS' first-line wording buckets (candidates for new patterns) ===")
    buckets: collections.Counter = collections.Counter()
    for r in miss:
        key = r["line"].split(" | ")[0][:48].lower()
        buckets[key] += len(server_tlds[r["server"]])
    for line, count in buckets.most_common(25):
        print(f"  {count:4} TLDs  {line!r}")

    print("\n=== ERR (blocked/unreachable) buckets ===")
    for detail, count in collections.Counter(r["detail"] for r in err).most_common():
        print(f"  {count:4} servers  {detail}")

    if args.out:
        with args.out.open("w", encoding="utf-8") as fh:
            fh.write("status\tdetail\tserver\trep_tld\tn_tlds\tn_tlds_no_rdap\tfirst_lines\n")
            for r in sorted(rows, key=lambda r: (r["status"], r["server"])):
                fh.write(f'{r["status"]}\t{r["detail"]}\t{r["server"]}\t{r["tld"]}\t'
                         f'{len(server_tlds[r["server"]])}\t{no_rdap_count(r["server"])}\t'
                         f'{r["line"]}\n')
        print(f"\nFull per-server detail written to {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
