# Diff Output Rework — Design

**Date:** 2026-04-17
**Scope:** `HumanFormatter::format_diff` in `seer-core/src/output/human.rs`
**Status:** Approved, ready for implementation plan

## Problem

The current human-readable output of `seer diff <a> <b>` is hard to scan:

- Column headers are missing — the `Diff: a vs b` line appears once and the reader must remember which side is which while scrolling through rows.
- The `|` separator floats with value length, so columns never line up.
- Every row carries equal visual weight; matching and differing rows look identical.
- Multi-value rows (A records, nameservers) are comma-joined onto a single line and wrap unpredictably.

The data model in `seer-core/src/diff.rs` is fine. Only the human renderer needs work. JSON and Markdown renderers are out of scope.

## Goals

1. Readers can tell at a glance which column belongs to which domain.
2. Readers can tell at a glance which rows differ and which match.
3. Long and multi-value content stays inside its column without corrupting alignment.
4. Plain (no-color) output remains legible — information lives in glyphs and layout, not color alone.

## Non-Goals

- No changes to `DomainDiff`, `RegistrationDiff`, `DnsDiff`, or `SslDiff` structs.
- No changes to `JsonFormatter::format_diff` or `MarkdownFormatter::format_diff`.
- No change to which fields are shown or in what order.
- No interactive / paging behavior.

## Layout

Example rendered output:

```
Diff: example.com vs google.com

                      example.com            google.com
                      ──────────────         ─────────────────────
  Registration
    Registrar       ≠ IANA                   MarkMonitor
    Organization    ≠ —                      Google LLC
    Created         ≠ 1995-08-14             1997-09-15
    Expires         ≠ 2026-08-13             2028-09-14

  DNS
    Resolves        = yes                    yes
    A Records       ≠ 93.184.216.34          142.250.185.46
                      93.184.216.35          142.250.185.47
    Nameservers     ≠ a.iana-servers.net     ns1.google.com

  SSL
    Issuer          ≠ DigiCert Inc           Google Trust Services
    Valid Until     ≠ 2025-03-01             2025-02-15
    Days Remaining  ≠ 89                     75
    Valid           = yes                    yes
```

Four logical columns, in order:

1. **Label gutter** — section indent (`    `) plus the field name, padded to the width of the widest field label across every row (so `Registrar`, `Organization`, `A Records`, `Nameservers`, `Valid Until`, `Days Remaining` all line up, regardless of which section they belong to). Section headers are not part of this padding calculation.
2. **Marker gutter** — exactly one glyph (`=` or `≠`) followed by one space. Continuation lines (wrap / multi-value) leave this gutter blank (two spaces).
3. **Column A** — value for `domain_a`, left-justified, padded to the column-A width.
4. **Column B** — value for `domain_b`, left-justified. No trailing pad needed.

A **column-header block** appears once, directly under the `Diff:` header and before the first section, consisting of two lines:

- Line 1: `domain_a` and `domain_b` left-aligned over their respective value columns.
- Line 2: a Unicode box-drawing horizontal rule (`─`) under each name, equal in length to that name's rendered width.

Section headers (`Registration`, `DNS`, `SSL`) are unchanged from today — indent two spaces, rendered with the existing label color, followed by a blank line (no trailing colon in the new layout, since sections are now visually separated by the column structure).

## Column Widths

Two constants drive the layout:

- `LABEL_PAD`: computed at render time as the max label width across all rows (not a constant).
- `COLUMN_CAP`: a `const usize = 40`. Hard cap for each value column.

Width computation for the value columns, on each render:

1. Compute `max_a` = widest single-line token in column A across all rows (including multi-value items rendered individually).
2. Compute `max_b` similarly.
3. `column_width = min(max(max_a, max_b, domain_a.width(), domain_b.width()), COLUMN_CAP)`.
4. Both columns use `column_width` so they stay symmetric.

"Widest token" is measured in display cells. We assume ASCII for now; if non-ASCII arrives, fall back to `str::chars().count()`. Grapheme-cluster width is out of scope.

## Wrapping

When a scalar value exceeds `COLUMN_CAP`:

- Break at the last whitespace boundary at or before `COLUMN_CAP`. If no whitespace exists in that window (e.g. a long nameserver), hard-break at `COLUMN_CAP`.
- Emit continuation lines in the same column. Continuation lines have an empty label gutter (spaces of width `LABEL_PAD`) and an empty marker gutter (`"  "`).
- The other column's value sits on the first row only; subsequent continuation rows leave that column blank unless that side also wrapped.

When both sides wrap, lines align row-by-row: row 0 of column A next to row 0 of column B, row 1 next to row 1, etc. Shorter side is padded with blank lines.

## Multi-Value Fields

`a_records` and `nameservers` are `(Vec<String>, Vec<String>)`. Rendering:

- Each list is displayed one item per line in its column.
- Row 0 gets the label and marker; rows 1..N get empty label gutter and empty marker gutter.
- Lists align by index — index 0 of column A next to index 0 of column B — not by value. This keeps the output deterministic and simple. Readers comparing unordered sets can still spot identity via the `=` marker.
- If one list is longer than the other, the shorter side pads with blank lines.

A single list item that exceeds `COLUMN_CAP` wraps per the scalar rule above.

## Equality Rules

A row is marked `=` (green) when both sides are equal under these rules; otherwise `≠` (red):

- `Option<String>`: `None == None`, `Some(a) == Some(b)` iff string-equal after trim. Empty strings treated as `None`.
- `Option<i64>`: direct equality, `None == None`.
- `bool`: direct equality.
- `Vec<String>` (lists): compared as sorted sets — `a.sorted() == b.sorted()`. Whitespace trimmed per item; empty items dropped.

Equality is computed once per row before emitting.

## Colors

Reuse existing `HumanFormatter` helpers (`self.success`, `self.error`, `self.label`, `self.value`, plus a dim helper if one exists — otherwise add a local `dim()` using the Catppuccin overlay color).

- `=` marker and all value text on a matching row → green.
- `≠` marker and all value text on a differing row → red.
- Section headers and field labels → existing label color.
- Column-header domain names and the `─` rule → existing label color.
- `—` (em dash) for empty/None values → dim, regardless of row match/mismatch.

Plain mode (no-color): color codes are already no-ops via the existing formatter. Glyphs (`=`, `≠`, `—`, `─`) survive, and the ASCII structure remains legible.

## Empty Values

A `None` or empty-string value renders as a single em-dash `—`, dim. This replaces today's literal `N/A`.

## Error / Degenerate Cases

- Both sides fully absent (all `None`, empty lists): render all rows with `—` in both columns, markers all `=`, everything green. Output still has the full structure so the reader sees what was checked.
- Very short domain names (`a.io` vs `b.io`): column widths clamp up to the widest value row, not the domain name, so the layout doesn't collapse.
- Domain names longer than `COLUMN_CAP`: column header wraps under the same rules as value cells.

## Tests

All tests live in `seer-core/src/output/human.rs` under the existing `#[cfg(test)] mod tests`.

1. **Snapshot — mixed matches and diffs.** Build a `DomainDiff` with some matching fields and some differing; assert the rendered string contains the expected column headers, `=` and `≠` markers in the right rows, and aligned columns.
2. **All matching.** Every row renders `=`; no `≠` in output.
3. **All differing.** Every row renders `≠`; no `=` in output.
4. **Long scalar wraps.** A value longer than `COLUMN_CAP` produces a continuation line with empty label and marker gutters.
5. **Multi-value list renders one per line.** Two nameservers per side produce two rows, first row marked, second row continuation.
6. **Set-based list equality.** `["ns1", "ns2"]` vs `["ns2", "ns1"]` marked `=`.
7. **Uneven list lengths.** One side has 3 items, the other has 1; output renders 3 rows, shorter column blank on rows 1 and 2.
8. **Empty values render em-dash.** `None` on both sides → `—` in both columns, row marked `=`.
9. **Plain mode retains glyphs.** With colors disabled, output still contains `=` / `≠` / `—` / `─`.

## Rollout

One PR. No feature flag; the old format is simply replaced. No migration needed because the JSON renderer is unchanged and is what programmatic consumers use.

## Open Questions

None.
