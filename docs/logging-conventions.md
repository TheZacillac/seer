# Logging Conventions

Project-wide rubric for log-level choice. Applies to all crates in the Arcanum suite.

## Rules

| Level | Rule | When to use |
|-------|------|-------------|
| `error!` | Failure that was silently swallowed | Effectively never. Errors propagate via `Result<T>`. |
| `warn!` | Handled degradation that affects the user's result, **or** evidence of misconfig/misuse | "all 4 IANA registries failed", "unsafe WHOIS server rejected", "circular referral", "partial WHOIS read", "lock poisoned (recovering)", "config parse failed, using defaults" |
| `info!` | Notable one-time operational milestone (not per-request) | "bootstrap loaded N/4 registries", "MCP server started on stdio" |
| `debug!` | Useful when troubleshooting; silent by default | per-registry fetch/parse failure when others succeed, retry-attempt notices, stale-cache served after refresh fail, "lookup successful for X" |
| `trace!` | Wire-level detail | "sent WHOIS query of N bytes" |

## Defaults

| Interface | Default level | Override |
|-----------|---------------|----------|
| `seer-cli` | `error` | `ARCANUM_LOG_LEVEL` or `RUST_LOG` |
| `seer-api` | `INFO` | standard Python `logging` config |
| `seer-mcp` | `INFO` | standard Python `logging` config |
| `seer-py` (library) | host-controlled via `pyo3-log` | host Python logger |

## Principles

- **Per-request events at `debug!`.** The default cut should be quiet on a successful run.
- **`warn!` must be actionable or surprising.** If a user can't act on it and it's expected to appear regularly in production, it belongs at `debug!`.
- **One `info!` per lifecycle event.** Bootstrap loads, server starts. Not per-request.
- **Errors propagate, they don't log.** A function that returns `Err(_)` should not also `error!`.
