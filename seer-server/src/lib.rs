//! `seer-server`: seer-core's lookups over HTTP, as JSON, for websites.
//!
//! It runs alongside the Python `seer-api` and serves the single-domain
//! operations; bulk jobs, SSE streams and MCP stay there. Callers are
//! anonymous (the public routes, when `[server] public = true`) or keyed
//! (`Authorization: Bearer $SEER_API_KEY`).
//!
//! Module map: [`error`] turns failures into `{"detail": …}` responses.

pub mod error;

#[cfg(test)]
mod test_support;
