//! `seer-server`: seer-core's lookups over HTTP, as JSON, for websites.
//!
//! It runs alongside the Python `seer-api` and serves the single-domain
//! operations; bulk jobs, SSE streams and MCP stay there. Callers are
//! anonymous (the public routes, when `[server] public = true`) or keyed
//! (`Authorization: Bearer $SEER_API_KEY`).
//!
//! Module map: [`settings`] validates the config and runs the startup
//! checks; [`state`] holds the shared seer-core clients; [`routes`] is the
//! route table and its handlers; [`edge`] holds the checks handlers run
//! before calling core; [`app`] builds the router and its layers; [`tier`]
//! decides who may call what; [`error`] turns failures into
//! `{"detail": …}` responses.

pub mod app;
pub mod edge;
pub mod error;
pub mod routes;
pub mod settings;
pub mod state;
pub mod tier;

#[cfg(test)]
mod test_support;
