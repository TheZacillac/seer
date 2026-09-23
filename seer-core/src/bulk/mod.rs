//! Concurrent bulk execution over a list of domains.
//!
//! [`BulkExecutor`] fans a batch of [`BulkOperation`]s out with bounded
//! concurrency (default 10, clamped to 1–50) and paces dispatch with a
//! slot-based rate limiter (default 100 ms between starts). A failed operation
//! never stops the batch: each [`BulkResult`] carries its own success flag,
//! error and duration. Progress and per-result callbacks let a UI stream rows
//! as they complete.
//!
//! [`parse_domains_from_file`] reads plain-text or CSV lists (first column;
//! blank lines, `#` comments, a UTF-8 BOM and dotless entries such as a
//! header row are skipped).

mod executor;

pub use executor::{
    parse_domains_from_file, BulkExecutor, BulkOperation, BulkResult, BulkResultData,
    ProgressCallback, ResultCallback,
};
