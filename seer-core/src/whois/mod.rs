mod client;
mod parser;
pub mod parsers;
mod servers;

pub use client::WhoisClient;
pub use parser::WhoisResponse;
pub use servers::{get_registry_url, get_tld};
