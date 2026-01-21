mod client;
mod parser;
mod servers;

pub use client::WhoisClient;
pub use parser::WhoisResponse;
pub use servers::{get_registry_url, get_tld};
