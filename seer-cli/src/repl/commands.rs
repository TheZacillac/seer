use seer_core::output::OutputFormat;
use seer_core::SeerConfig;

#[derive(Debug, Clone)]
pub struct CommandContext {
    pub output_format: OutputFormat,
    /// User config (`~/.seer/config.toml`) — threaded into client construction
    /// so the REPL honors per-protocol timeouts, nameserver, and bulk
    /// concurrency instead of silently using library defaults.
    pub config: SeerConfig,
}

impl CommandContext {
    pub fn new() -> Self {
        let config = SeerConfig::load();
        let output_format = config.output_format.parse().unwrap_or_default();
        Self {
            output_format,
            config,
        }
    }
}

impl Default for CommandContext {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum CommandResult {
    Continue,
    Exit,
    Error(String),
}
