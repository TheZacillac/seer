use seer_core::output::OutputFormat;

#[derive(Debug, Clone)]
pub struct CommandContext {
    pub output_format: OutputFormat,
}

impl CommandContext {
    pub fn new() -> Self {
        let config = seer_core::SeerConfig::load();
        let output_format = config.output_format.parse().unwrap_or_default();
        Self { output_format }
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
