use seer_core::output::OutputFormat;

#[derive(Debug, Clone)]
pub struct CommandContext {
    pub output_format: OutputFormat,
}

impl CommandContext {
    pub fn new() -> Self {
        Self {
            output_format: OutputFormat::Human,
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
