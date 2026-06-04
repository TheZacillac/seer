//! Raw-output serialization (stub — completed in the raw-view task).
use crate::tui::action::LensData;
use seer_core::output::OutputFormat;

pub fn serialize(_data: &LensData, _format: OutputFormat) -> String {
    String::new()
}
