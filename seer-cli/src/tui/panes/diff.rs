//! Diff lens runtime state. Domain B is an option (`options::DIFF`).

#[derive(Default)]
pub struct DiffState {
    /// Domain A set by `:diff a b`; empty means "the session domain". Reset
    /// when the session domain changes.
    pub a: String,
}

impl DiffState {
    /// Domain A: the `:diff` override, else the session domain.
    pub fn effective_a(&self, session: Option<&str>) -> Option<String> {
        if self.a.is_empty() {
            session.map(str::to_string)
        } else {
            Some(self.a.clone())
        }
    }
}
