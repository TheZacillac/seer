//! Compare lens runtime state. Its resolvers are options (`options::COMPARE`).

#[derive(Default)]
pub struct CompareState {
    /// Domain set by `:compare <domain> …`; `None` compares the session
    /// domain. Reset when the session domain changes.
    pub domain: Option<String>,
}

impl CompareState {
    /// The domain being compared: the `:compare` override, else `session`.
    pub fn effective_domain(&self, session: Option<&str>) -> Option<String> {
        self.domain.clone().or_else(|| session.map(str::to_string))
    }
}
