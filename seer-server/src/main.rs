//! The `seer-server` binary: set up logging, load the config, run the
//! startup checks and serve. Every failure is one line on stderr and exit
//! code 1; nothing here panics or calls `process::exit`.

use std::process::ExitCode;

use seer_core::SeerConfig;
use seer_server::settings::Settings;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    init_logging();
    // Strict: a config file with a typo stops the server instead of
    // silently starting it on defaults.
    let config = match SeerConfig::load_strict() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("seer-server: {error}");
            return ExitCode::FAILURE;
        }
    };
    let settings = match Settings::new(&config.server, std::env::var("SEER_API_KEY").ok()) {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("seer-server: {error}");
            return ExitCode::FAILURE;
        }
    };
    let bind = settings.bind;
    match seer_server::serve(settings, &config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("seer-server: cannot serve on {bind}: {error}");
            ExitCode::FAILURE
        }
    }
}

/// JSON log lines on stdout. The level comes from `ARCANUM_LOG_LEVEL` (the
/// variable the CLI and bindings already use), defaulting to `info`; a
/// value that is not a valid filter falls back to `info`.
fn init_logging() {
    let filter = std::env::var("ARCANUM_LOG_LEVEL")
        .ok()
        .and_then(|level| EnvFilter::try_new(level).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .init();
}
