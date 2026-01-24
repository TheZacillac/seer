# Display Module

Display utilities for the CLI including loading spinners.

## Overview

This module provides UI utilities for the command-line interface:
- Loading spinners for async operations
- Consistent progress indication

## Files

| File | Description |
|------|-------------|
| `mod.rs` | Module exports |
| `spinner.rs` | Loading spinner implementation |

## Public API

### Spinner

Animated loading spinner for async operations.

```rust
use std::sync::Arc;

pub struct Spinner {
    // Internal state
}

impl Spinner {
    /// Create and start a new spinner with a message
    pub fn new(message: &str) -> Arc<Self>;

    /// Update the spinner message
    pub fn set_message(&self, message: &str);

    /// Stop the spinner and clear the line
    pub fn finish(&self);
}
```

## Usage Examples

### Basic Spinner

```rust
use crate::display::Spinner;

let spinner = Spinner::new("Looking up domain...");

// Perform long operation
let result = lookup_domain().await;

spinner.finish();
println!("Result: {:?}", result);
```

### Updating Message

```rust
let spinner = Spinner::new("Starting lookup...");

// Update progress
spinner.set_message("Querying RDAP...");

// Continue operation
let rdap = query_rdap().await;

spinner.set_message("Falling back to WHOIS...");

let whois = query_whois().await;

spinner.finish();
```

### With Arc for Callbacks

```rust
use std::sync::Arc;

let spinner = Arc::new(Spinner::new("Processing..."));

// Pass to callback
let spinner_clone = spinner.clone();
let callback = move |message: &str| {
    spinner_clone.set_message(message);
};

process_with_callback(callback).await;

spinner.finish();
```

## Implementation Details

The spinner:
- Runs in a background thread
- Displays animated characters (⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏)
- Updates in place using carriage return
- Clears the line when finished
- Uses ANSI escape codes for terminal control

## Integration with Commands

The CLI uses spinners for all long-running operations:

```rust
async fn execute_lookup(domain: &str) {
    let spinner = Spinner::new(&format!("Looking up {}", domain));

    let result = smart_lookup(domain).await;

    spinner.finish();

    match result {
        Ok(data) => println!("{}", format_result(&data)),
        Err(e) => eprintln!("Error: {}", e),
    }
}
```
