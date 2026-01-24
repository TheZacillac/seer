# REPL Module

Interactive Read-Eval-Print Loop for Seer.

## Overview

This module implements an interactive shell for Seer with:
- Command parsing and execution
- Tab completion for commands
- Command history with persistence
- Session state management
- Loading indicators during operations

## Files

| File | Description |
|------|-------------|
| `mod.rs` | REPL main loop and session state |
| `commands.rs` | Command parsing and context |
| `completer.rs` | Tab completion logic |

## Public API

### Repl

Main REPL structure.

```rust
pub struct Repl {
    // Session state including output format
}

impl Repl {
    /// Create a new REPL instance
    pub fn new() -> Result<Self>;

    /// Run the REPL main loop
    pub async fn run(&mut self) -> Result<()>;
}
```

## Supported Commands

| Command | Description |
|---------|-------------|
| `lookup <domain>` | Smart lookup (RDAP/WHOIS) |
| `whois <domain>` | WHOIS lookup |
| `rdap <query>` | RDAP lookup (domain/IP/ASN) |
| `dig <domain> [type]` | DNS query |
| `propagation <domain> [type]` | DNS propagation check |
| `status <domain>` | Domain status check |
| `set output <format>` | Change output format (human/json) |
| `help` | Show help message |
| `exit` / `quit` | Exit REPL |

## Features

### Command History

- History saved to `~/.seer_history`
- Arrow keys navigate history
- Persistent across sessions

### Tab Completion

- Completes command names
- Shows available commands on double-tab

### Session State

- Output format persists across commands
- Can be changed with `set output`

### Error Handling

- Invalid commands show error without exiting
- Network errors displayed with details
- Help text suggests correct usage

## Usage

```rust
use crate::repl::Repl;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut repl = Repl::new()?;
    repl.run().await
}
```

## Example Session

```
$ seer
Welcome to Seer - Domain Name Helper
Type 'help' for available commands

seer> lookup example.com
[Smart lookup output...]

seer> set output json
Output format set to json

seer> dig example.com MX
[JSON DNS output...]

seer> set output human
Output format set to human

seer> help
Available commands:
  lookup <domain>           - Smart lookup (RDAP first, then WHOIS)
  whois <domain>            - WHOIS lookup
  rdap <domain|ip|asn>      - RDAP lookup
  dig <domain> [type]       - DNS query (default: A)
  propagation <domain> [type] - DNS propagation check
  status <domain>           - Domain status check
  set output <human|json>   - Change output format
  help                      - Show this help
  exit, quit                - Exit REPL

seer> exit
Goodbye!
```

## Implementation Details

### Main Loop

1. Display prompt
2. Read line with rustyline
3. Parse command and arguments
4. Execute command with spinner
5. Display result or error
6. Repeat

### Command Parsing

Commands are parsed as whitespace-separated tokens:
- First token: command name
- Remaining tokens: arguments

### Spinner

Long-running operations display a spinner using the `display::Spinner` utility to indicate progress.
