# Contributing to TL-Rustscan

First off, thanks for taking the time to contribute! 🎉

The following is a set of guidelines for contributing to TL-Rustscan. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## How Can I Contribute?

### Core Principle: Precision First

The primary goal of TL-Rustscan is **precision**. When submitting code, please adhere to the following principles:

1.  **Quality over Quantity**: If a fingerprint rule might cause a large number of false positives (e.g., matching a generic "404 Not Found" page), please do not add it, or add stricter constraints (e.g., limit to Header or Title).
2.  **Consider Edge Cases**: Can your code handle network timeouts? Can it handle packet fragmentation? Can it handle non-standard HTTP responses?
3.  **Avoid Blocking**: All I/O operations must be asynchronous (Async) or run in independent threads. Blocking operations in the core loop are strictly prohibited.

### Reporting Bugs

This section guides you through submitting a bug report for TL-Rustscan. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

*   **Use a clear and descriptive title** for the issue to identify the problem.
*   **Describe the exact steps to reproduce the problem** in as much detail as possible.
*   **Provide specific examples to demonstrate the steps**. Include links to files or GitHub projects, or copy/pasteable snippets, which you use in those examples.
*   **Describe the behavior you observed after following the steps** and point out what exactly is the problem with that behavior.
*   **Explain which behavior you expected to see instead and why.**
*   **Include screenshots and animated GIFs** which show you following the described steps and clearly demonstrate the problem.

### Pull Requests

*   Fill in the required template
*   Do not include issue numbers in the PR title
*   Include screenshots and animated GIFs in your pull request whenever possible.
*   Follow the Rust coding style.
*   Make sure all tests pass (`cargo test`).

### Adding Fingerprints

If you want to add new service fingerprints, please consider updating the `fingerprints.json` file instead of hardcoding them in Rust.
The file supports the following fields:
*   `name`: Fingerprint name (e.g., "Spring Boot")
*   `match_mode`: Match mode (supports "keyword" or "regex")
*   `pattern`: Keyword or Regex to match.
    *   **Keyword**: Automatically case-insensitive.
    *   **Regex**: Case-sensitive by default. Add `(?i)` at the beginning for case-insensitivity.
    *   **Note**: Rust regex does not support backreferences `\1` or lookarounds `(?=)`, `(?<!)`, etc.
*   `location`: Match location ("body", "header", "banner", "title")

### Adding Red Team Plugins

If you want to add new vulnerability POCs or brute-force modules, please follow these steps:

1.  **Location**: All plugin code should be located in the `src/plugins/` directory.
2.  **Implement Trait**: New plugins must implement the `ScanPlugin` trait.
    *   `name()`: Return the plugin name.
    *   `is_rscan_only()`: Must return `true` for offensive plugins (brute-force/vuln).
    *   `scan()`: Execute the specific scanning logic.
3.  **Register Plugin**: Register your new plugin in the `PluginManager::new` function in `src/plugins/mod.rs`.
4.  **Safety**: Ensure your POC is safe and only performs verification (e.g., `whoami` or `version`). **Strictly prohibit** destructive operations (e.g., `rm -rf` or uploading Webshells).

## Styleguides

### Git Commit Messages

*   Use the present tense ("Add feature" not "Added feature")
*   Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
*   Limit the first line to 72 characters or less
*   Reference issues and pull requests liberally after the first line

### Rust Styleguide

*   Use `cargo fmt` to format your code.
*   Use `cargo clippy` to catch common mistakes.

Thank you for your contribution!
