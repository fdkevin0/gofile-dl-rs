# Contributing

Bug reports, documentation improvements, and focused pull requests are welcome.
For larger architectural or protocol changes, open an issue first to agree on
the problem and scope.

All participation is governed by the [code of conduct](CODE_OF_CONDUCT.md).
Report security vulnerabilities through the [security policy](SECURITY.md)
instead of public issues or pull requests.

## Development

Before opening a pull request, run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --doc --locked
```

Add regression tests for behavior changes and update relevant documentation.
Keep code, comments, commit messages, documentation, issues, and pull requests
in English. Never include credentials, tokens (`GOFILE_PREMIUM_TOKEN`,
`SECRET_KEY`, `AUTH_PASSWORD`), share passwords, or private state in code,
logs, or fixtures.

## Pull requests

Create a branch from `main` and keep each pull request focused on one logical
change. Explain the problem, resulting behavior, and validation performed. All
changes to `main` go through a pull request with passing CI and resolved review
discussions. A second person's approval is not required for this
single-maintainer project, and pull requests are squash merged.
