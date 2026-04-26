# Contributing to linux-malware-detect

## How to Contribute

- **Bug reports**: Open a GitHub Issue with steps to reproduce
- **Feature requests**: Open a GitHub Issue with use case and rationale
- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md)

## Development Setup

```bash
git clone https://github.com/rfxn/linux-malware-detect.git
cd linux-malware-detect
# Project-specific setup instructions
```

## Code Standards

- All shell scripts pass `bash -n` and `shellcheck`
- Tests use the BATS framework: `make -C tests test`
- Commit messages follow project conventions (see CHANGELOG for format)

## Pull Requests

1. Fork the repository
2. Create a feature branch from the current release branch
3. Make your changes with tests
4. Ensure all tests pass: `make -C tests test`
5. Submit a pull request with a clear description

## License

By contributing, you agree that your contributions will be licensed
under the GNU GPL v2.
