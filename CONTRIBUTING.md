# Contributing to Bifrost

Thank you for your interest in contributing to Bifrost! This document provides guidelines for contributing to the project.

## Development Setup

### Prerequisites

- Go 1.22 or later
- Make
- Docker (optional, for container builds)
- golangci-lint (for linting)

### Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/bifrost-proxy.git
   cd bifrost-proxy
   ```

3. Install dependencies:
   ```bash
   go mod download
   ```

4. Build the project:
   ```bash
   make build
   ```

5. Run tests:
   ```bash
   make test
   ```

## Code Style

### Go Code

- Follow the [Effective Go](https://golang.org/doc/effective_go) guidelines
- Run `gofmt` on all code
- Use `golangci-lint` for static analysis
- Write meaningful commit messages
- Add tests for new functionality
- Keep functions focused and small
- Document exported functions and types

### Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line

Example:
```
Add rate limiting per user

- Implement token bucket algorithm
- Add configuration options for limits
- Include tests for edge cases

Fixes #123
```

## Pull Request Process

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and commit them

3. Ensure all tests pass:
   ```bash
   make test
   make lint
   ```

4. Push to your fork and create a pull request

5. Fill out the pull request template with relevant information

6. Wait for review and address any feedback

## Testing

- Write unit tests for all new code
- Aim for >80% code coverage
- Use table-driven tests where appropriate
- Mock external dependencies

Run tests with coverage:
```bash
go test -cover ./...
```

## Reporting Issues

- Check if the issue already exists
- Use the issue templates when available
- Provide clear reproduction steps
- Include relevant logs and configuration
- Specify your environment (OS, Go version, etc.)

## Security Issues

If you discover a security vulnerability, please report it through [GitHub Security Advisories](https://github.com/rennerdo30/bifrost-proxy/security/advisories/new) instead of opening a public issue.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Follow project maintainers' decisions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

Feel free to open an issue for questions or discussions about the project.
