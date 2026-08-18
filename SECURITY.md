# Security Policy

## Reporting a vulnerability

Report security issues privately through
[GitHub Security Advisories](https://github.com/scthornton/prisma-airs-py/security/advisories/new)
rather than opening a public issue.

Please include a description of the issue, reproduction steps, and the affected version.
Expect an initial response within five working days. Findings are handled under
coordinated disclosure: a fix and advisory are published together, and reporters are
credited unless they prefer otherwise.

Vulnerabilities in the Prisma AIRS service itself, rather than in this client, should go
to [Palo Alto Networks product security](https://www.paloaltonetworks.com/security-disclosure).

## Supported versions

This project is pre-1.0. Only the latest release receives security fixes.

## Handling credentials

This client authenticates with long-lived secrets, so a few properties are deliberate:

- **Nothing is written to the repository.** Credentials resolve from environment
  variables or `~/.prisma-airs/config.json`. Both `.env` and `config.json` are
  gitignored, and a `gitleaks` pre-commit hook backstops that.
- **Secrets are never logged.** Debug output redacts the API key, client secret, and
  bearer tokens. Access tokens are held in memory only and are never persisted to disk.
- **Tokens are short-lived.** OAuth2 access tokens expire in roughly fifteen minutes and
  are refreshed in-process; the client does not cache them across runs.
- **Errors are sanitised.** Upstream error bodies are surfaced for diagnostics, but
  request headers — including `Authorization` — are stripped from exception context.

If you are storing credentials for CI, use your platform's secret store and grant the
service account only the tenant scopes it needs.
