# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Pydantic models for every remaining API plane: management, AI gateway, red teaming,
  model security, and DLP, plus shared enums and error shapes. Namespaced by domain under
  `prisma_airs.models`.
- `airs config` command group: `set`, `get`, `unset`, `list`, and `path`.
- Resumable bulk-scan state and an advisory lock, with on-disk formats interchangeable
  with the TypeScript CLI's.
- `Scanner` client for the AI Runtime Security scan API: `scan`, `sync_scan`,
  `async_scan`, `query_by_scan_ids`, and `query_by_report_ids`, with regional endpoint
  selection.
- Pydantic models for the scan request, verdict, and threat report surfaces.
- HTTP transport core: retry policy with full jitter, OAuth2 token management with
  single-flight refresh, and API key, bearer, and tenant-header auth strategies.
- `airs runtime scan`, which exits 0 on `allow`, 1 on any other verdict, and 2 when the
  scan could not be completed.
- Config file support at `~/.prisma-airs/config.json`, resolved behind flags and
  environment variables.
- Two-package uv workspace: `prisma-airs-sdk` (library) and `prisma-airs-cli` (`airs`
  command).
- Project tooling: Ruff lint and format, Mypy in strict mode, pytest with layered test
  markers, pre-commit hooks including gitleaks secret scanning.
- CI running lint, type checks, a Python 3.10–3.13 test matrix, and distribution builds.

[Unreleased]: https://github.com/scthornton/prisma-airs-py/commits/main
