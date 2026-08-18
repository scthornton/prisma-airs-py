# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Two-package uv workspace: `prisma-airs-sdk` (library) and `prisma-airs-cli` (`airs`
  command).
- Project tooling: Ruff lint and format, Mypy in strict mode, pytest with layered test
  markers, pre-commit hooks including gitleaks secret scanning.
- CI running lint, type checks, a Python 3.10–3.13 test matrix, and distribution builds.

[Unreleased]: https://github.com/scthornton/prisma-airs-py/commits/main
