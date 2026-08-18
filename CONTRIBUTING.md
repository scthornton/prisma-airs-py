# Contributing

## Setup

The project uses [uv](https://docs.astral.sh/uv/) and is a two-package workspace.

```bash
git clone https://github.com/scthornton/prisma-airs-py
cd prisma-airs-py
uv sync
uv run pre-commit install
```

## Checks

Everything CI runs, you can run locally:

```bash
uv run ruff check .          # lint
uv run ruff format .         # format
uv run mypy .                # types (strict)
uv run pytest                # tests
```

## Test tiers

Tests are marked so the bulk of the suite runs with no credentials and no network.

| Tier | Marker | Needs | Runs in CI |
| --- | --- | --- | --- |
| Unit | *(none)* | nothing | yes |
| Contract | *(none)* | nothing — HTTP is mocked with `respx` | yes |
| Parity | `parity` | Node.js and the TypeScript reference package | separate workflow |
| Live | `live` | real Prisma AIRS credentials | manual only |

```bash
uv run pytest                            # unit + contract (the default)
uv run pytest -m live                    # against a real tenant
uv run pytest -m "not live and not parity"
```

Contract tests assert the *exact* request a client produces — URL, headers, and body.
That is what keeps the port honest, so new client methods need one.

Live tests must be safe to run repeatedly against a real tenant: read-only where
possible, and self-cleaning where not. Never commit a fixture captured from a live run
without scrubbing tenant identifiers.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/), imperative mood, subject
under 72 characters:

```
feat(scan): add regional endpoint selection
fix(auth): refresh token inside the pre-expiry buffer
test(management): cover cursor pagination edge cases
```

Scopes follow the package layout: `scan`, `auth`, `management`, `aigateway`, `redteam`,
`modelsec`, `dlp`, `cli`, `http`. Keep commits atomic — one logical change each.

## Pull requests

Keep them small and single-purpose. Every PR should state what changed and how it was
verified, and must leave CI green. Anything touching request construction should say
explicitly whether parity with the reference implementation was checked.
