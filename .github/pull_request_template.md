## What changed

<!-- A sentence or two. What does this do, and why now? -->

## How it was verified

<!-- Which tiers ran: unit, contract, parity, live. Paste output where it helps. -->

- [ ] `uv run ruff check .` and `uv run ruff format --check .`
- [ ] `uv run mypy .`
- [ ] `uv run pytest`

## Parity

<!-- Delete this section if the change does not touch request construction. -->

- [ ] Request URL, headers, and body match the TypeScript reference
- [ ] Error mapping and exit codes match

## Notes for review

<!-- Anything worth a second pair of eyes: trade-offs, deferred work, open questions. -->
