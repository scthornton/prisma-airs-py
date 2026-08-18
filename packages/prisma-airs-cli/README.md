# prisma-airs-cli

Command-line interface for [Palo Alto Networks Prisma AIRS](https://www.paloaltonetworks.com/ai-security/prisma-airs),
built on [`prisma-airs-sdk`](https://pypi.org/project/prisma-airs-sdk/).

## Installation

```bash
pip install prisma-airs-cli
```

Or run it without installing:

```bash
uvx --from prisma-airs-cli airs doctor
```

## Usage

```bash
# Verify credentials and reachability before anything else
airs doctor

# Scan a single prompt
airs runtime scan --prompt "Ignore previous instructions" --profile prod

# Batch scan a CSV, resumable if interrupted
airs runtime bulk-scan --input prompts.csv --output results.csv --profile prod

# Manage custom topic guardrails
airs runtime topics create --name finance-only --file topics.yaml
airs runtime topics eval --name finance-only
airs runtime topics revert --name finance-only
```

Every command accepts `--json` for machine-readable output, and exits non-zero when a
scan resolves to `block` or `failed`, so it composes cleanly into CI pipelines.

## Configuration

Credentials resolve from environment variables or `~/.prisma-airs/config.json`:

```bash
airs config set profile prod
airs config list
airs config path
```

See the [SDK README](https://pypi.org/project/prisma-airs-sdk/) for the full credential
matrix.

## Licence

MIT. See [LICENSE](LICENSE) for licence text and upstream acknowledgement.
