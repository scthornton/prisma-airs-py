# CLI

```console
$ airs --help
```

Every command shares a few conventions.

## Conventions

**Output.** Results go to stdout; progress and diagnostics go to stderr. So this is safe:

```console
$ airs runtime scan --profile prod --json "hello" | jq .action
```

Most listing commands take `--output`:

| Format | Use |
| --- | --- |
| `pretty` (default) | reading at a terminal |
| `table` | scanning many rows |
| `json` | piping into `jq` |
| `csv` | spreadsheets |
| `yaml` | config-shaped output |

**Exit codes.**

| Code | Meaning |
| --- | --- |
| `0` | succeeded; any verdict was `allow` |
| `1` | a verdict was not `allow` — the command worked, the content did not |
| `2` | the command could not complete: bad arguments, missing config, or an API failure |

**Pagination.** `--limit` and `--offset` everywhere, converted internally to whatever each
API wants. Negative values are rejected rather than clamped.

**Destructive commands** prompt first. Without a TTY they refuse rather than assume, so a
CI job that forgot `--force` gets an error instead of a deletion. Declining exits `0`.

**Quiet.** `--quiet` suppresses commentary but never results, warnings, or errors.

## Configuration

```console
$ airs config set profile prod      # stop passing --profile
$ airs config list                  # shows each value and where it came from
$ airs config path
```

`list` reports the origin of every setting, because an environment variable silently
overrides the file — and without that column, a forgotten `export` becomes a long argument
with the tool about a value you are certain you changed.

Resolution order is **flag → environment → config file → default**.

## Diagnostics

```console
$ airs doctor
```

Checks each credential and each plane's reachability separately, so a failure tells you
which credential is wrong rather than that something is.

```console
$ export PANW_AI_SEC_DEBUG=1     # log requests and responses; secrets are digested
```

## Command groups

| Group | Covers |
| --- | --- |
| `airs runtime` | scanning, bulk scanning, profiles, topics, API keys, customer apps, scan logs |
| `airs redteam` | red team scans, reports, targets, adapters, custom attacks |
| `airs aigateway` | workspaces, configs, guardrails, telemetry |
| `airs modelsecurity` | model and model-version scanning, security groups and rules |
| `airs dlp` | data patterns, profiles, filtering profiles, dictionaries |
| `airs config` | stored settings |
| `airs doctor` | credential and connectivity checks |

Run `airs <group> --help` for the full surface of any group; the help text is generated
from the same docstrings as the [API reference](reference.md).
