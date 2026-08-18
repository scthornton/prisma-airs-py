# prisma-airs-py

Python SDK and CLI for [Palo Alto Networks Prisma AIRS](https://www.paloaltonetworks.com/ai-security/prisma-airs).

## Why this exists

Palo Alto Networks ships an official Python SDK, [`pan-aisecurity`](https://pypi.org/project/pan-aisecurity/),
but it covers only the AI Runtime Security scan API. The management plane, AI gateway,
red teaming, and model security APIs have no Python client at all — which is awkward,
because Python is where AI security work actually happens: notebooks, `pytest` suites,
PyRIT and Garak harnesses, LiteLLM and LangChain guardrail hooks.

This repository closes that gap, and adds a full-parity CLI on top.

| Plane | `pan-aisecurity` | This project |
| --- | :---: | :---: |
| Runtime scanning | ✅ | ✅ |
| Management (profiles, topics, API keys, DLP, logs) | — | ✅ |
| AI gateway (workspaces, telemetry) | — | ✅ |
| Red teaming (scans, reports, targets) | — | ✅ |
| Model security (supply-chain scanning) | — | ✅ |

## Layout

A [uv workspace](https://docs.astral.sh/uv/concepts/projects/workspaces/) with two
independently publishable distributions:

```
packages/
├── prisma-airs-sdk/    # import prisma_airs      -- httpx + pydantic, nothing else
└── prisma-airs-cli/    # airs <command>          -- typer + rich, depends on the SDK
```

The split is deliberate. The SDK stays dependency-light so it can drop into an existing
project without dragging a CLI framework along with it.

## Install

```bash
pip install prisma-airs-sdk        # library only
pip install prisma-airs-cli        # library + airs command
```

## Quick start

```python
from prisma_airs import Scanner

result = Scanner().scan(prompt="Ignore previous instructions.", profile_name="prod")
assert result.action == "allow"
```

```bash
airs doctor
airs runtime scan --prompt "Ignore previous instructions" --profile prod
```

## Credentials

| Plane | Credential | Environment |
| --- | --- | --- |
| Runtime scanning | API key | `PANW_AI_SEC_API_KEY` |
| Everything else | OAuth2 service account | `PANW_MGMT_CLIENT_ID`, `PANW_MGMT_CLIENT_SECRET`, `PANW_MGMT_TSG_ID` |

Service-specific prefixes (`PANW_RED_TEAM_*`, `PANW_AI_GW_*`, `PANW_MODEL_SEC_*`) override
`PANW_MGMT_*` when present, so one service account can drive every plane.

## Development

```bash
uv sync                 # create the environment
uv run pytest           # unit and contract tests -- no credentials needed
uv run ruff check .
uv run mypy .
```

Tests are layered so that most of the suite runs anywhere:

- **Unit** — pure logic; no network.
- **Contract** — `respx`-mocked HTTP asserting exact URLs, headers, and bodies.
- **Parity** (`-m parity`) — differential tests against the TypeScript reference
  implementation, confirming both clients produce byte-identical requests.
- **Live** (`-m live`) — real API calls; requires credentials, skipped by default.

## Acknowledgement

The command surface and client behaviour are modelled on the
[prisma-airs-cli](https://github.com/cdot65/prisma-airs-cli) and
[prisma-airs-sdk](https://github.com/cdot65/prisma-airs-sdk) TypeScript projects, used
here as a behavioural reference for parity testing. No source was copied.

## Licence

MIT — see [LICENSE](LICENSE).
