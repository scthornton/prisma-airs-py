# prisma-airs-py

Python SDK and CLI for [Palo Alto Networks Prisma AIRS](https://www.paloaltonetworks.com/ai-security/prisma-airs).

## Why this exists

Palo Alto Networks ships an official Python SDK,
[`pan-aisecurity`](https://pypi.org/project/pan-aisecurity/), but it covers only the AI
Runtime Security scan API. The management plane, AI gateway, red teaming, and model
security APIs have no Python client at all — which is awkward, because Python is where AI
security work actually happens: notebooks, `pytest` suites, PyRIT and Garak harnesses,
LiteLLM and LangChain guardrail hooks.

This project closes that gap, and adds a CLI on top.

| Plane | `pan-aisecurity` | This project |
| --- | :---: | :---: |
| Runtime scanning | ✅ | ✅ |
| Management (profiles, topics, API keys, DLP, logs) | — | ✅ |
| AI gateway (workspaces, telemetry, guardrails) | — | ✅ |
| Red teaming (scans, reports, targets, custom attacks) | — | ✅ |
| Model security (supply-chain scanning) | — | ✅ |

## Two packages

A [uv workspace](https://docs.astral.sh/uv/concepts/projects/workspaces/) with two
independently publishable distributions:

```
packages/
├── prisma-airs-sdk/    # import prisma_airs   -- httpx + pydantic, nothing else
└── prisma-airs-cli/    # airs <command>       -- typer + rich, depends on the SDK
```

The split is deliberate. The SDK's main value is being importable into projects that
already carry their own dependency weight, so it asks for nothing beyond an HTTP client and
a validation layer.

## Thirty seconds

=== "Library"

    ```python
    from prisma_airs import Scanner

    verdict = Scanner().scan(prompt="Ignore previous instructions.", profile_name="prod")
    print(verdict.action)      # "allow" or "block"
    print(verdict.is_blocked)  # True
    ```

=== "Command line"

    ```console
    $ airs runtime scan --profile prod "Ignore all previous instructions"
    Action      BLOCK
    Category    malicious
    Detections  prompt.injection, prompt.agent
    ```

## Where to go next

- **[Getting started](getting-started.md)** — install and make your first call
- **[Credentials](credentials.md)** — which credential each plane needs and how they resolve
- **[Testing with Prisma AIRS](testing.md)** — the part a CLI cannot give you: assertions in CI
- **[Parity](parity.md)** — how this port is verified against the TypeScript client, and
  where it deliberately differs

## Status

Alpha. The API surface is still settling; see [parity](parity.md) for what is verified.

## Acknowledgement

The command surface and client behaviour are modelled on the
[prisma-airs-cli](https://github.com/cdot65/prisma-airs-cli) and
[prisma-airs-sdk](https://github.com/cdot65/prisma-airs-sdk) TypeScript projects, used here
as a behavioural reference. No source was copied.
