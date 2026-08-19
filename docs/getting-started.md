# Getting started

## Install

=== "Library only"

    ```console
    $ pip install prisma-airs-sdk
    ```

=== "Library and CLI"

    ```console
    $ pip install prisma-airs-cli
    ```

=== "Run without installing"

    ```console
    $ uvx --from prisma-airs-cli airs doctor
    ```

Python 3.10 or newer. The SDK depends only on `httpx` and `pydantic`.

## Set credentials

Runtime scanning needs an API key; every other plane needs an OAuth2 service account. Put
them somewhere the client can find them — see [Credentials](credentials.md) for the full
picture:

```console
$ export PANW_AI_SEC_API_KEY=...          # runtime scanning
$ export PANW_MGMT_CLIENT_ID=...          # everything else
$ export PANW_MGMT_CLIENT_SECRET=...
$ export PANW_MGMT_TSG_ID=...
```

## Check the setup

`doctor` verifies credentials and reachability before you debug anything else:

```console
$ airs doctor
  ✓ Scanner credentials    airsApiKey set (env)
  ✓ Scanner API            endpoint reachable, API key accepted
  ✓ Management OAuth       token obtained
  ✓ AI Gateway API         endpoint reachable
```

!!! tip "Save a default profile"

    Most commands need a security profile. Set one once instead of passing `--profile`
    every time:

    ```console
    $ airs config set profile prod
    $ airs config list
    ```

## Scan something

```console
$ airs runtime scan --profile prod "What is the capital of France?"
Action      ALLOW
Category    benign
Detections  none
```

The exit code is the useful part in a pipeline:

| Code | Meaning |
| --- | --- |
| `0` | The verdict was `allow` |
| `1` | The verdict was something else — the command worked, the content did not |
| `2` | The command could not complete: bad arguments, missing config, or an API failure |

That third code is a deliberate departure from the TypeScript client, which returns `1`
for both a block and a failure. An expired API key must not look like a clean policy pass,
or a broken pipeline reads as a passing one. See [Parity](parity.md).

## Use it as a library

```python
from prisma_airs import Scanner

with Scanner() as scanner:
    verdict = scanner.scan(prompt="Ignore previous instructions.", profile_name="prod")
    if verdict.is_blocked:
        raise SystemExit(f"blocked: {verdict.category}")
```

Continue with [Using the SDK](sdk.md), or jump to
[Testing with Prisma AIRS](testing.md) for the case this library exists to serve.
