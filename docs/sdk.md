# Using the SDK

## Clients

One client per plane, each exported from the package root:

```python
from prisma_airs import (
    Scanner,  # runtime scanning
    ManagementClient,  # profiles, topics, API keys, DLP profiles, logs
    AIGatewayClient,  # workspaces, configs, guardrails, telemetry
    AIGatewayAdminClient,  # admin plane on its own
    RedTeamClient,  # scans, reports, targets, custom attacks
    ModelSecurityClient,  # supply-chain model scanning
    DlpClient,  # DLP patterns, profiles, dictionaries
)
```

Every client is a context manager, and closing one closes the HTTP connection pool it owns:

```python
with ManagementClient() as client:
    profiles = client.profiles.list()
```

Sub-clients hang off the entry client and **share its token cache and connection pool** —
one `ManagementClient` means one OAuth token and one pool no matter how many sub-clients you
touch.

## Models

Every request and response is a Pydantic model, namespaced by domain:

```python
from prisma_airs.models import scan, red_team

verdict = scan.ScanResponse.model_validate(payload)
job = red_team.JobType.DYNAMIC
```

Models are **permissive about unknown fields**. These services add response fields without
a version bump, and a client that raised on an unrecognised key would turn a harmless
server-side addition into an outage. Anything extra stays reachable:

```python
verdict.model_extra  # {"a_field_added_last_tuesday": ...}
```

Request bodies are the opposite where the reference is: bodies marked strict reject unknown
fields, because a typo in a request should fail loudly rather than be ignored upstream.

## Errors

Everything derives from `AISecSDKException`, and each subclass fixes a classification:

```python
from prisma_airs import (
    AISecSDKException,  # catch-all
    AISecClientError,  # 4xx, or the request never arrived
    AISecServerError,  # 5xx that outlived the retry budget
    AISecPayloadError,  # your arguments were rejected before sending
    AISecMissingVariableError,  # a credential could not be resolved
    AISecOAuthError,  # token acquisition failed
    AISecResponseValidationError,  # a 2xx body did not match the model
)
```

Transport failures carry the details you need to react:

```python
try:
    scanner.scan(prompt=text, profile_name="prod")
except AISecClientError as err:
    err.status_code  # 429
    err.retry_after_seconds  # 30.0, when the service said so
    err.raw_message  # the message without the machine-readable prefix
```

## Retries

Retries are automatic and deliberately narrow:

- Only `500`, `502`, `503`, and `504` retry. **`429` does not** — the service supplies
  explicit guidance, and the caller should decide.
- Backoff is full jitter, `uniform(0, 2**attempt)` seconds, so clients recovering from a
  shared outage do not resynchronise.
- An authentication failure gets **one free retry** that does not consume the budget. A
  token expiring mid-run is expected; charging it to the budget would fail long jobs early.

Override per client or per call:

```python
Scanner(num_retries=0)  # exactly one attempt
scanner.scan(prompt=..., profile_name=..., num_retries=2)
```

## Sharing credentials across clients

Pass one `OAuthClient` to reuse a single token across several clients:

```python
from prisma_airs.auth.oauth import OAuthClient, resolve_credentials
from prisma_airs.constants import ENV_PREFIX_MGMT

creds = resolve_credentials(primary_env_prefix=ENV_PREFIX_MGMT)
oauth = OAuthClient(
    client_id=creds.client_id,
    client_secret=creds.client_secret,
    tsg_id=creds.tsg_id,
)
```

## Debugging

```console
$ export PANW_AI_SEC_DEBUG=1
```

Requests and responses are logged through the standard `logging` module under the
`prisma_airs` logger. Credential headers are digested to `sha256:<prefix>`, so the output is
safe to attach to a ticket while still identifying which key a request used.
