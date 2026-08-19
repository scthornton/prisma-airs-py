# Credentials

Prisma AIRS uses two different credential types, and which one you need depends on the
plane you are calling.

| Plane | Credential | Environment |
| --- | --- | --- |
| Runtime scanning | API key | `PANW_AI_SEC_API_KEY` |
| Management, AI gateway, red team, model security | OAuth2 service account | `PANW_MGMT_CLIENT_ID`, `PANW_MGMT_CLIENT_SECRET`, `PANW_MGMT_TSG_ID` |

The OAuth2 service account comes from Strata Cloud Manager, under
**Identity & Access → Service Accounts**. The TSG ID belongs to the tenant itself.

## One account, every plane

Each OAuth2 client declares its own environment prefix and falls back to `PANW_MGMT_*`
when it is unset, so a single service account drives everything:

| Client | Primary prefix | Fallback |
| --- | --- | --- |
| Management (and DLP) | `PANW_MGMT_*` | — |
| Red team | `PANW_RED_TEAM_*` | → `PANW_MGMT_*` |
| Model security | `PANW_MODEL_SEC_*` | → `PANW_MGMT_*` |
| AI gateway | `PANW_AI_GW_*` | → `PANW_MGMT_*` |

Resolution happens **per field**, so a service-specific client ID can be combined with a
shared tenant ID:

```console
$ export PANW_MODEL_SEC_CLIENT_ID=...      # this client only
$ export PANW_MODEL_SEC_CLIENT_SECRET=...
$ export PANW_MGMT_TSG_ID=...              # shared with everything else
```

Precedence for every field is: **constructor argument → service prefix → `PANW_MGMT` →
error**. Nothing is guessed; a missing value names the variables it looked for.

## Where to put them

=== "Environment"

    ```console
    $ export PANW_AI_SEC_API_KEY=...
    ```

=== "A file the client reads"

    ```console
    $ mkdir -p ~/.prisma-airs
    $ cat > ~/.prisma-airs/.env <<'EOF'
    PANW_AI_SEC_API_KEY=...
    PANW_MGMT_CLIENT_ID=...
    PANW_MGMT_CLIENT_SECRET=...
    PANW_MGMT_TSG_ID=...
    EOF
    $ chmod 600 ~/.prisma-airs/.env
    ```

=== "In code"

    ```python
    from prisma_airs import ManagementClient

    client = ManagementClient(client_id="...", client_secret="...", tsg_id="...")
    ```

!!! warning "Non-credential settings only"

    `~/.prisma-airs/config.json` — managed by `airs config` — holds preferences such as the
    default profile and region. It is **not** for secrets. Keep credentials in the
    environment or a `.env` file with restricted permissions.

## How tokens are handled

- **Short-lived.** Access tokens last about fifteen minutes and are refreshed in-process.
  Nothing is cached to disk between runs.
- **Refreshed early.** A token is replaced 30 seconds before it expires, so one cannot
  lapse mid-request.
- **Tracked on a monotonic clock.** An NTP correction or a laptop resuming from sleep
  cannot make a live token look expired, or an expired one look live.
- **Fetched once under load.** Concurrent callers arriving on a cold cache collapse into a
  single token request rather than stampeding the auth endpoint.
- **Never logged.** Debug output digests credential headers to `sha256:<prefix>`, so it can
  be pasted into a ticket while still identifying which key was used.

## Regions

Runtime scanning has regional endpoints. Pass `--region`, or set `PANW_AI_SEC_REGION`:

| Region | Endpoint |
| --- | --- |
| `us` (default) | `service.api.aisecurity.paloaltonetworks.com` |
| `de` | `service-de.api.aisecurity.paloaltonetworks.com` |
| `in` | `service-in.api.aisecurity.paloaltonetworks.com` |
| `sg` | `service-sg.api.aisecurity.paloaltonetworks.com` |

An unknown region is rejected rather than silently falling back to `us` — a quiet fallback
would send regulated content to the wrong jurisdiction.

## Diagnosing

```console
$ airs doctor
```

`doctor` checks each credential and each plane's reachability separately, so a failure
tells you *which* credential is wrong rather than that "something" is.
