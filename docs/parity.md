# Parity with the TypeScript client

This project is a port. The value of a port is that it behaves like the thing it was ported
from, so parity is verified rather than assumed — and where it deliberately differs, that is
written down here rather than discovered later.

## How it is verified

Four tiers, in increasing order of what they prove and decreasing order of how often they
run.

### Unit

Pure logic, no network: retry backoff, error classification, `Retry-After` parsing, the
bulk-scan state machine, token expiry, output formatting. Runs everywhere, needs nothing.

### Contract

`respx`-mocked HTTP asserting the *exact* request each client method produces — method,
URL, query parameters, headers, and body. A test that only checks the response shape proves
almost nothing about a port; these check what goes on the wire.

### Differential

The strongest check available without a tenant. Both CLIs run as real processes against the
same recording HTTP server, with the same credentials and the same arguments, and the
requests that arrive are compared field by field.

```console
$ git clone https://github.com/cdot65/prisma-airs-cli && cd prisma-airs-cli
$ npm install && npm run build
$ AIRS_PARITY=1 AIRS_REFERENCE_CLI=$PWD/dist/cli/index.js uv run pytest -m parity
```

!!! warning "The npm package is not the reference"

    `@cdot65/prisma-airs-cli` on npm publishes an **older command surface than the
    repository source at the same version number**. The published `runtime scan` takes only
    `--profile` and `--response`; the repository source takes considerably more. Diffing
    against npm therefore measures the wrong thing, which is why the harness requires a
    locally built checkout and skips rather than guessing.

The single most informative assertion in this tier is `x-payload-hash`. The scan service
authenticates with an HMAC over the request body, keyed by the API key. Both clients are
given the same key, so **matching hashes prove the two bodies were byte-identical** —
including key order, separator whitespace, and non-ASCII encoding. Structural equality of
the parsed JSON would not prove that, and it is exactly where a naive port goes wrong:
Python's `json.dumps` pads separators and escapes non-ASCII as `\uXXXX`, either of which
changes the digest and produces a signature rejection that presents as a bad API key.

### Live

Real calls against a real tenant. Marked `live`, skipped by default, run deliberately.

## Deliberate differences

Each of these was a decision, not an oversight.

### Exit codes

The reference returns `1` both for a blocked verdict and for an outright failure. This port
separates them:

| Code | This port | Reference |
| --- | --- | --- |
| `0` | verdict was `allow` | success |
| `1` | verdict was not `allow` | blocked **or** failed |
| `2` | could not complete | usage error |

An expired API key must not look like a clean policy pass, or a broken pipeline reads as a
passing one. Both clients still exit non-zero on a block, so a script that only checks
success/failure behaves identically.

### `num_retries` is rejected, not clamped

The reference silently clamps an out-of-range retry budget into `[0, 5]`. Every client here
raises instead, so a caller asking for a budget they will not get hears about it rather than
wondering why a long run gave up early.

### Validation errors

Building a model raises Pydantic's `ValidationError`, with the offending field named.
Calling a client raises `AISecPayloadError`. The boundary is: constructing a model is
Pydantic's contract, calling a client is ours.

### Enum rendering

Enum members render as their wire value on **every** supported Python. A plain
`(str, Enum)` renders as the value on 3.10 and as `Class.MEMBER` from 3.11, because 3.11
changed `Enum.__format__` for mixin enums — so the same code would send different text
depending on the interpreter. `enum.StrEnum` fixes this from 3.11; this project supports
3.10, so it pins the behaviour itself.

### Output formatting

CSV and YAML go through the standard library and PyYAML rather than string concatenation.
The reference builds YAML by joining `key: value` pairs, which mangles any value containing
a colon, and builds CSV with a hand-rolled quoting rule. This is one place where matching
the reference exactly would mean reproducing a bug.

### Deprecated flag aliases

The reference carries deprecated aliases (`--size`, `--page-size`, `--page`) alongside the
canonical `--limit` and `--offset`. Only the canonical flags are ported. A new client has no
back-compatibility to maintain, and carrying an alias forward makes it permanent.

## What parity does *not* cover

Honest limits:

- **Response rendering.** Pretty-printed human output is not compared; only requests and
  exit codes are. Two clients can present the same verdict differently without either being
  wrong.
- **Planes without an endpoint override.** The differential harness needs both clients
  pointed at a local server. Where the reference offers no environment override for a
  plane's base URL, that plane is covered by contract tests only.
- **The reference's own correctness.** Differential testing proves this port agrees with
  the reference. Where the reference is wrong about the API, this port inherits it — except
  where noted above.
