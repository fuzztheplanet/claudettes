# findings.json — the machine-checkable findings contract

Prose rules get skipped under time pressure; a validator does not. This file is
the schema that `scripts/validate_findings.py` enforces. It encodes the four
pre-draft invariants and the verdict/severity rules from `SKILL.md` so a machine
refuses the mistakes that most often give a speculative finding unearned
authority — a needs-validation lead carrying a severity, a confirmed finding with
no evidence, a hardening nit scored as Medium.

It is deliberately small. It is not a replacement for judgment; it is the floor
every record clears before a human reads it. It is also the contract a multi-agent
run emits against — each hunter and critic in
`skw-orchestrating-vulnerability-research` returns one record of this shape, so the
lead can deduplicate by `id` and reconcile without parsing prose.

## Shape

`findings.json` is a JSON array of records. Every record has:

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | Stable fingerprint. Pattern `^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`. Same string in every state and across runs; derived from root cause + primary location, never from severity or wave. Unique within the file. |
| `verdict` | string | One of `confirmed`, `needs_validation`, `hardening`, `rejected`. |
| `title` | string | One line, non-empty. |
| `location` | string | Repository-relative `file:line`, endpoint, function, or message — the target's native interface, non-empty. |

The remaining required fields depend on `verdict`. No record may carry a field
that belongs to a different verdict (for example a `needs_validation` record with
`severity`, or a `confirmed` record with `blocker`).

### `verdict: "confirmed"`

A vulnerability demonstrated by an independent observation.

- `severity` — one of `informational`, `low`, `medium`, `high`, `critical`. Required.
- `confidence` — one of `low`, `medium`, `high`. Optional, but if present it may
  **not** be `low` (confirmed + low confidence cannot coexist; downgrade to a
  candidate instead).
- `evidence` — array, **non-empty**. Each item is a string or an object with a
  `type` (`command`, `request`, `response`, `crash`, `screenshot`, `test`, …) and
  a `detail`. A confirmed finding with no evidence is rejected.
- `reproduction` — string, non-empty. The steps someone else can run, or the
  environment it cannot leave (an offline sample, a lab target, a credential the
  reader supplies). Named via `reproduction_environment` when it is not portable.
- `root_cause` — string, non-empty.
- `remediation` — string, non-empty. Names the change, not "validate input".
- Forbidden here: `blocker`, `validation_plan`, `reason`.

### `verdict: "needs_validation"`

The source path is proven but a decisive fact lives outside what you can observe.

- `blocker` — string, non-empty. One concrete missing fact, not a worry.
- `validation_plan` — object with at least one of:
  - `local` — a bounded check the reader can run (a fixture, a unit test, a
    rendered config);
  - `owner_observed` — one setting or fact to ask the owner to read.
  Non-destructive. Never "send live traffic to find out".
- `evidence` — array, optional (the source trace supporting the claim).
- Forbidden here: `severity`, `confidence`, `reproduction`, `remediation`,
  `reason`. A severity on a needs-validation record is the headline failure this
  schema exists to catch.

### `verdict: "hardening"`

A defense-in-depth gap with no reachable boundary violation. Advice, not a finding.

- `note` — string, non-empty. What is missing and why it is only hardening (what
  already prevents the attack).
- Forbidden here: `severity`, `evidence`, `reproduction`, `blocker`,
  `validation_plan`.

### `verdict: "rejected"`

A candidate disproved during validation, retained so a later run does not re-raise
the same unsupported claim without new evidence.

- `reason` — string, non-empty. What refuted it (the control, the missing
  prerequisite, the already-shipped fix).
- Forbidden here: `severity`, `reproduction`, `remediation`, `blocker`,
  `validation_plan`.

## Example

```json
[
  {
    "id": "authz/report-export/missing-tenant-scope",
    "verdict": "confirmed",
    "title": "Tenant isolation bypass in report export",
    "location": "api/handlers/reports.go:214",
    "severity": "high",
    "confidence": "high",
    "evidence": [
      {"type": "request", "detail": "GET /api/v2/reports/1042/export returned tenant B's rows"}
    ],
    "reproduction": "Auth as trial-user@tenant-a; request a neighbouring report id; response is another tenant's CSV. Confirmed on IDs 1042, 1043, 1055.",
    "root_cause": "export query looks up by primary key with no tenant predicate",
    "remediation": "add AND tenant_id = ? at the data-access layer; audit the 14 other findByID callers"
  },
  {
    "id": "xff/rate-limit/trusts-client-header",
    "verdict": "needs_validation",
    "title": "Rate limiter keyed on client-supplied X-Forwarded-For",
    "location": "middleware/ratelimit.go:38",
    "blocker": "exploitable only if the ingress does not overwrite X-Forwarded-For; the repo contains no ingress config",
    "validation_plan": {
      "owner_observed": "confirm whether the ingress/LB sets (not appends) X-Forwarded-For before the app sees it",
      "local": "run the middleware behind a fixture that forwards a spoofed XFF and observe the limiter key"
    }
  },
  {
    "id": "headers/app/missing-csp",
    "verdict": "hardening",
    "title": "No Content-Security-Policy header",
    "location": "server/middleware.go:12",
    "note": "no reflected or stored HTML sink reaches user output on the audited surface, so this is defense-in-depth, not a finding"
  }
]
```

## Running it

```bash
python3 -I scripts/validate_findings.py findings.json
```

Exit status is `0` when every record is valid, `1` otherwise, with one line per
problem naming the record `id` and the rule it broke. It is zero-dependency
(Python 3 standard library only) so it runs anywhere the audit does.
