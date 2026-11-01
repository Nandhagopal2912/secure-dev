# Trust Boundaries

Every arrow in this chain crosses a boundary where data changes trust level.
Controls belong *at* the boundary, on the receiving side, because the sender is
never the thing you can rely on.

```text
User ──1──► Web UI ──2──► API ──3──► Queue ──4──► Worker ──5──► Untrusted target
                           │                        │
                           └──6──► PostgreSQL ◄──6──┘
```

| # | Boundary | Crossing it | Trust of the input |
|---|---|---|---|
| 1 | User → Web UI | Browser interaction | Untrusted |
| 2 | Web UI → API | HTTP requests | Untrusted |
| 3 | API → Queue | Scan job payloads | Untrusted on read |
| 4 | Queue → Worker | Scan job payloads | Untrusted on read |
| 5 | Worker → Target | Repositories, images, endpoints, **and scanner output** | Hostile |
| 6 | Services → PostgreSQL | SQL | Parameterised only |
| 7 | Stored conclusions → readers | Findings, issues, risk scores | Derived, and served back out |

## 1–2. User and Web UI → API

The UI is not a security control. It runs on the user's machine and anything it
enforces can be bypassed by talking to the API directly. Every restriction that
matters is enforced server-side (CLAUDE.md §15.4).

Controls: input validation on every field, size caps on every parse, a
structured error envelope that never echoes attacker input, security response
headers, server-generated request IDs (a client-supplied `X-Request-Id` is
discarded so log correlation cannot be poisoned).

**Not yet implemented:** authentication and authorization. Every endpoint is
currently public. See `threat-model.md` T-11.

## 3–4. API → Queue → Worker

This is the boundary that keeps untrusted content away from the API process.

The API **never executes target content** — no scanners, no builds, no package
manager installs, no git hooks. It validates, persists, and enqueues. That is
the whole of its involvement (§14.1).

Job payloads are plain data: a scan ID, a validated target, scanner names. A
payload never carries a command line, a script, or anything else a worker would
execute. `TestJobPayloadCarriesNoExecutableFields` fails if an executable-looking
field is ever added to the struct.

The worker **re-validates every payload on arrival**. SecureOps wrote the
message, but that is not a reason to trust it: the payload may have been sitting
in Redis, and a target that resolved to a public address at enqueue time may
resolve to a loopback address now.

## 5. Worker → Untrusted target

The only boundary where hostile content is actually touched, and the only place
scanner binaries run.

Controls, layered so each assumes the one above it failed:

- **Input** — allow-listed schemes (no `file://`, no `git://`), path containment
  inside the workspace, rejection of values beginning with `-`
- **Network** — SSRF policy at resolution *and* at dial time
- **Process** — `exec.CommandContext` with an argument vector; no shell anywhere
- **Environment** — explicit allow-list; the worker's own credentials are never
  inherited by a scanner subprocess
- **Filesystem** — ephemeral `0700` workspace, destroyed when the job ends
- **Resource** — per-scanner timeout, output cap that terminates the process,
  job timeout, concurrency cap
- **Process tree** — child runs in its own process group; the group is killed
- **Container** — non-root, read-only rootfs, all capabilities dropped, tmpfs
  workspace

Scanner *output* is untrusted too. A compromised or malicious scanner can emit
hostile output, so parsing is bounded and validated (§15.7).

### Egress during a scan, which is new

Until image targets, this boundary had a simple property: **no scan needed the
network**. Vulnerability databases and rulesets were provisioned before a worker
claimed a job, so the moment untrusted content was on disk, egress could be
denied outright (ADR 012).

An image target breaks that, necessarily — the bytes live in a registry. The
narrowing is scoped rather than general (ADR 025, T-51):

- Egress is declared **per target kind**, not per adapter, so a filesystem scan
  still needs none. A filesystem scan is the one running over attacker-supplied
  content on disk, and it keeps the stronger posture.
- The registry host is validated against the address policy **before** the job
  is enqueued, so the reference cannot name an internal address (T-49).
- `--image-src remote` forbids the local container runtime, so a mounted socket
  cannot turn an image scan into a read of the host's images (T-50).
- No registry credentials exist to leak: the subprocess environment is an
  allow-list and `HOME` does not resolve. Public registries only.

The declaration is metadata today. Nothing yet reads `NetworkKinds` to *impose*
a network policy — that arrives with the Phase 12 Kubernetes work, and until
then this is a documented intent rather than an enforced boundary.

### The boundary DAST inverts

Every other adapter, image targets included, **pulls** untrusted content toward
the worker. ZAP and httpprobe are the only ones that send traffic **outward** to
a host somebody else operates, which makes SecureOps a potential attack tool
rather than only a potential victim (ADR 026, ADR 041, T-52). httpprobe also
opens those connections from inside the worker process rather than from a
subprocess (T-64).

The controls run in the other direction accordingly:

- **No active scanning.** The `activeScan` job is absent from the automation
  plan, not disabled in it, so no configuration change switches it on. Passive
  rules observe traffic the spider already generated; every request is one a
  browser would have made. SecureOps does not test for injection, and that is a
  stated limitation rather than an oversight.
- **The plan is escaped.** It is a YAML document built around a caller-supplied
  URL, and an unescaped one injects jobs into it — confirmed, not theorised
  (T-53).
- **The proxy binds loopback.** ZAP needs a listener even headless; a wildcard
  bind would make the worker an open forward proxy for the length of the scan
  (T-54).
- **The address policy already covered this.** `validateEndpoint` has applied
  it since Phase 2 — audited rather than assumed, because the image path had
  the same omission and did not (T-56, T-49).

And the familiar direction still applies: what comes back is untrusted, and the
report embeds the application's URLs and response fragments, so it is rewritten
before storage exactly as trivy's is (T-55).

## 6. Services → PostgreSQL

Parameterised statements only. pgx's extended protocol will not execute a
concatenated multi-statement string, which makes the rule enforceable rather
than a convention.

Workers hold least privilege: no database superuser, no cloud credentials, no
registry write access.

## 7. Stored findings and derived views

New with Phases 4-6, and a boundary in a different sense from the others: not a
place where data crosses between components, but a place where SecureOps'
*conclusions* accumulate and are served back out.

What crosses it: the durable findings record, the correlated issues derived from
it, the exploitation likelihood attached to both, and the risk score derived
from all three. Scan-time data is
observations about one repository at one moment; this is a maintained,
deduplicated, ranked inventory that outlives every scan that fed it.

Why it is drawn separately. The controls that matter here are not the ones that
matter at Boundary 5. Isolation and argv-only execution protect the act of
scanning; they say nothing about who may read the result, how long a conclusion
survives after it stops being true, or whether a derived view discloses more
than the data it was derived from. All three of those are live questions the
moment findings persist.

Reading is gated by authentication (T-11) and nothing finer — every valid token
reaches every project (T-23), which is why the impact of that gap grew with this
boundary rather than staying where Phase 3 left it. See T-36, T-37, T-38.

## When to update this document

Whenever a boundary moves: a new component, a new datastore, a change to what
executes untrusted content, or a change to how components authenticate to each
other (§21).
