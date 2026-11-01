# SecureOps roadmap

Where the project stands, what is left, and what is deliberately not on the
list. Updated at the end of each phase.

Authoritative on sequencing; [CLAUDE.md](../CLAUDE.md) §26 is authoritative on
what each phase contains, and the
[threat model](security/threat-model.md) on what is and is not defended.

**Last updated: 2026-09-08**, at the close of Phase 12b — the last open work.

---

## Where we are

**Every phase is complete.** Phase 14 closed on
2026-09-08 with a full threat-model re-read, the architecture and API documents
brought back in line, and a [security review](security/review.md) of the system
as a whole. Phase 12a put the platform on a cluster and closed the last Open
threat; 12b's scan-job machinery is merged and not deployable, and the roadmap
entry below says exactly why. The pipeline in CLAUDE.md §3 runs end to end: a target
goes in; a risk score, a ranked list of fixes, and a PASS/WARN/FAIL verdict come
out — and a pipeline can now act on that verdict.

Threat model: **43 Mitigated · 18 Partial · 0 Open · 2 Prospective.** T-10 was
the last Open entry and Phase 12a closed it.

| Phase | Scope | State |
|---|---|---|
| 1 | Foundation: API, dashboard shell, PostgreSQL, Redis, Compose, CI | done |
| 2 | Scanner abstraction, target validation, scan lifecycle, worker | done |
| 3a | Scan API and interim authentication | done |
| 3b | Six adapters: gitleaks · syft · grype · semgrep · trivy · zap, and later httpprobe (ADR 041) | done |
| 4 | Normalization: canonical Finding, fingerprinting, dedup, persistence | done |
| 5 | Correlation: contextual issues, cross-domain escalation | done |
| 6 | Threat intelligence (EPSS) and the contextual risk engine | done |
| 7 | Remediation: vendor fix facts, consolidated actions, ranking | done |
| 8 | Policy engine: PASS/WARN/FAIL gates, durable audit log | done |
| 9 | Dashboard: posture, triage, issues, remediation, URL-bar scanning | done |
| 11 | Identity: accounts, roles, project scoping, administration | done |
| 10a | SBOM component storage: parse, persist, query | done |
| 10 | CI/CD integration: the CLI | done |
| 10 | CI/CD integration: the GitHub Action (report-only) | done |
| 10b | SBOM in correlation: deployment evidence on an issue | done |
| 12a | Kubernetes: the platform runs on a cluster | done |
| 12b | Kubernetes: a scan becomes an ephemeral Job | done |
| ~~13~~ | ~~Observability~~ | **dropped** — [ADR 034](adr/034-no-observability-phase.md) |
| 14 | Final hardening and documentation | done |

Two sequencing decisions worth knowing, both recorded rather than silent:

- **Phase 3 was split into 3a and 3b.** The specification's phase list never
  named an endpoint that creates a scan, so the scan API is recorded as its own
  step rather than folded into a phase that did not describe it (CLAUDE.md §26).
- **Phase 11 ran before Phase 10.** CI needs a credential confined to specific
  projects, and confinement was Phase 11's work. Handing CI a credential that
  reached every project would have shipped the exposure T-23 describes.
- **Phase 12 is split into 12a and 12b** ([ADR 038](adr/038-kubernetes-in-two-steps.md)).
  §26 names Kubernetes in one line covering two different changes: deployment
  configuration, and moving where a scan executes. 12a is a Helm chart and pod
  hardening with no Go changes; 12b makes a scan an ephemeral Job. Together they
  would be one pull request that both introduces Kubernetes and rewrites the
  worker, with no intermediate state where either half is verifiable.
- **SBOM work is split around Phase 10, as 10a and 10b.** Storage is additive
  and touches no engine, so it landed first and every scan since has captured
  an inventory — by the time correlation uses it there is history to work
  against rather than an empty table. Correlation is a §24 material change
  needing an ADR that amends 017, and holding CI integration for it was not
  worth it. The cost of that order is real and stated: until 10b lands, a gate
  judges scores that count packages nobody deployed.

---

## Phase 10 — CI/CD integration · done

The gate computed a verdict for two phases and nothing carried it anywhere.
Now it does.

- **`cmd/cli`** — submits a scan, polls it, prints every policy rule breached or
  not, and turns the verdict into an exit code
  ([ADR 036](adr/036-ci-client-and-exit-codes.md)). A plain binary, so any
  pipeline can use it, not only GitHub's. Exit `0` did not block, `1` blocked,
  `2` **did not run** — the last one separate because a client that exited 0
  when it could not reach the API would turn an outage into a silent, universal
  disabling of the gate.
- **`.github/actions/secureops-gate`** — wraps the client, posts a PR comment
  and a step summary. **Report-only by default** on the project owner's
  direction: `fail-on-gate` is `false`, so a blocking verdict is an annotation
  rather than a failed step. Whether a verdict stops a *merge* belongs in branch
  protection, where it is a setting rather than a code change. The one thing
  that is not configurable: a gate that could not run fails the step whatever
  that input says.
- **10a — SBOM component storage** ([ADR 035](adr/035-sbom-component-storage.md)).
  Syft's CycloneDX output is parsed into components and persisted per scan,
  readable at `/projects/{id}/components` and `/scans/{id}/components`.
- **10b — deployment evidence** ([ADR 037](adr/037-deployment-evidence-from-the-sbom.md)).
  An issue keyed by a package now carries whether that package is in the image
  the project ships: `deployed`, `not_deployed`, or `unknown`. It moves no
  severity and no risk score, and that is the decision rather than an omission —
  the useful direction is downward, and lowering a real vulnerability's standing
  because an inventory did not mention its package makes every way that
  inventory can be wrong into a way to under-report.

**Not done, and it is the honest gap:** SecureOps does not gate its own pull
requests. The Action cannot reach a `localhost` API from GitHub's runners, so it
is written, tested and merged while waiting on a hostname — which is 12a's.

## Phase 12 — Kubernetes · next

Split into two ([ADR 038](adr/038-kubernetes-in-two-steps.md)), because the
split is where the trust boundary moves. Every remaining security item lives
here, and they do not all close at the same time.

### 12a — the platform runs on a cluster · next

Deployment configuration. **No Go code changes.**

- A Helm chart for `api`, `worker`, `postgres` and `redis`.
- **Images by digest, not tag.** This closes **T-10**, the only Open threat: the
  scanner binaries inside the worker image are already built from source at
  pinned commit SHAs (ADR 009, T-28), so pinning the image digest fixes exactly
  which of them runs. A tag is mutable and settles nothing.
- `securityContext` everywhere: non-root, read-only root filesystem, no
  privilege escalation, all capabilities dropped, seccomp `RuntimeDefault`.
- `resources` requests and limits, so §14.3's bounds are enforced by the
  scheduler rather than by hope.
- Default-deny `NetworkPolicy` per workload, egress opened only to what each
  provably needs.
- An Ingress, which is what the merged GitHub Action is waiting on.

Split into 12a and 12b ([ADR 038](adr/038-kubernetes-in-two-steps.md)), because
the split is where the trust boundary moves.

### 12a — the platform runs on a cluster · done

A Helm chart for `api`, `worker`, `web`, `postgres` and `redis`. No Go changes.

- **T-10 is closed.** The chart selects every image by digest and *refuses to
  render a tag* — no escape hatch, because an escape hatch is how a control
  becomes optional. With T-28's source builds at pinned commit SHAs, the digest
  fixes exactly which scanner binaries a cluster runs.
- **T-08 improved and stays Partial.** Seccomp `RuntimeDefault`, read-only root
  filesystem, all capabilities dropped, non-root, scheduler-enforced limits —
  hardening, not a sandbox.
- Default-deny NetworkPolicy in both directions. The API has **no internet
  egress at all**; the worker may reach public hosts but not the cluster network
  or the metadata address.
- `make lint-chart` asserts all of this and runs in CI, with helm pinned by
  digest like the scanners.

Verified on a real `kind` cluster rather than by reading YAML: a full scan of
`gorilla/csrf` ran end to end (5 scanners, `complete_coverage: true`, gate
`pass`), `touch /` inside the worker is refused, the worker's connection to the
API's cluster IP is dropped while PostgreSQL connects, and every running
container resolved to `repository@sha256:...`.

Three defects were found by deploying and could not have been found by review:
migrations as a pre-install hook ran before the Secret existed, then before
PostgreSQL existed; and the credential generator died silently under
`set -o pipefail`.

### 12b — a scan becomes an ephemeral Job · done

Four changes ([ADR 039](adr/039-a-scan-is-a-job-and-the-job-holds-nothing.md),
[ADR 040](adr/040-scanner-data-is-baked-and-pinned.md)): the execution seam,
`cmd/scanjob` and the result channel, the Kubernetes executor, and the
scanners' data.

A scan runs in a pod holding **no** database credential, no queue credential and
no service-account token, with a per-scan filesystem quota and a network policy
derived from `Capabilities.NetworkKinds` — the declaration that had no non-test
caller from Phase 2 until here. A repository scan is two pods: one with egress
that clones, one with none that scans.

**Verified on a cluster**, five of five scanners succeeding with no degradations
and no route off the node. The scanners' provisioned data ships in the job image
because a pod with no egress cannot fetch it; it is read-only, and only the
three directories they write to are overlaid, so the process running untrusted
binaries cannot modify the data every finding derives from.

**T-51 and `Capabilities.NetworkKinds` are closed.** They spent a phase
implemented, tested and unshippable, which is worse than either done or absent.

Off by default. `SECUREOPS_SCAN_EXECUTOR=inprocess` is what compose runs and
what an upgrade keeps; turning it on means building the job image with
`--target scanjob` and setting `scanJobs.enabled`.

## Phase 14 — Final hardening and documentation · done

The last phase, and mostly reading rather than building.

- **A full threat-model review.** It has been amended per change and never
  re-read end to end since Phase 9. Sixty-three entries, of which the Phases 1-9
  ones have not been checked against the system as it now stands.
- **The architecture documents**, which describe engines that have since gained
  deployment evidence, an execution seam, and two package splits.
- **An OpenAPI audit** — the contract test proves handlers and spec agree in
  shape, not that the prose still describes what the endpoint does.
- **The README**, refreshed at the start of this phase rather than the end,
  because it is what a reader meets first.
- **A security review of the finished system**, against §14 and §15 rather than
  against the diff of the day — [docs/security/review.md](security/review.md).

Explicitly **not** in scope: finishing 12b. That is its own work with its own
risk, and folding it into a documentation phase would be how a hardening pass
turns into a feature branch.

## Not on the phase list

Product gaps rather than plan items. None blocks a phase; each is a judgement
call about what SecureOps should be, and is recorded here so that choosing not
to do it stays a choice rather than an oversight.

### Worth the most

**A dependency graph.** Syft's `cyclonedx-json` output carries no
`dependencies` array — verified against real output, not assumed. So transitive
reasoning is out of reach: whether upgrading a direct dependency resolves a
finding in a transitive one cannot be answered, and a remediation action speaks
only about the package it names.

Syft's native `syft-json` format does carry `artifactRelationships`. Getting the
graph means capturing a second output or replacing CycloneDX — a standard chosen
deliberately and consumed by tools other than this one. Both are real options
and neither was part of 10a.

This is now the largest remaining gain in the product's core claim, and both
halves around it are done: knowing what a build contains
([ADR 035](adr/035-sbom-component-storage.md)) and saying whether a finding's
package reached it ([ADR 037](adr/037-deployment-evidence-from-the-sbom.md)).
What is still missing is the reasoning *between* components.

**Acting on deployment evidence.** 10b records whether a package is in the
built artifact and deliberately moves no score. De-escalating on absence is the
half worth wanting and was refused: the engine cannot distinguish "not in the
artifact" from "not in the artifact we looked at". ADR 037 §4 lists the four
conditions that must hold before that changes, and names the honest blocker —
nobody has yet seen this run on a corpus, so the `not_deployed` rate is assumed
rather than known. Every scan since 10b has been accumulating that evidence.

### Trust-surface decisions

**Active scanning and authenticated DAST.** SecureOps does not test for
injection. ZAP's `activeScan` job is absent from the plan rather than disabled
in it, and its rules are absent from the worker image
([ADR 026](adr/026-dast-passive-only.md)). Active scanning delivers payloads to
a live application and writes to real forms; permission to do that is a fact
about who owns a deployment, not a flag on a scan, so it needs a per-project
authorization model that does not exist. Authenticated scanning needs
credentials workers deliberately do not hold (§14.7).

**Private registries.** Image scanning is public-only. Workers hold no registry
credentials and the trivy environment is an allow-list that cannot carry any.
Granting them is new trust surface, not a configuration change.

**Project scoping for machine credentials.** A `service` token is scoped by
configuration rather than membership, so rotating what a CI job may reach is an
edit to `SECUREOPS_API_TOKENS` and a restart.

### Identity conveniences

**Self-service on an account.** Nobody can change their own password or display
name, and there is no reset flow — a reset needs a delivery channel the product
does not have. An administrator creates accounts and changes roles.

**Per-session revocation.** Sessions are stateless, so one cannot be revoked
individually; disabling the person revokes all of them, and takes effect on
their next request. The cost of not having a sessions table.

**`admin` is global.** An administrator reaches every project by definition, so
a project cannot have its own administrator who is not also everyone else's. A
deliberate simplification for a single-team tool; the alternative is a tenancy
model.

**Project membership is edited through the API**, not the Access screen:
`PATCH /api/v1/users/{id}` with a `projects` array.

### Process gaps

**No approval step on a dismissal.** One `service` credential can dismiss a
finding and nobody countersigns. Every dismissal is audited, attributed and
reversible — but detection is not prevention, and an `ignored` finding never
expires.

**Risk weights are uncalibrated against real projects.** They are configuration
with the reasoning for every constant written down
([risk-engine](architecture/risk-engine.md)), so the ordering is trustworthy
and the absolute numbers are not. Correcting them needs evidence from real
estates, not argument.

**Corroboration counts distinct names, not distinct evidence.** Grype and Trivy
read overlapping advisory feeds, so their agreement is weaker than it looks.
Bounded by capping the raise at one step.

**Shallow clones, so no git history.** A credential committed and later removed
is not found. Full history would multiply clone size and time for untrusted
input.

**No project deletion.** Archiving is the only removal, by design: §17 requires
security-relevant records to be soft-deleted, and a project's scans, findings
and audit trail are exactly that.

---

## Dropped

**Phase 13 — Observability.** Removed on 2026-09-05
([ADR 034](adr/034-no-observability-phase.md)). Most of what the phase named
already shipped in Phases 1 and 2 — structured logging, health checks, and
per-scan telemetry persisted in `scan_results` — and what remained was a
Prometheus endpoint and OTel tracing that answer no question anybody is asking
about a single-operator tool. A metrics endpoint on a security tool is also a
disclosure surface that must be authenticated whether or not anybody reads it.

Where an operational question arises, the answer is to add the one measurement
that answers it, not to adopt a metrics stack. That is §4's own rule.
