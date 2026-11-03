# SecureOps — Claude Code Project Guide

**Authoritative specification:** [docs/SecureOps_Claude_Code_Project_Specification.md](docs/SecureOps_Claude_Code_Project_Specification.md)

This file governs every Claude Code session in this repository. It is the operational
distillation of the specification, not a replacement for it. Where this file and the
specification disagree, the specification wins — and the contradiction must be reported
and fixed rather than silently worked around.

---

## 1. Current Repository State (verified, not assumed)

**Phases 1-2 are complete. Phase 3a is complete (scan API + interim authentication
gate). Phase 3b is complete: repository fetching plus the Gitleaks, Syft, Grype,
Semgrep, Trivy, and ZAP adapters have all landed. Trivy serves image targets
against public registries (ADR 025) and ZAP serves endpoint targets, passive
only (ADR 026). Every target kind the model defines now has an adapter. Phase 4 is
complete (normalization, fingerprinting, deduplication, and
findings persistence with lifecycle). Phase 5 is complete (correlation: contextual
issues, cross-domain links, deterministic severity escalation). Phase 6 is
complete: threat-intelligence capture (EPSS with provenance, ADR 018) and the
risk engine (contextual scoring, max-dominant aggregation, ADR 019). Phase 7 is
complete: fix facts captured from vendor data, and the remediation engine
(consolidated actions ranked by risk removed, ADR 020). Phase 8 is complete:
the security policy engine and gate (ADR 021) plus the durable append-only
audit log (ADR 022). Phase 9 is complete: the dashboard reads the API
server-side with its own credential (ADR 027) and may submit a scan but not
judge one (ADR 029). Phase 11 is complete for identity and authorization
(ADR 033, three changes): scoped credentials, then local accounts with roles
and project membership, then user administration through an audited API and an
admin-only Access screen, plus project archiving. Phase 11's remaining line —
isolation, network restrictions, resource limits — belongs to Phase 12.
Phase 10 is complete: 10a stores a scan's SBOM components (ADR 035), the CI
client turns a gate verdict into an exit code and a report-only GitHub Action
wraps it (ADR 036), and 10b records on an issue whether its package reached the
built artifact, moving no severity and no score (ADR 037). Phase 12a is
complete: a Helm chart deploys the platform with every image selected by digest
— the chart refuses a tag, which closed T-10, the last Open threat — plus
non-root pods with read-only root filesystems and seccomp, scheduler-enforced
limits, and default-deny network policies; `make lint-chart` asserts these and
runs in CI. Phase 12b is complete (ADR 039, ADR 040): the execution seam,
`cmd/scanjob`, the result channel and the Kubernetes executor are merged, and a
scan can run in a pod holding no database, queue or cluster credential, with a
per-scan filesystem quota and a network policy derived from
`Capabilities.NetworkKinds`. A repository scan is two pods, the scanning half
with no egress at all — verified on a real cluster. The scanners' provisioned data ships in the
job image (ADR 040), read-only, with only the three directories they write to
overlaid — so all five scanners succeed in a pod with no egress, verified on a
cluster. The mode stays off by default: `SECUREOPS_SCAN_EXECUTOR=inprocess` is
what compose runs and what an upgrade keeps. Phase 14 is
complete: the threat model was re-read end to end, the correlation architecture
document and the OpenAPI contract were brought back in line with what shipped,
and [docs/security/review.md](docs/security/review.md) records the system read
against §14 and §15 as a whole.**
See §26 for why Phase 3 is split, and for the deviations that split records.

Git: branch `main`, remote `git@github.com:aizen299/secure-dev.git`.
Go module path: **`github.com/aizen299/secure-dev`** (matches the remote; the product name
in code, docs, and UI remains SecureOps).

What exists:

```text
LICENSE  CLAUDE.md  README.md  Makefile  .gitignore  .env.example
go.mod  go.sum  .golangci.yml  docker-compose.yml
cmd/api/          API server: config, logging, health, graceful shutdown
cmd/worker/       scan worker + scanner registration point
cmd/migrate/      migration runner (up / down / version)
cmd/useradd/      bootstrap the first admin account; password
                  from stdin, never a flag (ADR 033)
cmd/cli/          CI client: submit, wait, gate, exit code
                  (ADR 036)
cmd/scanjob/      runs one scan and reports it, holding no
                  credential of any kind (ADR 039)
cmd/useradd/      creates an account; the first admin (ADR 033)
internal/config/          env config + secret redaction        [tested]
internal/logging/         slog setup                           [tested]
internal/auth/            interim bearer tokens + roles
                          (ADR 006, ADR 023)                   [tested]
internal/projects/        project entity + store               [tested]
internal/httpapi/         chi router, middleware, auth gate,
                          projects + scans handlers, health    [tested]
internal/netguard/        SSRF address policy + dial guard     [tested]
internal/fetch/           git clone into the workspace         [tested]
internal/scanners/        Scanner interface, Target model,
                          registry, safe exec, workspace       [tested]
internal/scanners/gitleaks/  secret scanning, with the
                          ADR 007 redaction control            [tested]
internal/scanners/syft/   CycloneDX SBOM generation            [tested]
internal/scanners/grype/  known-vulnerability matching         [tested]
internal/scanners/semgrep/ SAST, with pinned rulesets          [tested]
internal/scanners/zap/    DAST against a running application;
                          passive only, with the ADR 026
                          redaction control; runs from the jar
                          in the worker image (ADR 030)         [tested]
internal/scanners/httpprobe/ DAST the passive scan cannot do:
                          CORS origin checks and the plain-HTTP
                          redirect, no external binary, no
                          payloads (ADR 041)                    [tested]
internal/scanners/trivy/  IaC + config (ADR 015 line-redaction
                          control); container image vulns from
                          public registries (ADR 025)           [tested]
internal/normalization/   canonical Finding, fingerprinting,
                          severity mapping, dedup, threat
                          intelligence (pure)                  [tested]
internal/correlation/     issues, links, severity escalation
                          (pure; ADR 017)                      [tested]
internal/risk/            contextual scoring, aggregation,
                          weights + digest (pure; ADR 019)     [tested]
internal/remediation/     consolidated actions, ranking by
                          risk removed (pure; ADR 020)         [tested]
internal/policies/        gate rules, PASS/WARN/FAIL, policy
                          + result persistence (ADR 021)       [tested]
internal/audit/           append-only audit records, written
                          in the caller's tx (ADR 022)         [tested]
internal/findings/        findings, issue, and risk-score
                          persistence; lifecycle state machine
                          + human transitions (ADR 024)        [tested]
internal/cli/             CI client: poll, gate, exit codes
                          (ADR 036)                            [tested]
internal/sbom/            CycloneDX -> components, per-scan
                          inventory storage (ADR 035)          [tested]
internal/users/           local accounts: Argon2id passwords,
                          roles, membership, stateless sessions,
                          last-admin guard (ADR 033)           [tested]
internal/scans/           lifecycle + PARTIAL semantics, store [tested]
internal/queue/           job queue (Redis + in-memory)        [tested]
internal/worker/          job runner, concurrency, timeouts    [tested]
internal/storage/postgres/ pgx pool + readiness probe
internal/storage/redis/    go-redis client + readiness probe
apps/web/         Next.js 16 dashboard: landing, projects, posture,
                  findings triage, issues, remediation, scans; a URL bar
                  that queues a repository or website scan; account login
                  carrying the person's own session (ADR 033); an
                  admin-only Access screen for accounts and roles, and
                  project archive/restore; server-side typed API client
                  (ADR 027); vitest unit tests (ADR 031)        [tested]
migrations/       0001_init, 0002_scan_results, 0003_scan_targets,
                  0004_scanner_degradations, 0005_findings,
                  0006_correlated_issues, 0007_threat_intelligence,
                  0008_risk_scores, 0009_fix_facts,
                  0010_security_policies, 0011_audit_logs,
                  0012_transition_notes, 0013_finding_image,
                  0014_finding_endpoint,
                  0015_audit_history_not_relation,
                  0016_users_and_membership,
                  0017_sbom_components, 0018_issue_deployment
                  (+ rollbacks)
tests/fixtures/<scanner>/  captured output, incl. hostile cases
deployments/docker/  api.Dockerfile (distroless), web.Dockerfile
tests/integration/   real Postgres + Redis, `integration` build tag
docs/adr/         000-template, 001-go-backend, 002-postgresql, 003-redis,
                  004-scanner-isolation, 005-keep-golang-migrate,
                  006-interim-bearer-token-auth,
                  007-secret-redaction-in-raw-results,
                  008-repository-fetching,
                  009-build-scanners-from-source,
                  010-scanner-degradation-reasons,
                  011-api-contract-enforced-by-tests,
                  012-vulnerability-database-provisioning,
                  013-govulncheck-as-a-second-gate,
                  014-semgrep-is-installed-not-built,
                  015-trivy-output-is-rewritten-before-storage,
                  016-canonical-finding-model-and-fingerprint,
                  017-correlation-issues-and-severity,
                  018-threat-intelligence-is-its-own-attribute,
                  019-risk-scoring-and-aggregation,
                  020-remediation-actions-and-prioritization,
                  021-policy-evaluation-and-gates,
                  022-durable-audit-log, 023-token-roles,
                  024-human-finding-transitions,
                  025-container-image-targets,
                  026-dast-passive-only,
                  027-dashboard-data-access,
                  028-audit-references-are-historical,
                  029-dashboard-authentication,
                  030-zap-in-the-worker-image,
                  031-a-test-harness-for-the-dashboard,
                  032-target-validation-is-its-own-endpoint,
                  033-identity-roles-and-project-scoping,
                  034-no-observability-phase,
                  035-sbom-component-storage,
                  036-ci-client-and-exit-codes,
                  037-deployment-evidence-from-the-sbom,
                  038-kubernetes-in-two-steps,
                  041-http-probe-for-cors-and-https,
                  042-resolving-respects-the-scanned-url
docs/architecture/  fingerprinting.md, normalization.md, correlation.md,
                  risk-engine.md, remediation.md, policy.md
.github/workflows/ci.yml
.github/actions/secureops-gate/  the CI gate, report-only (ADR 036)
scripts/install-scanner.sh  pinned, digest-verified scanner
                  downloads for CI (T-19, T-61)
```

What does **not** exist yet — do not assume otherwise, check the filesystem first:

- **Active scanning, and authenticated DAST.** The `activeScan` job is
  deliberately absent from the automation plan, not disabled in it (ADR 026), so
  SecureOps does not test for injection. Active scanning needs a per-project
  authorization model, because permission to attack a host is a fact about a
  deployment rather than a flag on a scan. Authenticated scanning needs
  credentials workers do not hold (§14.7).
- **Private registries.** Image scanning is public-only: workers hold no
  registry credentials (§14.7) and the trivy environment is an allow-list that
  cannot carry any. Image size is capped (`--max-image-size`, default 2GB), but
  that bounds the compressed size a manifest declares — layer expansion is still
  bounded only by the disk trivy extracts into, and closing that needs Phase
  12's ephemeral per-job filesystem (T-51).
- **No enforcement of `Capabilities.NetworkKinds`.** Adapters now declare which
  target kinds need egress, and nothing reads the declaration to impose a
  network policy. It is honest metadata awaiting Phase 12.
- `internal/assets/`, `reports/` — the remaining engines.
- **No approval step on a dismissal.** A `service` token can dismiss a finding
  alone (ADR 024). Every dismissal is audited, attributed, and reversible, but
  nobody countersigns and an `ignored` finding never expires.
- **No de-escalation on deployment evidence.** Correlation now says whether an
  issue's package is in the built artifact — `deployed`, `not_deployed`, or
  `unknown` (ADR 037) — and deliberately moves no severity and no score. Acting
  on absence is the half worth wanting and is refused: the engine cannot
  distinguish "not in the artifact" from "not in the artifact we looked at".
  ADR 037 §4 lists the four conditions that would have to hold, and names the
  blocker: nobody has seen this run on a corpus, so the `not_deployed` rate is
  assumed rather than known.
- **No dependency graph.** Syft's `cyclonedx-json` output carries no
  `dependencies` array -- verified, not assumed. So transitive reasoning is out
  of reach: whether upgrading a direct dependency resolves a finding in a
  transitive one cannot be answered, and a remediation action still speaks only
  about the package it names. Syft's native `syft-json` does carry
  `artifactRelationships`; capturing it is a separate decision.
- **No self-service on an account, and no password reset.** People sign in with
  accounts (ADR 033): local Argon2id passwords, three roles, project membership,
  and a session the API issues and the dashboard forwards in place of its own
  credential — so a viewer reads what a viewer may read and the audit trail
  records `user / <id>`. An admin manages accounts from the Access screen or
  `POST/PATCH /api/v1/users`, and the API refuses to demote or disable the last
  enabled administrator. What is missing: nobody can change their own password
  or name, there is no reset flow (it needs a delivery channel the product does
  not have), a session cannot be revoked individually — only by disabling the
  person — and project membership is edited through the API rather than the
  page. T-23 is Partial for those conveniences, not for a missing control.
- **A `service` token is scoped by configuration, not membership.** Tokens carry
  a role and a scope — `label:role:scope:secret` (ADR 023, ADR 033) — so a CI
  credential cannot edit a security policy and reaches only the projects it was
  granted. Enforced in the `/projects/{id}` middleware, in the `GET /projects`
  query, and on the five id-addressed endpoints that have no project in the URL.
  Rotating what a CI job may reach is an edit to `SECUREOPS_API_TOKENS` and a
  restart.
- **No project deletion.** Archiving is the only removal: it hides a project
  from lists and stops it accepting new scans, while its scans, findings,
  issues and history stay readable at their URLs, and it is reversible from the
  project's own page (ADR 033 §6, §17). A delete endpoint is deliberately
  absent, not missing.

Sections below describe the **intended** system. Phase 1 established the foundation only.

---

## 2. Purpose

SecureOps is a unified DevSecOps security assessment platform. It orchestrates
heterogeneous security scanners, normalizes their outputs into one canonical finding model,
correlates related findings across security domains, computes a context-aware project risk
score, generates prioritized remediation guidance, and enforces configurable security gates
in CI/CD.

The product identity — hold this line in code, docs, UI, and API design:

> **SecureOps turns fragmented security scanner output into one contextual security decision.**

It is **not** "a dashboard that runs several CLI tools." The value is the intelligence
layer: `NORMALIZE → CORRELATE → CONTEXTUALIZE → SCORE → REMEDIATE → GATE`.

---

## 3. Architecture Overview

```text
Next.js UI  ──►  Go API  ──┬──►  PostgreSQL   (durable domain state)
                           └──►  Redis queue  ──►  Scanner Workers (isolated)
                                                        │
                                                        ▼
                                     Normalization → Correlation → Risk
                                          → Remediation → Policy
                                                        │
                                              ┌─────────┴─────────┐
                                              ▼                   ▼
                                         Dashboard            CI/CD gate
```

The Go API **orchestrates**; it never executes scanners itself. Workers execute scanners in
isolation and are the only component that ever touches untrusted target content.

### Core scan pipeline (every scan follows this)

```text
Target → Target Validation → Scanner Selection → Async Job Creation → Scanner Execution
→ Raw Results → Parsing → Normalization → Deduplication → Cross-Domain Correlation
→ Context Enrichment → Risk Scoring → Remediation Generation → Policy Evaluation
→ Persistence → Report / Dashboard / CI Result
```

Each stage is a distinct, independently testable package. Do not collapse stages.

---

## 4. Technology Stack

| Layer | Choice | Notes |
|---|---|---|
| Frontend | Next.js + TypeScript + Tailwind + shadcn/ui + Recharts | consumes SecureOps API models only |
| Backend | Go + Chi | owns API, auth, orchestration, all engines, persistence |
| Database | PostgreSQL | relational; no document store "for convenience" |
| Queue/Cache | Redis | async scan jobs, transient state, caching |
| Containers | Docker | non-root images |
| Orchestration | Kubernetes + Helm | **later phase only**; scanner jobs as ephemeral Jobs |
| CI/CD | GitHub Actions | least privilege, SHA-pinned third-party actions |
| Observability | structured logs, Prometheus metrics, health checks; OTel tracing where useful | proportional — do not build an observability platform |

**Do not add Python** unless a concrete ML/data-analysis requirement justifies it, recorded
in an ADR. **Do not add** Kafka, Elasticsearch, service meshes, or microservices without a
concrete requirement in an ADR.

### Verified local toolchain

Go 1.27.0 (darwin/arm64) · Node 26.7.0 · npm 11.19.0 · Docker 29.7.2 (daemon running) ·
Compose v5.4.0 · Git 2.50.1 · golangci-lint 2.13.1 · gitleaks 8.30.1 · syft 1.51.0 ·
grype 0.117.0 · trivy 0.74.0 · semgrep 1.174.0 · kubectl 1.36.1 · helm v4.2.4 ·
psql 17.11 · redis-cli 8.10.1 · gh 2.98.0

That list is what was last verified by hand, and the repository now needs more:
`go.mod` requires Go 1.27.3, the Dockerfiles name `golang:1.27.3-alpine`, and CI uses
semgrep 1.183.0. `make lint-go` needs golangci-lint 2.14.0 or later: 2.13.x cannot read
Go 1.27.3's export data, and reports `typecheck` errors on clean code.

OWASP ZAP 2.17.0 is installed locally but is **not on PATH** — on macOS it lives
inside `/Applications/ZAP.app`, so the adapter takes a configurable launcher path
(`SECUREOPS_ZAP_COMMAND`) and is skipped by tests when it is unset.

In the **worker image** ZAP is installed and runs from its jar rather than
through its launcher, which is bash (ADR 030). The image is the thing that opts
into jar mode, via `SECUREOPS_ZAP_JAR`; a local checkout leaves it unset and
keeps using the launcher.

Never assume a tool is present — probe with `command -v` (or run `make tools`),
and degrade gracefully with a clear error when a scanner binary is missing.

---

## 5. Target Repository Structure

Build toward this. **Do not create empty directories ahead of need.**

```text
apps/web/                 Next.js dashboard
cmd/api/                  Go API server binary
cmd/worker/               scanner worker binary
cmd/cli/                  CI/CD client binary
internal/auth/            authn + RBAC
internal/projects/        projects, repositories
internal/scans/           scan lifecycle, job orchestration
internal/scanners/        adapters ONLY (gitleaks, semgrep, syft, grype, trivy, zap)
internal/normalization/   raw → canonical Finding, fingerprinting, dedup
internal/correlation/     cross-domain correlation
internal/risk/            deterministic risk scoring
internal/remediation/     remediation aggregation + prioritization
internal/policies/        security policy / gate evaluation
internal/assets/          asset inventory
internal/sbom/            SBOM storage and querying
internal/reports/         report generation
migrations/               SQL migrations (forward + rollback)
deployments/docker/       Dockerfiles, compose
deployments/kubernetes/   manifests, Helm (later phase)
.github/workflows/        CI
docs/architecture|adr|security|api/
scripts/
tests/integration/  tests/fixtures/<scanner>/
.claude/settings.json  .claude/commands/
```

Package boundary rule: `internal/scanners/**` is the **only** place scanner-specific
knowledge may live. Nothing outside it imports a scanner adapter's parsing types.

Phases 1-2 added these packages, which the specification's structure does not name. They
are deliberate, not drift — keep using them rather than inventing parallels:

```text
cmd/migrate/              migration runner (up / down / version)
internal/config/          environment configuration + secret redaction
internal/logging/         slog construction
internal/httpapi/         chi router, middleware, error envelope, health
internal/netguard/        SSRF address policy, shared by target validation
internal/queue/           the scan job queue contract + Redis/in-memory impls
internal/worker/          the job runner (consumes queue, drives adapters)
internal/storage/postgres/  pgx pool      (implements httpapi.Probe)
internal/storage/redis/     go-redis client (implements httpapi.Probe)
```

The `scanners` root package holds the **contract only** — `Scanner`, `Target`, the
registry, and the safe-exec helpers. Adapters live in `internal/scanners/<name>/`
subpackages and import the root for the interface. The root must never import an adapter,
and must never branch on a scanner's name.

`docker-compose.yml` lives at the repository root (as the specification shows);
`deployments/docker/` holds the Dockerfiles.

---

## 6. Scanner Responsibilities

| Domain | Tool | Responsibility |
|---|---|---|
| SAST | Semgrep | source-code vulnerabilities |
| Secrets | Gitleaks | exposed credentials/secrets |
| SBOM | Syft | Software Bill of Materials generation |
| Dependency | Grype | known dependency vulnerabilities |
| Container | Trivy | container/image vulnerabilities |
| Repository / IaC / Config | Trivy | misconfiguration, IaC issues |
| API / DAST | OWASP ZAP | dynamic application testing — **passive only**, no active scanning (ADR 026) |
| API / DAST | httpprobe (built in) | CORS origin checks and the plain-HTTP redirect, which passive rules cannot observe (ADR 041) |
| License | Trivy / SBOM ecosystem | license and component visibility |

Every scanner has exactly one clear responsibility. Do not duplicate coverage across
scanners without a documented reason. ZAP ships in the worker image and runs from its
jar (ADR 030); the local dev loop does not depend on it, and every ZAP test that
needs a binary skips unless `SECUREOPS_ZAP_COMMAND` is set.

---

## 7. Scanner Abstraction (non-negotiable)

Every scanner is an adapter behind a stable internal interface:

```go
type Scanner interface {
    Name() string
    Version(ctx context.Context) (string, error)
    Scan(ctx context.Context, target Target) (RawResult, error)
}
```

Each adapter directory holds `scanner.go` (execution), `parser.go` (raw output → adapter
types), `mapper.go` (adapter types → canonical `Finding`).

**Hard rules:**

1. Scanner-specific logic stays **entirely** behind the adapter. No exceptions.
2. **Never** write `if scanner == "trivy"` / `switch scanner {...}` branching in
   normalization, correlation, risk, remediation, policy, API handlers, or the UI. If you
   feel the need, the adapter interface is wrong — fix the interface, or add a capability
   flag on the adapter.
3. The core platform must never import or depend on scanner-specific result formats.
4. Adding a new scanner must require **zero** changes outside `internal/scanners/<new>/`
   plus one registration entry. If it requires more, the abstraction has leaked — stop and
   fix it.
5. The UI consumes SecureOps domain models only. Raw scanner JSON never reaches the client.
6. Scanner binary version is captured per scan and persisted (results are only reproducible
   relative to a tool version).

---

## 8. Normalization Model

All scanner output converges on one canonical `Finding`:

```text
id · scanner · scanner_finding_id · category · severity · title · description
file · line · package · dependency · container · image · endpoint
cve · cwe · cvss · exploitability · evidence · remediation
fingerprint · confidence · asset_id · project_id · scan_id
first_seen · last_seen · status
```

Refine the concrete schema during implementation; keep the shape.

**Rules:**

- Raw scanner output is **persisted verbatim** (size-capped) for audit and reprocessing,
  then parsed. Never discard raw results.
- Normalization is pure and deterministic: `raw bytes → []Finding`, no I/O, no network.
  This is what makes it fixture-testable.
- Validate every normalized finding. Malformed or hostile scanner output must produce a
  structured parse error, never a panic and never a silently dropped finding.
- Severity is normalized to one SecureOps scale. Record the original scanner severity too.

### Fingerprinting & deduplication

```text
fingerprint = SHA256(vulnerability_type + normalized_location + package + CVE/CWE + affected_component)
```

- **Never** deduplicate on title equality or string similarity.
- Distinguish four relationships explicitly: `exact duplicate`, `likely duplicate`,
  `related`, `independent`. Do not merge findings because they look similar.
- The exact fingerprint inputs must be documented in
  `docs/architecture/` and covered by unit tests including near-miss cases.
- Fingerprints must be stable across scans so a finding's lifecycle survives re-scanning.

---

## 9. Correlation Engine

Correlates findings across SAST, secrets, dependencies, SBOM, containers, IaC, and APIs to
identify when several findings represent one underlying security problem.

- Correlation operates **only** on canonical findings plus asset inventory — never on raw
  scanner output.
- Correlation is deterministic and explainable: every correlation records **why** it was
  made (the linking evidence: shared package + version, shared image digest, shared file
  path, shared CVE, shared endpoint).
- Correlation **links** findings; it must not destroy them. A correlated group keeps its
  members individually queryable.
- Correlation must not invent relationships. When evidence is weak, emit `related` with a
  confidence value, not a merge.
- Example target behavior: Grype CVE on `express` + Semgrep unsafe Express config in
  `server.ts` + Trivy finding the same package in a production image → one contextual issue
  escalated to CRITICAL, with all three sources retained as evidence.

---

## 10. Risk Engine

```text
Risk = Severity Weight × Exploitability × Exposure × Asset Criticality × Confidence
```

Project score normalized to `0 (secure) … 100 (critical)`.

**Rules:**

- The risk engine is a **pure, deterministic, side-effect-free** function of findings +
  asset context. Same inputs → same score, always.
- No naive severity-to-number mapping. Contextual factors are the point: exploitability,
  exposure, reachability, asset criticality, deployment context (prod vs dev), internet
  exposure, known-exploit presence, whether the vulnerable component is actually deployed,
  affected component count, vulnerability density, confidence.
- The formula, every weight, and every factor's derivation are documented in
  `docs/architecture/risk-engine.md` **and** an ADR before implementation.
- Unit tests are mandatory and must cover boundary conditions, factor isolation, and score
  monotonicity (adding a finding must never reduce risk).
- Weights are configuration, not magic numbers scattered in code.
- No LLM/AI influences the score. Scoring is deterministic; AI may only explain.

---

## 11. Remediation Engine

- Deterministic scanner/vendor data (fixed version, upgrade path, patch reference) is
  **authoritative**. It is the source of truth for what to do.
- Consolidate and deduplicate recommendations across scanners; prioritize by risk;
  always identify the affected component.
- **Never invent fixes.** Never present AI-generated remediation as verified.
- AI assistance is permitted for *contextual explanation* and for *remediation
  prioritization guidance* (spec §4.4) — never for the facts of a fix, and never for the
  risk score itself (§10 is deterministic). Any AI-derived content must be structurally
  distinguishable from verified data in the model, the API response, and the UI
  (e.g. explicit `source: "vendor" | "scanner" | "ai_explanation"`).
- Do not label deterministic rule engines "AI."
- Track remediation status through the finding lifecycle.

---

## 12. Security Policy Engine

Produces `PASS` / `WARN` / `FAIL` from configurable per-project policy, e.g. max critical =
0, max high = 5, max secrets = 0, minimum risk score = 70.

**Rules:**

- Evaluation is deterministic and must **explain the exact conditions** that produced the
  result — never a bare verdict.
- Policy is data (per-project configuration), not hardcoded thresholds.
- Policy changes are security-sensitive: audit-logged, authorization-checked.
- Output is both machine-readable (for CI) and human-readable (for PR comments/dashboard).
- A `PARTIAL` scan (a scanner failed) must never be evaluated as if it were complete —
  surface degraded coverage in the gate result.

---

## 13. Scan Lifecycle & Asynchronicity

**Long-running scans are asynchronous. This is architectural, not an optimization.**

- `POST /scans` → **202 Accepted** with a `scan_id`, immediately. The HTTP request **never**
  blocks on scanner execution.
- Work is dispatched via Redis to workers. Progress is polled via `GET /scans/{id}` (or
  streamed), never by holding a request open.
- Scan states: `QUEUED · RUNNING · PARTIAL · COMPLETED · FAILED · CANCELLED`.
- A partial scanner failure **must not** be reported as a successful complete scan. Record
  per-scanner status, exit code, duration, and structured error.
- Jobs support cancellation, timeout, safe retries, concurrency limits, resource limits,
  progress reporting, and structured failure reporting.
- Scans are durable entities: id, project, commit SHA, branch, started_at, completed_at,
  status, scanner versions, result summary.

---

## 14. Scanner Isolation (critical security requirement)

SecureOps processes attacker-controlled repositories, Dockerfiles, manifests, and archives.

1. **The API server never executes untrusted repository content — no scanners, no builds,
   no package-manager installs, no `git hooks`, nothing.** The API only validates input,
   persists state, and enqueues jobs.
2. Scanner execution happens exclusively in isolated worker processes (later: ephemeral
   Kubernetes Jobs with security contexts and network policies).
3. Every scanner execution runs with: non-root user, restricted read-only filesystem where
   possible, ephemeral workspace destroyed after the job, CPU limit, memory limit, hard
   execution timeout, and network restrictions (deny by default; allow only what the
   scanner provably needs, e.g. vulnerability DB updates).
4. Never invoke scanners through a shell string. Use `exec.CommandContext` with an argument
   vector. No `sh -c`, no string interpolation of user-controlled values into commands.
5. Validate and canonicalize all paths. No path traversal outside the ephemeral workspace.
6. Validate target URLs against SSRF (block link-local, loopback, and private ranges unless
   explicitly configured).
7. Workers hold least privilege: no database superuser, no cloud credentials, no
   registry-write access.

### Resource exhaustion limits (all configurable)

`max repository size · max scan duration · max memory · max CPU · max output size ·
max concurrent scans · max artifact size · max file count · max archive expansion ratio`

Enforce them; exceeding a limit is a structured failure, not a crash.

---

## 15. Security Requirements (SecureOps must itself be secure)

1. **Never** hard-code credentials, tokens, or keys in source.
2. **Never** commit `.env` files, credentials, or key material. A `.gitignore` covering
   `.env*`, build output, and scanner artifacts is required before the first code lands.
3. **Never** log secrets, tokens, or raw finding evidence that contains a detected secret.
   Redact secret values in Gitleaks/Trivy findings — store a location and a hash, not the
   secret.
4. Authentication and authorization are enforced **server-side**, on every request. UI
   restrictions are not a security control.
5. RBAC roles: `Admin · Security Engineer · Developer · Viewer`. Authorization is checked at
   the API boundary and at the data layer for project scoping.
6. Audit-log security-sensitive actions: scan creation, project changes, policy changes,
   finding state changes, user/role changes, remediation actions. Record who, when, what
   changed, previous and new value.
7. Treat **all** of the following as untrusted input: repository contents, Dockerfiles,
   package manifests, archives, uploaded SBOMs, webhook payloads, **and scanner output
   itself** (poisoned scanner output is in the threat model).
8. Validate and bound every external input; size-cap every parse.
9. Use parameterized SQL only. No string-concatenated queries.
10. Containers run as non-root with dropped capabilities.
11. Least privilege everywhere: DB roles, CI tokens, Kubernetes service accounts, registry
    access.
12. **Never disable a security control to make a test or build pass.** Fix the code.
13. No security through obscurity.
14. Maintain `docs/security/threat-model.md`, `security-model.md`, `trust-boundaries.md`.
    Update the threat model whenever architecture changes materially.
15. Trust boundary chain to keep in mind:
    `User → Web UI → API → Orchestrator → Worker → Untrusted Repository`.

---

## 16. CI/CD Strategy

- GitHub Actions is a first-class integration:
  `PR/Push → SecureOps scan → normalize → correlate → risk → policy → PASS/FAIL/WARN`.
- CI output must be both machine-readable (JSON, for status checks) and human-readable
  (PR summary).
- **CI is attack surface.** Default `permissions: contents: read`; add scopes only where
  required and only on the job that needs them.
- Pin third-party actions to immutable commit SHAs, not mutable tags.
- Never expose sensitive credentials to `pull_request` workflows from forks.
- The repository's own pipeline must run: format → lint → build → unit tests → integration
  tests → self-scan (gitleaks, semgrep, syft/grype, trivy).
- SecureOps must dogfood itself: SecureOps scans SecureOps.

---

## 17. Database Conventions

- PostgreSQL only. Design the relational model deliberately; no document store for
  convenience.
- Expected entities: `users · projects · repositories · scans · findings ·
  finding_occurrences · assets · dependencies · containers · apis · sboms · remediations ·
  security_policies · policy_results · scan_metrics · audit_logs`.
- Every schema change is a versioned migration in `migrations/` with a rollback. Never edit
  an applied migration; add a new one.
- `snake_case` tables and columns; plural table names; explicit foreign keys; indexes
  justified by real query patterns.
- Timestamps are `timestamptz`, stored UTC.
- `findings` carries the stable `fingerprint` (indexed) — it is how lifecycle continuity
  works across scans.
- Finding lifecycle states: `OPEN · ACKNOWLEDGED · IN_PROGRESS · RESOLVED · REOPENED ·
  FALSE_POSITIVE · IGNORED`. Every transition records who, when, why, previous state, new
  state.
- Soft-delete or archive security-relevant records; audit logs are append-only.
- Database migrations are a security-sensitive change — review them explicitly.

---

## 18. API & Frontend Conventions

- REST under `/api/v1`. Versioned. Never silently change a public API contract.
- Resource-oriented, plural nouns; `202` for async scan creation; consistent structured
  error envelope; pagination on every list endpoint.
- Keep `docs/api/openapi.yaml` in sync with handlers — an API change with no spec change is
  incomplete.
- The frontend consumes SecureOps domain models only. No scanner-specific shapes, no raw
  scanner JSON, no scanner conditionals in components.
- Dashboard reads as a security operations view (score, severity distribution, trends,
  gate result, recent scans), not generic CRUD. Prioritize information hierarchy and
  actionability.
- Server state via a typed API client; types generated from or checked against the OpenAPI
  spec.

---

## 19. Testing Requirements

Testing is a first-class requirement, not a follow-up task.

**Unit tests (mandatory):** normalization, fingerprinting, deduplication, correlation, risk
calculation, remediation prioritization, policy evaluation, input validation.

**Integration tests:** API→database, API→queue, worker→scanner, worker→normalization,
normalization→persistence, policy→CI result.

**Scanner fixtures:** `tests/fixtures/<scanner>/` holds realistic captured scanner output.
Tests must **not** depend on live scanner execution — the deterministic engines are tested
against fixtures. Include malformed, truncated, empty, and hostile-output fixtures.

**End-to-end:** at least one complete path — test repository → scan → workers → normalized
findings → correlation → risk score → policy → API/dashboard result.

Rules: new behavior ships with tests. Fixtures containing real secrets are forbidden — use
synthetic values. Never weaken a test or a security control to get green.

---

## 20. Git Rules

- Preserve the MIT `LICENSE` — never remove, replace, or relicense it.
- **Commit only when explicitly instructed.** Never commit proactively.
- Never force-push, never rewrite history, never delete user work without explicit approval.
- Inspect `git status` and `git diff` before reporting work complete.
- Never commit secrets, `.env` files, credentials, scanner artifacts, SBOM output, build
  output, or `node_modules`.
- Do not modify files unrelated to the task at hand.
- Commit style: `type(scope): summary`, e.g.
  `feat(scanner): add gitleaks adapter` · `feat(risk): implement contextual risk scoring` ·
  `fix(correlation): prevent duplicate findings` · `test(normalization): add trivy fixtures` ·
  `docs(architecture): document scanner pipeline`.
- Note: the git remote is `secure-dev`, while the specification's preferred repository name
  is `secureops`. Use **SecureOps** as the product/module name in code and docs; do not
  rename the remote without instruction.

---

## 21. Documentation Rules

- Architecture documentation lives in `docs/`, not in code comments:
  `docs/architecture/` (overview, scanner-pipeline, correlation, risk-engine),
  `docs/adr/`, `docs/security/`, `docs/api/openapi.yaml`.
- Write an **ADR before** a meaningful architectural decision, not after. Each ADR states
  context, decision, alternatives considered, rationale, consequences.
- Initial ADR candidates: `001-go-backend`, `002-postgresql`, `003-redis`,
  `004-scanner-isolation`, `005-canonical-finding-model`, `006-contextual-risk-engine`,
  `007-kubernetes-scanner-jobs`.
- The risk formula, fingerprint strategy, and correlation rules **must** be documented
  before or alongside their implementation — they are the project's core innovation and
  the parts most likely to drift.
- Update the threat model when trust boundaries change.
- Do not duplicate the specification into other docs; link to it.

---

## 22. Development Workflow

```text
1. Requirement
2. Inspect the repository (never modify before inspecting)
3. Identify affected architecture and trust boundaries
4. Produce an implementation plan
5. Human reviews and approves the plan
6. Implement only the approved scope
7. Run tests
8. Run format + lint
9. Run security checks
10. Inspect the git diff
11. Report changes, risks, and limitations
12. Commit only when explicitly instructed
```

A feature request is **not** permission to rewrite the architecture. Work phase by phase;
prefer small coherent changes; preserve existing functionality; do not add dependencies
without a stated reason.

### Validation commands

Discover the real commands from the repository (`Makefile`, `package.json`) rather than
inventing them. Once the toolchain exists, expect roughly:

```bash
gofmt -l . && go vet ./... && go build ./... && go test ./... -race
```

```bash
npm --prefix apps/web run lint && npm --prefix apps/web run build
```

Self-scan (the five static scanners; ZAP is not part of the self-scan — SecureOps
has no running deployment to point DAST at during a build):

```bash
make security
```

That target runs gitleaks (scoped by `.gitleaks.toml`), semgrep against pinned rulesets
(`--config auto` is deliberately not used: it requires telemetry to be enabled and is not
reproducible), trivy, and syft/grype.

Prefer the `make` targets — they are the single source of truth for validation
(`make check` for all non-container checks, `make security` for the self-scan, `make tools`
to see what is available). ZAP is installed but is not on PATH and is not exercised by
`make security`. Never silently skip a validation step — report it as skipped and why.

---

## 23. Definition of Done

A feature is complete only when **all** of the following hold:

- [ ] Requirements understood and existing architecture inspected
- [ ] Implementation plan created and approved
- [ ] Code implemented within the approved scope
- [ ] **Unit tests added/updated and passing**
- [ ] **Integration tests added where applicable and passing**
- [ ] Formatting passes
- [ ] Linting passes
- [ ] Build passes
- [ ] **Security validation passes** — gitleaks (no secrets), semgrep (no new findings),
      trivy/grype on changed dependencies and images, and the change reviewed against
      §14 (scanner isolation) and §15 (security requirements)
- [ ] Documentation updated where necessary (ADR for architectural decisions)
- [ ] API contract / OpenAPI updated where necessary
- [ ] Database migrations reviewed (forward and rollback)
- [ ] `git diff` inspected; no unrelated files changed
- [ ] No secrets introduced
- [ ] Known limitations documented

"It compiles" is not done. "Tests pass but security checks were skipped" is not done.

When reporting completion, state: changed files · tests run and their results · lint status ·
security scan status · build status · known limitations · potential regressions. Report
failures honestly with output; never claim a skipped step passed.

---

## 24. Architectural Change Rules

Material architectural changes require an **ADR and human approval before implementation**.
Material means any of:

- changing the scanner abstraction or how adapters are registered
- changing the canonical finding model, fingerprint strategy, or dedup semantics
- changing the risk formula, its factors, or its weights
- changing correlation semantics
- changing trust boundaries, isolation, or the security model
- adding/removing a scanner, datastore, queue, language, or framework
- changing authentication, authorization, or audit behavior
- changing the database schema in a non-additive way
- changing CI permissions or Kubernetes privileges

Claude Code does **not** unilaterally redefine architecture. The project owner decides
architecture, security model, threat model, data model, major technology choices,
requirements, and acceptance criteria. Claude Code accelerates implementation and analysis
within those constraints.

High-risk operations requiring explicit confirmation: deleting files · changing
infrastructure · changing security policies · modifying CI permissions · modifying
Kubernetes privileges · executing untrusted code · changing authentication · changing
database migrations · installing large or security-sensitive dependencies.

---

## 25. Things Claude Must Never Do

1. Execute untrusted repository content on the API server — ever.
2. Run scanners synchronously inside an HTTP request.
3. Write scanner-specific conditionals outside `internal/scanners/**`.
4. Let raw scanner output reach the UI or the core engines unnormalized.
5. Deduplicate findings by title or fuzzy string similarity.
6. Present AI-generated remediation as verified, or label deterministic rules "AI."
7. Commit secrets, `.env` files, or generated artifacts.
8. Commit anything without an explicit instruction.
9. Remove or replace the MIT license.
10. Disable or weaken a security control to make tests, lint, or builds pass.
11. Build a shell command string from user-controlled input.
12. Put orchestration, scanners, persistence, scoring, and handlers into one package.
13. Start with Kubernetes YAML before the application runs locally.
14. Add Kafka, Elasticsearch, a service mesh, microservices, or Python without a
    justified, documented requirement.
15. Treat Claude Code or MCP as a runtime dependency — **SecureOps must function without
    Claude Code and without MCP.**
16. Assume a component described in this file already exists. Check first.
17. Silently change a public API contract.
18. Report work as complete when validation steps were skipped.

---

## 26. Implementation Phases

Work strictly phase by phase. Do not skip ahead.

| Phase | Content |
|---|---|
| 1 | Foundation: repo structure, Go API skeleton, Next.js app, PostgreSQL, Redis, Docker Compose, config, structured logging, health checks, `.gitignore`, basic CI |
| 2 | Scanner abstraction: `Scanner` interface, Target model, scan job model, lifecycle, worker infrastructure |
| 3a | Scan API (`POST /scans` and friends) + interim authentication — **not in the original list; see the note below** |
| 3b | Repository fetching, then scanner adapters one at a time: **Gitleaks** → **Syft** → Grype → Semgrep → Trivy (filesystem, then image) → ZAP |
| 4 | Normalization: raw result storage, parsers, canonical Finding, validation, fingerprinting, dedup |
| 5 | Correlation: cross-domain relationships, related findings, component/asset relationships |
| 6 | Risk engine (with mandatory unit tests on the formula) |
| 7 | Remediation engine |
| 8 | Security policy engine and gates |
| 9 | Dashboard |
| 10 | CI/CD integration: GitHub Actions, PR reporting, status checks |
| 11 | Security hardening: authn, RBAC, audit logging, isolation, resource limits, network restrictions, secret handling, input validation |
| 12a | Kubernetes: the platform runs on a cluster — Helm chart, digest-pinned images, security contexts, resource limits, network policies, Ingress. No Go changes (ADR 038) |
| 12b | Kubernetes: a scan becomes an ephemeral Job — per-Job filesystem quota and per-Job network policy, which is what makes `Capabilities.NetworkKinds` a control (ADR 039). Partly done: merged and unshipped, pending a volume for provisioned scanner data |
| ~~13~~ | ~~Observability~~ — **dropped 2026-09-05 (ADR 034)**. Structured logging, health checks and per-scan telemetry shipped in Phases 1-2; a metrics endpoint and tracing answer no question this tool raises |
| 14 | Final hardening and documentation: threat model, architecture docs, ADRs, OpenAPI, README, security review |

The sequencing, what is left, and what is deliberately absent from the plan are
in [docs/ROADMAP.md](docs/ROADMAP.md). Update it at the end of each phase.

**A recorded deviation, 2026-08-31.** The phase list above never named an endpoint
that creates a scan. Phase 2 built the job model, the lifecycle, the queue, and the
worker, but nothing could drive any of it, and Phase 3 (adapters) would have had no
way to be exercised end to end. The scan API was therefore built first, as **3a**.

Two consequences worth being explicit about, because both are deviations rather
than plan:

- **Authentication moved from Phase 11 to 3a.** Not scope creep, and not a decision
  to pull Phase 11 forward: `POST /scans` is a write endpoint, §15.4 requires
  server-side authentication on every request, and the threat model recorded that
  T-11 "becomes urgent the moment a write endpoint ships." Shipping 3a without a
  credential check would have knowingly published the exposure. What landed is an
  interim gate (ADR 006) that authenticates but does not authorize; Phase 11 still
  owns identity, RBAC, and the audit log, which are now tracked as T-23 and T-24.
- **The numbering is the project owner's call.** 3a/3b is a placeholder that keeps
  the record honest, not a redefinition of the plan. Claude Code does not
  unilaterally renumber the phases (§24); if the owner prefers to fold 3a into
  Phase 2, promote it to its own phase, or leave it as is, that decision replaces
  this note.

**A second recorded deviation, 2026-09-02.** Phase 3b is incomplete and has been
since PR #14: Trivy image targets and the ZAP adapter were marked "later" in the
README and the work moved on to Phase 4. Unlike the 3a split above, that was
never written down as a decision — the *state* was recorded in §1 and the
README, but no ADR and no note explained why §26's "work strictly phase by
phase, do not skip ahead" was set aside. This note closes that gap rather than
pretending the sequence was followed.

The reasons, stated now so they can be argued with:

- **ZAP needs a running application, not a repository.** Every adapter that
  exists is a static analyser over a checkout. DAST needs the target deployed,
  an `endpoint` target kind, and network egress from the worker — which cuts
  against §14.3's deny-by-default network posture and is a trust-boundary
  change, not just another adapter. ZAP is also not installed locally (§4).
- **Trivy image targets need registry read access.** §14.7 gives workers no
  registry credentials. Granting them is new trust surface.
- **Neither blocked Phases 4-6**, which needed *some* findings to normalize,
  correlate, and score — not every domain.

What it cost, which is the part worth being honest about: `KindImage` and
`KindEndpoint` were fully modelled and validated in `internal/scanners/target.go`
with no adapter serving either, so a scan submitted for one was accepted and
then failed with "no registered scanner supports this target kind". Correlation
served no `image:` or `endpoint:` key, which meant §9's own worked example — a
Grype CVE plus a Semgrep misuse plus Trivy finding the same package in a
production image, escalated to one CRITICAL issue — **could not be
demonstrated**. The gap blocked the product's flagship claim, not a peripheral
feature.

**Resolved for images, 2026-09-03 (ADR 025).** Trivy now serves `KindImage`
against public registries, and the repository/image leg of that example is
demonstrated by `TestRepositoryAndImageFindingsCorrelate` against captured
output from both scanners. Two things stayed honest in the doing of it. The
`image:` correlation key was **not** added — every finding in an image shares
it, which makes it a filter rather than a relationship, so it is an indexed
column and the cross-domain escalation runs on `purl:` as it already did. And
the Semgrep leg of the example is still missing: joining a SAST finding to a
package needs reachability analysis that no scanner provides and correlation
will not guess. The example is two thirds reachable, not whole.

Closing it also surfaced a live security gap rather than only a missing
feature: `validateImage` had never applied the SSRF address policy that
`validateRepository` and `validateEndpoint` both applied. Inert while no
adapter served the kind, and live the moment one did. Fixed in the same change
(T-49).

**Resolved for endpoints, 2026-09-03 (ADR 026).** ZAP has landed, which closes
Phase 3b: every target kind the model defines now has an adapter, and
`KindEndpoint` no longer accepts a scan that is guaranteed to fail.

Three things stayed honest in the doing of it. **DAST is passive only** — the
`activeScan` job is absent from the automation plan rather than disabled in it,
because active scanning delivers attack payloads to a live application, writes
to real forms, and needs a per-project authorization model that does not exist;
so SecureOps does not test for injection, and says so. The `endpoint:`
correlation key was **not** added, by the same test that rejected `image:`:
only ZAP produces URL paths, so every member of such a bucket carries one
category and no issue can form. And **ZAP is not in the worker image** — it is a
Java application, so packaging it is an infrastructure change of its own, and
until then an endpoint scan in a deployed worker degrades through the tested
"binary missing" path.

Unlike the image work, this one surfaced no latent security gap:
`validateEndpoint` had applied the SSRF address policy since Phase 2. That was
audited rather than assumed, precisely because the sibling image path had the
same omission and did not (T-56, T-49).

It is recorded here so
that it is a deferral rather than an oversight.

**A third recorded deviation, 2026-09-07.** Phase 12 is split into 12a and 12b
(ADR 038, approved). §26's single line covers two different changes: deployment
configuration, and moving where a scan executes. Only the second one moves a
trust boundary — a scan stops running inside a long-lived worker and starts
running in a Job that dies with it — and that is what makes the per-scan
filesystem quota (T-51) and the per-scan network policy
(`Capabilities.NetworkKinds`, which has no non-test caller today) possible at
all. Shipping both as one change would mean a pull request that introduces
Kubernetes and rewrites the worker together, with no intermediate state where
either half is verifiable.

The numbering is again the project owner's call, as 3a/3b and 10a/10b were.

Security is designed in from Phase 1 (isolation boundaries, no shell execution, no secrets)
even though Phase 11 hardens it. Phase 11 is not permission to defer security thinking.
