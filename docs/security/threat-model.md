# Threat Model

Threats are enumerated per trust boundary (see `trust-boundaries.md`). Each
carries an honest status:

- **Mitigated** — a control exists and a test covers it
- **Partial** — a control exists but does not cover the whole threat
- **Open** — the surface exists and no control does
- **Prospective** — the surface does not exist yet; the entry records the
  controls its introduction must carry

"Mitigated" is never claimed on the strength of an intention. Where a test
enforces the control, it is named, because a security control without a test is
a comment.

**On Prospective, which is new.** Two entries were carrying **Open** for
endpoints that do not exist — an SBOM upload and a webhook — and their own text
said so. That is not an exposure; it is a requirement waiting for its feature,
and counting it as an exposure makes the backlog read as twice its real size
while saying nothing true about the system as it stands today. The entries are
worth keeping: they are what a reviewer should check the day those endpoints are
added. They are not worth counting.

**On Partial, which is not a waiting room.** Nine entries are Partial because
that is the honest end state, not because work is outstanding: you mitigate a
supply chain, you do not close it. Reading the Partial count as a to-do list is
the mistake this document should not invite, so each of those entries says
plainly what would and would not change its status.

Last reviewed **end to end on 2026-09-08**, in Phase 14 — the re-read the
previous note said was still outstanding. Covers every phase that has shipped:
the six scanner adapters, the normalization, correlation, risk, remediation and
policy engines, the dashboard, identity and project scoping, the CI client and
Action, SBOM storage and deployment evidence, and the Kubernetes deployment.

That re-read is why several entries below read differently, and the drift ran in
the direction nobody looks for: **entries understating their own posture**, by
still naming a future phase as their fix after that phase had shipped.

- **T-36** said any credential reads every project's inventory. That stopped
  being true when Phase 11 landed.
- **T-38** asked that issues be scoped "when someone implements Phase 11". They
  were, in the same route group as findings.
- **T-18** named Phase 11 as its fix, and Phase 11 came and went without
  touching database roles — an entry whose owner had quietly disappeared.

The Phase 12b entries are the opposite case and worth flagging: T-51 and
`Capabilities.NetworkKinds` describe controls that are implemented, tested, and
**not deployable**. The scan-job machinery is merged; the volume carrying
provisioned scanner data is not built, so the mode is off by default. They stay
Partial because the control cannot be turned on, not because it is missing.

---

## Boundary 5a — Worker → untrusted target: execution

The highest-value boundary. Everything here assumes the target is hostile.

### T-01 Command injection via target values · **Mitigated**

A crafted ref, image reference, or path reaching a shell would give arbitrary
execution as the worker.

Scanners are invoked with `exec.CommandContext` and an argument vector. There is
no shell in the path, so metacharacters are inert data. `Run` additionally
refuses a binary name containing shell syntax, so a caller cannot smuggle in a
command line.

*Tests:* `TestRunNeverInvokesAShell` fires six payloads (`;`, `$()`, backticks,
`&&`, `|`, newline) and asserts none executed.
`TestRunRejectsCommandLineAsBinaryName`.

### T-02 Argument injection · **Mitigated**

Subtler than T-01 and missed by "block shell metacharacters" filters: a ref of
`--upload-pack=...` contains no metacharacters, is a single argv element, and is
still read by git as a flag.

Target values beginning with `-` are rejected during validation.

*Test:* `TestValidateRejectsLeadingDashArguments`.

### T-03 Path traversal out of the workspace · **Mitigated**

Filesystem targets are canonicalised and containment-checked against the
workspace root. A hostile scan ID cannot steer the workspace path either — the
directory suffix is generated, and the ID is sanitised to a safe character set.

*Tests:* `TestValidateFilesystemRejectsTraversal` (six traversal shapes),
`TestWorkspaceRejectsPathInjectionInScanID`.

### T-04 SSRF via repository or endpoint URL · **Partial**

An attacker submits a target resolving to cloud metadata, a loopback admin
service, or an internal host, using SecureOps as a proxy.

Blocked at DNS resolution *and* again at dial time via a `net.Dialer` `Control`
hook, which is what survives DNS rebinding. Every resolved address must pass,
not merely one. Cloud metadata endpoints are named explicitly. Permitting
private ranges is opt-in and refused in production.

**Why partial:** the dial-time guard covers connections *SecureOps* makes. A
scanner subprocess performing its own DNS and its own connections is outside it.
Closing that fully requires network policy at the container level (Phase 12).

*Tests:* `TestValidateRepositorySSRF`, `TestValidateEndpointSSRF`,
`TestCheckHostRejectsMixedResolution`, `TestControlFunc`.

### T-05 Resource exhaustion · **Mitigated**

Zip bombs, pathological repositories, infinite scanner output.

Per-scanner timeout, job timeout, concurrency cap, and an output cap that
**terminates the process** rather than merely discarding bytes — an early
implementation only discarded, which let a scanner emitting infinite output burn
its full timeout. All limits are configurable.

*Tests:* `TestRunOutputSizeLimit` asserts both the error *and* that abort is
immediate; `TestRunTimeoutIsEnforced`; `TestConcurrencyIsBounded`.

### T-06 Credential theft by a scanner subprocess · **Mitigated**

A malicious scanner binary, or one subverted by hostile input, reads the
worker's environment for the database DSN or Redis password.

The child environment is an explicit allow-list, never inherited. A `nil` env is
forced to empty so it cannot happen by omission.

*Test:* `TestRunDoesNotLeakParentEnvironment`.

### T-07 Untrusted content outliving the scan · **Mitigated**

Ephemeral `0700` workspace removed on completion, including on failure and
cancellation. The child runs in its own process group and the group is killed,
so a leaked helper cannot hold the workspace open.

*Tests:* `TestWorkspaceIsDestroyedAfterJob`, `TestWorkspaceLifecycle`.

### T-08 Container escape · **Partial**

Non-root, read-only root filesystem, all capabilities dropped,
`no-new-privileges`, tmpfs workspace, distroless image with no shell.

**Improved in Phase 12a**, and still Partial. Every pod now runs with seccomp
`RuntimeDefault`, a read-only root filesystem, all capabilities dropped, no
privilege escalation and CPU/memory limits enforced by the scheduler — verified
on running pods, not in the YAML that requested them: `touch /` inside the
worker is refused and the process is uid 65532.

**Why still partial:** these are hardening measures, not a sandbox, and one
worker still runs every scan in one filesystem and one network namespace in the
default mode. Phase 12b gives each scan its own pod, filesystem quota and
network policy where it is enabled (ADR 039), which is a stronger boundary and
still not a sandbox. Partial is the honest end state here rather than a task —
a container is not a VM however it is configured.

### T-09 Poisoned scanner output · **Partial**

Scanner output is attacker-influenced and is treated as untrusted input. Output
is size-capped, and a result carrying any degradation reason is recorded as
*not* succeeded so it can never be normalized as if whole (ADR 010).

**Why partial:** every adapter now validates its own output before persisting
it, and normalization (Phase 4) has not started, so nothing yet parses that
output into the canonical model where a hostile value would do damage.

### T-10 Scanner binary tampering · **Mitigated**

A compromised scanner binary on the worker runs with the worker's privileges.

**Closed in Phase 12a.** The Helm chart selects every image by digest and
**refuses to render one that is not** — no `allowTags`, no development mode,
because an escape hatch is how a control becomes optional. Combined with T-28,
which builds each scanner from source at a pinned commit SHA, the digest fixes
exactly which binaries a cluster runs: the image is content-addressed, and its
contents were built from content-addressed sources.

This was the last **Open** entry in this document.

*Tests:* `TestEveryImageIsPinnedByDigest` and `TestTheChartRefusesATag` — the
second is the one that matters, since an assertion that every image happens to
carry a digest proves nothing about whether a tag would be accepted if offered.
*Verified in a cluster:* every running container resolved to
`repository@sha256:...`, read back from the pods rather than from the manifest.

**The residue, stated rather than buried:** `docker-compose.yml` still runs
`:latest` locally. That is the development loop and not the deployed form
(`deployments/kubernetes/README.md` says so), but a deployment that ran compose
in production would not carry this control. The digest also attests to bytes
rather than to a publisher — the same limit as T-19, and signature verification
remains the shared remaining work with T-28.

---

## Boundaries 1–2 — User and UI → API

### T-11 Unauthenticated access · **Mitigated (interim)**

Closed in Phase 3, in the same change that introduced the first write endpoints
(`POST /projects`, `POST /scans`). Every `/api/v1` endpoint except health
requires a bearer token (ADR 006).

What this stops: an anonymous caller enqueueing unbounded scan jobs, using the
target validator as an SSRF oracle to map which internal hosts resolve, or
reading every project's scan history.

The controls, all enforced at startup rather than per request, so a weak
configuration cannot be deployed:

- at least one token is required, in every environment — the API refuses to
  start without one, so there is no permissive fallback path;
- secrets must be at least 32 characters;
- secrets are hashed at load, compared as SHA-256 digests with
  `subtle.ConstantTimeCompare`, and every configured credential is checked on
  every request, so neither the outcome nor the matching credential's position
  is observable through timing;
- a rejected token is never logged, echoed, or included in the challenge.

Health endpoints stay open deliberately: a liveness probe that needs a
credential fails during a rotation, and an orchestrator would then restart a
healthy process.

*Tests:* `TestEveryResourceEndpointRequiresAuthentication` (enumerates the whole
authenticated surface, so a route added without the gate fails),
`TestBadCredentialsAreRejected`, `TestAuthenticateRejectsPrefixesAndExtensions`,
`TestNewRequiresAtLeastOneCredential`, `TestNewEnforcesMinimumTokenLength`,
`TestTheRejectedTokenIsNeverEchoed`,
`TestIntegrationEndpointsRejectMissingCredentials`.

*Verified by control test:* removing `r.Use(s.requireAuth)` from the router
makes `TestEveryResourceEndpointRequiresAuthentication` fail.

### T-23 No authorization model · **Partial**

The other half of what T-11 used to cover, restated separately because
authentication is now done and authorization is not.

Every valid token is equivalent. There is no tenancy boundary, no per-project
scoping, and no role model, so any credential reaches any project. This is safe
only for a single-tenant deployment, which is what SecureOps is today.

**The impact grew substantially in Phases 4-6 while the vulnerability stayed the
same.** When this was written the API served project names and scan statuses.
It now serves every project's full vulnerability inventory, the file paths of
correlated issues, and EPSS exploitation probabilities — which is to say, a
ranked attack plan. See T-36 and T-38. Nothing about the missing control
changed; what it fails to protect did.

A token labels a client, not a person, so "who ran this scan?" is answerable
only to the granularity of that label. There is also no revocation short of a
restart.

Phase 11 owns the fix: the four RBAC roles (Admin, Security Engineer, Developer,
Viewer), authorization checked at the API boundary *and* at the data layer for
project scoping.

**Narrowed in Phase 8.** Tokens now carry a role — `viewer`, `service`, `admin`
— and editing a security policy requires `admin` (ADR 023). The credential CI
holds can no longer switch off the gate that judges it, which was the realistic
path from a leaked or over-shared token to a silently disabled control.

**Scoped in Phase 11 (ADR 033).** A credential now carries a `Scope` alongside
its role, and the two answer different questions: role is *what* it may do,
scope is *where*. `SECUREOPS_API_TOKENS` gains a fourth field —
`label:role:scope:secret` — and a token without one **fails to start**, because
a default of `*` would leave this entry exactly where it was while every
deployment kept working and noticed nothing.

Enforcement is in three places, because one was not enough:

- **The `/projects/{projectID}` subtree** goes through middleware that resolves
  the project and refuses one outside the scope. A route added later is scoped
  by existing rather than by somebody remembering.
- **`GET /projects` filters in the query.** Filtering a fetched page would
  return the right rows and the wrong `has_more`, which leaks the size of the
  estate a caller cannot see — the T-38 disclosure with a pagination header on
  it.
- **The five endpoints addressed by an opaque id** — three scan routes and two
  finding routes — resolve the entity and check its owner. There is no project
  in those URLs, so middleware cannot reach them; without this a confined
  credential could still read another project's scans, findings and gate
  verdicts by id.

An out-of-scope entity answers **404, never 403**. A 403 confirms the id names
something real, which turns enumeration into a map of the estate.

*Tests:* `TestAScopedTokenCannotReachAnotherProject`,
`TestAScopedTokenCannotReachAnotherProjectByEntityID`,
`TestListingProjectsShowsOnlyWhatTheScopeReaches`,
`TestAnOutOfScopeProjectIsIndistinguishableFromAMissingOne`,
`TestNewRefusesAPreScopeToken`, `TestTheZeroScopeReachesNothing`. Removing
either scope check makes all four handler tests fail — confirmed rather than
assumed.

**Identity landed on 2026-09-04 (ADR 033, change B).** There are users now:
local accounts with Argon2id passwords, three roles for people, and project
membership. A person signs in and the API issues a session token the dashboard
forwards in place of its own credential — so a viewer reads what a viewer may
read, and the audit trail records `user / <id>` rather than a token label.

Revocation improved as a side effect rather than by design. The session is
stateless, but the user row is read on **every request**, so disabling an
account takes effect on the next request instead of at the next restart.
Verified: the same token answered 200, then 401 after a `disabled_at` was set,
with no restart in between.

**Administration landed on 2026-09-05 (ADR 033, change C).** Accounts, roles
and membership are now managed through the API and the dashboard, each change
audited against the administrator who made it rather than applied with SQL by
nobody. `GET/POST /users` and `PATCH /users/{id}` are admin-only; the dashboard
has an Access screen behind the same gate, and the link is hidden from anyone
who is not an admin — a courtesy, not the control, since the page itself asks
the API and renders its refusal.

Two properties were worth building rather than assuming:

- **The last enabled administrator cannot be demoted or disabled.** The check
  is inside the same transaction as the write, because a check before it would
  let two concurrent demotions each see the other's admin. A deployment with no
  administrator cannot appoint one, and the only way back is SQL.
- **A project is archived, never deleted** (§17). Its scans, findings, issues
  and history stay readable at their URLs; what changes is that it leaves the
  lists and accepts no new scans. Restoring is one click from the same page.

That last one was where the real defects were, and they were found by archiving
a project in a browser and looking for the way back — not by reading the code.
Six handlers resolved the project a second time with a lookup that filters
archived rows, having already been handed the one the scope middleware
resolved. So the project's own page, its scans, findings, issues and
remediation all 404'd once archived, and the control that restores it lives on
that page. Archive was a one-way door wearing a reversible name. The handlers
now use the project the middleware resolved, and the handler fake was corrected
to filter archived rows as the real store does — it had been permissive enough
to let the broken versions pass their tests.

**Partial**, and the residue is now narrow and specific:

- **No project-scoping for a `service` token beyond what change A gave it.** A
  machine credential is scoped by configuration, not by membership, so rotating
  what a CI job may reach is an edit to `SECUREOPS_API_TOKENS` and a restart.
- **No self-service.** Nobody can change their own password or name; an admin
  creates the account with a password and there is no rotation path short of
  another `useradd`. A password reset needs a delivery channel the product does
  not have.
- **One session per person, revocable only by disabling them.** Stateless
  sessions cannot be revoked individually. Nobody has asked for that on a tool
  with one operator, and it is the cost of not having a sessions table.
- **Membership is edited through the API, not the dashboard.** The Access
  screen shows which projects a person reaches and says plainly that changing
  the set is a `PATCH`. A control that silently did nothing would be worse.

**Policy changes named a token, not a person — fixed 2026-09-07.** The policy
handler built its audit actor by hand instead of using the shared helper, and
was the only handler that did. So the most security-sensitive write in the API
(ADR 022) recorded `token_label` even when a person made the change, and
recorded their *email* rather than their user id — which ADR 033 forbids
precisely because a record outlives the account it names. Both halves were
wrong, and the trail from before the fix names addresses whose accounts have
since been deleted.

Found by reading a real audit trail after a question about it, not by a test.
The lesson is narrow and worth keeping: a shared helper only helps where it is
called, and one handler quietly not calling it produced a weaker record exactly
where the strongest one was required (§15.6).

**A scoping hole, found and closed on 2026-09-05.** Creating a project granted
its creator no membership, so a scoped person could create one and then be
refused by every endpoint addressed by its id. This is recorded here rather
than only in the changelog because of what it says about the enforcement above:
the three checks were correct and complete, and the gap was that nothing ever
put a newly created project *into* anybody's scope. An enforcement point can be
right while the thing it enforces against is empty.

It failed toward refusal rather than disclosure — nobody saw a project they
should not have — so it was a usability defect with a security shape rather
than a vulnerability. The handler fake had returned one fixed global scope for
every person, which is why no test caught it; that fake now derives scope from
role and membership as the real store does.

*Tests:* the scope suite from change A, plus `TestUserActorNamesAPerson`,
`TestAnExtendedExpiryDoesNotVerify`, `TestASessionDoesNotVerifyUnderADifferentKey`,
`TestTheLastAdminCannotBeDemotedOrDisabled`, `TestCreatingAProjectMakesTheCreatorAMember`,
`TestCreatingAProjectGrantsNoMembershipToAGlobalCaller`, `TestAnArchivedProjectCanBeBroughtBack`,
`TestAnArchivedProjectStaysReadable`, `TestAnArchivedProjectAcceptsNoNewScans`,
and the password suite in `internal/users`.

### T-24 No durable audit log · **Mitigated**

§15.6 requires security-sensitive actions to be recorded with who, when, what
changed, and the previous and new value. Until Phase 8 there was audit
*logging* — a structured line per mutation — and no audit *log*: nothing
durable, nothing queryable, no before or after.

The append-only `audit_logs` table now records policy changes (ADR 022),
project creation, scan creation, and finding status changes (ADR 024). Every
one is written in the transaction of the change it describes, so a record
cannot be lost while the change survives, and a rejected change leaves no
record claiming it happened.

Two items on §15.6's list have nothing to write: `user/role changes`, because
there is no user management, and `remediation actions`, because a remediation
plan is derived advice rather than a stored action somebody takes. Both become
real in later phases and inherit the table rather than a requirement.

The attribution is a token label rather than a person (ADR 006, ADR 023), which
is weaker than §15.6 will eventually want and is recorded as what it is.

*Tests:* `TestAPolicyChangeIsAuditedWithItsBeforeAndAfter`,
`TestScanAndProjectCreationAreAudited`, `TestADismissalIsAuditedWithBothStates`,
`TestARefusedTransitionLeavesNoTrace`, `TestAFailedProjectCreateLeavesNoAuditRecord`,
`TestAnAuditEntryRollsBackWithItsTransaction`.

### T-12 Log-correlation poisoning · **Mitigated**

A client-supplied `X-Request-Id` is discarded and a server-generated ID used.

*Test:* `TestRequestIDIsServerGeneratedAndNotClientControlled`.

### T-13 Information disclosure through errors · **Mitigated**

Handler panics return a fixed message; the panic value and stack stay in logs.
Readiness reports a dependency as unavailable without the driver error, which
can carry hostnames and credentials. Validation errors never echo input.

*Tests:* `TestPanicIsRecoveredWithoutLeakingDetail`,
`TestReadinessDoesNotLeakDependencyErrorDetail`,
`TestValidationErrorsDoNotEchoInput`, `TestValidationErrorsDoNotLeakCredentials`.

---

## Boundaries 3–4 — API → queue → worker

### T-14 Job payload as an execution vector · **Mitigated**

A payload carrying a command line would make the worker a remote-execution
service for anything that can write to Redis.

Payloads are plain data and are re-validated on arrival rather than trusted
because we wrote them.

*Tests:* `TestJobPayloadCarriesNoExecutableFields`,
`TestInvalidTargetIsRejectedOnArrival`.

### T-15 Malformed or oversized queue payload · **Mitigated**

Payloads are size-capped and validated on read; a malformed payload is rejected
without crashing the worker, and a poison job is retired after `MaxAttempts`
rather than cycling forever.

*Tests:* `TestRedisQueueRejectsMalformedPayload`,
`TestJobExceedingMaxAttemptsIsRetired`, `TestPanicInJobDoesNotKillWorker`.

### T-16 Result rewriting by a replayed worker · **Mitigated**

A duplicate delivery upgrading a `PARTIAL` scan to `COMPLETED` would erase
evidence of degraded coverage.

State transitions are enforced in the domain model *and* in SQL — `Finalize`
only matches non-terminal scans.

*Test:* `TestFinalizeIsIdempotentAgainstReplay`, against a real database.

---

## Boundary 6 — Services → PostgreSQL

### T-17 SQL injection · **Mitigated**

Parameterised statements only. pgx's extended protocol refuses concatenated
multi-statement text, which enforces the rule structurally.

### T-18 Over-privileged database access · **Partial**

Least privilege is stated policy; every component still shares one PostgreSQL
role.

**This entry named Phase 11 as its fix, and Phase 11 shipped without it.**
Recorded rather than quietly re-pointed at Phase 14: ADR 033 delivered identity,
roles and project scoping at the API boundary, which is where §15.5 asks for
them — and said nothing about the database role underneath. An entry whose fix
is a phase that has since completed is an entry with no owner, which is the
failure mode this whole document exists to avoid.

What would actually close it, now that it has to be argued rather than deferred:
separate roles for the API, the worker and the migration runner, with the worker
denied write access to `audit_logs` and to the tables it has no reason to touch.
The migration runner is the one that genuinely needs DDL, and it runs as a Helm
hook rather than continuously (12a), so it is also the easiest to separate.

Phase 12b narrows it in a direction nobody planned: a scan running as an
ephemeral Job holds **no** database credential at all (ADR 039), so the process
that touches untrusted content is out of scope for this entry entirely. That is
merged and not yet deployable, so it narrows nothing today.

---

## Supply chain and CI

### T-19 Dependency compromise · **Partial**

grype and trivy run on every CI run; an SBOM is generated and retained.
`.grype.yaml` suppresses six CVEs in golang-migrate's Docker-based test drivers,
which `go version -m` confirms are not linked into any binary. Rules are scoped
to specific vulnerability IDs, so a new CVE in those modules still fails.

Scanner binaries downloaded by CI are pinned by **version and SHA-256 digest**
(`scripts/install-scanner.sh`), verified before extraction, and a mismatch
refuses to install rather than warning. Until 2026-09-07 CI piped the vendors'
installers into a shell — `curl -sSfL … | sh` — which pinned the *tool* and left
whatever the URL served free to run as the *installer*; trivy's came off the
`main` branch, mutable by definition. The worker image never had this problem:
it builds its scanners from source at pinned commit SHAs (T-28). The gap was
that CI and the image were held to different standards and nothing said so.

**Why partial:** the digest attests to the bytes, not to the publisher — it is
recorded from the same origin that serves them, so it detects a later
substitution and not an original compromise. Signature or provenance
verification is the remaining work, shared with T-28 and T-10.

### T-20 Compromised CI token · **Partial**

`contents: read` by default with no per-job escalation; third-party actions
pinned to immutable commit SHAs; `persist-credentials: false` on checkout.

**Why partial:** no branch protection or required reviews configured, so a
compromised account can still push directly to `main` — as happened, benignly,
with Phase 1.

### T-61 The pipeline definition as an execution surface · **Mitigated**

The self-scan covered every language in this repository and not the workflows
that run it. §16 says CI is attack surface; until 2026-09-07 saying so was the
whole control, and two classes were sitting behind it.

**Script injection.** The gate action interpolated GitHub context values into
`run:` bodies, `github.ref_name` among them. A composite action's expressions
are substituted as *text* before bash parses the script, so quoting is no
defence against a value that supplies its own closing quote — and on a fork's
pull request the attacker chooses the branch name. The result would execute on
the runner with the workflow token in its environment. Every such value now
arrives through `env:` and is read as `"$VAR"`.

**Unpinned installers.** Covered under T-19.

The control is `--config p/github-actions` in `make scan-sast`, so this is a
gate rather than a thing to remember. Verified by putting the interpolation
back and confirming the rule fires on it, then removing it again — a control
that has never been seen to fail is a claim, not a control.

**What it does not cover:** third-party actions are pinned to immutable commit
SHAs, and what those actions then do is not audited; and the runner is
GitHub's, so a compromise of it is not defended here.

### T-62 The gate credential on infrastructure we do not control · **Partial**

Phase 10 put a SecureOps credential onto other people's CI runners. That is a
real widening: the token lives in a secret store SecureOps does not operate, on
a machine it does not administer, in a process that also executes the repository
being scanned.

What bounds it:

- **It is a `service` token, so it cannot edit the policy judging it** (ADR 023).
  This is the control that matters most — the realistic path from a leaked CI
  credential to a silently disabled gate runs through the policy, not the scan.
- **It is scoped, so it reaches only its own projects** (ADR 033 change A). A
  leaked token from one pipeline does not read another team's findings.
- **It is read from `SECUREOPS_API_TOKEN`, never a flag.** A flag is visible in
  `ps` and in CI logs. The client never prints it, and the Action passes it
  through `env:` on the one step that needs it.
- **It is never exposed to a fork's workflow** (§16), and the PR comment step
  is skipped on a fork rather than failing there.

**Why partial:** a token has no rotation mechanism and is revocable only by
restarting the API, which is T-23's residue reaching a new place rather than a
new gap. And a compromised runner can do everything the token can: submit
scans, read findings for its projects, and dismiss a finding — because a
`service` role may dismiss and nobody countersigns (T-48).

Not defended: GitHub's runner itself. If it is compromised beneath us, the
credential is theirs for as long as it is valid.

*Tests:* `TestAServiceTokenCannotDisableTheGate` — the one that matters, since
a CI credential able to edit its own policy makes every other control here
decorative — plus `TestAScopedTokenCannotReachAnotherProject`,
`TestAScopedTokenCannotReachAnotherProjectByEntityID`,
`TestNewRefusesAPreScopeToken`, and `TestForkPullRequestsSkipTheComment`.

### T-63 Deployment evidence derived from an attacker's own inventory · **Mitigated**

10b compares a finding's package against the bill of materials of the image the
project ships — and that bill of materials is produced by cataloguing an
artifact the target controls. A hostile image that omits or misreports package
metadata makes a real vulnerability look absent from the build.

This is mitigated by the decision rather than by a check, which is worth being
explicit about: **deployment evidence moves no severity and no risk score**
(ADR 037). There is no arithmetic for a crafted inventory to influence. The
worst it achieves is a line of prose a human reads before deciding, and that
line names the scan and the date it compared against rather than asserting a
timeless fact.

Two structural properties back that up:

- **Absence is only ever claimed from a complete inventory.** A component list
  truncated at the 10,000 cap yields `unknown`, never `not_deployed` — absent
  from a prefix is not absent.
- **`unknown` is the default and a first-class value**, not a gap that reads as
  "probably fine". Most projects have no image scan at all.

This is the concrete case T-21 anticipated in the abstract: an SBOM must not be
trusted as evidence that a component is present. Here it is trusted only as
evidence shown to a person.

*Tests:* `TestDeploymentNeverChangesSeverity`,
`TestATruncatedInventoryCannotProveAbsence`, `TestNoArtifactMeansUnknown`,
`TestOnlyComponentIssuesAreClassified`, `TestAnEmptyPURLIsNotAMatch`.

*Verified by control test:* the severity test was rewritten during review — its
first version used a two-domain issue that ADR 017 had already escalated to
critical, so an injected deployment escalation changed nothing detectable and
the test passed without testing. It now uses a single-domain, medium-severity
fixture where a change would show.

### T-21 Malicious uploaded SBOM · **Prospective**

No SBOM upload endpoint exists. Nothing in the API accepts a caller-supplied
SBOM, so there is no surface here to attack and nothing to mitigate.

Kept because it is the checklist for the day one is added. An uploaded SBOM is
attacker-controlled structured input parsed by the platform itself rather than
by a sandboxed scanner, which makes it one of the few untrusted inputs that
would not cross the worker boundary first. It must be size-capped before
parsing, schema-validated, parsed with a decoder that will not expand a
declared length into an allocation, and bounded in component count — and it
must not be trusted as evidence that a component is present, which is a
correlation question rather than a parsing one.

Was **Open** until 2026-09-04. That was wrong: it described the absence of a
control on an absence of a feature.

### T-22 Insecure webhook · **Prospective**

No webhook endpoint exists. Nothing in the API accepts an unauthenticated
callback.

Kept for the same reason as T-21. When one is added it needs signature
verification against a shared secret, constant-time comparison of that
signature, replay protection with a bounded timestamp window, a size cap
applied before the body is read into memory, and its own rate limit — a webhook
is the one endpoint whose caller is chosen by a third party rather than by us.

Was **Open** until 2026-09-04, for the same reason T-21 was.

---

## Boundary 5b — Worker → untrusted target: content and results

### T-25 Malicious repository content at fetch time · **Partial**

Phase 3b added the fetch step, which is where SecureOps pulls
attacker-controlled content onto a machine it owns. `git` is a large program
with a long history of remote-triggered surprises, so the clone refuses every
capability it does not need (ADR 008):

- `protocol.allow=never` with only https and ssh re-enabled. This blocks `ext::`,
  which executes an arbitrary command named in the URL, and `file://`, which
  reads the worker's own disk. It also blocks a **bare local path**, because git
  treats one as the `file` transport — verified, not assumed.
- `--recurse-submodules=no`. A submodule is an attacker-controlled URL fetched
  on our behalf, bypassing the target validator entirely.
- `credential.helper=` empty, `GIT_TERMINAL_PROMPT=0`, `GIT_ASKPASS=/bin/true`.
  Git never attaches host credentials to an attacker-chosen URL, and a private
  repository fails fast instead of pinning a worker slot on a password prompt.
- `core.hooksPath=/dev/null` and `core.symlinks=false`.
- An allow-list environment, so the subprocess cannot inherit the database URL,
  the Redis password, or cloud credentials.
- Hard timeout, plus post-clone size and file-count limits. Exceeding one is a
  structured failure with its own scan `failure_reason`.

Partial rather than mitigated: the limits are enforced *after* the clone,
because git offers no reliable pre-flight size check. A hostile repository can
therefore cause a worker to write up to the limit before being stopped. The
workspace is ephemeral and destroyed either way, so the limit is what bounds the
damage.

*Tests:* `TestCloneArgsCarryTheSecurityControls`,
`TestCloneArgsTerminateOptionParsing`, `TestCloneEnvIsAnAllowList`,
`TestLocalPathsCannotBeCloned`, `TestMeasureEnforcesTheSizeLimit`,
`TestMeasureEnforcesTheFileCountLimit`, `TestMeasureDoesNotFollowSymlinks`.

### T-26 Harvested credentials in the results database · **Mitigated**

A secret scanner's output contains the credentials it found. Persisting that
verbatim, as §8 requires for raw results, would make the SecureOps database a
store of live credentials drawn from every repository ever scanned — and would
turn a SecureOps compromise into a compromise of every customer's third-party
systems.

Resolved in ADR 007 in favour of §15.3: gitleaks runs with `--redact`, so the
value never enters SecureOps' memory, and the adapter **verifies** redaction
before returning anything. Output that cannot be proven redacted is discarded
and the scanner result fails. Location, rule, line, entropy, and fingerprint all
survive, which is what an engineer needs in order to rotate the secret.

Verified against a public repository of planted secrets: 22 findings detected,
zero credentials persisted.

*Tests:* `TestAssertRedactedRejectsALiveSecret`, `TestUnredactedMatchIsStillRejected`,
`TestRedactionErrorDoesNotLeakTheSecret`, `TestScanFindsSecretsAndRedactsThem`,
`TestIsRedactedSecret`, `TestIsRedactedMatch`.

*Verified by control test:* removing `--redact` from the argv, and separately
neutering `assertRedacted`, each make the corresponding test fail.

### T-27 Scanner report written into the scanned tree · **Mitigated**

gitleaks scans every file under its source, so a report written inside the
checkout is scanned on the next run and its own contents reported as findings —
inflating counts silently. The report is written to a sibling directory inside
the ephemeral workspace instead.

*Tests:* `TestTheReportIsNotWrittenIntoTheScannedDirectory`, `TestScanIsRepeatable`.

### T-28 Scanner binary supply chain · **Partial**

Scanner binaries are built from source at a **pinned commit SHA**, with the
checkout verified by `git rev-parse` before building (ADR 009). A commit SHA is
content-addressed, so unlike a tag it cannot be moved — this is stronger than
verifying a publisher checksum, which comes from the same origin as the binary
it attests to.

This also closed a vulnerability problem rather than only a provenance one. The
published gitleaks 8.30.1 binary carries **32 HIGH/CRITICAL CVEs** — 21 in a Go
standard library from the 1.24.11 toolchain it was built with, 11 in x/crypto
and x/text — and 8.30.1 is the latest release, so there was nothing to upgrade
to. Rebuilding with this project's toolchain and patched x/ libraries brings the
image to **0 HIGH/CRITICAL**, with output verified byte-identical to the release
binary across 22 findings.

Partial, not mitigated, for two reasons:

- The build trusts GitHub to serve the content at that SHA. A compromise of the
  repository's history would still be inherited. Signature or provenance
  verification (Sigstore) would close this and is the remaining work.
- Pinned dependency bumps go stale as new advisories land. `make scan-image` is
  what surfaces that, and it is a manual step — see T-29.

Related to T-10.

### T-29 Container images are not scanned by the pipeline · **Mitigated**

`make security` and the CI self-scan ran `trivy fs`, which scans the filesystem
and Dockerfiles but never a **built image**. That is how a worker image carrying
32 HIGH/CRITICAL CVEs reached a working state unnoticed — it was found only by
running `trivy image` by hand.

The CI self-scan job now builds both images and scans them, failing on any
HIGH/CRITICAL. `make scan-image` runs the same commands locally. It is
deliberately not part of `make security`, which must stay fast enough to run
before every commit — CI is where the slower, thorough check belongs.

This closed on the same PR that added a second scanner binary to the worker
image, which is exactly when the gap would have mattered again: syft's
source build shipped two x/mod advisories that the check caught.

### T-30 Worker filesystem layout leaked into stored artifacts · **Mitigated**

Syft's file cataloger names components by **absolute path**, so an SBOM
generated from an ephemeral, randomly-suffixed workspace embedded the worker's
internal layout — and produced a different document for every scan of the
identical commit. That is a minor information disclosure and a real
reproducibility defect: Phase 4 cannot fingerprint a component's identity across
scans if the document changes each run.

The file cataloger is disabled, which costs nothing (it contributed 13 file
components and zero library components on this repository), and the adapter
asserts the result: an SBOM referencing the workspace or its parent is discarded
and the scanner result fails.

*Tests:* `TestWorkspacePathLeakIsRejected`, `TestWorkspaceParentPathIsAlsoRejected`,
`TestRealSBOMContainsNoWorkspacePaths`, `TestArgsDisableTheFileCataloger`,
`TestSBOMComponentsAreStableAcrossRuns`.

*Verified by control test:* dropping `--select-catalogers -file`, and separately
neutering the assertion, each make the corresponding test fail.

### T-31 A scanner succeeds against untrustworthy data · **Mitigated**

A scanner can exit 0, emit well-formed output, and still be wrong in the one
direction that matters: reporting fewer findings than exist.

Grype matches against a local vulnerability database. It does ship a staleness
guard — `db.validate-age`, five days by default — but that guard **fails the
scan**, discarding findings that are real, so SecureOps disables it (ADR 010).
With it off, a stale database produces a **false clean**: exit 0, well-formed
output, fewer vulnerabilities than exist, and no signal anywhere for a gate to
read. Verified by forcing the age limit to one second: grype exits 1 with the
guard on, and returns a full report from the same database with it off.

Trivy has the same property; ZAP will have its own variants (an unauthenticated
crawl, a ruleset that failed to load).

This is more dangerous than a scanner that crashes. A crash is visible and
someone fixes it; a false clean is indistinguishable from good news.

`ScannerResult` carries a set of **degradation reasons** rather than a single
flag or a bare `degraded` status. Any reason at all makes `Succeeded()` false,
so the scan settles at `PARTIAL` and `complete_coverage` is false — and the
reason itself reaches the API, because §12 requires a gate to explain the exact
conditions behind its verdict, and "degraded" alone is not actionable.

The Grype adapter is the first real producer. It disables grype's own age
guard deliberately — that guard exits 1 and discards findings that are real —
assesses the same five-day threshold itself, and degrades instead, keeping both
the findings and the warning (ADR 012). A report that cannot prove its own
freshness degrades as `unknown_vulnerability_db`, because silence is not
evidence of freshness. A database grype marks invalid is refused outright: stale
data is correct but incomplete, invalid data is wrong in ways that cannot be
characterised.

*Tests:* `TestUnknownDegradationReasonStillDegradesScan`,
`TestDegradedIsDistinctFromFailed`, `TestTruncatedResultDegradesScan`,
`TestScannerDegradationsReachTheClient`, `TestStaleDatabaseDegrades`,
`TestStalenessBoundary`, `TestUnprovableFreshnessDegrades`,
`TestInvalidDatabaseIsRefusedNotDegraded`.

*Verified by control test:* making `Succeeded()` ignore degradations, dropping
the reasons in the worker, and rendering them as `null` in the API each make the
corresponding test fail.

### T-32 The vulnerability database as supply chain · **Partial**

Grype downloads a 2.0 GB database over the network and then trusts it to decide
what counts as vulnerable. Anything that can alter it can make a vulnerable
dependency look clean, without touching a single line of SecureOps or of the
scanned repository. That is supply chain in exactly the sense §15.7 means, and
it is a more attractive target than the scanner binary: it changes daily, so a
substitution is easier to hide in normal churn.

`GRYPE_DB_VALIDATE_BY_HASH_ON_START=true` — the database is verified against the
hash published alongside it on every run, so a modified archive is rejected.
Provisioning happens once at worker startup, before any job is claimed, so the
download never coincides with attacker-controlled content on disk (ADR 012).

**Why partial:** the hash is published by the same origin that serves the
database, so this detects corruption and interception but not a compromise of
Anchore's publishing infrastructure — the same limitation ADR 009 records for
publisher checksums generally. Pinning a known-good database digest would close
it and would also freeze vulnerability data, which is worse. No transparency log
exists for this artifact to check against.

*Test:* `TestEnvDisablesEgressAndGrypesOwnAgeGuard` asserts hash validation stays
on; a control test confirms the assertion fails when it is removed.

### T-33 Unfixable advisories in a vendored scanner dependency · **Partial**

Grype vendors `github.com/docker/docker` for image scanning. Five advisories
against it report `Fixed in: N/A`, and v28.5.2 is the newest release that
exists, so no grype version avoids them. Two are HIGH under trivy, which is the
gate `make scan-image` and CI enforce.

Everything fixable was fixed first: grype pinned up to v0.118.0,
`golang.org/x/mod` to v0.40.0, `go.opentelemetry.io/otel` to v1.44.0.

The remaining two are recorded as **accepted risk** in `.trivyignore.yaml`,
scoped to those two CVE IDs, scoped to the grype binary's path, and carrying an
expiry date trivy enforces. Approved by the project owner per §24. The reasoning:
both are Docker Engine API handlers, the worker runs no daemon and mounts no
socket, and the adapter declares filesystem targets only, so grype's
image-scanning path — the only reason the dependency is linked — is never
invoked.

**Why partial, and stated plainly:** this is a judgement that the exposure needs
a Docker daemon we do not run. It is not proof the code is unreachable.
govulncheck reports the vulnerable symbols as present in the binary; an early
assumption that they would not even be compiled in was wrong. The exception
expires rather than persisting, which is the control that keeps this from
quietly becoming permanent.

A second gap this exposed is now closed: govulncheck runs as a second
binary-level gate (ADR 013). It found **eleven** advisories across the three
scanner binaries where trivy found two, and **four of them had published
fixes** — archive-parsing flaws in the exact code path a secret scanner points
at untrusted repositories. Those were fixed, not accepted.

The open question this entry recorded is also answered, and it does not change
the verdict. Measured with a call behind a runtime-false condition: govulncheck's
binary mode reports symbols surviving linker dead-code elimination and performs
no call-graph analysis, while source mode proves only static reachability. Both
reported the unreachable call. So neither mode establishes runtime
exploitability, and "present in the binary" remains the accurate description of
what is known here.

*Also accepted, in `.govulnignore.yaml`:* the same five Docker advisories under
their Go ids. Same rules — per-binary, justified, expiring — with one addition:
an entry that stops matching anything fails the build, so the list cannot rot.
`GO-2026-5932` (`x/crypto/openpgp`) was accepted here until a fix appeared; the
scanners now pin the commit that removes the package.

*Verified by control test:* backdating `expired_at` makes the build fail again,
renaming the CVE ids makes the real two resurface, and pointing `paths` at
another binary removes the suppression — so the exception is narrow in all three
dimensions rather than a disabled scanner.

*Revisit:* if grype is ever given an image target, which would invalidate the
reasoning above. Image targets shipped without doing so: trivy serves them, and the
grype adapter accepts filesystem targets only (re-reviewed 2026-11-03).

### T-34 Matched source stored as a finding · **Mitigated**

Semgrep can embed the matched line in every finding (`extra.lines`). For a rule
that fires on a credential, that line **is** the credential, and §15.3 forbids
storing it. ADR 007 raised this when Gitleaks landed and left it open, because
nothing then produced such output.

Unauthenticated semgrep writes `requires login` there instead — verified against
a local ruleset with a planted key, which appeared nowhere in the output. That
is a property of semgrep's login state, not of any flag SecureOps sets, so it is
not relied on.

The adapter checks every finding before persisting and discards the entire
result if any carries source, whether or not the source looks like a secret: a
control that tried to tell the difference would eventually guess wrong. The
environment allow-list is the first line of the same defence — `SEMGREP_APP_TOKEN`
cannot be inherited, because nothing unlisted reaches a scanner subprocess.

`p/secrets` is deliberately absent from the default rulesets. Gitleaks owns
secret detection (§6), and including it would mean reimplementing ADR 007's
redaction control here a second time.

*Tests:* `TestMatchedSourceIsRefused` (a credential and ordinary source, both
refused), `TestRedactedSourceIsAccepted`, `TestIsRedactedSource`,
`TestEnvIsAnAllowListWithoutTokens`, and `TestScanAgainstRealSemgrep`, which
holds a live run to the same assertion.

*Verified by control test:* neutering the assertion makes the leak fixtures pass.

### T-35 Source content stored as a misconfiguration finding · **Mitigated**

Trivy reports each misconfiguration with the source lines that caused it, in
`CauseMetadata.Code.Lines[]`. Infrastructure-as-code is where hardcoded secrets
live, so those lines are routinely a credential: a Terraform resource with a
password produces a finding whose cause lines contain that password. Measured
rather than assumed — a planted value appeared verbatim in the JSON.

It appeared in **two** fields. `Content` is the line; `Highlighted` is the same
line with ANSI colour. Redacting only the obvious one leaves the secret in the
document, which is the sort of thing that is found by looking at output rather
than by reading a schema.

Trivy offers no flag to omit them (`--render-cause` affects only the table
report), so the adapter rewrites the document before anything is persisted:
structural walk, three fields replaced with a fixed marker, file and line
numbers and rule and severity all kept. A fixed marker rather than truncation,
because the first characters of a line containing a credential can still be the
credential.

The rewrite walks a decoded structure, so a trivy schema change could move those
fields somewhere it does not look. `assertNoSourceContent` re-walks the result
and discards the whole report if anything survived, so a schema change makes
scans fail rather than leak.

This makes trivy the only adapter whose stored output is not byte-identical to
what the scanner emitted, recorded in ADR 015 rather than left as a surprise.

*Tests:* `TestRedactionRemovesSourceContent`, `TestRedactionKeepsWhatRemediationNeeds`,
`TestAssertionCatchesWhatTheRewriteMisses`, `TestHighlightedIsRedactedToo`, and
`TestScanAgainstRealTrivy`, which holds a live run to the same assertion.

*Verified by control test:* dropping `Highlighted` from the redacted field list,
disabling the rewrite, and neutering the assertion each make the corresponding
test fail.

---

## Boundary 7 — Stored findings and derived views

New with Phases 4-6. Until Phase 4, a scan produced raw output and a status;
nothing durable described what was wrong with a project. Now SecureOps keeps a
queryable record of every vulnerability it has ever seen, correlates those
records into issues, attaches exploitation likelihood to them, reduces the whole
picture to a single number that a CI gate will eventually act on, and turns that
number into advice somebody will act on directly.

That record is a security asset in its own right, and the threats below are
about the asset rather than about the scanning that produced it.

### T-36 The findings store as an attack map · **Partial**

Concentrating every finding for every project into one queryable place creates
something no individual scan report was: a maintained, deduplicated, severity-
ranked inventory of how to attack the software this instance watches.

Phase 6 sharpened it. EPSS attaches a calibrated exploitation probability to
each finding, so `GET /api/v1/projects/{id}/findings` sorted by that field is
not a vulnerability list — it is a prioritised exploitation roadmap, ordered by
what is most likely to work right now.

**Authorization now bounds it, which it did not when this was written.** Phase 11
landed (ADR 033): a person holds a role and a project membership, a machine token
holds a role and a scope, and both are enforced in the project middleware, in the
`GET /projects` query, and on the id-addressed endpoints that carry no project in
the URL. A viewer scoped to one project reads one project's inventory. The
"any credential reads everything" sentence this entry used to carry was true
until Phase 11 and is not true now.

Partial rather than Mitigated for what remains, which is narrower than it was:

- **An `admin` is global by construction.** An administrator reaches every
  project, so the concentrated inventory is fully readable by one role. That is
  a deliberate simplification for a single-team tool, and the alternative is a
  tenancy model.
- **A machine token's scope is configuration**, not membership, so rotating what
  CI may reach is an edit to `SECUREOPS_API_TOKENS` and a restart.
- The store is still what it is: a maintained, deduplicated, EPSS-ranked
  inventory of how to attack the software this instance watches. Scoping
  bounds who sees it; it does not make it less valuable to whoever does.

The most dangerous single field — a detected secret's value — is never stored at
all (T-26, T-34, T-35).

### T-37 A scan falsely resolving a finding · **Mitigated**

A finding wrongly marked `resolved` tells someone a vulnerability was fixed when
nobody checked. It is the same class of error as reporting a `PARTIAL` scan as
clean (§13), reached through the lifecycle instead of through the status field,
and it is worse than a missed finding because it actively ends an
investigation.

Two ways in, both closed. A scanner that did not run cannot resolve its
findings: only scanners that completed without degradation are eligible. And
resolution requires **every** scanner that has ever reported a finding to have
completed — checking only the first reporter would resolve a grype+trivy finding
the moment grype came back clean, even with trivy failed and never asked.

The conservative direction is deliberate: dropping a scanner from a project
leaves its old findings open rather than silently declaring them fixed.
Stale-but-open is a state someone can see; a false `resolved` is not.

*Tests:* `TestAFailedScannerResolvesNothing`,
`TestOneFailedReporterBlocksASharedFinding`.

*Verified by control test:* removing the all-reporters clause makes the second
test fail while the other four lifecycle tests still pass — which is why the
defect existed unnoticed in the first place.

### T-38 Derived views disclosing repository structure · **Partial**

Findings deliberately carry no file path: location lives on the occurrence, and
`GET /findings` does not serve it.

Correlated issues do. A file-keyed issue's identity **is** a path in the scanned
repository, published as `key_value` on `GET /issues`. For a private repository
that is structure disclosure — directory layout, and which files carry both a
secret and a code weakness.

**Scoped since Phase 11.** Issues are served from `/{projectID}/issues`, inside
the route group whose middleware resolves the project against the caller's
membership or token scope — so they are scoped exactly as findings are, which is
what this entry asked for.

Bounded rather than closed for what is left: the path is the only thing exposed,
never file content; an `admin` reaches every project by construction; and the
disclosure remains a consequence of the correlation design rather than an
oversight. A file-keyed issue's identity *is* a path, and there is no way to
publish the issue without publishing it.

### T-39 Poisoned threat intelligence · **Mitigated**

Scanner output is untrusted (§15.7), and threat intelligence arrives inside it.
A hostile or broken EPSS value could distort prioritisation — the more so once
the risk engine consumes it.

Values are range-checked at the adapter, and a bad one drops the *value* while
keeping the finding: discarding a real vulnerability because its likelihood
metadata was malformed would be the wrong trade. Every drop is recorded as a
parse note rather than swallowed.

Provenance is mandatory. An EPSS with no source or no observation date is
rejected, because a number of unknown origin and unknown age looks like evidence
without being any. The rule is enforced three times independently — a pointer in
Go, an omitted JSON field, and a database CHECK — so a partially written value
cannot exist at rest.

Absence is never zero. EPSS probabilities are genuinely small, so a zero default
would be indistinguishable from a real signal saying "essentially nobody is
exploiting this" (ADR 018).

*Tests:* `TestABadEPSSDropsTheValueNotTheFinding`, `TestProvenanceIsRequired`,
`TestOutOfRangeValuesAreRejected`, `TestAbsentEPSSDoesNotBecomeZero`,
`TestAPartialEPSSRowIsRejectedByTheDatabase`.

*Verified by control test:* forcing the store to write `0.0` for an absent value
is rejected by the database constraint before the assertion runs.

### T-40 Correlation cost as a denial of service · **Mitigated**

Correlation compares findings pairwise within a bucket. A hostile repository
engineered to produce many thousands of findings sharing one CVE, component, or
file would make that quadratic, inside the scan-completion path.

Buckets are capped at 500. Beyond that the bucket is truncated in fingerprint
order — deterministically, so the same findings survive every run — and the
truncation is *reported* rather than absorbed, following ADR 010: silence would
be indistinguishable from "nothing correlated".

*Tests:* `TestAnOversizedBucketIsTruncatedAndReported`,
`TestTruncationIsDeterministic`.

### T-41 Correlation asserting a relationship that does not exist · **Mitigated**

Not a classic attack, but a security defect: a wrong correlation sends someone
to investigate a link nobody has evidence for, and an escalated severity built
on it misdirects remediation effort.

Issues are keyed by a single shared attribute, never by transitive closure over
the link graph — A related to B by CVE and B to C by file must not place A and C
in one issue, because no rule ever evaluated that pair. Severity escalates by at
most one step, only across distinct domains, and never mutates the members it
was derived from. Every link and every membership carries readable evidence.

Dismissed findings are excluded entirely: correlating a `false_positive` back
into a live issue would resurrect a decision somebody already made.

*Tests:* `TestIssuesDoNotChainTransitively`, `TestEscalationDoesNotMutateMembers`,
`TestDismissedFindingsAreNotCorrelated`.

### T-42 A risk score read as more complete than it is · **Mitigated**

The risk engine scores the findings it has. A scan in which a scanner failed
produces fewer findings, and fewer findings produce a *lower* score — so
degraded coverage is arithmetically indistinguishable from an improvement. A CI
gate reading only the number would pass a release precisely because the scanner
that would have blocked it crashed.

Every stored score carries the status of the scan it was computed for, joined
at read time rather than copied so it cannot go stale, and the API exposes both
`scan_status` and a pre-applied `complete` flag. §13's rule that `partial` is
never a synonym for `completed` therefore reaches the consumer of the score,
not just the scan record.

This is a control the Phase 8 policy engine must actually use; the mitigation
here is that the information is present and unavoidable, not that a gate exists
yet to honour it.

*Tests:* `TestRiskReportsWhetherTheScanWasComplete`,
`TestRiskScoreSurvivesTheRoundTrip`.

### T-43 A re-tuning silently changing what stored scores mean · **Mitigated**

Risk weights are configuration by design (§10), which means they will be
re-tuned. A score of 62 computed under one weight table and a score of 71
computed under another are measurements of different things, and a trend line
drawn across the change is fiction that looks like evidence — the more
dangerous kind, because it invites a decision.

Every persisted score records a digest of the weight configuration in force.
Scores with different digests are visibly incomparable, and the digest is
canonical by construction so identical weights always produce it identically.

*Tests:* `TestRiskScoreSurvivesTheRoundTrip`, `TestAScanPersistsItsRiskScore`,
`TestDefaultWeightsMatchTheDesignDocument`.

### T-44 Remediation advice that sends effort the wrong way · **Mitigated**

Not a classic attack, but a security defect with the same shape as T-41. A
remediation plan is acted on: a wrong upgrade target wastes the one window
somebody had to fix something, and a fabricated fix is worse than no advice
because it looks like an answer.

No action names a version no scanner reported (§11, §25.6). Where several
advisories on one component report different fixed versions, the action lists
them all rather than choosing — choosing needs ecosystem-specific version
ordering, and a comparator correct for semver is wrong for PEP 440 or Debian
epochs. Fix state is four-valued, so "no fix yet", "there will never be one",
and "nobody told us" cannot collapse into a claim that an upgrade exists; the
database enforces the same rule independently of the Go model.

*Tests:* `TestNoActionNamesAVersionNoScannerReported`,
`TestUnknownFixStateProducesNoUpgrade`, `TestWontFixNeverCarriesAnUpgradeTarget`,
`TestTheDatabaseRejectsAVersionOnAnUnfixableState`.

### T-45 Generated content presented as verified remediation · **Mitigated**

§11 permits AI for contextual explanation and prioritization guidance and
forbids it for the facts of a fix; §25.6 forbids presenting AI-generated
remediation as verified, and forbids labelling deterministic rules "AI". The
failure mode is a plausible-sounding fix with no provenance being read as
vendor guidance and applied.

Every statement in an action carries its source — `vendor`, `scanner`, or
`derived` — in the model and in the API response. `ai_explanation` is declared
so that AI content would be structurally visible if it were ever added, and is
never produced: no model integration exists, and §25.15 forbids treating Claude
Code or MCP as a runtime dependency. Prioritization is arithmetic, not
judgement, so no part of the ranking is generated either.

*Tests:* `TestNoStatementIsEverSourcedAI`, `TestNoRemediationStatementIsSourcedAI`.

### T-46 A weakened gate that nobody can trace · **Mitigated**

A security policy is the control that decides whether insecure code ships.
Someone who raises the critical-findings limit from 0 to 50 turns the gate off,
and until Phase 8 the only record of that was a log line reading
`PUT /policy 200` — no previous value, no new value, and nothing durable.

`audit_logs` is append-only at the database level, enforced by a trigger rather
than by convention, and every policy change is written into it **in the same
transaction as the change itself**. `audit.Write` takes a `pgx.Tx` and not a
pool, so writing outside the transaction is a compile error: the failure it
guards against only becomes observable when a commit fails, which is precisely
when nobody is watching.

Before and after are stored as JSON, so "what exactly changed" is answerable
rather than only "something changed". A creation records a NULL previous value,
which is what distinguishes it from an edit.

**This does not close T-23.** The log records who weakened a gate; nothing
decides whether they were entitled to. Detection is not prevention.

*Tests:* `TestAPolicyChangeIsAuditedWithItsBeforeAndAfter`,
`TestAnAuditEntryRollsBackWithItsTransaction`,
`TestTheAuditLogRefusesUpdatesAndDeletes`,
`TestARejectedPolicyChangeIsNotAudited`.

### T-47 A broken scan passing the gate because it broke · **Mitigated**

The most dangerous arithmetic in the system. A scanner that crashes reports
nothing; fewer findings breach fewer rules; and a gate reading only the numbers
passes a release precisely because the scanner that would have blocked it died.
The worse the scan, the more likely it passes.

A scan that is not `completed` can never produce `pass`. The treatment is
configurable between `warn` and `fail`, and `pass` is not a value the policy
model or the `policy_level` enum will accept — a database CHECK rejects a
passing verdict on an incomplete scan independently of the Go code. The gate
result carries the scan status and whether coverage changed the verdict, so a
warning caused by a crashed scanner is distinguishable from one caused by a
breached rule.

**The CI half landed in Phase 10.** The same reasoning applies one layer out: a
client that exited 0 because it could not reach the API would turn an outage
into a silent, universal disabling of the gate — every build green, nothing
checked. So `cmd/cli` exits **2** for "did not run", distinct from 1 for
"blocked", and the GitHub Action fails the step on a 2 regardless of
`fail-on-gate`. Report-only means "do not act on a verdict", never "do not
notice that there was none" (ADR 036).

*Tests:* `TestAnIncompleteScanNeverPassesEvenWithNoBreaches`,
`TestAPolicyCannotAllowAnIncompleteScanToPass`,
`TestTheDatabaseRefusesAPassingIncompleteScan`,
`TestCoverageDowngradeIsNotClaimedWhenARuleAlreadyCausedIt`,
`TestExitCodeContract`, `TestAnUnreachableAPICannotPassABuild`,
`TestARefusedCredentialCannotPassABuild`, `TestATimeoutCannotPassABuild`,
`TestAFailedScanIsNotAVerdict`, `TestMissingConfigurationCannotPassABuild`,
`TestAGateThatDidNotRunAlwaysFails` (the Action's half).

### T-48 Dismissal used to hide a real finding · **Partial**

Marking a finding a false positive lowers the project's risk score, removes its
remediation work, and can turn a failing gate green. It is now something a
person can do, which means it is something a person can do wrongly — in error,
under deadline pressure, or deliberately to ship a release.

The design refuses the worst version: a person cannot set `resolved` or
`reopened`, so nobody can assert that a scanner confirmed a fix (ADR 024 §2).
Every dismissal records who, when, why from a fixed vocabulary, and the note
behind the judgement, atomically with the change. Dismissals are reversible, so
a wrong one is correctable rather than permanent.

**Partial, not mitigated.** Detection is not prevention. There is no approval
step — one `service` credential dismisses and nobody countersigns — and no
expiry, so an `ignored` finding stays ignored until somebody reopens it, where
a time-boxed exception would be the better primitive. Both need the identity
model Phase 11 owns, and a scheduler that does not exist.

*Tests:* `TestAPersonCannotDeclareAFindingResolved`,
`TestADismissalIsAuditedWithBothStates`, `TestADismissalCanBeUndone`.

---

### T-49 An image reference as an SSRF primitive · **Mitigated**

`POST /scans` has accepted `KindImage` since Phase 2, and `validateImage`
checked the reference against a character allow-list and **nothing else** —
while `validateRepository` and `validateEndpoint` both ran the address policy.

The gap was inert for as long as it existed: no adapter served image targets, so
every such scan failed at dispatch with "no registered scanner supports this
target kind", and nothing ever dialled. Registering the trivy image adapter is
precisely what would have made it live. A reference of `169.254.169.254/latest`
or `10.0.0.5:5000/app` would have been accepted at the API and connected to from
the worker — the cloud metadata endpoint and the internal network reached
through a field designed to name a public image.

`validateImage` now extracts the registry host and runs it through the same
`netguard` policy as every other target (§14.6). Extraction follows the
distribution specification: the first path component is a registry when it
contains a dot or a colon, or is exactly `localhost`; otherwise the reference is
on the default registry, which is checked too, because a reference naming no
host still reaches the network.

Found while implementing ADR 025 rather than reported, and fixed in the same
change that made it reachable — not in a follow-up.

### T-50 An image scan reading the worker's own container runtime · **Mitigated**

Trivy's `--image-src` defaults to `docker,containerd,podman,remote`, in that
order. It tries the **local container runtime first** and only falls back to the
registry. A worker with a socket mounted — which is a normal deployment mistake
rather than an exotic one — would let a scan read any image on the host,
including images the request never named and images built from other tenants'
code. The address policy that validated the reference would be bypassed
entirely, because no network call would happen.

The adapter pins `--image-src remote`. A test asserts the flag and fails if it
is removed or changed, because this is the kind of default that a dependency
upgrade could quietly restore.

Registry credentials are a separate leg of the same threat and are handled
structurally: the trivy subprocess receives an allow-listed environment, so
`TRIVY_USERNAME`, `TRIVY_PASSWORD`, `DOCKER_CONFIG`, and `GITHUB_TOKEN` cannot
reach it, and `HOME=/nonexistent` keeps it from reading `~/.docker/config.json`.
Public registries only (§14.7, ADR 025).

### T-51 Registry egress during a scan of attacker-supplied input · **Partial**

Every adapter before this one ran with no egress at all: databases and rulesets
are provisioned before a worker claims a job, so a scan of untrusted content
needs nothing from the network (ADR 012). An image target cannot work that way —
the bytes are in a registry and must be fetched during the scan.

This is a genuine narrowing of §14.3's deny-by-default posture, and it is scoped
rather than opened:

- Egress is declared per target kind (`Capabilities.NetworkKinds`), so a
  filesystem scan still runs with none.
- The destination is validated before the job is enqueued (T-49) and is limited
  to what the address policy permits.
- The vulnerability database is still provisioned ahead of time; the scan runs
  `--skip-db-update`, so the only egress is to the registry.

**The size cap now exists.** Since 2026-09-04 an image scan passes
`--max-image-size` (default 2GB, matching the repository fetch cap, since both
answer the same question — how much attacker-chosen content one scan may pull).
Trivy refuses before it fetches: *"compressed image size 3.79MB exceeds maximum
allowed size 1MB"*. The check belongs to the component doing the pulling, which
is the only place it can stop the transfer rather than measure it afterwards. A
test asserts the flag is in the argument vector, so its removal — it is marked
EXPERIMENTAL by trivy 0.74 — surfaces as a failing test rather than as a
silently unbounded pull.

**Partial**, for two reasons that remain.

The cap bounds the **compressed** size the manifest declares. §14 also requires
a `max archive expansion ratio`, and a layer that decompresses far larger than
it downloads is bounded only by the filesystem trivy extracts into.

**Both residues now have a control, and it is off by default.** Phase 12b
(ADR 039, ADR 040) runs a scan in its own Kubernetes Job: the workspace is a
per-scan volume with a `sizeLimit`, so an over-expanding layer fills a volume
that dies with the scan rather than the node's disk; and the Job's network policy
is rendered from `Capabilities.NetworkKinds`, which had no non-test caller from
Phase 2 until then. A repository scan is two pods, and the one that runs the
scanners has no egress at all — verified on a cluster, five of five scanners
succeeding with no route off the node.

**Still Partial, and the reason has changed.** It is no longer "nothing enforces
this". It is that `SECUREOPS_SCAN_EXECUTOR` defaults to `inprocess`, which is
what compose runs and what an upgrade keeps, and in that mode the workspace is a
named volume with no quota and the egress declaration documents intent rather
than imposing it. A control that exists and is switched off protects nothing;
this entry closes for a deployment that turns it on, and not before.

### T-52 SecureOps as an attack tool · **Mitigated**

DAST is the first scanner that sends requests to a host somebody else operates,
and ZAP's active scanner sends *crafted attack payloads* — SQL injection, XSS,
command injection, path traversal. Three problems, none of which this platform
can currently manage:

- **It changes state.** A payload delivered to a real form submits that form.
- **It is attack traffic**, and whether it is authorized depends on who owns the
  target. A project may name any endpoint the address policy permits, so a tool
  that attacks on the strength of a typed URL will eventually be pointed at a
  host its operator does not own.
- **It needs a scope nobody declared.** Permission to test is a fact about a
  deployment, not a flag on a scan.

The adapter runs `spider` and `passiveScan-wait` only. The `activeScan` job is
**absent from the automation plan** rather than present and disabled, so no
configuration change can switch it on, and a test asserts the plan mentions no
active-scanning job at all.

**The payloads are also absent from the image** (ADR 030). ZAP's distribution
ships 50 add-ons; the worker installs the nine the plan uses, and what is left
out includes `ascanrules` — the active scan rules themselves — along with `fuzz`
and `spiderAjax`. So there is now no configuration *and* no code in the worker
that could deliver an attack payload. A test reads the add-on list out of the
Dockerfile and fails if `ascanrules` reappears, because "install everything to
fix the build" is exactly how this control would be lost.

The cost is stated rather than hidden: **SecureOps does not test for
injection.** Active scanning needs a per-project authorization model and is the
project owner's decision (§24, ADR 026).

### T-60 A Java runtime in the worker image · **Partial**

ADR 030 puts a headless JRE and ~114 MB of ZAP into the worker — the one
container that executes scanner binaries against attacker-controlled input. A
JVM is a large runtime with a continuous advisory stream of its own, and ZAP is
a substantial Java application on top of it. The worker's attack surface grows
by both.

Four things bound it.

The JRE comes from **Alpine's package index**, not from ZAP's own bundled JVM,
so it is patched on the distribution's schedule rather than an application
vendor's. ZAP's artifact is **pinned and checksum-verified** against the digest
its publisher states, the ADR 014 pattern (T-28).

The **add-on set is trimmed to nine**, which removes 194 MB of code that would
otherwise be loadable — including the active scan rules, which is the T-52 point
above rather than only a size one.

And it is **in scope for the existing gates**: the JVM and ZAP enter the image
scan and the self-scan like every other dependency, so an advisory against them
surfaces the same way one against gitleaks does.

**Partial**, not mitigated, and the residue is measured rather than asserted.
Unlike every Go scanner here, ZAP cannot be rebuilt from source with this
project's toolchain (ADR 009 does not transfer; ADR 014's reasoning does), so a
CVE in a library ZAP vendors cannot be patched by us — it waits for an upstream
release. That is the same position semgrep is in, and it is worth naming twice.

Trivy does see the jars. On the image as built it reports **10 findings in ZAP's
dependencies, all MEDIUM or LOW, none HIGH or CRITICAL** — six in log4j, the
rest in commons-* and json-lib. Six of the ten have fixed versions published
upstream and we cannot apply them, which is exactly the residue described above,
now with a number on it. The Alpine package set, the JRE included, reports zero.

The two HIGH findings in the image predate this change and are unrelated:
`CVE-2026-41567` and `CVE-2026-42306` in the docker library grype vendors,
neither with a fix available.

### T-53 A crafted endpoint rewriting the scan plan · **Mitigated**

ZAP is driven by an Automation Framework plan — a YAML document the adapter
builds with the target URL in it. A URL containing a quote and a newline could
close the scalar and append plan structure, and the job it would most obviously
append is `activeScan`, turning a passive scan into an attack against a target
of the submitter's choosing.

Confirmed rather than theorised: with quoting removed, a crafted endpoint
injects an `activeScan` job into the plan, and the control test catches it.

Three layers: the endpoint is validated at the API boundary, re-checked in the
worker against a scheme and character allow-list, and escaped when written into
the plan (quotes and backslashes escaped, newlines stripped). The test asserts
plan *structure* — that no line declares a job the adapter did not write —
rather than the absence of a substring, because a quoted value may legitimately
contain the text.

### T-54 The scanner proxy as an open relay · **Mitigated**

ZAP is a proxy, and it requires a listener even in headless command mode. Bound
to a wildcard address it would be an open forward proxy on the worker for the
duration of every scan — reachable by anything that can route to the worker, and
able to reach anything the worker can.

The adapter passes `-host 127.0.0.1` explicitly. A test asserts it, and the
control test confirms that changing it to `0.0.0.0` fails that test.

### T-55 Target application content stored as a DAST finding · **Mitigated**

The ZAP counterpart of T-34 (semgrep) and T-35 (trivy), and it is the same
mistake in a third costume: a scanner embeds the thing it scanned, and the thing
it scanned contains credentials.

Measured against ZAP 2.17.0. A target serving one link to `/search?api_key=…`,
one hidden form token, and one session cookie produced: the API key in **seven**
`instances[].uri` values, the form token in **two** `otherinfo` values, and
nothing from the cookie — ZAP reports cookie names only.

The report is rewritten before storage. `uri` and `nodeName` lose their query
string and fragment; `evidence`, `otherinfo`, and `attack` are replaced with a
digest of the original. The digest rather than a bare marker is what §15.3 asks
for — "a location and a hash, not the secret" — and it lets two scans be
compared without the value ever being stored.

`attack` is redacted even though it is always empty without active scanning, so
the control does not depend on the scan mode staying as it is.

Verified after the rewrite and the report discarded if anything survived, the
same fail-closed check ADR 015 established: the rewrite walks a decoded
document, so a schema change that renamed a field would make it silently miss
content. The mapper checks again before the database.

### T-56 DAST reaching an internal application · **Mitigated**

An endpoint target names a host to connect to, and the worker is inside the
deployment's network. Unlike the image case (T-49), the gap was already closed:
`validateEndpoint` has applied the `netguard` address policy since Phase 2, so
loopback, private, link-local, and cloud metadata addresses are refused.

Checked rather than assumed while implementing ADR 026 — the image adapter had
exposed exactly this omission on a sibling code path, so the endpoint path was
audited for it and is genuinely clean.

Note the deliberate exception: `Policy.AllowPrivate` permits internal targets
for self-hosted deployments that legitimately scan their own network, and cloud
metadata endpoints stay blocked regardless of that setting.

### T-64 A scanner that opens its own connections · **Mitigated**

Every other adapter is a subprocess. `httpprobe` (ADR 041) makes HTTP requests
from inside the worker, chosen partly by what a target answers, because the CORS
check follows same-site redirects. So a hostile target could try to steer the
worker somewhere, or feed it something oversized.

Every connection goes through `netguard.Policy.ControlFunc`, on the concrete
address after DNS, so a rebinding name is refused and cloud metadata is refused
whatever `SECUREOPS_ALLOW_PRIVATE_TARGETS` says. A redirect is followed at most
three times, only to the same host or its `www.` variant and never from HTTPS down
to HTTP. The environment's proxy settings are ignored. Response bodies are never
read, headers are capped, and what is stored is a closed set of classifications,
so nothing a target sent reaches storage as text (§15.3). Tests cover each of
these, and each was confirmed by removing the control and watching a test fail.

It sends no attack payloads, so T-52's reasoning holds: each request is one a
browser could make.

### T-57 The dashboard sees everything, for everyone · **Mitigated**

The dashboard holds one credential on behalf of every person who opens it.
Without a gate in front, anyone who could reach it saw every project's
findings: which packages are vulnerable, where the secrets were committed,
which endpoints lack which headers, and which gate is failing. That is a map of
the estate's weak points, which is the T-36 problem with a web page in front of
it. It was bound to loopback in `docker-compose.yml` — a deployment convention,
not a control, and one that does not survive the first person who exposes the
port.

**A login now stands in front of it** (ADR 029). A shared password is exchanged
for an HMAC-SHA256 session cookie carrying its own expiry inside the signed
payload; the signature is verified server-side in every page and route handler,
and the edge middleware only tests for the cookie's presence because the edge
runtime has no `node:crypto`. An unset password admits nobody rather than
everybody.

**This entry previously said a password prompt would be "theatre".** That
judgement is withdrawn, and the reasoning is recorded rather than deleted. It
was right about what a shared password *is* — it authenticates a browser and
not a person, so it cannot make the audit trail name anybody — and wrong to
conclude that therefore nothing should be done before Phase 11. The exposure
being argued about was unauthenticated read access to the whole estate's weak
points, and a control that reduces that is worth having even though it does not
also solve attribution. The two problems are separable; treating them as one
kept the larger one open for the sake of the smaller one.

**Closed on 2026-09-04 (ADR 033).** The shared password is gone — removed
rather than deprecated, because a session minted from it had no identity behind
it and would have kept this entry open while looking like it was closed. The
dashboard refuses to start if the variable is still configured.

People sign in with accounts now, and the dashboard forwards their session to
the API in place of its own credential. A viewer sees the projects they are a
member of and no others; the "sees everything, for everyone" this entry is named
for is no longer true of either half.

**Mitigated.** What remains is not about the dashboard: see T-23 for the
narrowed residue on identity.

### T-59 The dashboard can now queue work · **Partial**

ADR 029 moved the dashboard from a `viewer` credential to a `service` one so
the URL bar can create a project and submit a scan. Compromising the page is
therefore worth more than it was: a session grants the ability to make the
worker clone arbitrary `https://` URLs, which is unbounded work and an outbound
request the attacker chooses.

Four things bound it.

The **login gates it** — before ADR 029 an anonymous page could not have had
this endpoint at all, which is why the session landed in the same change rather
than after it.

The **address policy is not reimplemented in the browser tier.** The route
handler shape-checks for `https://` and then hands the URL to the API, which
applies `netguard` exactly as it does for a CI client (T-49, T-56). A second,
weaker copy of those rules in the dashboard would be a place for the two to
disagree, and the weaker one would win.

The credential is **`service`, not `admin`** (ADR 023). The dashboard cannot
edit the policy that judges the scans it queues, and cannot dismiss a finding.

Every submission is **audited** (ADR 022) — against the dashboard's token
label, not a person, which is the T-57 residue seen from the write side.

**Per-user attribution arrived on 2026-09-04 (ADR 033).** A scan queued through
the dashboard is now recorded against the person who queued it, not against the
dashboard's credential. Verified end to end: submitting one produced
`user / <id> / scan.create`, resolving to a named account.

**The dashboard gained admin writes on 2026-09-05 (change C)** — creating
accounts, changing roles and membership, archiving a project. That widens what a
compromised page can do, and the bound is that none of it is decided in the
browser tier: every one of those route handlers forwards to the API and renders
its answer, so an admin-only action taken from a viewer's session is refused by
the API, not by a hidden button. The Access link is hidden from non-admins as a
courtesy; the page behind it still asks.

**Partial.** There is still no rate limit on submissions, so a valid session can
queue scans as fast as it can post; the queue's concurrency limits bound the
worker's load but not the depth of the backlog. That is what is left of this
entry, and it is a smaller thing than what it was written for.

### T-58 The API credential reaching the browser · **Mitigated**

A dashboard that fetches from the browser puts its credential in browser
memory, in a page payload, or both. This one never does: every read happens in a
Server Component or a route handler, and `apps/web/src/lib/api.ts` opens with
`import "server-only"`, so a client component that imports it fails the build
rather than shipping the token.

The command palette needs project names in the browser, which is exactly the
case that would otherwise justify a client fetch. It calls a Next route handler
in the same server process instead, and that handler returns names and ids —
never the credential, and never the upstream error text, which can carry
internal detail (§15.3).

A consequence worth stating: the browser talks only to the dashboard and the
dashboard talks to the API, so the SecureOps API is never exposed to the user's
network by this design and needs no CORS policy for it.

## Summary

| Status | Count | Notable |
|---|---|---|
| Mitigated | 44 | T-01, T-02, T-03, T-05, T-06, T-07, T-10, T-11*, T-12, T-13, T-14, T-15, T-16, T-17, T-24, T-26, T-27, T-29, T-30, T-31, T-34, T-35, T-37, T-39, T-40, T-41, T-42, T-43, T-44, T-45, T-46, T-47, T-49, T-50, T-52, T-53, T-54, T-55, T-56, T-57, T-58, T-61, T-63, T-64 |
| Partial | 18 | T-04, T-08, T-09, T-18, T-19, T-20, T-23, T-25, T-28, T-32, T-33, T-36, T-38, T-48, T-51, T-59, T-60, T-62 |
| Open | 0 | — the first time this row has been empty |
| Prospective | 2 | T-21, T-22 — no such endpoint exists |

\* T-11 is mitigated by an interim control (ADR 006) that Phase 11 replaces.

**The seventeen Partials are not seventeen tasks.** Nine of them —
T-04, T-09, T-19, T-20, T-25, T-28, T-32, T-33, T-60 — are Partial as an end
state. A supply chain is mitigated, never closed; `Policy.AllowPrivate` is a
deliberate exception for deployments that legitimately scan their own network;
and ZAP's vendored dependencies cannot be patched here at all, because it is
the one scanner that cannot be rebuilt from source (ADR 030). Rewriting any of
them as Mitigated would make this document less honest rather than more
complete.

The other nine resolve into two bodies of work. **Seven of them are one
change**: T-18, T-36, T-38, T-48, T-57 and T-59 each name per-user identity,
RBAC, or project scoping as the residue that keeps them Partial, and T-23 is
that same gap named directly. That is Phase 11, and ADR 033's first change has
now taken the authorization half of it — a credential is confined to the
projects it was granted. What is left there is identity: a scope belongs to a
credential, not to a person. **T-51 is the eighth and ninth**, and splits: its
size cap landed, while its expansion ratio and `NetworkKinds` enforcement wait
for **Phase 12b** — both need a pod per scan, which 12a does not give them. T-10
went with 12a and is now Mitigated; T-08 improved there and stays Partial,
because hardening is not a sandbox however it is configured.

**No Open entries remain.** T-10 was the last, and Phase 12a closed it: the Helm
chart selects every image by digest and refuses to render a tag. That is worth
stating plainly and also worth not over-reading — eighteen Partials remain, nine
of them permanently, and "no Open threats" means no surface with *no* control,
not a system without exposure.

**T-23 is no longer the one to fix first.** It was, for six phases:
authentication landed in Phase 3 alongside the first write endpoints and
authorization did not, leaving a single-tenant assumption as the only thing
making that acceptable. ADR 033 closed the substance of it across three changes
— scoped credentials, then people with roles and membership, then administration
through an audited API instead of SQL. What is left is listed under T-23 itself
and is a set of conveniences, not a missing control.

What comes first now is **T-51's residue and T-10**, both of which need Phase 12
and a cluster: archive-expansion limits, `NetworkKinds` enforcement, and
digest-pinned scanner images. Nothing before that is blocked on a boundary this
document calls unguarded.

Phase 3a widened the attack surface: `POST /scans` is the first endpoint that
accepts an attacker-chosen target. The SSRF guard (T-04) and the
argument-injection defences (T-05) moved from theoretical to load-bearing, and
both are now exercised at the API boundary as well as in the worker.

Phase 3b widened it much further. The worker now **fetches and parses
attacker-controlled content** (T-25), which is the single most dangerous thing
this system does, and it handles credentials it discovers (T-26). Both are new
with this phase and both are the reason the worker runs as a separate,
non-root, read-only container with an ephemeral tmpfs workspace and no package
manager.

Parses rather than executes, stated precisely because the distinction bounds the
threat: all five scanners are static analysers, and the fetch disables hooks,
symlinks, submodules, and every protocol but https and ssh. The exposure is
parser bugs in five parsers, not arbitrary code execution by design. That is
still the highest-value boundary; it is not the same threat as running the
target's build.

**Phases 4-6 added a boundary rather than widening one.** SecureOps now keeps a
durable, correlated, likelihood-ranked record of every vulnerability it has
seen. Nothing about scanning changed; what changed is that the product now holds
an asset worth stealing (T-36), publishes derived views that disclose more than
the findings themselves (T-38), and can be wrong in a new and dangerous way — by
declaring a vulnerability fixed when nobody checked (T-37).

The controls added with them are mostly about *not lying*: a scan may not
resolve what it did not verify, correlation may not assert links it cannot
explain, and a threat-intelligence value may not exist without provenance. Those
are security properties, not quality ones — each failure mode ends an
investigation that should have continued.

**Phases 7-9 widened it once more, and the pattern held.** The remediation
engine may not invent a fix (T-45); the gate may not report a degraded scan as a
clean one (§13); and the dashboard, which arrived last, brought the first
credential held on somebody else's behalf (T-58) and the first write a browser
can trigger (T-59). ADR 029's login closed the unauthenticated read of the whole
estate that T-57 described, and ADR 032 stopped a refused target leaving a
project behind it — the smaller of the two, and the one that shows what
"authorization exists, identity does not" looks like from the outside.

Phase 3b's remaining adapter closed on 2026-09-04. ZAP ships in the worker
image, which put a JVM in the container that executes untrusted content (T-60)
and, in the same change, removed ZAP's active-scan rules from the image
entirely — so T-52's control is now the absence of the payloads as well as the
absence of the job.

## Review triggers

Update when a trust boundary changes, a component is added, a threat changes
status, or a phase completes (§15.14, §21).

This document went four pull requests without an update — Phases 4, 5, and 6's
threat-intelligence capture all landed while it still described Phase 2. No
CI check enforces the trigger above, so it depends on the reviewer noticing.
Worth remembering that "documentation updated where necessary" is part of the
Definition of Done (§23), and that a threat model describing a system two phases
old understates its own open threats — which is exactly what happened to T-23.
