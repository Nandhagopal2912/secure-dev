# ADR 042: A website scan only resolves what it looked at again

- **Status:** Proposed
- **Date:** 2026-11-01

## Context

`resolveUnreported` closes findings a scan did not report. Its rule is that a finding
may be resolved when every scanner that ever reported it completed this scan. That
rule assumes each run of a scanner looks at the same thing, which holds for a repository
or an image, where a scanner reads the whole target every time.

It does not hold for a website. `httpprobe` checks exactly the URL it is given (ADR 041),
and ZAP crawls outward from it. So in one project:

1. A scan of `/api/account` opens a High CORS finding.
2. A clean scan of `/login` completes, and does not report that finding.
3. The finding is marked `resolved`, although nobody looked at `/api/account` again.

The score then improves and the gate can pass with the problem still open. ADR 041 recorded
this as a known limitation. It is the error `resolveUnreported`'s own comment warns about: a
false "fixed" is worse than a stale open finding.

## Decision

For a scan whose target kind is `endpoint`, a finding is additionally eligible to resolve
only if the scan that **most recently reported it targeted the same URL path** as this one.

- **The comparison is of scan targets, not of finding locations.** A ZAP scan starting at `/`
  may report a finding on `/login`. Rescanning `/` can resolve it, because that is the scan
  that could find it again. A scan starting at `/login` cannot.
- **Only the path counts.** Origin and query are removed for the reasons ADR 026 gives: preview
  hostnames churn, and queries are per-request noise. The escaped path goes through
  `NormalizeLocation`, so `/api//account` and `/api/account/` are one page, while `/files/a%2Fb`
  and `/files/a/b` stay two.
- **The most recent reporter decides.** If `/a` and then `/b` reported a finding, a clean scan of
  `/a` proves little, since its crawl may no longer reach that page. A clean scan of `/b` closes
  it. Requiring every reporter would leave findings open whenever a project stops scanning one.
- **Every other target kind behaves exactly as before,** including a stored scan with no target.
- **If a path cannot be worked out, nothing is resolved,** which is the conservative direction.

No schema change is needed. `scans.target` has held what each scan pointed at since migration
0003, and `finding_occurrences` already says which scans reported a finding. The comparison is
in Go, so it shares that normalization, and any other kind of scan pays only for one read.

## Alternatives considered

**One URL per project, as a convention.** Needs no code, and nothing enforces it. A person who
forgets gets a false "fixed" with no warning.

**Never auto-resolving website findings.** Cannot be falsely fixed, and real fixes would stay open
until a person closes them, which teaches people to ignore the list.

**Letting any earlier reporter resolve it.** The first draft of this ADR. Simpler, and it brings
back a false "fixed" whenever a finding is reachable from only one of the URLs that reported it.

**Comparing paths in SQL.** Also the first draft. It worked out the path a second way, which
disagreed with identity on paths like `/api//account`, and it ran over every scan in the project.

**Comparing each finding's own location to the target.** Wrong for ZAP, which reports on pages other
than the one it started from, so its findings would almost never resolve.

**Adding the host to the comparison.** More exact for a project with several real hosts, and it would
leave every finding open forever in a CI preview setup, where each pull request has a new hostname.
This is the trade ADR 026 already made for identity, so resolving follows it.

**Asking adapters to declare their coverage through `Capabilities`.** More general, and a larger change
to the scanner contract than one bug justifies. The target kind already answers the question today.

## Consequences

**What becomes possible.** A project can scan several URLs, and `resolved` on a website finding now means
that URL was looked at again.

**What becomes harder.** A finding stays open until its URL is scanned again. Fixing a problem and never
rescanning that URL leaves it open. That is a visible state, and rescanning clears it.

The most-recent rule has its own cost. If `/a` and then `/b` reported a finding and the project goes back
to scanning only `/a`, clean scans of `/a` cannot close it, even once it is fixed. Someone has to scan `/b` again.

A URL that can no longer be scanned is harder still. If a host is retired, scans of it fail rather than
complete, so its findings never close by themselves, and they keep counting toward the score and the gate.
ADR 024 forbids a person setting `resolved`, so the only way out is marking them `ignored` or `false_positive`,
neither of which is quite what happened. A way to retire a target is a separate decision.

**ZAP changes too, on purpose.** It had a milder form of the same bug.

**What this does not solve.**

- **Other target kinds have the same gap.** Nothing compares targets for them. Scanning image B in a project
  can resolve findings from image A, because trivy completed and did not report them. A repository scan can
  resolve trivy's image findings too, and scanning a different repository in one project has the same effect.
  An earlier draft of this ADR said other kinds were unaffected, and that was wrong. Fixing them changes how
  every scanner's findings close, so it is left to the project owner.
- Two real hosts in one project that share a path still count as one target, as they already count as one
  finding under ADR 026. A clean scan of staging's `/login` can resolve a finding from production's `/login`.
  Two ports on one host are the same: a clean scan of `:3000/api` can resolve a finding from `:8443/api`.
- A rescan of the same URL can still miss a page ZAP's crawl did not reach this time, and resolve a finding
  on it. Only a scan of that page itself could tell.
- Findings already marked resolved are not reopened by this change. The next scan that reports one reopens it.

**Approval.** Under §24 the project owner decides architecture and the data model, and this changes what
`resolved` means across the platform, so it is the owner's decision. This change was built and tested in a
fork, and its status stays `Proposed` until the owner has decided.
