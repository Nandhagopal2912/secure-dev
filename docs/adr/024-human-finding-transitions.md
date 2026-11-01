# ADR 024: A person may judge a finding, but may not declare it fixed

- **Status:** Accepted
- **Date:** 2026-09-03

## Context

§17 gives the finding lifecycle seven states — `OPEN · ACKNOWLEDGED ·
IN_PROGRESS · RESOLVED · REOPENED · FALSE_POSITIVE · IGNORED` — and requires
every transition to record who, when, why, the previous state, and the new one.

Three engines already honour the dismissed states. Risk scores a
`false_positive` at zero, remediation produces no work for one, and the gate
does not count it. `finding_status_history` has existed since Phase 4 with an
`actor` column whose own comment says a named principal appears "when someone
acknowledges or ignores a finding".

Nothing can produce that transition. The only status changes SecureOps can make
are the automatic ones a scan drives: first seen, reopened, resolved-on-rescan.
**A human cannot mark a false positive**, which has now survived three phases
that depend on it being possible.

The cost is concrete. A gate that fails a build on a finding nobody can dismiss
is a gate teams route around — by weakening the policy, or by ignoring the
verdict. Either outcome is worse than the finding, because it disables the
control for everything else too.

That settles *that* transitions must exist. It leaves *which*, and one of them
is not a matter of convenience.

## Decision

**1. A person may set `acknowledged`, `in_progress`, `false_positive`,
`ignored`, and `open`.**

`open` is the undo: a dismissal is a judgement, and judgements are revisited.
Without a way back, a mistaken `false_positive` is permanent and the honest
response becomes never dismissing anything.

**2. A person may not set `resolved` or `reopened`.**

These are not opinions. `resolved` means *a scanner stopped reporting this* (for a website scan, on a rescan of the same URL: ADR 042), and
`reopened` means *a scanner saw it again*. Both are observations, and the
platform's account of them is only worth anything if it is the platform's.

Letting someone mark a finding resolved by hand produces precisely the false
assurance SecureOps exists to prevent: the risk score drops, the gate passes,
the dashboard shows green, and nothing was fixed. Worse, it is
indistinguishable afterwards from a finding a scan actually confirmed gone —
the two would sit in the same state with the same name.

A real fix that no scanner can see is what `ignored` is for, with a note saying
why. That records the same decision without claiming a verification nobody
performed.

**3. Every human transition carries a reason from a fixed vocabulary, plus an
optional free-text note.**

The vocabulary keeps "why" queryable, which is what makes "show me everything
dismissed as an accepted risk" answerable. The note is where the actual
argument goes, because `accepted_risk` alone does not tell the next reader what
was accepted or on whose authority.

The note is stored on the transition, not only in the audit record: a reviewer
reading a finding's history should not have to join against another table to
learn why it is in the state it is in.

**4. A transition and its audit record are written in one transaction.**

Same rule as ADR 022, for the same reason. A dismissal is a security-sensitive
action under §15.6, and a record that can be lost while the change survives
leaves a gap that looks exactly like nobody having done anything.

**5. Transitions require `service`; nothing about them requires `admin`.**

Dismissing a finding is triage, and triage is what the people using this tool do
all day. Requiring `admin` would push teams back to weakening the policy —
which *is* admin-gated — to get the same outcome, making the stricter rule
produce the worse behaviour.

## Alternatives considered

**Allow `resolved`.** More flexible, and it lets a project be scored clean on
an assertion no scan supports. The state would then mean two different things
depending on who wrote it, and nothing downstream could tell them apart.

**Dismissals only — `false_positive`, `ignored`, `open`.** The smallest
surface, and it leaves triage with nowhere to record that work has started, so
`acknowledged` and `in_progress` stay decorative in a spec that names them.

**Free text instead of a reason vocabulary.** Expressive and unqueryable.
"Everything dismissed as an accepted risk in the last quarter" is a question a
security team asks, and free text cannot answer it.

**Require `admin` for dismissals.** Rejected on incentives, per decision 5.

**Wait for Phase 11 identity.** The consistent choice, and it keeps a gate
nobody can triage against for two more phases. The actor recorded today is a
token label rather than a person, which ADR 006 and ADR 023 already say plainly;
that is a weaker attribution than Phase 11 will give, not an absent one.

## Consequences

**Easier.** The gate becomes usable: a false positive can be dismissed rather
than worked around. The three engines that already honour dismissed states stop
honouring a state nothing could produce. §17's lifecycle is real rather than
documented.

**Harder.** Dismissal is now a way to make a project look better without
improving it, which is exactly why it is audited, attributed, and reversible.
The audit log is the control that makes it survivable, not the state machine.

**Committed to.** A person may judge a finding and may not declare it verified.
Every transition records who, when, why, from, and to. A dismissal is
reversible. The record and the change are atomic.

**Known limits.** The actor is a token label, not a person (ADR 006, ADR 023).
There is no approval workflow: one credential dismisses, and nobody
countersigns. There is no expiry — an `ignored` finding stays ignored until
somebody reopens it, where a time-boxed exception would be the better primitive
and needs a scheduler that does not exist.
