# ADR 041: An HTTP probe for what passive DAST cannot see

- **Status:** Proposed
- **Date:** 2026-11-01

## Context

ZAP is the only adapter that looks at a running application, and it runs in
passive mode (ADR 026). Passive rules read the traffic the spider generates, and
the spider never sends a made-up `Origin` header. So a common and serious
misconfiguration is invisible to SecureOps: a server that accepts an `Origin` it
should not, and also sends `Access-Control-Allow-Credentials: true`. Any website
can then make a visitor's browser call that server with their cookies and read the
answer. ZAP's rule 10098 sees a literal `*`, but a server that only says yes when
asked looks fine until somebody asks.

The same scan also never asks what happens at the `http://` address of an HTTPS
site. A site can have flawless HTTPS and still serve its pages unencrypted on
port 80, or redirect there only temporarily.

Answering both takes a status code and a few headers. Neither needs a new binary.

## Decision

Add an adapter, `internal/scanners/httpprobe`, written in Go, serving
`KindEndpoint` and `CategoryDAST`, and declaring egress for `KindEndpoint`. It runs
alongside ZAP and sends at most eight requests per scan (sections 2 and 3), none of
them carrying a payload.

Beyond its own folder and fixtures it adds one registration in
`internal/scanners/all`, one setting in `config.ScannerSettings` (section 5), and one
row in the dashboard's hand-kept scanner list (`scan-progress.tsx`). The setting and
the row go past §7 rule 4, so **they need the owner's approval**. The setting is there
because this is the first adapter that makes its own connections and so enforces the
address policy itself.

### 1. Why this stays inside ADR 026

ADR 026 rules out active scanning because attack payloads change state, are attack
traffic, and need an authorization model that does not exist. This adapter sends no
payloads. Each request is one a browser could make: a browser sends `Origin` on
cross-site requests, `null` from a sandboxed iframe, and an `OPTIONS` preflight
before many of them, and anyone can type an `http://` address. It needs no
authorization model, for the same reason ZAP's spider does not. The preflight names
`POST` in a header, and no `POST` is ever sent.

The line is the point, so it is stated: **exposed-file probing and rate-limit
spoofing are out of scope.** Asking for `/.env` or forging `X-Forwarded-For` is
probing for weakness rather than behaving like a visitor, and belongs to the
per-project authorization model ADR 026 defers. A test asserts what is sent.

### 2. The CORS check

Four questions, each on `secureops-probe.invalid` or `null`. `.invalid` is reserved
by RFC 2606 and can never resolve, so nobody can have configured it as trusted.

| Question | Origin sent | What a yes means |
|---|---|---|
| `GET` | `https://secureops-probe.invalid` | The server trusts any origin. |
| Preflight (`OPTIONS`) | the same | The same, on a server that only shows CORS settings on a preflight. Some APIs only answer here. |
| `GET` | `https://<target host>.secureops-probe.invalid` | The server checks only how the origin starts, so an attacker can copy the name with a domain of their own. |
| `GET` | `null` | Any page can read this from a sandboxed iframe. |

The first question follows up to three same-site redirects (section 5), and the rest
are asked of the page it reached. "Yes" means `Access-Control-Allow-Origin` came back
equal to what was sent.

| Result | With credentials | Without | Why |
|---|---|---|---|
| Trusts any origin | **High**, `cors-reflected-origin-credentials` | **Low**, `cors-reflected-origin` | With cookies, any site can read this endpoint as the visitor. Not critical, because an unauthenticated scan cannot see what the endpoint returns to a signed-in user. Without them, any site reads only what an anonymous visitor could; worth fixing because it is usually one setting from the worse case. |
| Trusts a lookalike | **High**, `cors-lookalike-origin-credentials` | **Low**, `cors-lookalike-origin` | The same reasoning. |
| Trusts `null` | **High**, `cors-null-origin-credentials` | **Low**, `cors-null-origin` | The same reasoning. |

- **One mistake is one finding.** A server that trusts any origin on a real request
  also trusts a lookalike and `null`, so only the first is reported for it.
- **A yes on the preflight alone has medium confidence,** and shares the same rule. A
  preflight says the request may be sent, not that its answer may be read. So it does
  not stop the lookalike and `null` questions from reporting, which may be worse.
- **Credentials mean the exact value `true`.** A browser accepts nothing else.
- **`*` is not reported.** ZAP's rule 10098 already does, in the `pscanrules` add-on
  the worker image installs, and browsers refuse credentials with `*`. It is recorded
  in the output, as are a fixed `null` and any other fixed value.

### 3. The HTTPS redirect check

Send `GET` to the plain address. For an `https://` target that is port 80 of the same
host, whatever port the target itself uses, because that is where a browser goes for
`http://host`, and the path is `/`. For an `http://` target it is the target itself, so
an HTTP-only endpoint needs no special path: it simply reports what it serves.

An HTTPS target on a custom port says nothing about who owns port 80 of its host, so a
finding from that case is reported with low confidence.

| Answer | Result | Why |
|---|---|---|
| 301 or 308 to `https:` | no finding | Correct. |
| 302, 303, or 307 to `https:` | **Low**, `http-redirect-temporary` | It does upgrade, but browsers keep returning to the plain address first. |
| Redirect to `http:` or a relative path | **Low**, low confidence, `http-redirect-stays-plain` | A later hop may reach HTTPS. This check follows no redirects, so that cannot be known. |
| 2xx | **Medium**, `http-served-plain` | A page is readable and changeable on the network path. |
| 408, 425, 429, or 5xx | no finding, and the result is degraded | The service could not answer, which is no evidence either way. |
| Any other 4xx | **Low**, low confidence, `http-error-plain` | Something is listening, but nothing shows it serves real content. |
| Connection refused, HTTPS target | no finding | Nothing is listening, which is safer than any redirect. |
| Connection times out, HTTPS target that just answered | **Info**, low confidence, `http-port-unverified` | See below. |

**A silent port 80 is reported as a note when HTTPS just answered.** A firewall that
drops port 80 sends nothing back, so the connection times out. That site is safe. But
the worker's own network dropping outbound port 80 looks exactly the same, and in that
case this check has not really run. Calling it safe would hide that, and calling it
incomplete would make the whole scan `PARTIAL`, casting doubt on CORS results that came
back fine and teaching people to ignore `PARTIAL`.

So the doubt gets its own finding, `http-port-unverified`, which says what is unknown
and how to check. If one site shows it, that site's firewall is the likely reason. If
every site shows it, the scanner's network is. It only applies to a timeout while
connecting, on a host that answered over HTTPS moments earlier. Severity `info` carries
a weight of 0.05 in the risk engine, so it does not move a gate.

The cost is stated: a note does not stop anything, so someone has to read it. And since
the scanner still counts as complete, an open `http-served-plain` finding can be resolved
if the worker's network later starts blocking port 80, with this note as the only clue.

### 4. A check that cannot finish is not a pass

Other network failures must never read as clean (§13), so this adapter emits one
degradation, `probe_incomplete`, in the set ADR 010 defines. The constant lives in
the adapter rather than in `scanners`, because the type allows it.

- **One check gets no answer:** findings from the other are kept, and the result is
  degraded. A timeout after connecting, DNS failures, and certificate failures all
  count, and so does a refused connection when plain HTTP is itself the target.
  Certificate verification is never skipped, because that would report on whoever
  answered.
- **Neither check gets an answer:** the scanner fails, and stores nothing.
- **A redirect the CORS check cannot follow:** degraded unless the origin was accepted.
  Headers on a redirect describe the redirect, not the page behind it, so their
  absence proves nothing. A redirected preflight is different: a browser treats it as
  a refusal, so that is a real answer.
- **A redirect with no usable `Location`, or a 3xx that moves nobody:** degraded.
- **An error page that did not echo the origin:** degraded on a 404 or 410, which name
  nothing to check, and on a 408, 425, 429 or 5xx, which mean the service could not
  answer. A sleeping service or a bad deploy says nothing about what the real page would
  send, and neither does a fixed `*` that a proxy adds to every response. An echoed
  origin still counts, because something chose to send it. A preflight's 404 or 501 is a
  real answer, from a server with no OPTIONS handler.
  **What this cannot catch:** a holding page that answers 200 looks like a real page, and
  a 401 or 403 still reads as an answer, although login checks often run before CORS
  handling. Treating those as inconclusive would make protected routes `PARTIAL` on every
  scan, so that trade is the owner's to decide.
- **A status outside 200-599:** recorded as no answer, so it cannot drop a finding while
  the scan still counts as finished.

A degraded result keeps its findings and stops a finding being resolved by a scan that
could not tell, which `TestHTTPProbeThroughThePipeline` shows against a real database.
The scan as a whole is `PARTIAL`, or `FAILED` where nothing fully succeeded, which is
`TerminalStatus` as it already stands.

### 5. SSRF: enforced when connecting, and only same-site redirects

The target has passed `netguard` at the API, but DNS can change between validation and
connection, so:

- **Every connection goes through `netguard.Policy.ControlFunc`,** which checks the
  concrete address after DNS. That is the defence T-56 relies on. A refused address
  fails the scanner.
- **The deployment's `SECUREOPS_ALLOW_PRIVATE_TARGETS` is honoured.** The policy comes
  from `config.ScannerSettings`, which now carries it, and defaults to strict. Cloud
  metadata stays refused whatever it says.
- **The CORS check follows at most three redirects, by its own decision at each hop.**
  Most sites redirect `example.com` to `www.example.com`, and stopping there would
  leave them unanswered. A hop is allowed only to the same host or its `www.` variant,
  and never from HTTPS down to HTTP. A subdomain is not the same site. Each hop is a new
  connection through the same control, so a target cannot steer the worker off its own
  host. The HTTP client itself follows nothing.
- **The plain-HTTP check follows nothing.** The first hop is the whole answer.
- **The environment's proxy settings are ignored.** A proxy would make the connection,
  and the address policy would only ever see the proxy.

### 6. The adapter holds and sends no credentials

Credentials typed into a target URL (`https://user:pass@host`) are removed, because Go
would otherwise turn them into an `Authorization` header (§14.7). For an HTTPS target, the
plain-HTTP request also drops the target's path and query, because either can carry a token
and sending them unencrypted would create the very exposure being looked for. For an
`http://` target it drops the query and keeps the path, since that is the address given.
The HTTPS request keeps both, since the endpoint may need them and they are encrypted.

### 7. Raw output is a record the adapter writes itself

§8 requires raw output to be stored and re-parsable, and there is no tool output to
store. So `Scan` writes a small JSON record of what it asked and what came back, and
`parser.go` reads it back through the same validation as anything else, because scanner
output is untrusted even when the scanner is ours (§15.7).

The record holds **classifications, never values**: `reflected` rather than the header,
`https` rather than the `Location`, `timeout` rather than Go's error text (which contains
the URL). It holds no host, which is also why the lookalike origin is recorded only as
a kind. Response bodies are never read. So ADR 026's redaction has nothing to rewrite
here: what is never stored cannot leak, and a test plants a token in every place a target
could put one and asserts none of it is stored.

### 8. Identity

ADR 026's rule, unchanged: category `dast`, the rule id, and the URL path of the target
that was asked for, without origin or query. Preview hostnames churn, and queries are
where credentials live. No new fingerprint field.

### 9. Version

There is no binary to ask, and §7 rule 6 still ties every result to what produced it. So
`Version` is a constant in the adapter, bumped when what the checks send or conclude
changes. A finding can then be traced to the logic that made it.

## Alternatives considered

**Wrapping an existing tool.** `deploy-checkup`, a Python CLI that does these checks,
prompted this work. §25 forbids adding Python without a documented requirement, and a
status and a few headers is no such requirement.

**ZAP scripts or an active rule.** ZAP can send custom headers, but through scripting
add-ons or active rules. The image deliberately leaves `ascanrules` out (T-52), and
bringing in machinery for attack traffic to send one header runs against that control.

**Never following redirects.** The first draft of this ADR. Simpler, and it left every
apex-to-www site `PARTIAL`, which is too many to be useful.

**Letting the HTTP client follow redirects.** Would hand the decision to a default
policy that does not know what a site is. Following them one at a time keeps that
decision in one tested function.

**Treating every port 80 timeout as incomplete.** The first draft too, and the most
defensible against a false clean. It makes one correct firewall setup look broken forever,
and marks good results from the other check as incomplete along with it.

**Treating a silent port 80 as safe with nothing to show for it.** The second draft. It
removes the false alarm, and a deployment whose egress blocks port 80 would then report
every HTTPS site as fine, on every scan, without ever having checked.

**Rating a yes without credentials as Medium or as nothing.** Medium overstates what is
readable by anyone anyway. Nothing would hide a server whose logic is one setting from
the High row.

**Reporting `*` too.** It would duplicate ZAP's rule under a second identity, which §6
asks not to do.

**Adding `probe_incomplete` to `internal/scanners/scanner.go`,** beside the other reasons.
That is where the vocabulary has lived so far, and moving it there is a one-line change
if the owner prefers it.

## Consequences

**What becomes possible.** SecureOps can report the CORS mistakes that matter most,
whether an endpoint's plain address is safe, and do so on the sites where a redirect or
a firewall would otherwise have left it silent.

**What becomes harder.** An endpoint scan has one more scanner that can make it `PARTIAL`,
though for a stated reason: a real network failure, a broken certificate, a redirect to
another site, an error page at the target, or a service that is not ready. Each can be resolved
by fixing it, by scanning the final URL, or by waking the service first. ZAP also fails when its
starting URL returns 404, so scanning such a URL ends as `FAILED`, because nothing fully succeeded.

**What is not solved, stated plainly:**

- **Resolving depends on rescanning the same URL.** It checks one URL per scan, so a finding
  closes only when that URL is scanned again. ADR 042 made this so, in place of a clean scan
  of any URL in the project closing it.
- **The Kubernetes scan pod still cannot reach a private target.** ADR 039's network policy
  excludes private ranges from the pod's egress, for ZAP as well, whatever this setting
  says. Widening that is a Kubernetes privilege change (§24), so `LoadScanJob` leaves the
  setting at its strict default and the scan fails fast rather than timing out. In the
  in-process worker, which is the default, the setting works.
- **A lookalike only catches a check on how the origin starts.** A server that checks how it
  ends (`evilexample.com`) would need an origin on a real domain, which this adapter will
  not invent. And the application's own frontend is unknown: `Target` holds one
  `EndpointURL`, so "is my own site allowed?" cannot be asked, and an over-broad list such as
  `*.example.com` is not found.
- **It is unauthenticated,** like all DAST here (ADR 026). The High rating says what could be
  read, not what was.
- **One path per scan.** It checks the URL it is given and does not crawl.
- **A subdomain redirect is not followed,** even from a company's own `example.com` to
  `app.example.com`. Telling those apart from another party's subdomain needs a public suffix
  list, so it reads as incomplete. The answer is to scan the final URL.
