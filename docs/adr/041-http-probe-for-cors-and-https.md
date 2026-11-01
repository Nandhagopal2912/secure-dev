# ADR 041: An HTTP probe for what passive DAST cannot see

- **Status:** Proposed
- **Date:** 2026-11-01

## Context

ZAP is the only adapter that looks at a running application, and it runs in
passive mode (ADR 026). Passive rules read the traffic the spider generates, and
the spider never sends a made-up `Origin` header. So one common and serious
misconfiguration is invisible to SecureOps: a server that copies whatever
`Origin` it receives into `Access-Control-Allow-Origin`, and also sends
`Access-Control-Allow-Credentials: true`. Any website can then make a visitor's
browser call that server with their cookies and read the answer. ZAP's rule
10098 sees a literal `*`, but a server that only reflects when asked looks fine
until somebody asks.

The same scan also never asks what happens at the `http://` address of an HTTPS
site. A site can have flawless HTTPS and still serve its pages unencrypted on
port 80, or redirect there only temporarily.

Answering both takes a status code and two headers. Neither needs a new binary.

## Decision

Add an adapter, `internal/scanners/httpprobe`, written in Go, serving
`KindEndpoint` and `CategoryDAST`, and declaring egress for `KindEndpoint`. It
makes exactly two requests, both plain `GET`s, and runs alongside ZAP. Adding it
changes nothing outside its own folder, its fixtures, and one registration in
`internal/scanners/all` (§7 rule 4).

### 1. Why this stays inside ADR 026

ADR 026 rules out active scanning because attack payloads change state, are
attack traffic, and need an authorization model that does not exist. This adapter
sends no payloads. Each request is one a browser could make: a browser sends
`Origin` on cross-site requests, and anyone can type an `http://` address. It
needs no authorization model, for the same reason ZAP's spider does not.

The line is the point, so it is stated: **exposed-file probing and rate-limit
spoofing are out of scope.** Asking for `/.env` or forging `X-Forwarded-For` is
probing for weakness rather than behaving like a visitor, and belongs to the
per-project authorization model ADR 026 defers. A test asserts what is sent.

### 2. The CORS check

Send `GET <endpoint>` with `Origin: https://secureops-probe.invalid`. `.invalid`
is reserved by RFC 2606 and can never resolve, so nobody can have configured it
as trusted: if it comes back, the server is echoing.

| `Access-Control-Allow-Origin` | Credentials | Result | Why |
|---|---|---|---|
| our origin | `true` | **High**, `cors-reflected-origin-credentials` | Any site can read this endpoint as the visitor. Not critical, because an unauthenticated scan cannot see what the endpoint returns to a signed-in user. |
| our origin | absent | **Low**, `cors-reflected-origin` | Browsers attach no cookies, so any site reads only what an anonymous visitor could. Worth fixing because it is usually one setting away from the row above. |
| `*` | any | no finding | ZAP's rule 10098 already reports it, in the `pscanrules` add-on the worker image installs. Browsers refuse credentials with `*`, so asking for both achieves nothing. Recorded in the output. |
| `null` or another fixed value | any | no finding | Not reflection. Recorded in the output as a classification. |
| absent | any | no finding | The expected result. |

### 3. The HTTPS redirect check

Send `GET` to the plain address. For an `https://` target that is port 80 of the
same host, whatever port the target itself uses, because that is where a browser
goes for `http://host`. For an `http://` target it is the target itself, so an
HTTP-only endpoint needs no special path: it simply reports what it serves.

| Answer | Result | Why |
|---|---|---|
| 301 or 308 to `https:` | no finding | Correct. |
| 302, 303, or 307 to `https:` | **Low**, `http-redirect-temporary` | It does upgrade, but browsers keep returning to the plain address first. |
| Redirect to `http:` or a relative path | **Low**, low confidence, `http-redirect-stays-plain` | A later hop may reach HTTPS. Redirects are not followed, so this cannot be known. |
| 2xx | **Medium**, `http-served-plain` | A page is readable and changeable on the network path. |
| 4xx or 5xx | **Low**, low confidence, `http-error-plain` | Something is listening, but nothing shows it serves real content. |
| Connection refused, HTTPS target | no finding | Nothing is listening, which is safer than any redirect. |

The remediation text and rules are this adapter's own, and each finding references
its CWE: 942 for CORS and 319 for cleartext.

### 4. A check that cannot finish is not a pass

A network failure must never read as clean (§13), so this adapter emits one
degradation, `probe_incomplete`, in the set ADR 010 defines. The constant lives in
the adapter rather than in `scanners`, because the type allows it and §7 rule 4
asks for no change outside the folder.

- **One check gets no answer:** findings from the other are kept, and the result
  is degraded. Timeouts, DNS failures, and certificate failures all count, and so
  does a refused connection when plain HTTP is itself the target. Certificate
  verification is never skipped, because that would report on whoever answered.
- **Neither check gets an answer:** the scan fails, and stores nothing.
- **The CORS request is answered with a redirect:** the result is degraded unless
  our origin was echoed. Headers on a redirect describe the redirect, not the page
  behind it, so their absence proves nothing. The way to get an answer is to scan
  the final URL.
- **A redirect with no usable `Location`, or a 3xx that moves nobody:** degraded.

A timeout on port 80 is degraded even though a firewall silently dropping port 80
is safe. It cannot be told apart from a network fault, and a false alarm is the
right way to be wrong here. This does mean a site like that scans as `PARTIAL`.

### 5. SSRF: enforced when connecting, and no redirects

The target has passed `netguard` at the API, but DNS can change between validation
and connection, so:

- **Every connection goes through `netguard.Policy.ControlFunc`,** which checks the
  concrete address after DNS. That is the defence T-56 relies on, and ZAP as a
  separate process cannot use it. A refused address fails the scan.
- **Redirects are never followed.** The first hop's status and `Location` scheme
  answer the question, so no `Location` ever becomes a request and a target cannot
  steer the worker anywhere.
- **The environment's proxy settings are ignored.** A proxy would make the
  connection, and the address policy would only ever see the proxy.

### 6. The adapter holds and sends no credentials

Credentials typed into a target URL (`https://user:pass@host`) are removed, because
Go would otherwise turn them into an `Authorization` header (§14.7). The plain-HTTP
request also drops the target's query string, the place applications carry
credentials, because sending it would create the very exposure being looked for.
The HTTPS request keeps it, since the endpoint may need it and it is encrypted.

### 7. Raw output is a record the adapter writes itself

§8 requires raw output to be stored and re-parsable, and there is no tool output to
store. So `Scan` writes a small JSON record of what it sent and what came back, and
`parser.go` reads it back through the same validation as anything else, because
scanner output is untrusted even when the scanner is ours (§15.7).

The record holds **classifications, never values**: `reflected` rather than the
header, `https` rather than the `Location`, `timeout` rather than Go's error text
(which contains the URL). Response bodies are never read. So ADR 026's redaction
has nothing to rewrite here: what is never stored cannot leak, and a test plants a
token in every place a target could put one and asserts none of it is stored.

### 8. Identity

ADR 026's rule, unchanged: category `dast`, the rule id, and the URL path, without
origin or query. Preview hostnames churn, and queries are where credentials live.
No new fingerprint field.

### 9. Version

There is no binary to ask, and §7 rule 6 still ties every result to what produced
it. So `Version` is a constant in the adapter, bumped when what the checks send or
conclude changes. A finding can then be traced to the logic that made it.

## Alternatives considered

**Wrapping an existing tool.** `deploy-checkup`, a Python CLI that does these checks,
prompted this work. §25 forbids adding Python without a documented requirement, and
a status and two headers is no such requirement.

**ZAP scripts or an active rule.** ZAP can send custom headers, but through
scripting add-ons or active rules. The image deliberately leaves `ascanrules` out
(T-52), and bringing in machinery for attack traffic to send one header runs against
that control.

**Following redirects.** Would resolve `http-redirect-stays-plain` and the CORS
redirect case, but makes every `Location` a request the target chooses, with a
re-check needed at each hop. Reading the first hop is simpler and cannot be steered.

**Rating an echo without credentials as Medium or as nothing.** Medium overstates
what is readable by anyone anyway. Nothing would hide a server whose logic is one
setting from the High row.

**Reporting `*` too.** It would duplicate ZAP's rule under a second identity, which
§6 asks not to do.

**Adding `probe_incomplete` to `internal/scanners/scanner.go`,** beside the other
reasons. That is where the vocabulary has lived so far, and moving it there is a
one-line change if the owner prefers it.

## Consequences

**What becomes possible.** SecureOps can report the CORS misconfiguration that
matters most, and whether an endpoint's plain address is safe.

**What becomes harder.** An endpoint scan has one more scanner that can make it
`PARTIAL`: a target behind a redirect, or one whose port 80 silently drops traffic.
Each says why, and can be resolved by scanning the final URL or by accepting it.

**What is not solved, stated plainly:**

- **Private targets are refused, even with `SECUREOPS_ALLOW_PRIVATE_TARGETS=true`.**
  `config.ScannerSettings` does not carry that setting, so the adapter uses the
  strictest policy, and a private target's scan is `PARTIAL` because this scanner
  failed. It fails safe. Honouring the setting means changing `internal/config` and
  the scan Job's environment, which is more than §7 rule 4 allows, so **it is a
  question for the project owner rather than something this change decides.**
- **Trusted origins cannot be checked.** `Target` holds one `EndpointURL`, so the
  adapter does not know the application's own frontend and cannot ask "is my own
  site allowed?". Only reflection of an unknown origin is tested, so an over-broad
  allow-list (`*.example.com`, or a `null` origin) is not found.
- **Only `GET` is asked.** A server that answers CORS only on a preflight `OPTIONS`
  shows nothing here, and reads as no finding.
- **It is unauthenticated,** like all DAST here (ADR 026). The High rating says what
  could be read, not what was.
- **One path per scan.** It checks the URL it is given and does not crawl.
