# httpprobe fixtures

This adapter has no external binary, so "captured output" means what its own
`Scan` writes. `reflected-credentials.json` is held equal to real output by
`TestFixtureMatchesRealOutput`; the others follow the same format, written by
hand. No third-party host was contacted to produce any of them, and the
`NOTAREAL*` value is synthetic.

| Fixture | What it is |
|---|---|
| `reflected-credentials.json` | Every origin trusted with credentials allowed, and a page served over plain HTTP. |
| `reflected-temporary-redirect.json` | Every origin trusted without credentials, and a 302 to HTTPS. |
| `clean.json` | No CORS header on any question, and a 301 to HTTPS. Distinct from a failed scan. |
| `wildcard.json` | `*` with credentials requested. Recorded, not reported: ZAP covers it, and browsers refuse it. |
| `lookalike-and-null.json` | A server that rejects an unknown origin but trusts a lookalike domain and `null`. |
| `preflight-only.json` | A server that only says it trusts an origin when asked by preflight. |
| `plain-refused.json` | Nothing listening on port 80. A safe answer, not a failure. |
| `plain-filtered.json` | Port 80 ignored while HTTPS answered. Produces a note saying what could not be confirmed, and leaves the scan complete. |
| `cors-failed.json` | One check failed and the other found something. The finding survives. |
| `root-path.json` | The site root, which normalizes to nothing and has to stay readable. |
| `hostile.json` | Written to attack the mapper: traversal in the path and markup where a classification belongs. |
| `no-base-probe.json` | A record that never asked the first question, which must not read as clean. |
| `failed-with-answer.json` | A record claiming a request both failed and was answered. Neither half may become a finding. |
| `path-with-query.json` | A credential in the stored path, which this adapter can never write. Refused. |
| `unknown-schema.json` | A record format this version does not understand. |
| `wrong-tool.json` | Valid JSON from something else. |
| `truncated.json` | Cut mid-object, as a size cap or killed process would leave it. |
| `malformed.json` | Structurally broken JSON. |
| `empty.json` | No output. Distinct from `clean.json`. |
