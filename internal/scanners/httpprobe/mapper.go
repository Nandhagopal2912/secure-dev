package httpprobe

import (
	"fmt"
	"net/http"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// rule is one thing this adapter can report. Its ID is the identity a finding
// keeps across scans, so changing one is a re-fingerprinting event (ADR 026).
type rule struct {
	id          string
	title       string
	description string
	remediation string
	cwe         string
	severity    normalization.Severity
	confidence  normalization.Confidence
	reference   string
}

const (
	cweCORS      = "CWE-942"
	cweCleartext = "CWE-319"

	refCORS      = "https://cwe.mitre.org/data/definitions/942.html"
	refCleartext = "https://cwe.mitre.org/data/definitions/319.html"

	fixCORS = "Compare the Origin header against a fixed list of trusted origins, and " +
		"send Access-Control-Allow-Origin only for an exact match."
	fixRedirect = "Redirect plain HTTP to HTTPS with a permanent redirect (301 or 308)."

	withCookies = " and also sent Access-Control-Allow-Credentials: true. A page there can " +
		"make a visitor's browser send this request with their cookies and read the response."
	withoutCookies = " Without Access-Control-Allow-Credentials a browser will not attach " +
		"cookies, so such a page can read only what an anonymous visitor could."
)

// corsRule builds one of the CORS rules, which differ only in what was trusted.
func corsRule(id, title, description string, severity normalization.Severity) rule {
	return rule{
		id:          id,
		title:       title,
		description: description,
		remediation: fixCORS,
		cwe:         cweCORS,
		severity:    severity,
		confidence:  normalization.ConfidenceHigh,
		reference:   refCORS,
	}
}

var (
	ruleReflectedWithCredentials = corsRule(
		"cors-reflected-origin-credentials",
		"CORS trusts any origin and allows credentials",
		"The endpoint accepted an origin it could not have been configured to trust,"+withCookies,
		normalization.SeverityHigh)
	ruleReflected = corsRule(
		"cors-reflected-origin",
		"CORS trusts any origin",
		"The endpoint accepted an origin it could not have been configured to trust."+withoutCookies,
		normalization.SeverityLow)
	ruleLookalikeWithCredentials = corsRule(
		"cors-lookalike-origin-credentials",
		"CORS trusts a lookalike domain and allows credentials",
		"The endpoint accepted a domain that only starts with its own host name,"+withCookies,
		normalization.SeverityHigh)
	ruleLookalike = corsRule(
		"cors-lookalike-origin",
		"CORS trusts a lookalike domain",
		"The endpoint accepted a domain that only starts with its own host name."+withoutCookies,
		normalization.SeverityLow)
	ruleNullWithCredentials = corsRule(
		"cors-null-origin-credentials",
		"CORS trusts the null origin and allows credentials",
		"The endpoint accepted Origin: null, which any page can send from a sandboxed iframe,"+withCookies,
		normalization.SeverityHigh)
	ruleNull = corsRule(
		"cors-null-origin",
		"CORS trusts the null origin",
		"The endpoint accepted Origin: null, which any page can send from a sandboxed iframe."+withoutCookies,
		normalization.SeverityLow)

	rulePlainServed = rule{
		id:    "http-served-plain",
		title: "Page is served over plain HTTP",
		description: "A successful response came back over unencrypted HTTP with no redirect to " +
			"HTTPS, so anyone on the network path can read or change it.",
		remediation: fixRedirect,
		cwe:         cweCleartext,
		severity:    normalization.SeverityMedium,
		confidence:  normalization.ConfidenceHigh,
		reference:   refCleartext,
	}
	rulePlainError = rule{
		id:    "http-error-plain",
		title: "Plain HTTP answers with an error instead of redirecting",
		description: "An error response came back over unencrypted HTTP with no redirect to HTTPS. " +
			"Something is listening on the plain address, but whether it serves real content " +
			"could not be determined from this response.",
		remediation: fixRedirect,
		cwe:         cweCleartext,
		severity:    normalization.SeverityLow,
		confidence:  normalization.ConfidenceLow,
		reference:   refCleartext,
	}
	// A note rather than a problem. A silent port 80 is safe if the site's firewall
	// dropped the connection and unknown if the scanner's own network did, and this
	// adapter cannot tell which. Marking the whole scan PARTIAL for it would also
	// cast doubt on CORS results that came back fine, so the doubt is stated here
	// instead (ADR 041).
	rulePortUnverified = rule{
		id:    "http-port-unverified",
		title: "Plain HTTP could not be checked",
		description: "HTTPS answered but port 80 did not. If only this site shows this, its firewall " +
			"is probably blocking port 80, which is safe. If every site shows it, the scanner's own " +
			"network is probably blocking port 80, and this check has not really run.",
		remediation: "To confirm, run curl -I http://<host> from another network. If every site " +
			"shows this, allow outbound port 80 for the scanner and scan again.",
		cwe:        cweCleartext,
		severity:   normalization.SeverityInfo,
		confidence: normalization.ConfidenceLow,
		reference:  refCleartext,
	}
	ruleRedirectTemporary = rule{
		id:    "http-redirect-temporary",
		title: "Plain HTTP redirects to HTTPS only temporarily",
		description: "The redirect to HTTPS uses a temporary status, so browsers and search engines " +
			"keep going back to the plain address first.",
		remediation: fixRedirect,
		cwe:         cweCleartext,
		severity:    normalization.SeverityLow,
		confidence:  normalization.ConfidenceHigh,
		reference:   refCleartext,
	}
	ruleRedirectPlain = rule{
		id:    "http-redirect-stays-plain",
		title: "Plain HTTP redirects to another plain HTTP address",
		description: "The first redirect stays on unencrypted HTTP. A later hop might reach HTTPS, " +
			"but this check follows no redirects, so that could not be established.",
		remediation: fixRedirect,
		cwe:         cweCleartext,
		severity:    normalization.SeverityLow,
		confidence:  normalization.ConfidenceLow,
		reference:   refCleartext,
	}
)

// Normalize converts this adapter's stored record into canonical findings.
//
// Pure: bytes in, findings out, no I/O (§8).
func Normalize(data []byte, scanID string) (normalization.Result, error) {
	rec, err := parseRecord(data)
	if err != nil {
		return normalization.Result{}, err
	}

	path := normalization.NormalizeLocation(rec.Path)
	if path == "" {
		// The site root normalizes to nothing, so it is spelled out to stay
		// readable. Same convention as the ZAP adapter.
		path = "/"
	}

	out := normalization.Result{}
	if err := rec.CORS.validate(); err != nil {
		out.Errors = append(out.Errors, "cors: "+err.Error())
	} else {
		for _, r := range corsFindings(rec.CORS) {
			appendFinding(&out, r, path, scanID)
		}
	}
	if err := rec.Redirect.validate(); err != nil {
		out.Errors = append(out.Errors, "https_redirect: "+err.Error())
	} else if r, found := redirectFinding(rec.Redirect); found {
		if rec.Redirect.OtherPort {
			r.confidence = normalization.ConfidenceLow
		}
		appendFinding(&out, r, path, scanID)
	}
	return out, nil
}

// corsFindings decides what the CORS observation means.
//
// A server that trusts any origin on a real request also trusts a lookalike and
// null, and that is one mistake rather than three, so nothing further is reported
// for it. A preflight alone proves less, so it does not stop the other questions
// from reporting, which may be worse.
//
// `*` is deliberately not reported. ZAP's passive rule 10098 already does, and
// browsers refuse to send credentials to it (ADR 041).
func corsFindings(c corsObservation) []rule {
	base, _ := c.base()
	preflight, _ := c.probe(kindPreflight)

	baseTrusts := base.AllowOrigin == allowOriginReflected
	preflightTrusts := preflight.AllowOrigin == allowOriginReflected
	var out []rule
	if baseTrusts || preflightTrusts {
		credentials := (baseTrusts && base.AllowCredentials) || (preflightTrusts && preflight.AllowCredentials)
		r := ruleReflected
		if credentials {
			r = ruleReflectedWithCredentials
		}
		// The preflight alone says the request may be sent, not that its answer
		// may be read, so it is reported with less confidence.
		if !baseTrusts {
			r.confidence = normalization.ConfidenceMedium
		}
		out = append(out, r)
	}
	if baseTrusts {
		return out
	}

	if lookalike, ok := c.probe(kindLookalikeOrigin); ok && lookalike.AllowOrigin == allowOriginReflected {
		if lookalike.AllowCredentials {
			out = append(out, ruleLookalikeWithCredentials)
		} else {
			out = append(out, ruleLookalike)
		}
	}
	if null, ok := c.probe(kindNullOrigin); ok && null.AllowOrigin == allowOriginReflected {
		if null.AllowCredentials {
			out = append(out, ruleNullWithCredentials)
		} else {
			out = append(out, ruleNull)
		}
	}
	return out
}

// redirectFinding decides what the plain-HTTP observation means.
func redirectFinding(r redirectObservation) (rule, bool) {
	switch {
	case r.Failure == failureFiltered:
		return rulePortUnverified, true
	case r.Failure != "":
		return rule{}, false
	case isNotReady(r.Status):
		return rule{}, false
	case r.Status >= 400:
		return rulePlainError, true
	case !isRedirect(r.Status):
		return rulePlainServed, true
	case !isFollowableRedirect(r.Status):
		return rule{}, false
	case r.LocationScheme == locationHTTP:
		return ruleRedirectPlain, true
	case r.LocationScheme != locationHTTPS:
		return rule{}, false
	case r.Status == http.StatusMovedPermanently, r.Status == http.StatusPermanentRedirect:
		return rule{}, false
	default:
		return ruleRedirectTemporary, true
	}
}

func appendFinding(out *normalization.Result, r rule, path, scanID string) {
	fingerprint, err := normalization.Fingerprint(normalization.FingerprintInput{
		Category: scanners.CategoryDAST,
		RuleID:   r.id,
		Location: path,
	})
	if err != nil {
		out.Errors = append(out.Errors, fmt.Sprintf("%s: %v", r.id, err))
		return
	}

	finding := normalization.Finding{
		Fingerprint:      fingerprint,
		Scanner:          Name,
		ScannerFindingID: r.id,
		ScannerSeverity:  string(r.severity),
		Category:         scanners.CategoryDAST,
		Severity:         r.severity,
		Confidence:       r.confidence,
		Title:            r.title,
		Description:      r.description,
		Remediation:      r.remediation,
		Endpoint:         "GET " + path,
		CWE:              r.cwe,
		Fix:              normalization.Fix{References: []string{r.reference}},
		Status:           normalization.StatusOpen,
	}
	if err := finding.Validate(); err != nil {
		out.Errors = append(out.Errors, fmt.Sprintf("%s: %v", r.id, err))
		return
	}

	out.Findings = append(out.Findings, finding)
	out.Occurrences = append(out.Occurrences, normalization.Occurrence{
		Fingerprint: fingerprint,
		ScanID:      scanID,
		File:        path,
		Scanner:     Name,
	})
}

// Normalize implements normalization.Normalizer, so the worker can normalize
// this adapter's output without knowing which adapter it is (§7 rule 2).
func (s *Scanner) Normalize(raw []byte, scanID string) (normalization.Result, error) {
	return Normalize(raw, scanID)
}
