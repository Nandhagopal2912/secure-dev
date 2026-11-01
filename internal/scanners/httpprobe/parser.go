package httpprobe

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ErrMalformedRecord reports output that is not a usable record from this
// adapter. Stored output is reparsed later (§8), and scanner output is
// untrusted input even when the scanner is ours (§15.7).
var ErrMalformedRecord = errors.New("httpprobe did not produce a valid record")

const (
	// recordSchema changes when the record's meaning does.
	recordSchema = 1

	// maxRecordBytes bounds a parse (§15.8). A real record is under a kilobyte,
	// because the only unbounded thing in it is a capped path.
	maxRecordBytes = 16 << 10
)

// The values a record may hold. Each is a closed set, so nothing the target
// sent can reach storage as text.
const (
	kindUnknownOrigin   = "unknown_origin"
	kindPreflight       = "preflight"
	kindLookalikeOrigin = "lookalike_origin"
	kindNullOrigin      = "null_origin"

	allowOriginAbsent    = "absent"
	allowOriginReflected = "reflected"
	allowOriginWildcard  = "wildcard"
	allowOriginNull      = "null"
	allowOriginOther     = "other"

	locationNone  = "none"
	locationHTTPS = "https"
	locationHTTP  = "http"
	locationOther = "other"

	failureBlocked        = "blocked"
	failureRefused        = "refused"
	failureFiltered       = "filtered"
	failureDNS            = "dns"
	failureTLS            = "tls"
	failureConnectTimeout = "connect_timeout"
	failureTimeout        = "timeout"
	failureNetwork        = "network"
)

// record is what the adapter stores: what it sent and what came back, reduced
// to classifications. It holds no response body, no header value, no query
// string, and no host.
type record struct {
	Tool     string              `json:"tool"`
	Schema   int                 `json:"schema"`
	Path     string              `json:"path"`
	CORS     corsObservation     `json:"cors"`
	Redirect redirectObservation `json:"https_redirect"`
}

// corsObservation is the result of the CORS check: one entry per question
// asked, and how many same-site redirects it took to reach the page.
type corsObservation struct {
	RedirectsFollowed int         `json:"redirects_followed,omitempty"`
	Probes            []corsProbe `json:"probes"`
}

// corsProbe is one question put to the endpoint.
type corsProbe struct {
	Kind             string `json:"kind"`
	Failure          string `json:"failure,omitempty"`
	Status           int    `json:"status,omitempty"`
	AllowOrigin      string `json:"allow_origin,omitempty"`
	AllowCredentials bool   `json:"allow_credentials,omitempty"`
}

// redirectObservation is the result of the plain-HTTP check.
type redirectObservation struct {
	Failure        string `json:"failure,omitempty"`
	Status         int    `json:"status,omitempty"`
	LocationScheme string `json:"location_scheme,omitempty"`
	// OtherPort says the answer came from port 80 while the target is on another
	// port, so it may belong to a different service.
	OtherPort bool `json:"other_port,omitempty"`
}

// base is the first probe, the one the other three depend on.
func (c corsObservation) base() (corsProbe, bool) {
	return c.probe(kindUnknownOrigin)
}

func (c corsObservation) probe(kind string) (corsProbe, bool) {
	for _, p := range c.Probes {
		if p.Kind == kind {
			return p, true
		}
	}
	return corsProbe{}, false
}

// answered reports whether the endpoint replied to the first probe at all.
func (c corsObservation) answered() bool {
	base, ok := c.base()
	return ok && base.Failure == ""
}

// blocked reports whether the address policy refused any probe.
func (c corsObservation) blocked() bool {
	for _, p := range c.Probes {
		if p.Failure == failureBlocked {
			return true
		}
	}
	return false
}

// incomplete reports whether this check reached no conclusion.
func (c corsObservation) incomplete() bool {
	if len(c.Probes) == 0 {
		return true
	}
	for _, p := range c.Probes {
		if p.incomplete() {
			return true
		}
	}
	return false
}

// incomplete reports whether this probe reached no conclusion.
//
// A redirect is inconclusive unless it echoed the origin: headers on a redirect
// describe the redirect, not the page it leads to. A preflight is the exception,
// because a browser treats a redirected preflight as a refusal, so that answer
// is a real "no" (ADR 041).
func (p corsProbe) incomplete() bool {
	if p.Failure != "" {
		return true
	}
	return p.Kind != kindPreflight && isRedirect(p.Status) && p.AllowOrigin != allowOriginReflected
}

// incomplete reports whether this check reached no conclusion.
//
// Refused and filtered are conclusions: a visitor cannot get a page from a port
// that refuses them or ignores them. Every other failure might only be the
// network.
func (r redirectObservation) incomplete() bool {
	if r.Failure != "" {
		return r.Failure != failureRefused && r.Failure != failureFiltered
	}
	if !isRedirect(r.Status) {
		return false
	}
	if !isFollowableRedirect(r.Status) {
		return true
	}
	return r.LocationScheme != locationHTTPS && r.LocationScheme != locationHTTP
}

func isRedirect(status int) bool { return status >= 300 && status < 400 }

// isFollowableRedirect reports whether a browser would act on this status's
// Location. 300, 304, and the rest do not move a visitor anywhere.
func isFollowableRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

// recordPath is the part of the endpoint the record keeps. EscapedPath rather
// than Path: decoding would turn %3F into a real '?' and make a path look like
// it carried a query.
func recordPath(endpoint *url.URL) string {
	if p := endpoint.EscapedPath(); p != "" {
		return p
	}
	return "/"
}

func (r record) encode() ([]byte, error) {
	out, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("%w: could not serialise", ErrMalformedRecord)
	}
	return out, nil
}

// parseRecord reads stored output back.
//
// Error messages never quote the input. It came from a run against an untrusted
// application, and these messages end up in logs.
func parseRecord(data []byte) (record, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return record{}, fmt.Errorf("%w: output was empty", ErrMalformedRecord)
	}
	if len(data) > maxRecordBytes {
		return record{}, fmt.Errorf("%w: larger than %d bytes", ErrMalformedRecord, maxRecordBytes)
	}

	var r record
	if err := json.Unmarshal(data, &r); err != nil {
		return record{}, fmt.Errorf("%w: output is not valid JSON", ErrMalformedRecord)
	}
	if r.Tool != Name {
		return record{}, fmt.Errorf("%w: record is not from %s", ErrMalformedRecord, Name)
	}
	if r.Schema != recordSchema {
		return record{}, fmt.Errorf("%w: unknown schema", ErrMalformedRecord)
	}
	if !safePath(r.Path) {
		return record{}, fmt.Errorf("%w: unusable path", ErrMalformedRecord)
	}
	return r, nil
}

// safePath holds a stored path to what recordPath can produce. A query or
// fragment here means something other than this adapter wrote the record, and
// a query is where credentials live (ADR 026).
func safePath(p string) bool {
	if !strings.HasPrefix(p, "/") || len(p) > maxEndpointLength {
		return false
	}
	return !strings.ContainsFunc(p, func(r rune) bool {
		return r == '?' || r == '#' || r < 0x20 || r == 0x7f
	})
}

// validate reports the first problem with this observation: a probe outside its
// closed set, a repeated probe, or a missing first probe. A record with no first
// probe says nothing about CORS, and must not read as a clean one.
func (c corsObservation) validate() error {
	if _, ok := c.base(); !ok {
		return errors.New("no unknown_origin probe")
	}
	seen := map[string]bool{}
	for _, p := range c.Probes {
		if err := p.validate(); err != nil {
			return err
		}
		if seen[p.Kind] {
			return errors.New("repeated probe")
		}
		seen[p.Kind] = true
	}
	if c.RedirectsFollowed < 0 || c.RedirectsFollowed > maxRedirects {
		return errors.New("redirects_followed is out of range")
	}
	return nil
}

func (p corsProbe) validate() error {
	switch p.Kind {
	case kindUnknownOrigin, kindPreflight, kindLookalikeOrigin, kindNullOrigin:
	default:
		return errors.New("unknown probe kind")
	}
	if p.Failure != "" {
		// No answer means nothing to describe. A record claiming both did not
		// come from this adapter, and must not produce a finding.
		if p.Status != 0 || p.AllowOrigin != "" || p.AllowCredentials {
			return errors.New("failed probe carries an answer")
		}
		return validFailure(p.Failure)
	}
	if !validStatus(p.Status) {
		return errors.New("status is out of range")
	}
	switch p.AllowOrigin {
	case allowOriginAbsent, allowOriginReflected, allowOriginWildcard, allowOriginNull, allowOriginOther:
		return nil
	default:
		return errors.New("unknown allow_origin value")
	}
}

// validate reports the first thing in this observation outside its closed set.
func (r redirectObservation) validate() error {
	if r.Failure != "" {
		if r.Status != 0 || r.LocationScheme != "" {
			return errors.New("failed check carries an answer")
		}
		return validFailure(r.Failure)
	}
	if !validStatus(r.Status) {
		return errors.New("status is out of range")
	}
	switch r.LocationScheme {
	case locationNone, locationHTTPS, locationHTTP, locationOther:
		return nil
	default:
		return errors.New("unknown location_scheme value")
	}
}

func validFailure(f string) error {
	switch f {
	case failureBlocked, failureRefused, failureFiltered, failureDNS, failureTLS,
		failureConnectTimeout, failureTimeout, failureNetwork:
		return nil
	default:
		return errors.New("unknown failure value")
	}
}

func validStatus(status int) bool { return status >= 100 && status <= 599 }
