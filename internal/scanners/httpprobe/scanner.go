// Package httpprobe checks a live endpoint for two things ZAP's passive rules
// cannot see: whether it trusts an Origin it should not, and whether its
// plain-HTTP address sends visitors to HTTPS.
//
// Everything specific to these checks lives here and nowhere else (CLAUDE.md
// §7). It is the one adapter with no external binary: the requests are ordinary
// Go HTTP, because the only thing either check needs is a status and a few
// headers. See ADR 041.
//
// Every request is one a browser could have made. There are no attack payloads,
// which is why this fits inside ADR 026 rather than needing the authorization
// model that active scanning would.
package httpprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/aizen299/secure-dev/internal/netguard"
	"github.com/aizen299/secure-dev/internal/scanners"
)

const (
	// Name is the adapter's stable identifier.
	Name = "httpprobe"

	// Version identifies this adapter's checks. There is no binary to ask, and
	// §7 rule 6 still wants results tied to the logic that produced them, so
	// this changes whenever what the checks send or conclude changes.
	Version = "1.0.0"

	// probeDomain is reserved by RFC 2606 and can never resolve, so nobody can
	// have configured an origin on it as trusted. If a server says it trusts
	// one, its check of the Origin header is what is wrong.
	probeDomain = "secureops-probe.invalid"

	// probeOrigin asks whether the server trusts any origin at all.
	probeOrigin = "https://" + probeDomain

	// nullOrigin is what a browser sends from a sandboxed iframe, which any
	// page can create.
	nullOrigin = "null"

	userAgent = "SecureOps-httpprobe/" + Version

	// DefaultTimeout bounds one request.
	DefaultTimeout = 15 * time.Second

	// maxRedirects bounds how far the CORS check follows a same-site redirect.
	maxRedirects = 3

	// maxHeaderBytes bounds what a hostile server can make us hold. Bodies are
	// never read at all.
	maxHeaderBytes = 64 << 10

	// maxEndpointLength matches the column that stores the target.
	maxEndpointLength = 2000
)

// DegradedProbeIncomplete means a check could not reach a conclusion, so its
// silence must not be read as a pass (ADR 010).
//
// Declared here rather than in the scanners package so that adding this adapter
// changes nothing it does not have to (§7 rule 4).
const DegradedProbeIncomplete scanners.Degradation = "probe_incomplete"

var (
	// ErrBlockedTarget means the address policy refused the connection. Nothing
	// was sent to that address, and nothing is stored.
	ErrBlockedTarget = errors.New("httpprobe: target address is not permitted")
	// ErrUnreachable means neither check got an answer, which is a failed scan
	// rather than a clean one (§13).
	ErrUnreachable = errors.New("httpprobe: target could not be reached")
)

// Scanner probes a live endpoint.
type Scanner struct {
	// Policy is enforced on every connection. The zero value is the strictest
	// one: no loopback, private, or link-local addresses.
	Policy netguard.Policy
	// Timeout bounds one request. Zero uses DefaultTimeout.
	Timeout time.Duration

	// plainPort replaces port 80 in the plain-HTTP check, because a test server
	// cannot listen there. Empty in production.
	plainPort string
	// tlsConfig lets a test trust its own certificate. Nil in production, which
	// means the system's roots with full verification.
	tlsConfig *tls.Config
}

// New returns a Scanner enforcing policy on every connection.
func New(policy netguard.Policy) *Scanner { return &Scanner{Policy: policy} }

// Name implements scanners.Scanner.
func (s *Scanner) Name() string { return Name }

// Capabilities implements scanners.Scanner.
func (s *Scanner) Capabilities() scanners.Capabilities {
	return scanners.Capabilities{
		Kinds:        []scanners.Kind{scanners.KindEndpoint},
		Categories:   []scanners.Category{scanners.CategoryDAST},
		NetworkKinds: []scanners.Kind{scanners.KindEndpoint},
	}
}

// Version implements scanners.Scanner.
func (s *Scanner) Version(context.Context) (string, error) { return Version, nil }

// Scan implements scanners.Scanner.
func (s *Scanner) Scan(ctx context.Context, target scanners.Target) (scanners.RawResult, error) {
	if target.Kind != scanners.KindEndpoint {
		return scanners.RawResult{Scanner: Name}, scanners.ErrUnsupportedTarget
	}
	// Re-checked rather than trusted: the worker is on the far side of a queue
	// from the validator.
	endpoint, err := parseEndpoint(target.EndpointURL)
	if err != nil {
		return scanners.RawResult{Scanner: Name}, err
	}

	started := time.Now()
	client := s.client()

	cors := s.checkCORS(ctx, client, endpoint)
	rec := record{
		Tool:     Name,
		Schema:   recordSchema,
		Path:     recordPath(endpoint),
		CORS:     cors,
		Redirect: s.checkRedirect(ctx, client, endpoint, cors.answered()),
	}

	raw := scanners.RawResult{
		Scanner:   Name,
		Version:   Version,
		Target:    target,
		Duration:  time.Since(started),
		StartedAt: started,
	}

	switch err := ctx.Err(); {
	case errors.Is(err, context.DeadlineExceeded):
		return raw, scanners.ErrExecTimeout
	case err != nil:
		return raw, err
	}
	if rec.CORS.blocked() || rec.Redirect.Failure == failureBlocked {
		return raw, fmt.Errorf("%w: %w", ErrBlockedTarget, netguard.ErrBlockedAddress)
	}
	if !rec.CORS.answered() && rec.Redirect.Failure != "" {
		return raw, ErrUnreachable
	}

	if rec.CORS.incomplete() || rec.Redirect.incomplete() {
		raw.Degrade(DegradedProbeIncomplete)
	}
	raw.Output, err = rec.encode()
	if err != nil {
		return raw, err
	}
	return raw, nil
}

// checkCORS asks the endpoint the questions a cross-site page would ask.
//
// The first question finds the page, following same-site redirects. The rest are
// only worth asking of a page that was reached.
func (s *Scanner) checkCORS(ctx context.Context, client *http.Client, endpoint *url.URL) corsObservation {
	base, page, hops := s.findPage(ctx, client, endpoint)
	obs := corsObservation{RedirectsFollowed: hops, Probes: []corsProbe{base}}
	if base.Failure != "" || isRedirect(base.Status) {
		return obs
	}

	obs.Probes = append(obs.Probes, s.probe(ctx, client, http.MethodOptions, page, kindPreflight, probeOrigin))
	// A server that trusts any origin also trusts these two, and that is one
	// mistake. Asking a live site again would change no finding.
	if base.AllowOrigin == allowOriginReflected {
		return obs
	}
	if origin, ok := lookalikeOrigin(page); ok {
		obs.Probes = append(obs.Probes, s.probe(ctx, client, http.MethodGet, page, kindLookalikeOrigin, origin))
	}
	obs.Probes = append(obs.Probes, s.probe(ctx, client, http.MethodGet, page, kindNullOrigin, nullOrigin))
	return obs
}

// findPage asks the first question, following redirects that stay on the site.
//
// A redirect's headers describe the redirect rather than the page, so stopping
// at the first one would leave most apex-to-www sites unanswered. Each hop is a
// new connection through the same address policy, and nextHop refuses to leave
// the site, so a target cannot use this to reach anything else (ADR 041).
func (s *Scanner) findPage(ctx context.Context, client *http.Client, endpoint *url.URL) (corsProbe, *url.URL, int) {
	current := endpoint
	for hops := 0; ; hops++ {
		probe, location := s.ask(ctx, client, http.MethodGet, current, kindUnknownOrigin, probeOrigin)
		if probe.Failure != "" || probe.AllowOrigin == allowOriginReflected ||
			!isFollowableRedirect(probe.Status) || hops == maxRedirects {
			return probe, current, hops
		}
		next, ok := nextHop(endpoint, current, location)
		if !ok {
			return probe, current, hops
		}
		current = next
	}
}

func (s *Scanner) probe(
	ctx context.Context, client *http.Client, method string, target *url.URL, kind, origin string,
) corsProbe {
	probe, _ := s.ask(ctx, client, method, target, kind, origin)
	return probe
}

// ask sends one CORS question and classifies the answer. The Location is
// returned for findPage to act on, and is never part of the probe.
func (s *Scanner) ask(
	ctx context.Context, client *http.Client, method string, target *url.URL, kind, origin string,
) (corsProbe, string) {
	probe := corsProbe{Kind: kind}

	status, header, err := s.send(ctx, client, method, target.String(), origin)
	if err != nil {
		probe.Failure = classifyFailure(err)
		return probe, ""
	}
	if !isFinalStatus(status) {
		probe.Failure = failureInvalidStatus
		return probe, ""
	}
	probe.Status = status
	probe.AllowOrigin = classifyAllowOrigin(header.Get("Access-Control-Allow-Origin"), origin)
	// Exact, because a browser accepts nothing else.
	probe.AllowCredentials = strings.TrimSpace(header.Get("Access-Control-Allow-Credentials")) == "true"
	return probe, header.Get("Location")
}

// nextHop works out where a redirect leads, and whether to go there. Only to
// the same site, as start defines it, and never from HTTPS down to plain HTTP.
func nextHop(start, current *url.URL, location string) (*url.URL, bool) {
	location = strings.TrimSpace(location)
	ref, err := url.Parse(location)
	if err != nil || location == "" {
		return nil, false
	}
	next := current.ResolveReference(ref)
	if next.Scheme != "http" && next.Scheme != "https" {
		return nil, false
	}
	if current.Scheme == "https" && next.Scheme == "http" {
		return nil, false
	}
	if !sameSite(start.Hostname(), next.Hostname()) {
		return nil, false
	}
	next.User = nil
	next.Fragment = ""
	return next, true
}

// sameSite reports whether two hosts are the same one, or differ only by the
// www. that apex-to-www redirects add or remove.
func sameSite(a, b string) bool {
	normalize := func(host string) string {
		return strings.TrimPrefix(strings.ToLower(host), "www.")
	}
	return a != "" && normalize(a) == normalize(b)
}

// lookalikeOrigin builds an origin that starts with the target's own host and
// is on a domain the target cannot own. A server that checks only how the Origin
// starts will accept it. An IPv6 host cannot be written as a domain name, so it
// has none.
func lookalikeOrigin(page *url.URL) (string, bool) {
	host := page.Hostname()
	if host == "" || strings.Contains(host, ":") {
		return "", false
	}
	return "https://" + host + "." + probeDomain, true
}

// checkRedirect asks what happens to a visitor who arrives over plain HTTP.
//
// The first hop is the whole answer, so this check follows nothing.
func (s *Scanner) checkRedirect(
	ctx context.Context, client *http.Client, endpoint *url.URL, httpsAnswered bool,
) redirectObservation {
	var obs redirectObservation

	status, header, err := s.send(ctx, client, http.MethodGet, s.plainURL(endpoint), "")
	if err != nil {
		obs.Failure = classifyFailure(err)
		switch {
		case endpoint.Scheme == "http" && obs.Failure == failureRefused:
			// A refused port proves there is no plain listener only when HTTPS
			// is the target. When plain HTTP IS the target, it is just down.
			obs.Failure = failureNetwork
		case endpoint.Scheme == "https" && httpsAnswered && obs.Failure == failureConnectTimeout:
			// The host just answered on HTTPS and ignored this port. Probably a
			// firewall at the site, possibly the scanner's own network, so it
			// is reported as a note rather than as a pass (ADR 041).
			obs.Failure = failureFiltered
		}
		return obs
	}
	if !isFinalStatus(status) {
		obs.Failure = failureInvalidStatus
		return obs
	}
	obs.Status = status
	obs.LocationScheme = classifyLocation(header.Get("Location"))
	obs.OtherPort = servesFromOtherPort(endpoint)
	return obs
}

// servesFromOtherPort reports whether the plain-HTTP answer may come from a
// different service than the target: an HTTPS target on a custom port says
// nothing about what owns port 80 of its host.
func servesFromOtherPort(endpoint *url.URL) bool {
	port := endpoint.Port()
	return endpoint.Scheme == "https" && port != "" && port != "443"
}

// plainURL is the address a visitor reaches by typing http://.
//
// The query is dropped even though the target's own query is kept for the CORS
// check: it is where applications carry credentials, and this request would
// send them unencrypted. For an HTTPS target the path goes too, because a path
// can carry a token just as a query can, and whether plain HTTP redirects is a
// question about the host. A probe must not cause the exposure it looks for.
func (s *Scanner) plainURL(endpoint *url.URL) string {
	plain := *endpoint
	plain.RawQuery = ""
	if endpoint.Scheme == "https" {
		plain.Scheme = "http"
		plain.Path = "/"
		plain.RawPath = ""
		plain.Host = hostForPort(endpoint.Hostname(), s.plainPort)
	}
	return plain.String()
}

func hostForPort(host, port string) string {
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// send makes one request and closes the response without reading its body. The
// body holds nothing either check needs, and what is never read cannot be
// stored (§15.3).
func (s *Scanner) send(
	ctx context.Context, client *http.Client, method, target, origin string,
) (int, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if method == http.MethodOptions {
		// What makes it a preflight. It names a method and sends nothing: no
		// POST is ever made.
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header, nil
}

// client builds an HTTP client that cannot be led somewhere it should not go.
func (s *Scanner) client() *http.Client {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	dialer := &net.Dialer{
		// Shorter than the request's own bound, so a silently dropped port
		// shows up as a connection timeout and not as a slow request.
		Timeout: timeout / 3,
		// Runs on the concrete address after DNS, so a name that resolved to a
		// public address at validation and a private one now is still refused.
		Control: s.Policy.ControlFunc(),
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// Nil rather than the environment's proxy: a proxy would make the
			// connection, and the address policy would only ever see the proxy.
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			TLSClientConfig:        s.tlsConfig,
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: maxHeaderBytes,
		},
		// The client follows nothing by itself. findPage decides each hop.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// parseEndpoint re-applies the validator's scheme rule and removes credentials
// from the URL, which Go would otherwise send as a Basic auth header. Workers
// hold no credentials (§14.7), including ones typed into a target.
func parseEndpoint(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > maxEndpointLength {
		return nil, errors.New("httpprobe: endpoint is not acceptable")
	}
	// The parse error quotes the URL, which may carry a credential, so it is
	// not passed on.
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("httpprobe: endpoint is not acceptable")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, errors.New("httpprobe: endpoint is not acceptable")
	}
	u.User = nil
	u.Fragment = ""
	return u, nil
}

// classifyAllowOrigin reduces the header to what it means. The value itself is
// never stored: the target chose it, so it could contain anything.
func classifyAllowOrigin(value, sent string) string {
	value = strings.TrimSpace(value)
	switch value {
	case "":
		return allowOriginAbsent
	case sent:
		return allowOriginReflected
	case "*":
		return allowOriginWildcard
	case nullOrigin:
		return allowOriginNull
	default:
		return allowOriginOther
	}
}

// classifyLocation keeps only the scheme of a redirect. The rest of a Location
// can hold a session token.
//
// A relative Location counts as plain, because it resolves against the plain
// HTTP request that received it.
func classifyLocation(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return locationNone
	}
	u, err := url.Parse(value)
	if err != nil {
		return locationOther
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return locationHTTPS
	case "http", "":
		return locationHTTP
	default:
		return locationOther
	}
}

// classifyFailure names why a request got no answer. Error text is not kept,
// because Go's includes the URL and a URL can carry a credential.
func classifyFailure(err error) string {
	var (
		dnsErr   *net.DNSError
		certErr  *tls.CertificateVerificationError
		hostErr  x509.HostnameError
		authErr  x509.UnknownAuthorityError
		recErr   tls.RecordHeaderError
		opErr    *net.OpError
		netError net.Error
	)
	switch {
	case errors.Is(err, netguard.ErrBlockedAddress):
		return failureBlocked
	case errors.Is(err, syscall.ECONNREFUSED):
		return failureRefused
	case errors.As(err, &certErr), errors.As(err, &hostErr),
		errors.As(err, &authErr), errors.As(err, &recErr):
		return failureTLS
	case errors.As(err, &dnsErr):
		return failureDNS
	case errors.As(err, &opErr) && opErr.Op == "dial" && opErr.Timeout():
		return failureConnectTimeout
	case errors.As(err, &netError) && netError.Timeout():
		return failureTimeout
	default:
		return failureNetwork
	}
}
