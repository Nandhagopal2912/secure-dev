package httpprobe

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aizen299/secure-dev/internal/netguard"
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// fakeToken is synthetic and word-shaped (§19). It stands in for a credential
// a target or its URL might carry.
const fakeToken = "NOTAREALTOKEN"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../../tests/fixtures/httpprobe", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// testScanner may reach loopback, which is where httptest servers listen. Only
// the address-policy tests below use the strict default.
func testScanner() *Scanner {
	return &Scanner{Policy: netguard.Policy{AllowPrivate: true}, Timeout: 2 * time.Second}
}

func endpointTarget(raw string) scanners.Target {
	return scanners.Target{Kind: scanners.KindEndpoint, EndpointURL: raw}
}

// splitByOrigin serves the CORS request and the plain request differently. Only
// the CORS request carries an Origin, so one server can play both parts.
func splitByOrigin(cors, plain http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			cors(w, r)
			return
		}
		plain(w, r)
	}
}

func redirectTo(status int, location string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", location)
		w.WriteHeader(status)
	}
}

func respond(status int, headers map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
	}
}

func ruleIDs(t *testing.T, raw scanners.RawResult) []string {
	t.Helper()
	got, err := Normalize(raw.Output, "scan-1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(got.Errors) != 0 {
		t.Errorf("errors on the adapter's own output: %v", got.Errors)
	}
	ids := []string{}
	for _, f := range got.Findings {
		ids = append(ids, f.ScannerFindingID)
	}
	slices.Sort(ids)
	return ids
}

func TestCapabilities(t *testing.T) {
	c := New(netguard.Policy{}).Capabilities()

	if !c.Supports(scanners.KindEndpoint) {
		t.Error("httpprobe must accept endpoint targets")
	}
	for _, k := range []scanners.Kind{scanners.KindFilesystem, scanners.KindImage, scanners.KindRepository} {
		if c.Supports(k) {
			t.Errorf("httpprobe must not claim %s targets", k)
		}
	}
	if !c.Covers(scanners.CategoryDAST) || len(c.Categories) != 1 {
		t.Errorf("categories = %v, want dast only", c.Categories)
	}
	if !c.NeedsNetwork(scanners.KindEndpoint) {
		t.Error("an endpoint scan must declare the egress it needs")
	}
}

// There is no binary to ask, and a result must still say what produced it
// (§7 rule 6).
func TestVersionIsReportedPerScan(t *testing.T) {
	srv := httptest.NewServer(respond(http.StatusOK, nil))
	defer srv.Close()

	raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if raw.Version != Version || raw.Version == "" {
		t.Errorf("version = %q, want %q", raw.Version, Version)
	}
	if got, _ := New(netguard.Policy{}).Version(context.Background()); got != Version {
		t.Errorf("Version() = %q, want %q", got, Version)
	}
}

func TestScanRejectsOtherTargets(t *testing.T) {
	_, err := New(netguard.Policy{}).Scan(context.Background(), scanners.Target{Kind: scanners.KindImage, Image: "alpine"})
	if !errors.Is(err, scanners.ErrUnsupportedTarget) {
		t.Errorf("err = %v, want ErrUnsupportedTarget", err)
	}

	for _, bad := range []string{"", "ftp://example.com", "file:///etc/passwd", "http://", "not a url"} {
		if _, err := New(netguard.Policy{}).Scan(context.Background(), endpointTarget(bad)); err == nil {
			t.Errorf("endpoint %q was accepted", bad)
		}
	}
}

func TestScanFindings(t *testing.T) {
	const reflected = probeOrigin
	safeRedirect := redirectTo(http.StatusMovedPermanently, "https://example.test/")

	cases := []struct {
		name     string
		cors     http.HandlerFunc
		plain    http.HandlerFunc
		want     []string
		degraded bool
	}{
		{
			name:  "nothing wrong",
			cors:  respond(http.StatusOK, nil),
			plain: safeRedirect,
			want:  []string{},
		},
		{
			name: "echo with credentials",
			cors: respond(http.StatusOK, map[string]string{
				"Access-Control-Allow-Origin": reflected, "Access-Control-Allow-Credentials": "true",
			}),
			plain: safeRedirect,
			want:  []string{"cors-reflected-origin-credentials"},
		},
		{
			name:  "echo without credentials",
			cors:  respond(http.StatusOK, map[string]string{"Access-Control-Allow-Origin": reflected}),
			plain: safeRedirect,
			want:  []string{"cors-reflected-origin"},
		},
		{
			// ZAP's rule 10098 reports this, and browsers refuse credentials
			// with `*` even when the server asks for them.
			name: "wildcard is left to zap",
			cors: respond(http.StatusOK, map[string]string{
				"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true",
			}),
			plain: safeRedirect,
			want:  []string{},
		},
		{
			name:  "a fixed trusted origin is correct behaviour",
			cors:  respond(http.StatusOK, map[string]string{"Access-Control-Allow-Origin": "https://app.example.test"}),
			plain: safeRedirect,
			want:  []string{},
		},
		{
			name:  "reflection on an error page still counts",
			cors:  respond(http.StatusUnauthorized, map[string]string{"Access-Control-Allow-Origin": reflected}),
			plain: safeRedirect,
			want:  []string{"cors-reflected-origin"},
		},
		{
			// The header describes the redirect, not the page behind it, so
			// its absence proves nothing.
			name:     "a redirect tells us nothing about cors",
			cors:     redirectTo(http.StatusFound, "https://www.example.test/"),
			plain:    safeRedirect,
			want:     []string{},
			degraded: true,
		},
		{
			name:  "308 is permanent",
			cors:  respond(http.StatusOK, nil),
			plain: redirectTo(http.StatusPermanentRedirect, "https://example.test/"),
			want:  []string{},
		},
		{
			name:  "302 is temporary",
			cors:  respond(http.StatusOK, nil),
			plain: redirectTo(http.StatusFound, "https://example.test/"),
			want:  []string{"http-redirect-temporary"},
		},
		{
			name:  "307 is temporary",
			cors:  respond(http.StatusOK, nil),
			plain: redirectTo(http.StatusTemporaryRedirect, "https://example.test/"),
			want:  []string{"http-redirect-temporary"},
		},
		{
			name:  "served over plain http",
			cors:  respond(http.StatusOK, nil),
			plain: respond(http.StatusOK, nil),
			want:  []string{"http-served-plain"},
		},
		{
			name:  "error over plain http",
			cors:  respond(http.StatusOK, nil),
			plain: respond(http.StatusNotFound, nil),
			want:  []string{"http-error-plain"},
		},
		{
			name:  "redirect that stays plain",
			cors:  respond(http.StatusOK, nil),
			plain: redirectTo(http.StatusMovedPermanently, "http://example.test/next"),
			want:  []string{"http-redirect-stays-plain"},
		},
		{
			name:  "relative redirect stays plain",
			cors:  respond(http.StatusOK, nil),
			plain: redirectTo(http.StatusMovedPermanently, "/next"),
			want:  []string{"http-redirect-stays-plain"},
		},
		{
			name:     "redirect with no location is not a pass",
			cors:     respond(http.StatusOK, nil),
			plain:    respond(http.StatusMovedPermanently, nil),
			want:     []string{},
			degraded: true,
		},
		{
			name:     "a status that does not redirect is not a pass",
			cors:     respond(http.StatusOK, nil),
			plain:    respond(http.StatusNotModified, nil),
			want:     []string{},
			degraded: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(splitByOrigin(tc.cors, tc.plain))
			defer srv.Close()

			raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL+"/api"))
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if got := ruleIDs(t, raw); !slices.Equal(got, tc.want) {
				t.Errorf("rules = %v, want %v", got, tc.want)
			}
			if raw.Degraded() != tc.degraded {
				t.Errorf("degradations = %v, want degraded=%v", raw.Degradations, tc.degraded)
			}
		})
	}
}

// What the checks actually send. Each is a request a browser could make, which
// is what keeps this adapter on the right side of ADR 026.
func TestRequestsLookLikeABrowsers(t *testing.T) {
	var mu sync.Mutex
	var origins, methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		origins = append(origins, r.Header.Get("Origin"))
		methods = append(methods, r.Method)
		for _, h := range []string{"Authorization", "Cookie", "X-Forwarded-For"} {
			if r.Header.Get(h) != "" {
				t.Errorf("request carried %s", h)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL)); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	wantMethods := []string{http.MethodGet, http.MethodOptions, http.MethodGet, http.MethodGet, http.MethodGet}
	if !slices.Equal(methods, wantMethods) {
		t.Errorf("methods = %v, want %v", methods, wantMethods)
	}
	wantOrigins := []string{probeOrigin, probeOrigin, "https://127.0.0.1." + probeDomain, nullOrigin, ""}
	if !slices.Equal(origins, wantOrigins) {
		t.Errorf("origins = %v, want %v", origins, wantOrigins)
	}
	if !strings.HasSuffix(probeOrigin, ".invalid") {
		t.Errorf("probe origin %q must be on the reserved .invalid domain", probeOrigin)
	}
}

// The probe must not create the exposure it looks for.
func TestCredentialsInTheTargetAreNotSent(t *testing.T) {
	var mu sync.Mutex
	var rawQueries []string
	var sawAuth atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		rawQueries = append(rawQueries, r.URL.RawQuery)
		if r.Header.Get("Authorization") != "" {
			sawAuth.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	u.User = url.UserPassword("someone", fakeToken)
	u.RawQuery = "api_key=" + fakeToken

	if _, err := testScanner().Scan(context.Background(), endpointTarget(u.String())); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if sawAuth.Load() {
		t.Error("credentials in the target URL became an Authorization header (§14.7)")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(rawQueries) != 5 || rawQueries[4] != "" {
		t.Errorf("queries = %v: the plain-HTTP request must not carry the target's query", rawQueries)
	}
}

// §15.3. The record is built from classifications, so this should be impossible
// by construction; the test makes sure it stays that way.
func TestNothingFromTheTargetIsStored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session="+fakeToken)
		w.Header().Set("Server", fakeToken)
		if r.Header.Get("Origin") != "" {
			w.Header().Set("Access-Control-Allow-Origin", "https://"+fakeToken+".example.test")
			_, _ = w.Write([]byte(fakeToken))
			return
		}
		w.Header().Set("Location", "https://example.test/next?token="+fakeToken)
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer srv.Close()

	raw, err := testScanner().Scan(context.Background(),
		endpointTarget(srv.URL+"/login?api_key="+fakeToken))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	host := strings.TrimPrefix(srv.URL, "http://")
	for _, leaked := range []string{fakeToken, "api_key", host} {
		if strings.Contains(string(raw.Output), leaked) {
			t.Errorf("stored output contains %q: %s", leaked, raw.Output)
		}
	}
}

// A redirect off the site is not followed, by either check. "localhost" reaches
// the same machine, so a request would land if one were made.
func TestRedirectsOffTheSiteAreNotFollowed(t *testing.T) {
	var internalHits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		internalHits.Add(1)
	}))
	defer internal.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(internal.URL, "http://"))

	srv := httptest.NewServer(redirectTo(http.StatusFound, "http://localhost:"+port+"/admin"))
	defer srv.Close()

	raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := internalHits.Load(); got != 0 {
		t.Errorf("the redirect's destination received %d requests, want 0", got)
	}
	if !raw.Degraded() {
		t.Error("a redirect the CORS check could not follow must not read as a pass")
	}
}

// The usual reason for a redirect. The question is asked of the page it reaches,
// and the finding keeps the target's path as its identity.
func TestCORSFollowsSameSiteRedirects(t *testing.T) {
	var plainHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Header.Get("Origin") == "":
			plainHits.Add(1)
			redirectTo(http.StatusMovedPermanently, "https://example.test/")(w, r)
		case r.URL.Path == "/start":
			redirectTo(http.StatusMovedPermanently, "/page")(w, r)
		default:
			w.Header().Set("Access-Control-Allow-Origin", probeOrigin)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL+"/start"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if raw.Degraded() {
		t.Errorf("degradations = %v, want none", raw.Degradations)
	}
	got, err := Normalize(raw.Output, "scan-1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(got.Findings) != 1 || got.Findings[0].ScannerFindingID != ruleReflected.id {
		t.Fatalf("findings = %+v, want one %s", got.Findings, ruleReflected.id)
	}
	if got.Findings[0].Endpoint != "GET start" {
		t.Errorf("endpoint = %q, want the target's own path", got.Findings[0].Endpoint)
	}
	// The plain-HTTP check stops at the first answer.
	if plainHits.Load() != 1 {
		t.Errorf("plain check made %d requests, want 1", plainHits.Load())
	}
}

// A target must not be able to keep the worker walking.
func TestRedirectLoopStopsAndDoesNotPass(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			hits.Add(1)
		}
		redirectTo(http.StatusFound, "/again")(w, r)
	}))
	defer srv.Close()

	raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := hits.Load(); got != maxRedirects+1 {
		t.Errorf("CORS requests = %d, want %d", got, maxRedirects+1)
	}
	if !raw.Degraded() {
		t.Error("a redirect loop must not read as a pass")
	}
}

// A missing route or a service still waking up says nothing about the real page,
// so no header on that response must not read as "this site trusts nobody".
func TestErrorPagesWithNoHeaderAreNotAPass(t *testing.T) {
	cases := []struct {
		status   int
		degraded bool
	}{
		{http.StatusOK, false},
		{http.StatusBadRequest, false},
		{http.StatusUnauthorized, false},
		{http.StatusForbidden, false},
		{http.StatusNotFound, true},
		{http.StatusGone, true},
		{http.StatusRequestTimeout, true},
		{http.StatusTooEarly, true},
		{http.StatusTooManyRequests, true},
		{http.StatusInternalServerError, true},
		{http.StatusNotImplemented, true},
		{http.StatusBadGateway, true},
		{http.StatusServiceUnavailable, true},
		{http.StatusGatewayTimeout, true},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := httptest.NewServer(splitByOrigin(respond(tc.status, nil), respond(http.StatusOK, nil)))
			defer srv.Close()

			raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL+"/api/account"))
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if raw.Degraded() != tc.degraded {
				t.Errorf("degradations = %v, want degraded=%v", raw.Degradations, tc.degraded)
			}
		})
	}
}

// A header on an error page is still an answer: something chose to send it.
func TestErrorPagesWithAHeaderStillCount(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(splitByOrigin(
				func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
					w.Header().Set("Access-Control-Allow-Credentials", "true")
					w.WriteHeader(status)
				},
				respond(http.StatusOK, nil),
			))
			defer srv.Close()

			raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL+"/api/account"))
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if raw.Degraded() {
				t.Errorf("degradations = %v, want none", raw.Degradations)
			}
			got, err := Normalize(raw.Output, "scan-1")
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			if !slices.ContainsFunc(got.Findings, func(f normalization.Finding) bool {
				return f.Severity == normalization.SeverityHigh
			}) {
				t.Errorf("findings = %+v, want the reflected origin reported", got.Findings)
			}
		})
	}
}

// A proxy can add a fixed header to every response, so `*` on an error page says
// nothing about the real page.
func TestWildcardOnAnErrorPageIsNotAnAnswer(t *testing.T) {
	srv := httptest.NewServer(splitByOrigin(
		respond(http.StatusServiceUnavailable, map[string]string{"Access-Control-Allow-Origin": "*"}),
		respond(http.StatusOK, nil),
	))
	defer srv.Close()

	raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL+"/api/account"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !raw.Degraded() {
		t.Error("a wildcard on an error page must not read as a finished check")
	}
}

// A preflight that trusts any origin is the weaker evidence, so it must not hide a
// real request that trusts a lookalike with cookies.
func TestPreflightTrustDoesNotHideAWorseFinding(t *testing.T) {
	srv := httptest.NewServer(splitByOrigin(
		func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			switch {
			case r.Method == http.MethodOptions:
				w.Header().Set("Access-Control-Allow-Origin", origin)
			case strings.HasPrefix(origin, "https://127.0.0.1."):
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.WriteHeader(http.StatusOK)
		},
		redirectTo(http.StatusMovedPermanently, "https://example.test/"),
	))
	defer srv.Close()

	raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	want := []string{"cors-lookalike-origin-credentials", "cors-reflected-origin"}
	if got := ruleIDs(t, raw); !slices.Equal(got, want) {
		t.Errorf("rules = %v, want %v", got, want)
	}
}

// A browser accepts only the exact value, so anything else is not a credentials
// problem, however close it looks.
func TestCredentialsHeaderMustBeExact(t *testing.T) {
	srv := httptest.NewServer(splitByOrigin(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Credentials", "TRUE")
			w.WriteHeader(http.StatusOK)
		},
		redirectTo(http.StatusMovedPermanently, "https://example.test/"),
	))
	defer srv.Close()

	raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := ruleIDs(t, raw); !slices.Equal(got, []string{"cors-reflected-origin"}) {
		t.Errorf("rules = %v, want cors-reflected-origin", got)
	}
}

// A plain port that could not answer says nothing about whether it redirects, so it
// neither opens a finding nor lets one close. A 404 is an answer: nothing redirected.
func TestPlainPortThatIsNotReady(t *testing.T) {
	cases := []struct {
		status   int
		degraded bool
		want     []string
	}{
		{http.StatusTooManyRequests, true, []string{}},
		{http.StatusInternalServerError, true, []string{}},
		{http.StatusServiceUnavailable, true, []string{}},
		{http.StatusNotFound, false, []string{"http-error-plain"}},
		{http.StatusForbidden, false, []string{"http-error-plain"}},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			plain := httptest.NewServer(respond(tc.status, nil))
			defer plain.Close()
			_, plainPort, _ := net.SplitHostPort(strings.TrimPrefix(plain.URL, "http://"))

			srv := httptest.NewTLSServer(respond(http.StatusOK, nil))
			defer srv.Close()

			raw, err := tlsScanner(srv, plainPort).Scan(context.Background(), endpointTarget(srv.URL))
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if raw.Degraded() != tc.degraded {
				t.Errorf("degradations = %v, want degraded=%v", raw.Degradations, tc.degraded)
			}
			if got := ruleIDs(t, raw); !slices.Equal(got, tc.want) {
				t.Errorf("rules = %v, want %v", got, tc.want)
			}
		})
	}
}

// A status no real page has must not drop a finding quietly while the scan still
// counts as finished, because that scan could then close the finding.
func TestStatusesOutsideTheRangeAreNotAnswers(t *testing.T) {
	const oddStatus = 999
	reflecting := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(oddStatus)
	}
	permanent := redirectTo(http.StatusMovedPermanently, "https://example.test/")

	t.Run("on the CORS check", func(t *testing.T) {
		srv := httptest.NewServer(splitByOrigin(reflecting, permanent))
		defer srv.Close()

		raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL))
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if !raw.Degraded() {
			t.Error("must not read as a finished check")
		}
		if got := ruleIDs(t, raw); len(got) != 0 {
			t.Errorf("rules = %v, want none", got)
		}
	})

	t.Run("on the plain check", func(t *testing.T) {
		srv := httptest.NewServer(splitByOrigin(respond(http.StatusOK, nil), respond(oddStatus, nil)))
		defer srv.Close()

		raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL))
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if !raw.Degraded() {
			t.Error("must not read as a finished check")
		}
		if got := ruleIDs(t, raw); len(got) != 0 {
			t.Errorf("rules = %v, want none", got)
		}
	})

	t.Run("on both", func(t *testing.T) {
		srv := httptest.NewServer(respond(oddStatus, nil))
		defer srv.Close()

		if _, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL)); !errors.Is(err, ErrUnreachable) {
			t.Errorf("err = %v, want ErrUnreachable", err)
		}
	})
}

// A preflight refused with a 404 or 501 is a real answer from a server with no
// OPTIONS handler. One that hits a service still waking up is not.
func TestPreflightErrors(t *testing.T) {
	cases := []struct {
		status   int
		degraded bool
	}{
		{http.StatusBadRequest, false},
		{http.StatusNotFound, false},
		{http.StatusNotImplemented, false},
		{http.StatusServiceUnavailable, true},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodOptions {
					w.WriteHeader(tc.status)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL+"/api/account"))
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if raw.Degraded() != tc.degraded {
				t.Errorf("degradations = %v, want degraded=%v", raw.Degradations, tc.degraded)
			}
		})
	}
}

func TestNextHop(t *testing.T) {
	cases := []struct {
		name, start, location, want string
	}{
		{"relative path", "https://example.test/a", "/b", "https://example.test/b"},
		{"apex to www", "https://example.test/", "https://www.example.test/", "https://www.example.test/"},
		{"www to apex", "https://www.example.test/", "https://example.test/", "https://example.test/"},
		{"plain to https", "http://example.test/", "https://example.test/", "https://example.test/"},
		{"credentials removed", "https://example.test/", "https://u:p@example.test/", "https://example.test/"},
		{"another site", "https://example.test/", "https://evil.test/", ""},
		{"a subdomain is not the site", "https://example.test/", "https://api.example.test/", ""},
		{"lookalike", "https://example.test/", "https://example.test.evil.test/", ""},
		{"https down to plain", "https://example.test/", "http://example.test/", ""},
		{"another scheme", "https://example.test/", "file:///etc/passwd", ""},
		{"empty", "https://example.test/", "", ""},
		{"unparseable", "https://example.test/", "http://[bad", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, err := url.Parse(tc.start)
			if err != nil {
				t.Fatalf("start: %v", err)
			}
			next, ok := nextHop(start, start, tc.location)
			if tc.want == "" {
				if ok {
					t.Errorf("followed to %s, want refused", next)
				}
				return
			}
			if !ok || next.String() != tc.want {
				t.Errorf("next = %v (%v), want %s", next, ok, tc.want)
			}
		})
	}
}

// roundTripFunc lets a test decide what a request's connection does.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type fakeTimeout struct{}

func (fakeTimeout) Error() string   { return "i/o timeout" }
func (fakeTimeout) Timeout() bool   { return true }
func (fakeTimeout) Temporary() bool { return true }

// A silently dropped port 80 is safe, but only when the host just answered on
// HTTPS. Anywhere else, silence might be the network.
func TestSilentPlainPort(t *testing.T) {
	silent := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: fakeTimeout{}}
	})}
	cases := []struct {
		name          string
		target        string
		httpsAnswered bool
		want          string
		incomplete    bool
	}{
		{"https answered", "https://example.test/", true, failureFiltered, false},
		{"https did not answer", "https://example.test/", false, failureConnectTimeout, true},
		{"plain http is the target", "http://example.test/", true, failureConnectTimeout, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, err := url.Parse(tc.target)
			if err != nil {
				t.Fatalf("target: %v", err)
			}
			got := New(netguard.Policy{}).checkRedirect(context.Background(), silent, endpoint, tc.httpsAnswered)
			if got.Failure != tc.want {
				t.Errorf("failure = %q, want %q", got.Failure, tc.want)
			}
			if got.incomplete() != tc.incomplete {
				t.Errorf("incomplete = %v, want %v", got.incomplete(), tc.incomplete)
			}
		})
	}
}

// The doubt about a silent port is stated on its own, so it neither reads as a
// pass nor marks good results from the other check as incomplete.
func TestSilentPlainPortIsANoteAndKeepsTheScanComplete(t *testing.T) {
	data := fixture(t, "plain-filtered.json")
	rec, err := parseRecord(data)
	if err != nil {
		t.Fatalf("parseRecord: %v", err)
	}
	if rec.Redirect.incomplete() {
		t.Error("a silent port must not mark the scan incomplete")
	}
	got, err := Normalize(data, "scan-1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(got.Findings) != 1 || got.Findings[0].Severity != normalization.SeverityInfo {
		t.Fatalf("findings = %+v, want one info note", got.Findings)
	}
	if !strings.Contains(got.Findings[0].Remediation, "curl -I") {
		t.Errorf("remediation = %q, want it to say how to check", got.Findings[0].Remediation)
	}
}

// Timing out after connecting is a slow server, not a closed port.
func TestSlowPlainPortIsNotFiltered(t *testing.T) {
	var err error = &net.OpError{Op: "read", Net: "tcp", Err: fakeTimeout{}}
	if got := classifyFailure(err); got != failureTimeout {
		t.Errorf("classification = %q, want %q", got, failureTimeout)
	}
}

// reflectWhen trusts only the origins allowed says it should.
func reflectWhen(allowed func(*http.Request) bool, credentials bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if allowed(r) {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			if credentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}
		w.WriteHeader(http.StatusOK)
	}
}

func TestOriginMistakes(t *testing.T) {
	permanent := redirectTo(http.StatusMovedPermanently, "https://example.test/")
	isLookalike := func(r *http.Request) bool {
		return strings.HasPrefix(r.Header.Get("Origin"), "https://127.0.0.1.")
	}
	isNull := func(r *http.Request) bool { return r.Header.Get("Origin") == nullOrigin }
	everything := func(*http.Request) bool { return true }
	preflightOnly := func(r *http.Request) bool {
		return r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
	}

	cases := []struct {
		name       string
		cors       http.HandlerFunc
		want       []string
		confidence normalization.Confidence
	}{
		{"lookalike with credentials", reflectWhen(isLookalike, true), []string{"cors-lookalike-origin-credentials"}, normalization.ConfidenceHigh},
		{"lookalike", reflectWhen(isLookalike, false), []string{"cors-lookalike-origin"}, normalization.ConfidenceHigh},
		{"null with credentials", reflectWhen(isNull, true), []string{"cors-null-origin-credentials"}, normalization.ConfidenceHigh},
		{"null", reflectWhen(isNull, false), []string{"cors-null-origin"}, normalization.ConfidenceHigh},
		{
			"both mistakes are reported",
			reflectWhen(func(r *http.Request) bool { return isLookalike(r) || isNull(r) }, true),
			[]string{"cors-lookalike-origin-credentials", "cors-null-origin-credentials"},
			normalization.ConfidenceHigh,
		},
		// One mistake, not three.
		{"trusting everything is one finding", reflectWhen(everything, true), []string{"cors-reflected-origin-credentials"}, normalization.ConfidenceHigh},
		// A preflight says the request may be sent, not that its answer may be read.
		{"preflight only", reflectWhen(preflightOnly, true), []string{"cors-reflected-origin-credentials"}, normalization.ConfidenceMedium},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(splitByOrigin(tc.cors, permanent))
			defer srv.Close()

			raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL))
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if raw.Degraded() {
				t.Errorf("degradations = %v, want none", raw.Degradations)
			}
			got, err := Normalize(raw.Output, "scan-1")
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			ids := []string{}
			for _, f := range got.Findings {
				ids = append(ids, f.ScannerFindingID)
				if f.Confidence != tc.confidence {
					t.Errorf("%s confidence = %s, want %s", f.ScannerFindingID, f.Confidence, tc.confidence)
				}
			}
			slices.Sort(ids)
			if !slices.Equal(ids, tc.want) {
				t.Errorf("rules = %v, want %v", ids, tc.want)
			}
		})
	}
}

// A server whose preflight redirects is refusing it, as far as a browser cares.
func TestRedirectedPreflightIsAnAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			redirectTo(http.StatusFound, "/elsewhere")(w, r)
			return
		}
		if r.Header.Get("Origin") == "" {
			redirectTo(http.StatusMovedPermanently, "https://example.test/")(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if raw.Degraded() {
		t.Errorf("degradations = %v, want none", raw.Degradations)
	}
}

// The strict default, applied at connection time. Both a literal address and a
// name are refused, which is what survives DNS rebinding (T-56).
func TestBlockedAddressesAreRefusedAtConnection(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("server address: %v", err)
	}

	for _, target := range []string{srv.URL, "http://localhost:" + port} {
		raw, err := New(netguard.Policy{}).Scan(context.Background(), endpointTarget(target))
		if !errors.Is(err, ErrBlockedTarget) || !errors.Is(err, netguard.ErrBlockedAddress) {
			t.Errorf("%s: err = %v, want the address policy's refusal", target, err)
		}
		if len(raw.Output) != 0 {
			t.Errorf("%s: a refused target must store nothing", target)
		}
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("server received %d requests, want 0", got)
	}
}

// Cloud metadata stays blocked even where private targets are allowed. Refused
// before any packet is sent, so this needs no network.
func TestMetadataEndpointIsAlwaysRefused(t *testing.T) {
	_, err := testScanner().Scan(context.Background(), endpointTarget("http://169.254.169.254/latest/meta-data/"))
	if !errors.Is(err, ErrBlockedTarget) {
		t.Errorf("err = %v, want ErrBlockedTarget", err)
	}
}

// closedPort returns a port nothing is listening on.
func closedPort(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	_ = l.Close()
	return port
}

func TestPlainURL(t *testing.T) {
	cases := []struct{ target, want string }{
		{"https://example.test/app?api_key=x", "http://example.test/"},
		{"https://example.test:8443/reset/token", "http://example.test/"},
		{"https://[2001:db8::1]:8443/app", "http://[2001:db8::1]/"},
		{"http://example.test:8080/app?api_key=x", "http://example.test:8080/app"},
	}
	for _, tc := range cases {
		u, err := parseEndpoint(tc.target)
		if err != nil {
			t.Fatalf("%s: %v", tc.target, err)
		}
		if got := New(netguard.Policy{}).plainURL(u); got != tc.want {
			t.Errorf("%s: plain URL = %s, want %s", tc.target, got, tc.want)
		}
	}
}

// tlsScanner trusts srv's certificate and points the plain check at plainPort.
func tlsScanner(srv *httptest.Server, plainPort string) *Scanner {
	s := testScanner()
	s.plainPort = plainPort
	s.tlsConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	return s
}

// An HTTPS target whose plain port refuses connections is the safest answer
// there is: a definite "nothing is listening", so no finding and no degradation.
func TestRefusedPlainPortIsSafeForAnHTTPSTarget(t *testing.T) {
	srv := httptest.NewTLSServer(respond(http.StatusOK, nil))
	defer srv.Close()

	raw, err := tlsScanner(srv, closedPort(t)).Scan(context.Background(), endpointTarget(srv.URL))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := ruleIDs(t, raw); len(got) != 0 {
		t.Errorf("rules = %v, want none", got)
	}
	if raw.Degraded() {
		t.Errorf("degradations = %v, want none", raw.Degradations)
	}
}

// The plain check reaches a different port from the HTTPS target, and a finding
// there is reported against the target's path. Nothing of the target's URL except
// its host goes out unencrypted: a path can hold a token as well as a query can.
func TestPlainPortIsCheckedForAnHTTPSTarget(t *testing.T) {
	var plainURI atomic.Value
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainURI.Store(r.URL.RequestURI())
		w.WriteHeader(http.StatusOK)
	}))
	defer plain.Close()
	_, plainPort, _ := net.SplitHostPort(strings.TrimPrefix(plain.URL, "http://"))

	srv := httptest.NewTLSServer(respond(http.StatusOK, nil))
	defer srv.Close()

	raw, err := tlsScanner(srv, plainPort).Scan(context.Background(),
		endpointTarget(srv.URL+"/app?api_key="+fakeToken))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := ruleIDs(t, raw); !slices.Equal(got, []string{"http-served-plain"}) {
		t.Errorf("rules = %v, want http-served-plain", got)
	}
	if got := plainURI.Load(); got != "/" {
		t.Errorf("plain request asked for %q, want /", got)
	}
	got, err := Normalize(raw.Output, "scan-1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	// Port 80 of this host may be another service, so the finding says less.
	if got.Findings[0].Confidence != normalization.ConfidenceLow {
		t.Errorf("confidence = %s, want low for a target on a custom port", got.Findings[0].Confidence)
	}
	if got.Findings[0].Endpoint != "GET app" {
		t.Errorf("endpoint = %q, want the target's own path", got.Findings[0].Endpoint)
	}
}

// A bad certificate is not a pass. It is not bypassed either: skipping
// verification would mean reporting on whoever answered.
func TestUntrustedCertificateDoesNotReadAsAPass(t *testing.T) {
	srv := httptest.NewTLSServer(respond(http.StatusOK, map[string]string{
		"Access-Control-Allow-Origin": probeOrigin,
	}))
	defer srv.Close()

	s := testScanner()
	s.plainPort = closedPort(t)
	s.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}

	_, err := s.Scan(context.Background(), endpointTarget(srv.URL))
	// Neither check got an answer here: TLS failed, and nothing is listening.
	if !errors.Is(err, ErrUnreachable) {
		t.Errorf("err = %v, want ErrUnreachable", err)
	}
}

// A failed HTTPS check beside an answered plain one keeps the finding and says
// the CORS half is unknown.
func TestUntrustedCertificateWithPlainAnswerDegrades(t *testing.T) {
	plain := httptest.NewServer(respond(http.StatusOK, nil))
	defer plain.Close()
	_, plainPort, _ := net.SplitHostPort(strings.TrimPrefix(plain.URL, "http://"))

	srv := httptest.NewTLSServer(respond(http.StatusOK, nil))
	defer srv.Close()

	s := testScanner()
	s.plainPort = plainPort
	s.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}

	raw, err := s.Scan(context.Background(), endpointTarget(srv.URL))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !raw.Degraded() {
		t.Error("an unverifiable certificate must not read as a CORS pass")
	}
	if got := ruleIDs(t, raw); !slices.Equal(got, []string{"http-served-plain"}) {
		t.Errorf("rules = %v, want http-served-plain", got)
	}
}

// A refused connection means "nothing is listening" only when HTTPS is the
// target. Here plain HTTP is the target and it stopped answering between the
// two checks, so the second check has learned nothing.
func TestRefusedPlainHTTPTargetIsNotSafe(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The last CORS question. Stop accepting new connections, so the plain
		// check that comes next is refused. This request's is already open.
		if r.Header.Get("Origin") == nullOrigin {
			_ = srv.Listener.Close()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !raw.Degraded() {
		t.Error("a plain target that stopped answering must not read as a pass")
	}
}

func TestDownTargetFailsRatherThanPasses(t *testing.T) {
	target := "http://127.0.0.1:" + closedPort(t) + "/"

	raw, err := testScanner().Scan(context.Background(), endpointTarget(target))
	if !errors.Is(err, ErrUnreachable) {
		t.Errorf("err = %v, want ErrUnreachable", err)
	}
	if len(raw.Output) != 0 {
		t.Errorf("a failed scan stored output: %s", raw.Output)
	}
}

// One check timing out keeps the other check's findings and says the coverage
// is incomplete -- never a silent pass (ADR 010).
func TestOneCheckTimingOutDegrades(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(splitByOrigin(
		respond(http.StatusOK, map[string]string{"Access-Control-Allow-Origin": probeOrigin}),
		func(http.ResponseWriter, *http.Request) { <-release },
	))
	defer srv.Close()
	defer close(release)

	s := testScanner()
	s.Timeout = 200 * time.Millisecond

	raw, err := s.Scan(context.Background(), endpointTarget(srv.URL))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !slices.Contains(raw.Degradations, DegradedProbeIncomplete) {
		t.Errorf("degradations = %v, want %s", raw.Degradations, DegradedProbeIncomplete)
	}
	if got := ruleIDs(t, raw); !slices.Equal(got, []string{"cors-reflected-origin"}) {
		t.Errorf("rules = %v, want the finding from the check that finished", got)
	}
}

// A hostile server cannot make the worker hold unbounded headers (§15.8).
func TestOversizedHeadersDoNotReadAsAPass(t *testing.T) {
	srv := httptest.NewServer(splitByOrigin(
		respond(http.StatusOK, map[string]string{"X-Padding": strings.Repeat("a", maxHeaderBytes*2)}),
		redirectTo(http.StatusMovedPermanently, "https://example.test/"),
	))
	defer srv.Close()

	raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !raw.Degraded() {
		t.Error("a response too large to read must not read as a pass")
	}
}

func TestCancelledScanSaysSo(t *testing.T) {
	srv := httptest.NewServer(respond(http.StatusOK, nil))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	raw, err := testScanner().Scan(ctx, endpointTarget(srv.URL))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if len(raw.Output) != 0 {
		t.Error("a cancelled scan must store nothing")
	}
}

func TestExpiredDeadlineSaysSo(t *testing.T) {
	srv := httptest.NewServer(respond(http.StatusOK, nil))
	defer srv.Close()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	if _, err := testScanner().Scan(ctx, endpointTarget(srv.URL)); !errors.Is(err, scanners.ErrExecTimeout) {
		t.Errorf("err = %v, want ErrExecTimeout", err)
	}
}

// The fixture is the adapter's real output for this server, so the mapper tests
// below cannot drift from what Scan writes.
func TestFixtureMatchesRealOutput(t *testing.T) {
	srv := httptest.NewServer(splitByOrigin(
		reflectWhen(func(*http.Request) bool { return true }, true),
		respond(http.StatusOK, nil),
	))
	defer srv.Close()

	raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL+"/api/account"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	want := strings.TrimSpace(string(fixture(t, "reflected-credentials.json")))
	if string(raw.Output) != want {
		t.Errorf("output = %s\nwant %s", raw.Output, want)
	}
}

func TestNormalizeFixtures(t *testing.T) {
	cases := []struct {
		file string
		want []string
	}{
		{"clean.json", []string{}},
		{"reflected-credentials.json", []string{"cors-reflected-origin-credentials", "http-served-plain"}},
		{"reflected-temporary-redirect.json", []string{"cors-reflected-origin", "http-redirect-temporary"}},
		{"wildcard.json", []string{}},
		{"plain-refused.json", []string{}},
		{"plain-filtered.json", []string{"http-port-unverified"}},
		{"lookalike-and-null.json", []string{"cors-lookalike-origin-credentials", "cors-null-origin"}},
		{"preflight-only.json", []string{"cors-reflected-origin"}},
		{"cors-failed.json", []string{"http-served-plain"}},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			got, err := Normalize(fixture(t, tc.file), "scan-1")
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			if len(got.Errors) != 0 {
				t.Errorf("errors on a valid fixture: %v", got.Errors)
			}
			ids := []string{}
			for i, f := range got.Findings {
				ids = append(ids, f.ScannerFindingID)
				if err := f.Validate(); err != nil {
					t.Errorf("finding %d is invalid: %v", i, err)
				}
				if f.Category != scanners.CategoryDAST || f.Scanner != Name || f.ScannerSeverity == "" {
					t.Errorf("finding %d lost its source: %+v", i, f)
				}
			}
			slices.Sort(ids)
			if !slices.Equal(ids, tc.want) {
				t.Errorf("rules = %v, want %v", ids, tc.want)
			}
			// Every finding needs a sighting, or nothing can say where it is.
			if len(got.Occurrences) != len(got.Findings) {
				t.Errorf("occurrences = %d, findings = %d", len(got.Occurrences), len(got.Findings))
			}
		})
	}
}

func TestSeverities(t *testing.T) {
	cases := []struct {
		r          rule
		severity   normalization.Severity
		confidence normalization.Confidence
	}{
		{ruleReflectedWithCredentials, normalization.SeverityHigh, normalization.ConfidenceHigh},
		{ruleReflected, normalization.SeverityLow, normalization.ConfidenceHigh},
		{ruleLookalikeWithCredentials, normalization.SeverityHigh, normalization.ConfidenceHigh},
		{ruleLookalike, normalization.SeverityLow, normalization.ConfidenceHigh},
		{ruleNullWithCredentials, normalization.SeverityHigh, normalization.ConfidenceHigh},
		{ruleNull, normalization.SeverityLow, normalization.ConfidenceHigh},
		{rulePlainServed, normalization.SeverityMedium, normalization.ConfidenceHigh},
		{rulePortUnverified, normalization.SeverityInfo, normalization.ConfidenceLow},
		{rulePlainError, normalization.SeverityLow, normalization.ConfidenceLow},
		{ruleRedirectTemporary, normalization.SeverityLow, normalization.ConfidenceHigh},
		{ruleRedirectPlain, normalization.SeverityLow, normalization.ConfidenceLow},
	}
	for _, tc := range cases {
		if tc.r.severity != tc.severity || tc.r.confidence != tc.confidence {
			t.Errorf("%s = %s/%s, want %s/%s (ADR 041)", tc.r.id,
				tc.r.severity, tc.r.confidence, tc.severity, tc.confidence)
		}
	}
}

// Reprocessing stored output must give identical findings, or it is not
// reprocessable at all (§8).
func TestNormalizeIsDeterministic(t *testing.T) {
	data := fixture(t, "reflected-credentials.json")
	first, err := Normalize(data, "scan-1")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := Normalize(data, "scan-1")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if len(first.Findings) != len(second.Findings) {
		t.Fatalf("counts differ: %d vs %d", len(first.Findings), len(second.Findings))
	}
	for i := range first.Findings {
		if first.Findings[i].Fingerprint != second.Findings[i].Fingerprint {
			t.Errorf("finding %d fingerprinted differently across runs", i)
		}
	}
}

// ADR 026's identity: rule and path. The origin churns per preview environment
// and the query is where credentials are, so neither may move a fingerprint.
func TestIdentityIgnoresOriginAndQuery(t *testing.T) {
	scan := func(t *testing.T, srv *httptest.Server, suffix string) string {
		t.Helper()
		raw, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL+suffix))
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		got, err := Normalize(raw.Output, "scan-1")
		if err != nil || len(got.Findings) == 0 {
			t.Fatalf("Normalize: findings=%d err=%v", len(got.Findings), err)
		}
		return got.Findings[0].Fingerprint
	}

	first := httptest.NewServer(respond(http.StatusOK, nil))
	defer first.Close()
	second := httptest.NewServer(respond(http.StatusOK, nil))
	defer second.Close()

	base := scan(t, first, "/login")
	if got := scan(t, second, "/login"); got != base {
		t.Error("a different origin changed the fingerprint")
	}
	if got := scan(t, first, "/login?next="+fakeToken); got != base {
		t.Error("a query string changed the fingerprint")
	}
	if got := scan(t, first, "/admin"); got == base {
		t.Error("a different path kept the fingerprint")
	}
}

// Nothing here should panic, and nothing should read as a clean result (§8, §13).
func TestBrokenOutputIsRejected(t *testing.T) {
	for _, file := range []string{
		"empty.json", "malformed.json", "truncated.json", "wrong-tool.json",
		"unknown-schema.json", "path-with-query.json",
	} {
		t.Run(file, func(t *testing.T) {
			got, err := Normalize(fixture(t, file), "scan-1")
			if !errors.Is(err, ErrMalformedRecord) {
				t.Errorf("err = %v, want ErrMalformedRecord", err)
			}
			if len(got.Findings) != 0 {
				t.Errorf("broken output produced %d findings", len(got.Findings))
			}
		})
	}

	oversized := append(fixture(t, "clean.json"), strings.Repeat(" ", maxRecordBytes)...)
	if _, err := Normalize(oversized, "scan-1"); !errors.Is(err, ErrMalformedRecord) {
		t.Errorf("oversized record: err = %v, want ErrMalformedRecord", err)
	}
}

// One bad observation costs that check only, is reported, and never quotes what
// it could not read: the record is an untrusted document (§15.7).
func TestHostileRecord(t *testing.T) {
	got, err := Normalize(fixture(t, "hostile.json"), "scan-1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(got.Errors) != 1 {
		t.Errorf("errors = %v, want one for the unknown allow_origin", got.Errors)
	}
	for _, e := range got.Errors {
		if strings.Contains(e, "script") {
			t.Errorf("error quotes the hostile value: %s", e)
		}
	}
	if len(got.Findings) != 1 {
		t.Fatalf("findings = %d, want the one from the readable check", len(got.Findings))
	}
	// Traversal in a stored path is flattened, never preserved as a location.
	if strings.Contains(got.Occurrences[0].File, "..") {
		t.Errorf("file = %q still traverses", got.Occurrences[0].File)
	}
}

// A record that never asked about CORS says nothing about it, and must not read
// as a clean one.
func TestRecordWithoutTheFirstProbeIsReported(t *testing.T) {
	got, err := Normalize(fixture(t, "no-base-probe.json"), "scan-1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(got.Errors) != 1 {
		t.Errorf("errors = %v, want one", got.Errors)
	}
}

// A record claiming a request both failed and was answered did not come from
// this adapter, and neither half may become a finding.
func TestContradictoryRecordIsReported(t *testing.T) {
	got, err := Normalize(fixture(t, "failed-with-answer.json"), "scan-1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(got.Findings) != 0 {
		t.Errorf("findings = %+v, want none", got.Findings)
	}
	if len(got.Errors) != 2 {
		t.Errorf("errors = %v, want one per check", got.Errors)
	}
}

// Once a server has shown it trusts any origin, the other two questions cannot
// change the finding, so a live site is not asked them.
func TestTrustingAnyOriginStopsTheQuestions(t *testing.T) {
	var corsRequests atomic.Int32
	srv := httptest.NewServer(splitByOrigin(
		func(w http.ResponseWriter, r *http.Request) {
			corsRequests.Add(1)
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.WriteHeader(http.StatusOK)
		},
		redirectTo(http.StatusMovedPermanently, "https://example.test/"),
	))
	defer srv.Close()

	if _, err := testScanner().Scan(context.Background(), endpointTarget(srv.URL)); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := corsRequests.Load(); got != 2 {
		t.Errorf("CORS requests = %d, want the first question and the preflight", got)
	}
}

func TestRootPathIsSpelledOut(t *testing.T) {
	got, err := Normalize(fixture(t, "root-path.json"), "scan-1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(got.Findings) != 1 || got.Findings[0].Endpoint != "GET /" {
		t.Errorf("findings = %+v, want one at GET /", got.Findings)
	}
}
