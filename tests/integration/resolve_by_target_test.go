//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/projects"
	"github.com/aizen299/secure-dev/internal/queue"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// seedScanOfTarget adds a scan of target to a project, as the API would store it.
func seedScanOfTarget(t *testing.T, pool *pgxpool.Pool, projectID string, target scanners.Target) string {
	t.Helper()
	encoded, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("encode target: %v", err)
	}
	scanID := seedScanFor(t, pool, projectID)
	if _, err := pool.Exec(t.Context(),
		`UPDATE scans SET target = $1 WHERE id = $2`, encoded, scanID); err != nil {
		t.Fatalf("set target: %v", err)
	}
	return scanID
}

func endpoint(url string) scanners.Target {
	return scanners.Target{Kind: scanners.KindEndpoint, EndpointURL: url}
}

// recordEndpointScan records one completed httpprobe scan of url. It reports the
// given finding if fingerprint is set, and returns the scan id.
func recordEndpointScan(
	t *testing.T, pool *pgxpool.Pool, store *findings.Store, projectID, url, fingerprint string,
) string {
	t.Helper()
	scanID := seedScanOfTarget(t, pool, projectID, endpoint(url))
	result := normalization.DedupResult{}
	if fingerprint != "" {
		finding := dastFinding(fingerprint, "GET api")
		finding.Scanner = "httpprobe"
		finding.Sources = []string{"httpprobe"}
		result.Findings = []normalization.MergedFinding{finding}
		result.Occurrences = []normalization.Occurrence{
			{Fingerprint: fingerprint, ScanID: scanID, File: "api", Scanner: "httpprobe"},
		}
	}
	if err := store.RecordScan(t.Context(), projectID, scanID, result,
		[]string{"httpprobe"}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordScan: %v", err)
	}
	return scanID
}

// The bug this exists for: a clean scan of one page said nothing about another,
// and the finding was marked resolved anyway (ADR 042).
func TestAScanOfADifferentURLDoesNotResolveAFinding(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)
	_, projectID := seedScan(t, pool)
	fp := fingerprintOf("f1")

	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/api/account", fp)
	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/login", "")

	if got := findingStatus(t, pool, projectID, fp); got != "open" {
		t.Errorf("status = %q, want open: nobody looked at /api/account again", got)
	}
}

// What still has to work: looking again, and not finding it, closes it.
func TestRescanningTheSameURLResolvesAFinding(t *testing.T) {
	cases := []struct{ name, first, second string }{
		{"identical", "https://site.example.test/api/account", "https://site.example.test/api/account"},
		{"a new preview host", "https://pr-1.example.test/api/account", "https://pr-2.example.test/api/account"},
		{"a different query", "https://site.example.test/api/account?a=1", "https://site.example.test/api/account?b=2"},
		{"a fragment", "https://site.example.test/api/account", "https://site.example.test/api/account#top"},
		{"a trailing slash", "https://site.example.test/api/account", "https://site.example.test/api/account/"},
		{"a doubled slash", "https://site.example.test/api//account", "https://site.example.test/api/account"},
		{"a dot in the path", "https://site.example.test/api/./account", "https://site.example.test/api/account"},
		{"a port", "https://site.example.test:8443/api/account", "https://site.example.test/api/account"},
		{"the site root", "https://site.example.test", "https://site.example.test/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool := testPool(t)
			store := findings.NewStore(pool)
			_, projectID := seedScan(t, pool)
			fp := fingerprintOf("f2")

			recordEndpointScan(t, pool, store, projectID, tc.first, fp)
			recordEndpointScan(t, pool, store, projectID, tc.second, "")

			if got := findingStatus(t, pool, projectID, fp); got != "resolved" {
				t.Errorf("status = %q, want resolved", got)
			}
		})
	}
}

// A near miss on the path is a different page.
func TestASimilarPathIsADifferentURL(t *testing.T) {
	cases := []struct{ name, first, second string }{
		{"a longer path", "https://site.example.test/api", "https://site.example.test/api/account"},
		{"a shorter path", "https://site.example.test/api/account", "https://site.example.test/api"},
		{"the root", "https://site.example.test/api", "https://site.example.test/"},
		{"case", "https://site.example.test/API", "https://site.example.test/api"},
		{"an encoded slash", "https://site.example.test/files/a%2Fb", "https://site.example.test/files/a/b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool := testPool(t)
			store := findings.NewStore(pool)
			_, projectID := seedScan(t, pool)
			fp := fingerprintOf("f3")

			recordEndpointScan(t, pool, store, projectID, tc.first, fp)
			recordEndpointScan(t, pool, store, projectID, tc.second, "")

			if got := findingStatus(t, pool, projectID, fp); got != "open" {
				t.Errorf("status = %q, want open", got)
			}
		})
	}
}

// Two URLs in one project keep separate lives, which is what scanning several
// URLs needs. A finding reported from both can be closed from either.
func TestFindingsOnTwoURLsKeepSeparateLives(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)
	_, projectID := seedScan(t, pool)
	account := fingerprintOf("f4")
	login := fingerprintOf("f5")

	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/account", account)
	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/login", login)

	// Each scan above reported only its own, and neither closed the other.
	if got := findingStatus(t, pool, projectID, account); got != "open" {
		t.Errorf("account = %q, want open", got)
	}

	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/account", "")
	if got := findingStatus(t, pool, projectID, account); got != "resolved" {
		t.Errorf("account = %q after its own rescan, want resolved", got)
	}
	if got := findingStatus(t, pool, projectID, login); got != "open" {
		t.Errorf("login = %q, want open: only /account was looked at", got)
	}
}

// What matters is what the scan started from, not the page a finding is on. A
// crawl from / can report /login, and only another crawl from / can look again.
func TestTheComparisonIsOfTargetsNotFindingLocations(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)
	_, projectID := seedScan(t, pool)
	fp := fingerprintOf("f6")

	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/", fp)

	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/login", "")
	if got := findingStatus(t, pool, projectID, fp); got != "open" {
		t.Errorf("after a scan of another URL = %q, want open", got)
	}

	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/", "")
	if got := findingStatus(t, pool, projectID, fp); got != "resolved" {
		t.Errorf("after a rescan of the starting URL = %q, want resolved", got)
	}
}

// A finding two URLs have reported may only be reachable from one of them now. Only
// the URL that reported it most recently can say it has gone: the other coming back
// clean could just mean its crawl no longer gets there.
func TestOnlyTheMostRecentReporterCanResolve(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)
	_, projectID := seedScan(t, pool)
	fp := fingerprintOf("f7")

	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/a", fp)
	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/b", fp)

	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/a", "")
	if got := findingStatus(t, pool, projectID, fp); got != "open" {
		t.Errorf("after a clean scan of the older reporter = %q, want open", got)
	}

	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/b", "")
	if got := findingStatus(t, pool, projectID, fp); got != "resolved" {
		t.Errorf("after a clean scan of the most recent reporter = %q, want resolved", got)
	}
}

// An unusable URL cannot be compared with anything, on either side.
func TestAReporterWithNoUsableURLCannotBeMatched(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)
	_, projectID := seedScan(t, pool)
	fp := fingerprintOf("fa")

	first := seedScanOfTarget(t, pool, projectID, scanners.Target{Kind: scanners.KindEndpoint, EndpointURL: "not a url"})
	finding := dastFinding(fp, "GET api")
	finding.Scanner = "httpprobe"
	if err := store.RecordScan(t.Context(), projectID, first, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{finding},
		Occurrences: []normalization.Occurrence{{Fingerprint: fp, ScanID: first, File: "api", Scanner: "httpprobe"}},
	}, []string{"httpprobe"}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordScan: %v", err)
	}

	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/api", "")
	if got := findingStatus(t, pool, projectID, fp); got != "open" {
		t.Errorf("status = %q, want open", got)
	}
}

// The target as the API really stores it, not as a test writes it. If the stored
// shape ever stopped matching what resolving reads, nothing would ever resolve, and
// a test that writes the target itself would not notice.
func TestResolvingReadsTheTargetTheAPIStores(t *testing.T) {
	pool := testPool(t)
	client := testRedis(t)
	store := findings.NewStore(pool)

	key := "itest:resolve:" + uuid.NewString()
	t.Cleanup(func() { _ = client.Del(context.Background(), key).Err() })
	srv := newAPI(t, pool, queue.NewRedis(client, key))

	status, body := apiRequest(t, srv, http.MethodPost, "/api/v1/projects",
		fmt.Sprintf(`{"name":"Resolve","slug":%q,"environment":"production","criticality":"high"}`,
			"itest-"+uuid.NewString()[:8]), apiTestToken)
	if status != http.StatusCreated {
		t.Fatalf("create project: status = %d (body: %s)", status, body)
	}
	var project projects.Project
	if err := json.Unmarshal(body, &project); err != nil {
		t.Fatalf("decode project: %v", err)
	}
	cleanupProject(t, pool, project.ID)

	submit := func(url string) string {
		t.Helper()
		status, body := apiRequest(t, srv, http.MethodPost, "/api/v1/scans", fmt.Sprintf(
			`{"project_id":%q,"target":{"kind":"endpoint","endpoint_url":%q}}`, project.ID, url), apiTestToken)
		if status != http.StatusAccepted {
			t.Fatalf("create scan: status = %d (body: %s)", status, body)
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &created); err != nil {
			t.Fatalf("decode scan: %v", err)
		}
		return created.ID
	}
	record := func(scanID, fingerprint string) {
		t.Helper()
		result := normalization.DedupResult{}
		if fingerprint != "" {
			finding := dastFinding(fingerprint, "GET api/account")
			finding.Scanner = "httpprobe"
			result.Findings = []normalization.MergedFinding{finding}
			result.Occurrences = []normalization.Occurrence{
				{Fingerprint: fingerprint, ScanID: scanID, File: "api/account", Scanner: "httpprobe"},
			}
		}
		if err := store.RecordScan(t.Context(), project.ID, scanID, result,
			[]string{"httpprobe"}, time.Now().UTC()); err != nil {
			t.Fatalf("RecordScan: %v", err)
		}
	}
	fp := fingerprintOf("fb")

	record(submit("https://site.example.test/api/account"), fp)

	record(submit("https://site.example.test/login"), "")
	if got := findingStatus(t, pool, project.ID, fp); got != "open" {
		t.Errorf("after a scan of another URL = %q, want open", got)
	}

	record(submit("https://pr-9.example.test/api/account?a=1"), "")
	if got := findingStatus(t, pool, project.ID, fp); got != "resolved" {
		t.Errorf("after a rescan of the same path = %q, want resolved", got)
	}
}

// Without a usable path nothing can be compared, and nothing is resolved.
func TestAnEndpointScanWithNoURLResolvesNothing(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)
	_, projectID := seedScan(t, pool)
	fp := fingerprintOf("f8")

	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/api", fp)

	scanID := seedScanOfTarget(t, pool, projectID, scanners.Target{Kind: scanners.KindEndpoint})
	if err := store.RecordScan(t.Context(), projectID, scanID, normalization.DedupResult{},
		[]string{"httpprobe"}, time.Now().UTC()); err != nil {
		t.Fatalf("RecordScan: %v", err)
	}
	if got := findingStatus(t, pool, projectID, fp); got != "open" {
		t.Errorf("status = %q, want open", got)
	}
}

// A scan whose own URL cannot be read has looked at nothing we can name.
func TestAnEndpointScanWithAnUnusableURLResolvesNothing(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)
	_, projectID := seedScan(t, pool)
	fp := fingerprintOf("fc")

	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/api", fp)
	recordEndpointScan(t, pool, store, projectID, "not a url", "")

	if got := findingStatus(t, pool, projectID, fp); got != "open" {
		t.Errorf("status = %q, want open", got)
	}
}

// Repository scans keep the rule they have always had, whatever ref or URL they
// were given. ADR 042 records that gap, and this pins that it did not change.
func TestRepositoryScansResolveAsBefore(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)
	_, projectID := seedScan(t, pool)
	fp := fingerprintOf("f9")

	first := seedScanOfTarget(t, pool, projectID, scanners.Target{
		Kind: scanners.KindRepository, RepositoryURL: "https://git.example.test/org/app", Ref: "main"})
	if err := store.RecordScan(t.Context(), projectID, first, normalization.DedupResult{
		Findings:    []normalization.MergedFinding{secretFinding(fp, "gitleaks")},
		Occurrences: []normalization.Occurrence{occurrenceOf(fp, first, "gitleaks", 12)},
	}, []string{"gitleaks"}, time.Now().UTC()); err != nil {
		t.Fatalf("first scan: %v", err)
	}

	second := seedScanOfTarget(t, pool, projectID, scanners.Target{
		Kind: scanners.KindRepository, RepositoryURL: "https://git.example.test/org/app", Ref: "develop"})
	if err := store.RecordScan(t.Context(), projectID, second, normalization.DedupResult{},
		[]string{"gitleaks"}, time.Now().UTC()); err != nil {
		t.Fatalf("second scan: %v", err)
	}

	if got := findingStatus(t, pool, projectID, fp); got != "resolved" {
		t.Errorf("status = %q, want resolved", got)
	}
}
