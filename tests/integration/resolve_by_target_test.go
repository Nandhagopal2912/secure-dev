//go:build integration

package integration

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/normalization"
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

// Found from two URLs, either one looking again and finding nothing can close it.
// Requiring both would strand findings when a project stops scanning one.
func TestAFindingReportedFromTwoURLsResolvesFromEither(t *testing.T) {
	pool := testPool(t)
	store := findings.NewStore(pool)
	_, projectID := seedScan(t, pool)
	fp := fingerprintOf("f7")

	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/a", fp)
	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/b", fp)
	recordEndpointScan(t, pool, store, projectID, "https://site.example.test/b", "")

	if got := findingStatus(t, pool, projectID, fp); got != "resolved" {
		t.Errorf("status = %q, want resolved", got)
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

// Repository scans read the whole target every time, so they must keep resolving
// as they always have, whatever ref or URL they were given (ADR 042).
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
