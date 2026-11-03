//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"

	"github.com/aizen299/secure-dev/internal/findings"
	"github.com/aizen299/secure-dev/internal/netguard"
	"github.com/aizen299/secure-dev/internal/queue"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scanners/httpprobe"
	scanstore "github.com/aizen299/secure-dev/internal/scans/store"
	"github.com/aizen299/secure-dev/internal/worker"
)

// zapStandIn takes ZAP's place beside the adapter, as a real endpoint scan has
// it. A scan where nothing fully succeeded is FAILED rather than PARTIAL, so the
// degraded case below only means what it does in production with this present.
type zapStandIn struct{}

func (zapStandIn) Name() string { return "zap-stand-in" }
func (zapStandIn) Capabilities() scanners.Capabilities {
	return scanners.Capabilities{
		Kinds:      []scanners.Kind{scanners.KindEndpoint},
		Categories: []scanners.Category{scanners.CategoryDAST},
	}
}
func (zapStandIn) Version(context.Context) (string, error) { return "0.0.1-test", nil }
func (zapStandIn) Scan(_ context.Context, target scanners.Target) (scanners.RawResult, error) {
	return scanners.RawResult{Scanner: "zap-stand-in", Version: "0.0.1-test", Target: target, Output: []byte("{}")}, nil
}

// runHTTPProbeScan puts one scan of target through real Redis, the real worker,
// the real adapter, and real PostgreSQL. Local test servers are on loopback, so
// the policy allows it here; nothing else in this file relaxes it.
func runHTTPProbeScan(
	t *testing.T, pool *pgxpool.Pool, client *goredis.Client, scanID, projectID, target string,
) {
	t.Helper()
	// What the API stores for a real scan, which resolving reads (ADR 042).
	encoded, err := json.Marshal(scanners.Target{Kind: scanners.KindEndpoint, EndpointURL: target})
	if err != nil {
		t.Fatalf("encode target: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE scans SET target = $1 WHERE id = $2`, encoded, scanID); err != nil {
		t.Fatalf("set target: %v", err)
	}

	key := "secureops:itest:" + uuid.NewString()
	t.Cleanup(func() { _ = client.Del(context.Background(), key).Err() })

	policy := netguard.Policy{AllowPrivate: true}
	reg := scanners.NewRegistry()
	reg.MustRegister(httpprobe.New(policy))
	reg.MustRegister(zapStandIn{})

	store := scanstore.New(pool)
	root := t.TempDir()
	runner, err := worker.New(worker.Options{
		Registry:       reg,
		Queue:          queue.NewRedis(client, key),
		Store:          store,
		Sink:           store,
		Findings:       findings.NewStore(pool),
		Validator:      scanners.Validator{WorkspaceRoot: root, NetworkPolicy: policy},
		WorkspaceRoot:  root,
		Logger:         slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Concurrency:    1,
		PollTimeout:    200 * time.Millisecond,
		ScannerTimeout: 20 * time.Second,
		JobTimeout:     30 * time.Second,
	})
	if err != nil {
		t.Fatalf("worker.New: %v", err)
	}

	if err := queue.NewRedis(client, key).Enqueue(t.Context(), queue.Job{
		ScanID: scanID, ProjectID: projectID, Attempt: 1,
		Target: scanners.Target{Kind: scanners.KindEndpoint, EndpointURL: target},
	}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	drainQueue(t, runner, 8*time.Second)
}

func nextScan(t *testing.T, pool *pgxpool.Pool, projectID string) string {
	t.Helper()
	var scanID string
	if err := pool.QueryRow(t.Context(),
		`INSERT INTO scans (project_id, status) VALUES ($1, 'queued') RETURNING id`,
		projectID).Scan(&scanID); err != nil {
		t.Fatalf("insert scan: %v", err)
	}
	return scanID
}

func findingStates(t *testing.T, pool *pgxpool.Pool, projectID string) []string {
	t.Helper()
	stored, _, err := findings.NewStore(pool).ListByProject(
		t.Context(), projectID, findings.Filter{}, findings.Page{Limit: 50})
	if err != nil {
		t.Fatalf("ListByProject: %v", err)
	}
	out := []string{}
	for _, f := range stored {
		out = append(out, string(f.Severity)+"/"+string(f.Status))
	}
	slices.Sort(out)
	return out
}

// The whole life of a finding from this adapter: found, kept through a scan that
// could not tell, and resolved by one that could.
func TestHTTPProbeThroughThePipeline(t *testing.T) {
	pool := testPool(t)
	client := testRedis(t)

	// 0 misconfigured, 1 cannot tell, 2 fixed, 3 route gone.
	var state atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=NOTAREALTOKEN")
		origin := r.Header.Get("Origin")
		switch {
		case state.Load() == 3 && origin != "":
			w.WriteHeader(http.StatusNotFound)
		case state.Load() == 1 && origin != "":
			// A redirect off the site: the CORS check cannot reach a page.
			w.Header().Set("Location", "https://elsewhere.example.test/")
			w.WriteHeader(http.StatusFound)
		case state.Load() == 2 && origin == "":
			w.Header().Set("Location", "https://example.test/")
			w.WriteHeader(http.StatusMovedPermanently)
		case state.Load() != 2 && origin != "":
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	target := srv.URL + "/api/account?api_key=NOTAREALTOKEN"

	scanID, projectID := seedScan(t, pool)
	runHTTPProbeScan(t, pool, client, scanID, projectID, target)

	if got := scanStatus(t, pool, scanID); got != "completed" {
		t.Errorf("first scan status = %q, want completed", got)
	}
	var version string
	if err := pool.QueryRow(t.Context(),
		`SELECT scanner_version FROM scan_scanner_results WHERE scan_id = $1 AND scanner = $2`,
		scanID, httpprobe.Name).Scan(&version); err != nil {
		t.Fatalf("read scanner result: %v", err)
	}
	if version != httpprobe.Version {
		t.Errorf("scanner_version = %q, want %q (§7 rule 6)", version, httpprobe.Version)
	}
	if got, want := findingStates(t, pool, projectID), []string{"high/open", "medium/open"}; !slices.Equal(got, want) {
		t.Errorf("after the first scan = %v, want %v", got, want)
	}

	// §15.3: what the database holds, not only what the adapter returned.
	var output []byte
	if err := pool.QueryRow(t.Context(),
		`SELECT output FROM scan_raw_results WHERE scan_id = $1`, scanID).Scan(&output); err != nil {
		t.Fatalf("read raw result: %v", err)
	}
	if strings.Contains(string(output), "NOTAREALTOKEN") {
		t.Errorf("stored output carries the target's credential: %s", output)
	}

	// A scan that could not tell must not say the problem is gone (ADR 010).
	state.Store(1)
	partial := nextScan(t, pool, projectID)
	runHTTPProbeScan(t, pool, client, partial, projectID, target)
	if got := scanStatus(t, pool, partial); got != "partial" {
		t.Errorf("incomplete scan status = %q, want partial", got)
	}
	if got := findingStates(t, pool, projectID); slices.Contains(got, "high/resolved") {
		t.Errorf("after an incomplete scan = %v, the CORS finding must not be resolved", got)
	}

	// A route that has gone says nothing about whether the problem has (ADR 041).
	state.Store(3)
	gone := nextScan(t, pool, projectID)
	runHTTPProbeScan(t, pool, client, gone, projectID, target)
	if got := scanStatus(t, pool, gone); got != "partial" {
		t.Errorf("scan of a missing route status = %q, want partial", got)
	}
	if got := findingStates(t, pool, projectID); slices.Contains(got, "high/resolved") {
		t.Errorf("after a scan of a missing route = %v, the CORS finding must not be resolved", got)
	}

	// A clean scan of another page says nothing about this one (ADR 042).
	state.Store(2)
	elsewhere := nextScan(t, pool, projectID)
	runHTTPProbeScan(t, pool, client, elsewhere, projectID, srv.URL+"/login")
	if got := scanStatus(t, pool, elsewhere); got != "completed" {
		t.Errorf("scan of another page status = %q, want completed", got)
	}
	if got := findingStates(t, pool, projectID); slices.Contains(got, "high/resolved") {
		t.Errorf("after a scan of another page = %v, the CORS finding must stay open", got)
	}

	// Now really fixed, and a scan that can say so.
	state.Store(2)
	fixed := nextScan(t, pool, projectID)
	runHTTPProbeScan(t, pool, client, fixed, projectID, target)
	if got := scanStatus(t, pool, fixed); got != "completed" {
		t.Errorf("clean scan status = %q, want completed", got)
	}
	if got, want := findingStates(t, pool, projectID), []string{"high/resolved", "medium/resolved"}; !slices.Equal(got, want) {
		t.Errorf("after the fix = %v, want %v", got, want)
	}
}
