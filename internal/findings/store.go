// Package findings persists the canonical findings that normalization produces.
//
// Split from internal/normalization deliberately: that package is pure by
// contract, and a database handle in it would make the claim untrue. This one
// owns storage and the lifecycle state machine; that one owns the
// transformation.
package findings

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// Reasons recorded on a lifecycle transition. A fixed vocabulary rather than
// free text, so "why did this become resolved?" is a query rather than a search.
const (
	ReasonFirstSeen   = "first_seen"
	ReasonReopened    = "reopened"
	ReasonNotReported = "not_reported"
)

// ActorSystem is the actor for scan-driven transitions, which is most of them:
// a finding becomes resolved because a scan stopped reporting it, not because
// anyone decided anything. Phase 11 adds named principals.
const ActorSystem = "system"

// Store persists findings, their occurrences, their links, and their history.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// RecordScan persists one scan's normalized results.
//
// Everything happens in one transaction. A half-written scan would leave
// findings whose occurrences are missing, which reads as "seen but nowhere",
// and lifecycle transitions that no scan explains.
func (s *Store) RecordScan(
	ctx context.Context, projectID, scanID string, result normalization.DedupResult,
	completeScanners []string, at time.Time,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("record findings: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	idByFingerprint := make(map[string]string, len(result.Findings))
	for _, f := range result.Findings {
		id, err := upsertFinding(ctx, tx, projectID, scanID, f, at)
		if err != nil {
			return err
		}
		idByFingerprint[f.Fingerprint] = id
	}

	for _, occ := range result.Occurrences {
		findingID, ok := idByFingerprint[occ.Fingerprint]
		if !ok {
			// An occurrence for a finding that was not stored means the two
			// halves of one result disagree, which is a bug rather than data.
			return fmt.Errorf("record findings: occurrence for unknown fingerprint %s", occ.Fingerprint)
		}
		if err := insertOccurrence(ctx, tx, findingID, scanID, occ); err != nil {
			return err
		}
	}

	if err := resolveUnreported(ctx, tx, projectID, scanID, completeScanners, at); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// upsertFinding inserts a finding or advances an existing one, and records any
// lifecycle transition that results.
func upsertFinding(
	ctx context.Context, tx pgx.Tx, projectID, scanID string,
	f normalization.MergedFinding, at time.Time,
) (string, error) {
	var (
		id        string
		prevState *string
	)

	// The upsert returns the status as it was BEFORE this statement, so the
	// transition can be recorded accurately. Reading it afterwards would see
	// the new value and report every finding as unchanged.
	err := tx.QueryRow(ctx, `
		WITH previous AS (
		    SELECT id, status FROM findings
		     WHERE project_id = $1 AND fingerprint = $2
		)
		INSERT INTO findings (
		    project_id, fingerprint, scanner, scanner_finding_id, scanner_severity,
		    category, severity, confidence, title, description, remediation,
		    package, package_version, purl, cve, cwe, cvss, image, endpoint,
		    epss_probability, epss_percentile, epss_source, epss_observed_at,
		    fix_state, fix_versions, fix_references,
		    status, first_seen, last_seen)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$26,$27,
		        $19,$20,$21,$22,$23,$24,$25,'open',$18,$18)
		ON CONFLICT (project_id, fingerprint) DO UPDATE SET
		    last_seen = EXCLUDED.last_seen,
		    -- Severity can move: a vendor rescoring a CVE, or a second scanner
		    -- reporting it worse. Prose is refreshed for the same reason.
		    severity    = EXCLUDED.severity,
		    title       = EXCLUDED.title,
		    description = EXCLUDED.description,
		    remediation = EXCLUDED.remediation,
		    -- Threat intelligence is refreshed on every sighting: EPSS is
		    -- recomputed daily, so a stored value goes stale where a title
		    -- does not. Overwritten wholesale rather than merged, so the four
		    -- columns always describe one observation.
		    epss_probability = EXCLUDED.epss_probability,
		    epss_percentile  = EXCLUDED.epss_percentile,
		    epss_source      = EXCLUDED.epss_source,
		    epss_observed_at = EXCLUDED.epss_observed_at,
		    -- Fix facts are refreshed too. A vulnerability with no fix today
		    -- may have one next week, and a stale "no fix available" is how a
		    -- fixable finding sits unremediated. Overwritten wholesale so the
		    -- three columns always describe one advisory state.
		    fix_state      = EXCLUDED.fix_state,
		    fix_versions   = EXCLUDED.fix_versions,
		    fix_references = EXCLUDED.fix_references,
		    -- Refreshed, though it cannot in practice change: the repository
		    -- is part of this finding's fingerprint, so a different image is a
		    -- different row. Written on update anyway, so a finding stored
		    -- before this column existed gains it on its next sighting rather
		    -- than staying null forever.
		    image = EXCLUDED.image,
		    endpoint = EXCLUDED.endpoint,
		    -- A finding that was resolved and is reported again has come back.
		    -- Anything a person set -- acknowledged, ignored, false_positive --
		    -- is left alone: a scan must not overrule a human judgement.
		    status = CASE
		        WHEN findings.status = 'resolved' THEN 'reopened'::finding_status
		        ELSE findings.status
		    END
		RETURNING id, (SELECT status::text FROM previous)`,
		projectID, f.Fingerprint, f.Scanner, nullIfEmpty(f.ScannerFindingID),
		nullIfEmpty(f.ScannerSeverity), string(f.Category), string(f.Severity),
		string(f.Confidence), f.Title, nullIfEmpty(f.Description), nullIfEmpty(f.Remediation),
		nullIfEmpty(f.Package), nullIfEmpty(f.PackageVersion), nullIfEmpty(f.PURL),
		nullIfEmpty(f.CVE), nullIfEmpty(f.CWE), nullIfZero(f.CVSS),
		at.UTC(),
		epssProbability(f.Threat), epssPercentile(f.Threat),
		epssSource(f.Threat), epssObservedAt(f.Threat),
		fixState(f.Fix), emptySlice(f.Fix.FixedVersions), emptySlice(f.Fix.References),
		nullIfEmpty(f.Image), nullIfEmpty(f.Endpoint),
	).Scan(&id, &prevState)
	if err != nil {
		return "", fmt.Errorf("upsert finding: %w", err)
	}

	switch {
	case prevState == nil:
		// Newly discovered.
		if err := recordTransition(ctx, tx, id, nil, "open", ReasonFirstSeen, scanID, at); err != nil {
			return "", err
		}
	case *prevState == "resolved":
		// It came back. Distinct from never having been fixed.
		from := "resolved"
		if err := recordTransition(ctx, tx, id, &from, "reopened", ReasonReopened, scanID, at); err != nil {
			return "", err
		}
	}
	return id, nil
}

// resolveUnreported closes findings this scan did not report.
//
// The correctness question here is which findings a scan is entitled to
// resolve. A scan that ran only gitleaks says nothing about semgrep's findings,
// and marking them resolved would be a false "fixed" -- the same class of error
// as a PARTIAL scan reported as clean (§13, ADR 010).
//
// So a finding is eligible only when EVERY scanner that has ever reported it
// completed successfully in this scan. "Every", not "the first one": findings
// carry a single scanner column recording who saw it first, and a finding both
// grype and trivy report would otherwise resolve the moment grype came back
// clean, even though trivy failed and was never asked.
//
// The conservative direction is deliberate. A finding stays open until every
// scanner that vouched for it has had its say, which means dropping a scanner
// from a project's selection leaves that scanner's old findings open rather
// than silently declaring them fixed. Stale-but-open is a visible state; a
// false "resolved" is not.
//
// A website scan has one more condition, for the same reason. It looks at the URL
// it was given, not at the whole target, so a clean scan of /login says nothing
// about a finding from a scan of /api/account. See findingsThisScanLookedAt.
//
// Only website scans have this condition today. Other kinds keep the rule above,
// which has the same gap in another form: scanning image B can resolve findings
// from image A, because nothing here compares the two targets (ADR 042).
func resolveUnreported(
	ctx context.Context, tx pgx.Tx, projectID, scanID string,
	completeScanners []string, at time.Time,
) error {
	if len(completeScanners) == 0 {
		return nil
	}

	limited, eligible, err := findingsThisScanLookedAt(ctx, tx, projectID, scanID, completeScanners)
	if err != nil {
		return err
	}
	if limited && len(eligible) == 0 {
		return nil
	}

	rows, err := tx.Query(ctx, `
		UPDATE findings f
		   SET status = 'resolved'
		 WHERE f.project_id = $1
		   AND f.scanner = ANY($2)
		   AND f.status IN ('open', 'reopened')
		   -- Not reported by THIS scan.
		   AND NOT EXISTS (
		       SELECT 1 FROM finding_occurrences o
		        WHERE o.finding_id = f.id AND o.scan_id = $3
		   )
		   -- And no scanner that has ever reported it is missing from the
		   -- completed set. A single failed reporter blocks the resolve.
		   AND NOT EXISTS (
		       SELECT 1 FROM finding_occurrences o
		        WHERE o.finding_id = f.id AND NOT (o.scanner = ANY($2))
		   )
		   -- And, for a website scan, it must be something this scan looked at.
		   AND (NOT $4::boolean OR f.id::text = ANY($5::text[]))
		RETURNING f.id, f.status`,
		projectID, completeScanners, scanID, limited, eligible)
	if err != nil {
		return fmt.Errorf("resolve unreported findings: %w", err)
	}

	var ids []string
	for rows.Next() {
		var id, status string
		if err := rows.Scan(&id, &status); err != nil {
			rows.Close()
			return fmt.Errorf("resolve unreported findings: %w", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("resolve unreported findings: %w", err)
	}

	for _, id := range ids {
		// from_status is not read back per row: both 'open' and 'reopened'
		// transition to 'resolved' for the same reason, and the history's
		// value is in the reason and the timestamp.
		if err := recordTransition(ctx, tx, id, nil, "resolved", ReasonNotReported, scanID, at); err != nil {
			return err
		}
	}
	return nil
}

// findingsThisScanLookedAt says which open findings a website scan is entitled to
// resolve: those whose most recent report came from a scan of the same URL path.
//
// Most recent, rather than any earlier one, because a finding two URLs have reported
// may only be reachable from one of them now, and the other coming back clean would
// be a false "fixed". Only the path is compared, because preview hostnames churn
// (ADR 026). limited is false for any other kind of scan, which has no such
// condition. A scan with no usable URL is limited and entitled to nothing.
//
// Compared here rather than in SQL so that it uses the normalization identity uses,
// and so that a scan of any other kind costs one read (ADR 042).
func findingsThisScanLookedAt(
	ctx context.Context, tx pgx.Tx, projectID, scanID string, completeScanners []string,
) (limited bool, eligible []string, err error) {
	var kind, target *string
	err = tx.QueryRow(ctx, `
		SELECT target ->> 'kind', target ->> 'endpoint_url' FROM scans WHERE id = $1`,
		scanID).Scan(&kind, &target)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, fmt.Errorf("read scan target: %w", err)
	}
	if kind == nil || *kind != string(scanners.KindEndpoint) {
		return false, nil, nil
	}
	if target == nil {
		return true, nil, nil
	}
	current, ok := normalization.EndpointTargetPath(*target)
	if !ok {
		return true, nil, nil
	}

	rows, err := tx.Query(ctx, `
		SELECT DISTINCT ON (o.finding_id) o.finding_id::text, s.target ->> 'endpoint_url'
		  FROM finding_occurrences o
		  JOIN findings f ON f.id = o.finding_id
		  JOIN scans s ON s.id = o.scan_id
		 WHERE f.project_id = $1
		   AND f.scanner = ANY($3)
		   AND f.status IN ('open', 'reopened')
		   AND o.scan_id <> $2
		 ORDER BY o.finding_id, o.seen_at DESC, s.created_at DESC`,
		projectID, scanID, completeScanners)
	if err != nil {
		return true, nil, fmt.Errorf("read finding targets: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id string
		var reportedFrom *string
		if err := rows.Scan(&id, &reportedFrom); err != nil {
			return true, nil, fmt.Errorf("read finding targets: %w", err)
		}
		if reportedFrom == nil {
			continue
		}
		if path, ok := normalization.EndpointTargetPath(*reportedFrom); ok && path == current {
			eligible = append(eligible, id)
		}
	}
	if err := rows.Err(); err != nil {
		return true, nil, fmt.Errorf("read finding targets: %w", err)
	}
	return true, eligible, nil
}

func recordTransition(
	ctx context.Context, tx pgx.Tx, findingID string, from *string,
	to, reason, scanID string, at time.Time,
) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO finding_status_history
		    (finding_id, from_status, to_status, actor, reason, scan_id, changed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		findingID, from, to, ActorSystem, reason, nullIfEmpty(scanID), at.UTC())
	if err != nil {
		return fmt.Errorf("record status transition: %w", err)
	}
	return nil
}

func insertOccurrence(
	ctx context.Context, tx pgx.Tx, findingID, scanID string, o normalization.Occurrence,
) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO finding_occurrences
		    (finding_id, scan_id, scanner, file, start_line, end_line, seen_at)
		VALUES ($1,$2,$3,$4,$5,$6,now())
		ON CONFLICT (finding_id, scan_id, scanner, file, start_line) DO NOTHING`,
		findingID, scanID, o.Scanner, nullIfEmpty(o.File),
		nullIfZero(float64(o.StartLine)), nullIfZero(float64(o.EndLine)))
	if err != nil {
		return fmt.Errorf("insert occurrence: %w", err)
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullIfZero(f float64) any {
	if f == 0 {
		return nil
	}
	return f
}

// Page bounds a listing. Mirrors scans.Page: every list endpoint paginates
// (§18), and an unbounded query over findings is the one most likely to hurt.
type Page struct {
	Limit  int
	Offset int
}

const (
	defaultLimit = 50
	maxLimit     = 200
)

func (p Page) normalize() Page {
	if p.Limit <= 0 {
		p.Limit = defaultLimit
	}
	if p.Limit > maxLimit {
		p.Limit = maxLimit
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	return p
}

// Filter narrows a listing. Zero values mean "no constraint".
type Filter struct {
	Status   string
	Severity string
	Scanner  string
}

// Record is a stored finding as read back, with the sightings that support it.
type Record struct {
	normalization.Finding
	ID string
	// Sources are the distinct scanners that have reported this finding,
	// derived from its occurrences rather than stored: two scanners agreeing
	// is a fact about the sightings.
	Sources     []string
	Occurrences int
	FirstSeen   time.Time
	LastSeen    time.Time
}

const recordColumns = `
	f.id, f.fingerprint, f.scanner, f.scanner_finding_id, f.scanner_severity,
	f.category, f.severity, f.confidence, f.title, f.description, f.remediation,
	f.package, f.package_version, f.purl, f.cve, f.cwe, f.cvss, f.image, f.endpoint,
	f.epss_probability, f.epss_percentile, f.epss_source, f.epss_observed_at,
	f.fix_state, f.fix_versions, f.fix_references,
	f.status, f.first_seen, f.last_seen,
	(SELECT count(*) FROM finding_occurrences o WHERE o.finding_id = f.id),
	(SELECT coalesce(array_agg(DISTINCT o.scanner), '{}')
	   FROM finding_occurrences o WHERE o.finding_id = f.id)`

// ListByProject returns a project's findings, most severe first.
//
// Ordered by severity then recency because a findings list is read to decide
// what to do next, and the answer is almost always "the worst thing most
// recently seen".
func (s *Store) ListByProject(
	ctx context.Context, projectID string, filter Filter, page Page,
) ([]Record, bool, error) {
	page = page.normalize()

	rows, err := s.pool.Query(ctx, `
		SELECT `+recordColumns+`
		  FROM findings f
		 WHERE f.project_id = $1
		   AND ($2 = '' OR f.status::text = $2)
		   AND ($3 = '' OR f.severity::text = $3)
		   AND ($4 = '' OR f.scanner = $4)
		 ORDER BY
		     CASE f.severity
		         WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
		         WHEN 'unknown' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
		     f.last_seen DESC, f.id
		 LIMIT $5 OFFSET $6`,
		projectID, filter.Status, filter.Severity, filter.Scanner,
		page.Limit+1, page.Offset)
	if err != nil {
		return nil, false, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	return collectRecords(rows, page.Limit)
}

// ListByScan returns the findings a specific scan reported.
func (s *Store) ListByScan(
	ctx context.Context, scanID string, page Page,
) ([]Record, bool, error) {
	page = page.normalize()

	rows, err := s.pool.Query(ctx, `
		SELECT `+recordColumns+`
		  FROM findings f
		 WHERE EXISTS (
		     SELECT 1 FROM finding_occurrences o
		      WHERE o.finding_id = f.id AND o.scan_id = $1
		 )
		 ORDER BY
		     CASE f.severity
		         WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
		         WHEN 'unknown' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
		     f.last_seen DESC, f.id
		 LIMIT $2 OFFSET $3`,
		scanID, page.Limit+1, page.Offset)
	if err != nil {
		return nil, false, fmt.Errorf("list scan findings: %w", err)
	}
	defer rows.Close()

	return collectRecords(rows, page.Limit)
}

func collectRecords(rows pgx.Rows, limit int) ([]Record, bool, error) {
	out := make([]Record, 0, limit)
	for rows.Next() {
		var (
			r                     Record
			findingID, sevStr     string
			catStr, confStr       string
			statusStr             string
			scannerFindingID      *string
			scannerSeverity       *string
			description, remedy   *string
			pkg, pkgVersion, purl *string
			cve, cwe              *string
			image, endpoint       *string
			cvss                  *float64
			epssProb, epssPct     *float64
			epssSrc               *string
			epssObserved          *time.Time
			fixSt                 *string
			fixVersions, fixRefs  []string
		)
		if err := rows.Scan(
			&findingID, &r.Fingerprint, &r.Scanner, &scannerFindingID, &scannerSeverity,
			&catStr, &sevStr, &confStr, &r.Title, &description, &remedy,
			&pkg, &pkgVersion, &purl, &cve, &cwe, &cvss, &image, &endpoint,
			&epssProb, &epssPct, &epssSrc, &epssObserved,
			&fixSt, &fixVersions, &fixRefs,
			&statusStr, &r.FirstSeen, &r.LastSeen, &r.Occurrences, &r.Sources,
		); err != nil {
			return nil, false, fmt.Errorf("scan finding row: %w", err)
		}

		r.ID = findingID
		r.Category = scanners.Category(catStr)
		r.Severity = normalization.Severity(sevStr)
		r.Confidence = normalization.Confidence(confStr)
		r.Status = normalization.Status(statusStr)
		assignIfPresent(&r.ScannerFindingID, scannerFindingID)
		assignIfPresent(&r.ScannerSeverity, scannerSeverity)
		assignIfPresent(&r.Description, description)
		assignIfPresent(&r.Remediation, remedy)
		// A NULL fix state is `unknown`: nobody told us. It must not read back
		// as a state a scanner asserted.
		if fixSt != nil {
			r.Fix.State = normalization.FixState(*fixSt)
		}
		r.Fix.FixedVersions = fixVersions
		r.Fix.References = fixRefs
		assignIfPresent(&r.Package, pkg)
		assignIfPresent(&r.PackageVersion, pkgVersion)
		assignIfPresent(&r.PURL, purl)
		assignIfPresent(&r.Image, image)
		assignIfPresent(&r.Endpoint, endpoint)
		assignIfPresent(&r.CVE, cve)
		assignIfPresent(&r.CWE, cwe)
		if cvss != nil {
			r.CVSS = *cvss
		}
		// All four or none, enforced by findings_epss_all_or_nothing. Testing
		// every column rather than trusting the constraint costs nothing and
		// means a partially written row degrades to "no signal" instead of a
		// value with missing provenance.
		if epssProb != nil && epssPct != nil && epssSrc != nil && epssObserved != nil {
			r.Threat.EPSS = &normalization.EPSS{
				Probability: *epssProb,
				Percentile:  *epssPct,
				Source:      *epssSrc,
				ObservedAt:  *epssObserved,
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("scan finding rows: %w", err)
	}

	// One row beyond the limit was requested, so "is there more?" is answered
	// without a second count query.
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

func assignIfPresent(dst *string, v *string) {
	if v != nil {
		*dst = *v
	}
}

// The EPSS accessors below exist because a nil *EPSS must reach the database as
// four NULLs, not as four zero values. nullIfZero cannot express that: 0 is a
// legitimate EPSS probability, so "absent" and "lowest possible" would collapse
// into the same row (ADR 018).

func epssProbability(t normalization.ThreatIntel) any {
	if t.EPSS == nil {
		return nil
	}
	return t.EPSS.Probability
}

func epssPercentile(t normalization.ThreatIntel) any {
	if t.EPSS == nil {
		return nil
	}
	return t.EPSS.Percentile
}

func epssSource(t normalization.ThreatIntel) any {
	if t.EPSS == nil {
		return nil
	}
	return t.EPSS.Source
}

func epssObservedAt(t normalization.ThreatIntel) any {
	if t.EPSS == nil {
		return nil
	}
	return t.EPSS.ObservedAt.UTC()
}

// fixState renders a fix state for storage, mapping the zero value to NULL.
//
// `unknown` is the absence of a claim, and NULL is how the schema says that.
// Storing it as a fourth enum value would make "nobody told us" look like a
// state a scanner asserted.
func fixState(f normalization.Fix) any {
	if f.State == normalization.FixStateUnknown {
		return nil
	}
	return string(f.State)
}

// emptySlice normalises a nil slice to an empty one, because the columns are
// NOT NULL and a nil would be written as NULL rather than as "{}".
func emptySlice(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
