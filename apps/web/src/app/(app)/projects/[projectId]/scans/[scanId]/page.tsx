import { notFound } from "next/navigation";
import { getScan, getScanGate, optional, ApiError } from "@/lib/api";
import { scanCoverageLabel } from "@/lib/scan-coverage";
import { PageBody } from "@/components/shell/page-header";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { ScanStatusBadge } from "@/components/security/status";
import { VerdictBadge } from "@/components/security/verdict";
import { EmptyState } from "@/components/security/empty";
import { RelativeTime } from "@/components/security/relative-time";
import { Metric } from "@/components/security/metric";

export const dynamic = "force-dynamic";

const SCANNER_STATUS_TONE: Record<string, string> = {
  succeeded: "text-pass",
  failed: "text-fail",
  skipped: "text-ink-faint",
  timed_out: "text-fail",
};

export default async function ScanDetail({
  params,
}: {
  params: Promise<{ projectId: string; scanId: string }>;
}) {
  const { scanId } = await params;

  let scan;
  try {
    scan = await getScan(scanId);
  } catch (error) {
    if (error instanceof ApiError && error.isNotFound) notFound();
    throw error;
  }
  const gate = await optional(() => getScanGate(scanId));

  const target =
    scan.target.repository_url ?? scan.target.image ?? scan.target.endpoint_url ?? scan.target.kind;

  return (
    <PageBody className="space-y-4">
      <Card>
        <CardHeader>
          <div className="min-w-0 space-y-1.5">
            <div className="flex items-center gap-2">
              <ScanStatusBadge status={scan.status} />
              {!scan.complete_coverage && (
                <span className="text-[12px] text-warn">Degraded coverage</span>
              )}
            </div>
            <p className="truncate font-mono text-[13px] text-ink">{target}</p>
          </div>
          {gate && <VerdictBadge verdict={gate.verdict} size="lg" />}
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Metric label="Target kind" value={<span className="text-[15px] capitalize">{scan.target.kind}</span>} />
            <Metric
              label="Commit"
              value={
                <span className="font-mono text-[15px]">
                  {scan.commit_sha ? scan.commit_sha.slice(0, 8) : "—"}
                </span>
              }
              hint={scan.branch}
            />
            <Metric
              label="Queued"
              value={<span className="text-[15px]"><RelativeTime value={scan.queued_at} /></span>}
            />
            <Metric
              label="Finished"
              value={
                <span className="text-[15px]">
                  {scan.completed_at ? <RelativeTime value={scan.completed_at} /> : "—"}
                </span>
              }
            />
          </div>
          {scan.failure_reason && (
            <p className="mt-4 rounded-md border border-fail/25 bg-fail-dim px-3 py-2 text-[12px] text-fail">
              {scan.failure_reason}
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Scanner coverage</CardTitle>
          <span className="text-[12px] text-ink-faint">
            {scanCoverageLabel(scan.results?.length ?? 0, scan.requested_scanners?.length ?? 0)}
          </span>
        </CardHeader>
        <CardContent>
          {scan.results && scan.results.length > 0 ? (
            <div className="space-y-px">
              {scan.results.map((result) => (
                <div
                  key={result.scanner}
                  className="grid grid-cols-[130px_90px_minmax(0,1fr)_auto] items-baseline gap-3 border-b border-line py-2 last:border-b-0"
                >
                  <span className="font-mono text-[12px] text-ink">{result.scanner}</span>
                  <span
                    className={`text-[12px] capitalize ${
                      SCANNER_STATUS_TONE[result.status] ?? "text-ink-muted"
                    }`}
                  >
                    {result.status.replace(/_/g, " ")}
                  </span>
                  <span className="min-w-0 truncate text-[12px] text-ink-faint">
                    {/* Degradations are why a scan is PARTIAL rather than
                        COMPLETE. Showing them is what makes the state
                        actionable instead of merely alarming (ADR 010). */}
                    {result.error ??
                      (result.degradations && result.degradations.length > 0
                        ? result.degradations.map((d) => d.replace(/_/g, " ")).join(", ")
                        : "")}
                  </span>
                  <span className="text-right font-mono text-[11px] text-ink-faint">
                    {result.version ?? "—"}
                    {result.duration_ms !== undefined && (
                      <span className="ml-2">{(result.duration_ms / 1000).toFixed(1)}s</span>
                    )}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState title="No scanner results" description="This scan has not reported yet." />
          )}
        </CardContent>
      </Card>

      {gate && (
        <Card>
          <CardHeader>
            <CardTitle>Gate</CardTitle>
            <VerdictBadge verdict={gate.verdict} />
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-[13px] leading-relaxed text-ink-muted">{gate.summary}</p>
            <div className="space-y-1 rule pt-3">
              {gate.conditions.map((condition, i) => (
                <div
                  key={`${condition.kind}-${i}`}
                  className="flex items-baseline justify-between gap-4 py-1"
                >
                  <span className="min-w-0 flex-1 truncate text-[12px] text-ink-muted">
                    {condition.explanation}
                  </span>
                  <span
                    className={`shrink-0 font-mono text-[12px] tabular-nums ${
                      condition.breached ? "text-fail" : "text-ink-faint"
                    }`}
                  >
                    {formatMetric(condition.observed)} / {formatMetric(condition.max)}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </PageBody>
  );
}

/** Mirrors the API's own formatting: counts whole, a score to one decimal.
 *  A gate that quotes fifteen decimals reads as broken rather than precise. */
function formatMetric(value: number): string {
  return Number.isInteger(value) ? String(value) : value.toFixed(1);
}
