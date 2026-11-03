import Link from "next/link";
import { ArrowRightIcon, ArrowUpRightIcon, PlugZapIcon } from "lucide-react";
import {
  listProjects,
  getProjectRisk,
  collect,
  optional,
  MissingCredentialError,
  type Project,
  type Risk,
} from "@/lib/api";
import { PageBody } from "@/components/shell/page-header";
import { SetupNotice } from "@/components/shell/setup-notice";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/security/empty";
import { Metric, Trend } from "@/components/security/metric";
import { Distribution, ScoreBar, type Segment } from "@/components/security/distribution";
import { Pipeline, DotGrid } from "@/components/security/pipeline";
import { Reveal, Stagger, StaggerItem, Counter } from "@/components/security/motion";
import { ScanBar } from "@/components/security/scan-bar";
import { Logo } from "@/components/security/wordmark";
import { RelativeTime } from "@/components/security/relative-time";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";

interface Row {
  project: Project;
  risk: Risk | null;
}

/**
 * The score bands, and the one place they are defined.
 *
 * The same thresholds colour a score, sort it into the distribution, and label
 * it. Three copies of these numbers would eventually disagree, and a project
 * shown as "high" in one panel and "medium" in another is a dashboard nobody
 * trusts twice.
 */
/*
 * `text` is written out rather than interpolated as `text-${color}`. Tailwind
 * generates classes by scanning source text, so a constructed class name is
 * simply absent from the stylesheet -- and the failure is a score that renders
 * in the default colour, which looks like a design choice rather than a bug.
 */
interface Band {
  label: string;
  color: string;
  text: string;
  min: number;
}

const CLEAN: Band = { label: "Clean", color: "pass", text: "text-pass", min: 0 };

const BANDS: Band[] = [
  { label: "Critical", color: "critical", text: "text-critical", min: 75 },
  { label: "High", color: "high", text: "text-high", min: 50 },
  { label: "Medium", color: "medium", text: "text-medium", min: 25 },
  { label: "Low", color: "low", text: "text-low", min: 0.05 },
  CLEAN,
];

function band(score: number): Band {
  return BANDS.find((b) => score >= b.min) ?? CLEAN;
}

type LoadResult =
  | { ok: true; rows: Row[]; addedThisWeek: number }
  | { ok: false; reason: "unconfigured" | "unreachable" };

async function load(): Promise<LoadResult> {
  try {
    const { items } = await collect<Project>(async (limit, offset) => {
      const page = await listProjects({ limit, offset });
      return { items: page.data, hasMore: page.pagination.has_more };
    }, 20);

    const rows = await Promise.all(
      items.map(async (project) => ({
        project,
        // Two points is all a delta needs, and asking for more would make this
        // request heavier for every project on the page to serve a panel that
        // only shows the last change.
        risk: await optional(() => getProjectRisk(project.id, { history: 2 })),
      })),
    );
    // Counted here rather than in the component: reading the clock during
    // render is impure, and this is data about the fetched rows anyway.
    const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    const addedThisWeek = rows.filter(
      (r) => new Date(r.project.created_at).getTime() >= weekAgo,
    ).length;

    return { ok: true, rows, addedThisWeek };
  } catch (error) {
    if (error instanceof MissingCredentialError) return { ok: false, reason: "unconfigured" };
    return { ok: false, reason: "unreachable" };
  }
}

export default async function Home() {
  const result = await load();

  return (
    <PageBody className="space-y-8 py-10">
      <Hero />

      <Reveal delay={0.14}>
        <ScanBar />
      </Reveal>

      {!result.ok ? (
        result.reason === "unconfigured" ? (
          <SetupNotice />
        ) : (
          <Card>
            <EmptyState
              icon={<PlugZapIcon className="size-4" />}
              tone="warn"
              title="The API is unreachable"
              description="Nothing can be read right now. This is not the same as having no findings."
            />
          </Card>
        )
      ) : (
        <Fleet rows={result.rows} addedThisWeek={result.addedThisWeek} />
      )}
    </PageBody>
  );
}

function Hero() {
  return (
    <section className="relative space-y-5">
      <DotGrid />
      <div className="flex items-start gap-3.5">
        <span className="mt-0.5 flex size-10 shrink-0 items-center justify-center rounded-lg border border-line-strong bg-panel text-ink">
          <Logo className="size-5" />
        </span>
        <div className="min-w-0">
          <h1 className="text-[21px] font-semibold leading-tight tracking-[-0.02em] text-ink">
            SecureOps
          </h1>
          <p className="mt-1.5 max-w-[58ch] text-[13px] leading-relaxed text-ink-muted">
            Turns fragmented security scanner output into one contextual security
            decision. Seven scanners across secrets, dependencies, code, containers,
            infrastructure and running applications — reduced to one finding model,
            correlated, scored, and gated.
          </p>
        </div>
      </div>

      <Reveal delay={0.08}>
        <Pipeline />
      </Reveal>
    </section>
  );
}

function Fleet({ rows, addedThisWeek }: { rows: Row[]; addedThisWeek: number }) {
  const scored = rows.filter((r) => r.risk !== null);
  const findings = scored.reduce((sum, r) => sum + (r.risk?.live_findings ?? 0), 0);
  const worst = [...scored].sort((a, b) => (b.risk?.score ?? 0) - (a.risk?.score ?? 0)).slice(0, 5);
  const degraded = scored.filter((r) => r.risk && !r.risk.complete).length;

  const distribution: Segment[] = BANDS.map((b) => ({
    label: b.label,
    color: b.color,
    value: scored.filter((r) => r.risk !== null && band(r.risk.score).label === b.label).length,
  }));

  const coverage: Segment[] = [
    { label: "Complete", color: "pass", value: scored.length - degraded },
    { label: "Degraded", color: "warn", value: degraded },
    { label: "Never scanned", color: "unknown", value: rows.length - scored.length },
  ];

  return (
    <section className="space-y-7">
      <Stagger className="grid grid-cols-2 gap-x-6 gap-y-5 lg:grid-cols-4">
        <StaggerItem>
          <Metric
            label="Projects"
            value={<Counter value={rows.length} />}
            trend={
              addedThisWeek > 0 ? (
                <Trend>
                  <ArrowUpRightIcon className="size-3" /> {addedThisWeek} added this week
                </Trend>
              ) : undefined
            }
          />
        </StaggerItem>
        <StaggerItem>
          <Metric
            label="Scored"
            value={<Counter value={scored.length} />}
            hint={`${rows.length - scored.length} never scanned`}
          />
        </StaggerItem>
        <StaggerItem>
          <Metric label="Live findings" value={<Counter value={findings} />} />
        </StaggerItem>
        <StaggerItem>
          <Metric
            label="Degraded coverage"
            value={<Counter value={degraded} />}
            tone={degraded > 0 ? "warn" : "faint"}
            hint={degraded > 0 ? "Scored from incomplete scans" : "All scores from complete scans"}
          />
        </StaggerItem>
      </Stagger>

      <Reveal delay={0.06}>
        <div className="grid gap-x-10 gap-y-6 rounded-lg border border-line bg-panel px-5 py-4 md:grid-cols-2">
          <Distribution
            title="Risk distribution"
            segments={distribution}
            total={scored.length}
            empty="Nothing is scored yet, so there is no distribution to draw."
          />
          <Distribution
            title="Scan coverage"
            segments={coverage}
            total={rows.length}
            empty="No projects yet."
          />
        </div>
      </Reveal>

      {worst.length > 0 && (
        <Reveal delay={0.1}>
          <Card className="overflow-hidden">
            <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
              <span className="eyebrow">Highest risk</span>
              <Link
                href="/projects"
                className="group inline-flex items-center gap-1 rounded text-[12px] text-ink-faint transition-colors duration-150 hover:text-ink"
              >
                All projects
                <ArrowRightIcon className="size-3 transition-transform duration-150 group-hover:translate-x-0.5" />
              </Link>
            </div>
            <ul>
              {worst.map(({ project, risk }, i) => (
                <li key={project.id}>
                  <RiskRow project={project} risk={risk!} rank={i + 1} />
                </li>
              ))}
            </ul>
          </Card>
        </Reveal>
      )}
    </section>
  );
}

function RiskRow({ project, risk, rank }: { project: Project; risk: Risk; rank: number }) {
  const tone = band(risk.score);
  // The previous score for the same project, when the API returned one. No
  // previous scan means no delta -- not a delta of zero, which would claim the
  // score held steady across a comparison that never happened.
  const previous = risk.history?.find((point) => point.scan_id !== risk.scan_id);
  const delta = previous ? risk.score - previous.score : null;

  return (
    <Link
      href={`/projects/${project.id}`}
      className={cn(
        "group relative flex items-center gap-4 border-b border-line px-4 py-3",
        "transition-colors duration-150 hover:bg-raised/50",
      )}
    >
      <span
        aria-hidden
        className="absolute inset-y-0 left-0 w-px scale-y-0 transition-transform duration-150 group-hover:scale-y-100"
        style={{ backgroundColor: `var(--color-${tone.color})` }}
      />
      <span className="w-4 shrink-0 text-[11px] tabular-nums text-ink-faint">{rank}</span>

      <span className="w-24 shrink-0 space-y-1.5">
        <span
          className={cn(
            "block text-[17px] font-medium leading-none tabular-nums tracking-tight",
            tone.text,
          )}
        >
          {risk.score.toFixed(1)}
        </span>
        <ScoreBar score={risk.score} color={tone.color} />
      </span>

      <span className="min-w-0 flex-1">
        <span className="block truncate text-[13px] text-ink">{project.name}</span>
        <span className="mt-0.5 flex items-center gap-2 text-[11px] text-ink-faint">
          <span className="tabular-nums">{risk.live_findings} findings</span>
          {!risk.complete && (
            <span className="text-warn" title="Scored from an incomplete scan">
              degraded
            </span>
          )}
        </span>
      </span>

      {delta !== null && Math.abs(delta) >= 0.05 && (
        <span
          className={cn(
            "hidden shrink-0 text-[11px] tabular-nums sm:block",
            delta > 0 ? "text-critical" : "text-pass",
          )}
          title="Change since the previous scan of this project"
        >
          {delta > 0 ? "+" : "−"}
          {Math.abs(delta).toFixed(1)}
        </span>
      )}

      <span className="hidden shrink-0 text-[11px] text-ink-faint md:block">
        <RelativeTime value={risk.computed_at} />
      </span>

      <ArrowRightIcon className="size-3 shrink-0 text-ink-faint opacity-0 transition-all duration-150 group-hover:translate-x-0.5 group-hover:opacity-100" />
    </Link>
  );
}
