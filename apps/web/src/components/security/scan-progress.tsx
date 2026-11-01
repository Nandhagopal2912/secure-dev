"use client";

import * as React from "react";
import { motion, AnimatePresence } from "motion/react";
import { CheckIcon, XIcon, TriangleAlertIcon, LoaderIcon } from "lucide-react";
import { cn } from "@/lib/utils";

import type { ScanMode } from "./scan-bar";

/**
 * Which scanners a scan runs, by what it points at.
 *
 * A website scan runs ZAP and httpprobe and nothing else, so listing the five static
 * scanners for one would leave four rows spinning forever and a counter stuck
 * at "0 / 5 reported" -- the progress panel confidently reporting a stall that
 * is not happening. The registry decides this server-side; this mirrors it so
 * the panel describes the scan actually running.
 */
const SCANNERS: Record<ScanMode, { id: string; label: string; detail: string }[]> = {
  repository: [
    { id: "gitleaks", label: "Secrets", detail: "committed credentials" },
    { id: "syft", label: "SBOM", detail: "what is actually here" },
    { id: "grype", label: "Dependencies", detail: "known vulnerabilities" },
    { id: "semgrep", label: "Code", detail: "static analysis" },
    { id: "trivy", label: "Config", detail: "IaC and misconfiguration" },
  ],
  endpoint: [
    { id: "httpprobe", label: "CORS and HTTPS", detail: "origin and redirect checks" },
    { id: "zap", label: "Passive DAST", detail: "crawl, then passive rules only" },
  ],
};

/** What happens after the scanners, inside the worker. */
const STAGES = ["Normalize", "Correlate", "Score", "Gate"];

interface Result {
  scanner: string;
  status: string;
  duration_ms?: number;
  degraded?: boolean;
}

interface Progress {
  status: string;
  complete_coverage: boolean;
  results: Result[];
}

/**
 * What a scan is doing, while it does it.
 *
 * Driven by real state polled from the worker, not by a timer. A scan takes
 * thirty to seventy-five seconds, so there is genuine progress here -- and an
 * invented one would be both less interesting and a small lie told during the
 * one moment the user is paying full attention.
 *
 * The pipeline stages light up only once every scanner has reported, because
 * that is when they actually run: normalization, correlation, scoring, and the
 * gate all happen after the last scanner finishes.
 */
export function ScanProgress({
  scanId,
  projectId,
  mode,
  onDone,
}: {
  scanId: string;
  projectId: string;
  mode: ScanMode;
  onDone: (projectId: string) => void;
}) {
  const scanners = SCANNERS[mode];
  const [progress, setProgress] = React.useState<Progress | null>(null);
  const finished = React.useRef(false);

  React.useEffect(() => {
    let cancelled = false;

    const poll = async () => {
      try {
        const response = await fetch(`/api/scans/${scanId}`);
        const body = (await response.json()) as Progress;
        if (cancelled) return;
        setProgress(body);

        if (["completed", "partial", "failed", "cancelled"].includes(body.status)) {
          if (finished.current) return;
          finished.current = true;
          // A beat to let the last row land before navigating. Not a
          // manufactured wait -- the scan is genuinely done; this is the
          // animation being allowed to finish.
          setTimeout(() => onDone(projectId), 900);
        }
      } catch {
        // A failed poll is a missed frame, not a failed scan. The next one
        // will pick the state up.
      }
    };

    void poll();
    const timer = setInterval(poll, 1200);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [scanId, projectId, onDone]);

  const byScanner = new Map((progress?.results ?? []).map((r) => [r.scanner, r]));
  const reported = scanners.filter((s) => byScanner.has(s.id)).length;
  const allReported = reported === scanners.length;
  const done = ["completed", "partial", "failed"].includes(progress?.status ?? "");

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
      className="overflow-hidden rounded-lg border border-line bg-panel"
    >
      <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
        <span className="eyebrow">Scanning</span>
        <span className="font-mono text-[11px] tabular-nums text-ink-faint">
          {reported} / {scanners.length} reported
        </span>
      </div>

      <ul className="divide-y divide-line">
        {scanners.map((scanner, i) => {
          const result = byScanner.get(scanner.id);
          const state = !result
            ? "waiting"
            : result.status === "succeeded"
              ? result.degraded
                ? "degraded"
                : "ok"
              : "failed";

          return (
            <motion.li
              key={scanner.id}
              initial={{ opacity: 0, x: -6 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.05, duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
              className="flex items-center gap-3 px-4 py-2.5"
            >
              <StateIcon state={state} />
              <div className="min-w-0 flex-1">
                <p className="text-[13px] text-ink">{scanner.label}</p>
                <p className="truncate text-[11px] text-ink-faint">{scanner.detail}</p>
              </div>
              <span className="font-mono text-[11px] tabular-nums text-ink-faint">
                {result?.duration_ms !== undefined
                  ? `${(result.duration_ms / 1000).toFixed(1)}s`
                  : ""}
              </span>
            </motion.li>
          );
        })}
      </ul>

      <div className="flex flex-wrap items-center gap-1.5 border-t border-line px-4 py-3">
        {STAGES.map((stage, i) => (
          <React.Fragment key={stage}>
            {i > 0 && <span className="text-[10px] text-ink-faint">→</span>}
            <motion.span
              animate={{
                opacity: allReported ? 1 : 0.35,
                color: done && allReported ? "var(--color-pass)" : "var(--color-ink-muted)",
              }}
              transition={{ delay: allReported ? i * 0.12 : 0, duration: 0.3 }}
              className="text-[11px] font-medium"
            >
              {stage}
            </motion.span>
          </React.Fragment>
        ))}

        <AnimatePresence>
          {done && (
            <motion.span
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              className="ml-auto text-[11px] font-medium text-pass"
            >
              Opening results…
            </motion.span>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}

function StateIcon({ state }: { state: "waiting" | "ok" | "degraded" | "failed" }) {
  const base = "flex size-5 shrink-0 items-center justify-center rounded-full";
  if (state === "waiting") {
    return (
      <span className={cn(base, "text-ink-faint")}>
        <LoaderIcon className="size-3 animate-spin" />
      </span>
    );
  }
  if (state === "ok") {
    return (
      <motion.span
        initial={{ scale: 0.6, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ type: "spring", stiffness: 500, damping: 22 }}
        className={cn(base, "bg-pass-dim text-pass")}
      >
        <CheckIcon className="size-3" strokeWidth={3} />
      </motion.span>
    );
  }
  if (state === "degraded") {
    return (
      <motion.span
        initial={{ scale: 0.6, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        className={cn(base, "bg-warn-dim text-warn")}
      >
        <TriangleAlertIcon className="size-3" />
      </motion.span>
    );
  }
  return (
    <motion.span
      initial={{ scale: 0.6, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      className={cn(base, "bg-fail-dim text-fail")}
    >
      <XIcon className="size-3" strokeWidth={3} />
    </motion.span>
  );
}
