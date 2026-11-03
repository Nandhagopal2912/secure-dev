"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { motion, useReducedMotion } from "motion/react";
import { ArrowRightIcon, GitBranchIcon, GlobeIcon, LoaderIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { SegmentedControl } from "@/components/ui/segmented-control";
import { CrossFade } from "./motion";
import { ScanProgress } from "./scan-progress";

/**
 * What a scan points at. Two genuine application states, not two button styles.
 *
 * Everything the form shows is derived from this: the heading, the field label,
 * the placeholder, the help text, the button, and the validation message. The
 * heading used to live in the page above this component, which is exactly how
 * "Website" could be selected while the page still said SCAN A REPOSITORY --
 * the state had no way to reach the words. Deriving all of it from one value
 * makes that contradiction unrepresentable rather than merely fixed.
 */
export type ScanMode = "repository" | "endpoint";

interface Copy {
  heading: string;
  field: string;
  placeholder: string;
  cta: string;
  busy: string;
  help: React.ReactNode;
  invalid: string;
}

const COPY: Record<ScanMode, Copy> = {
  repository: {
    heading: "Scan a repository",
    field: "Repository URL",
    placeholder: "https://github.com/owner/repository",
    cta: "Scan repository",
    busy: "Queueing",
    invalid: "Enter an https repository URL.",
    help: (
      <>
        Five scanners over the checkout — secrets, SBOM, dependencies, code and
        configuration. Public repositories only; workers hold no git credentials.
      </>
    ),
  },
  endpoint: {
    heading: "Scan a website",
    field: "Website URL",
    placeholder: "https://your-app.example.com",
    cta: "Scan website",
    busy: "Queueing",
    invalid: "Enter an https URL.",
    help: (
      <>
        No attack testing — SecureOps crawls the site and reports what its passive
        rules see, then checks how the URL answers cross-origin requests and
        whether plain HTTP redirects to HTTPS. It sends no attack payloads, so it
        does not test for injection, and it signs in to nothing. Scan only what
        you are authorised to test.
      </>
    ),
  },
};

const MODES = [
  { value: "repository" as const, label: "Repository", description: "Scan a git repository" },
  { value: "endpoint" as const, label: "Website", description: "Scan a running website" },
];

const MODE_VALUES = MODES.map((m) => m.value);

/**
 * Paste a URL, get a scan.
 *
 * The whole point is that this replaces a multi-line curl with a token pulled
 * out of .env. It exists only because the dashboard authenticates now
 * (ADR 029) -- an anonymous page able to queue clones is a way to make the
 * worker fetch arbitrary URLs.
 *
 * The kind is chosen, not inferred. ".git means repository" and "github.com
 * means repository" both look reasonable and are wrong often enough to matter:
 * a heuristic would clone a website or crawl a repository host, and the failure
 * reads as the platform being broken rather than the guess being wrong.
 *
 * The URL is not validated here beyond an obvious shape check. The API applies
 * the address policy and the argument-injection defences, and a second, weaker
 * copy of those rules in the browser is a place for the two to disagree. What
 * the API rejects is shown verbatim, because "scheme must be https" is exactly
 * what the person typing needs to read.
 */
export function ScanBar({ className }: { className?: string }) {
  const router = useRouter();
  const reduced = useReducedMotion();

  const [mode, setMode] = React.useState<ScanMode>("repository");
  const [url, setUrl] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [running, setRunning] = React.useState<{
    scanId: string;
    projectId: string;
    mode: ScanMode;
  } | null>(null);

  const copy = COPY[mode];
  const inputId = React.useId();
  const errorId = `${inputId}-error`;

  const onDone = React.useCallback(
    (projectId: string) => {
      setRunning(null);
      router.push(`/projects/${projectId}`);
      router.refresh();
    },
    [router],
  );

  // Switching mode clears an error about the other mode's rules. The URL is
  // kept: someone who pasted a URL and then realised they picked the wrong
  // kind should not have to paste it again.
  function changeMode(next: ScanMode) {
    setMode(next);
    setError(null);
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (busy || running) return;

    const target = url.trim();
    if (!/^https:\/\/\S+$/.test(target)) {
      setError(copy.invalid);
      return;
    }

    setBusy(true);
    setError(null);
    try {
      const response = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repository_url: target, kind: mode }),
      });
      const body = (await response.json()) as {
        project_id?: string;
        scan_id?: string;
        error?: string;
      };

      if (!response.ok || !body.project_id || !body.scan_id) {
        setError(body.error ?? "The scan could not be submitted.");
        return;
      }
      setUrl("");
      // Stay here and show the scan working. Navigating immediately would put
      // the person on a project page whose every panel says "no data yet",
      // which is the least informative moment of the whole run.
      setRunning({ scanId: body.scan_id, projectId: body.project_id, mode });
    } catch {
      setError("The dashboard could not reach its API.");
    } finally {
      setBusy(false);
    }
  }

  const disabled = busy || running !== null || url.trim() === "";

  return (
    <section className={cn("space-y-3", className)} aria-labelledby={`${inputId}-heading`}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* The heading lives inside the component that owns the mode, which is
            the whole repair: it cannot disagree with the selection because it
            is rendered from it. */}
        <CrossFade
          id={`${inputId}-heading`}
          active={mode}
          states={MODE_VALUES}
          className="h-4 min-w-0 flex-1 overflow-hidden"
          render={(m) => <h2 className="eyebrow flex items-center">{COPY[m].heading}</h2>}
        />

        <SegmentedControl label="What to scan" options={MODES} value={mode} onChange={changeMode} />
      </div>

      <form onSubmit={submit} className="flex flex-col gap-2 sm:flex-row">
        <div className="relative min-w-0 flex-1">
          <CrossFade
            aria-hidden
            active={mode}
            states={MODE_VALUES}
            className="pointer-events-none absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-ink-faint"
            render={(m) =>
              m === "endpoint" ? <GlobeIcon className="size-3.5" /> : <GitBranchIcon className="size-3.5" />
            }
          />
          <label htmlFor={inputId} className="sr-only">
            {copy.field}
          </label>
          <input
            id={inputId}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder={copy.placeholder}
            spellCheck={false}
            autoComplete="off"
            inputMode="url"
            aria-invalid={error !== null}
            aria-describedby={error ? errorId : undefined}
            className={cn(
              "h-9 w-full rounded-md border bg-surface pl-8 pr-3",
              "font-mono text-[13px] text-ink placeholder:text-ink-faint",
              "transition-[border-color,box-shadow] duration-150",
              "focus-visible:border-accent focus-visible:outline-none",
              "focus-visible:shadow-[0_0_0_3px_var(--color-accent-muted)]",
              error ? "border-fail/60" : "border-line-strong hover:border-ink-faint/60",
            )}
          />
        </div>

        <motion.button
          type="submit"
          disabled={disabled}
          whileTap={reduced || disabled ? undefined : { scale: 0.98 }}
          className={cn(
            "group inline-flex h-9 shrink-0 items-center justify-center gap-1.5 rounded-md px-3.5",
            "text-[13px] font-medium transition-colors duration-150",
            "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent",
            disabled
              ? "cursor-not-allowed bg-raised text-ink-faint"
              : "bg-ink text-inverse hover:bg-ink/90",
          )}
        >
          {busy ? (
            <LoaderIcon className="size-3.5 animate-spin" />
          ) : (
            <ArrowRightIcon className="size-3.5 transition-transform duration-150 group-hover:translate-x-0.5" />
          )}
          <span>{busy ? copy.busy : copy.cta}</span>
        </motion.button>
      </form>

      {/* Rendered conditionally, with an entrance in CSS and no exit at all.
          An error that has been cleared should be gone, not fading -- and a
          presence wrapper here would make its removal depend on an exit
          callback firing, which is the one thing that must not gate whether a
          stale error is still on screen. */}
      {error && (
        <p
          id={errorId}
          role="alert"
          className="animate-in rounded-md border border-fail/25 bg-fail-dim px-3 py-2 text-[12px] leading-relaxed text-fail"
        >
          {error}
        </p>
      )}

      {running && (
        <ScanProgress
          key={running.scanId}
          scanId={running.scanId}
          projectId={running.projectId}
          mode={running.mode}
          onDone={onDone}
        />
      )}

      {/* Height is reserved so switching mode does not shift the page. The two
          help texts differ in length, and a layout that jumps under the cursor
          is the most obvious way to make a considered interface feel cheap. */}
      <CrossFade
        active={mode}
        states={MODE_VALUES}
        className="min-h-[3.9rem] sm:min-h-[2.6rem]"
        render={(m) => (
          <p className="max-w-3xl text-[11px] leading-relaxed text-ink-faint">
            {COPY[m].help} Scanning the same target again adds to its history
            rather than creating a second project.
          </p>
        )}
      />
    </section>
  );
}
