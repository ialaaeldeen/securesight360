import { useEffect, useMemo, useState } from "react";
import type { LucideIcon } from "lucide-react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CalendarClock,
  Globe2,
  ShieldCheck,
  TrendingUp,
} from "lucide-react";

import { apiFetch } from "@/lib/api";

type AnyRecord = Record<string, unknown>;

type ScanDeduction = {
  rule_id?: string;
  title?: string;
  severity?: string;
  deduction?: number;
  evidence?: string;
  business_impact?: string;
  recommendation?: string;
};

type NormalizedScan = {
  id: string;
  target: string;
  score: number | null;
  rating: string;
  riskLevel: string;
  scannedAt: string | null;
  timestamp: number;
  executiveSummary: string;
  riskSummary: string;
  detectionSummary: string;
  findingsCount: number;
  deductions: ScanDeduction[];
};

const RISK_ORDER = ["minimal", "low", "moderate", "high", "critical"];

export function Overview() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [scans, setScans] = useState<NormalizedScan[]>([]);

  useEffect(() => {
    let mounted = true;

    async function loadHistory() {
      setLoading(true);
      setError(null);

      try {
        const payload = await apiFetch<unknown>("/api/v1/website/history/me");
        const normalized = extractScanRows(payload)
          .map(normalizeScan)
          .sort((a, b) => b.timestamp - a.timestamp);

        if (mounted) {
          setScans(normalized);
        }
      } catch (err) {
        if (mounted) {
          setError(
            err instanceof Error
              ? err.message
              : "Failed to load dashboard scan history."
          );
        }
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    }

    loadHistory();

    return () => {
      mounted = false;
    };
  }, []);

  const latest = scans[0] ?? null;

  const trendScans = useMemo(
    () =>
      [...scans]
        .filter((scan) => typeof scan.score === "number")
        .sort((a, b) => a.timestamp - b.timestamp)
        .slice(-10),
    [scans]
  );

  const averageScore = useMemo(() => {
    const scores = scans
      .map((scan) => scan.score)
      .filter((score): score is number => typeof score === "number");

    if (!scores.length) return null;

    return Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length);
  }, [scans]);

  const riskCounts = useMemo(() => {
    const counts: Record<string, number> = {
      minimal: 0,
      low: 0,
      moderate: 0,
      high: 0,
      critical: 0,
    };

    for (const scan of scans) {
      const key = normalizeRiskKey(scan.riskLevel);
      counts[key] = (counts[key] ?? 0) + 1;
    }

    return counts;
  }, [scans]);

  const latestHighPriorityCount =
    latest?.deductions.filter((item) =>
      ["critical", "high"].includes(String(item.severity ?? "").toLowerCase())
    ).length ?? 0;

  return (
    <div className="space-y-6">
      <section className="rounded-3xl border border-border/70 bg-card/80 p-6 shadow-sm">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/10 px-3 py-1 text-xs font-semibold text-primary">
              <ShieldCheck className="h-3.5 w-3.5" />
              Customer Security Dashboard
            </div>
            <h1 className="mt-4 text-3xl font-bold tracking-tight">
              Website security posture
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
              Real-time security overview based on your authorized website scan
              history. Scores, ratings, risk levels, and summaries are calculated
              from the SecureSight360 risk engine.
            </p>
          </div>

          <div className="rounded-2xl border border-border bg-background/70 px-4 py-3 text-sm">
            <div className="text-xs uppercase tracking-wide text-muted-foreground">
              Latest scanned target
            </div>
            <div className="mt-1 flex items-center gap-2 font-semibold">
              <Globe2 className="h-4 w-4 text-primary" />
              {latest?.target ?? "No scans yet"}
            </div>
            <div className="mt-1 text-xs text-muted-foreground">
              {latest?.scannedAt ? formatDate(latest.scannedAt) : "Run a scan to populate this dashboard"}
            </div>
          </div>
        </div>
      </section>

      {error && (
        <div className="rounded-2xl border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          {error}
        </div>
      )}

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Security Score"
          value={latest?.score !== null && latest?.score !== undefined ? `${latest.score}/100` : "—"}
          description={
            averageScore !== null
              ? `Average across history: ${averageScore}/100`
              : "No historical average yet"
          }
          icon={Activity}
        />

        <MetricCard
          label="Security Rating"
          value={latest ? `${latest.rating} Rating` : "—"}
          description="Professional rating from the latest risk assessment"
          icon={ShieldCheck}
        />

        <MetricCard
          label="Risk Level"
          value={latest ? `${toTitle(latest.riskLevel)} Risk` : "—"}
          description={
            latestHighPriorityCount
              ? `${latestHighPriorityCount} high-priority item(s) in latest scan`
              : "No high-priority items detected in latest scan"
          }
          icon={AlertTriangle}
        />

        <MetricCard
          label="Scan History"
          value={`${scans.length}`}
          description="Authorized scans recorded for this account"
          icon={CalendarClock}
        />
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.35fr_0.65fr]">
        <Panel
          title="Security score trend"
          subtitle="Latest scan scores over time from your actual scan history."
          icon={TrendingUp}
        >
          <ScoreTrendChart scans={trendScans} loading={loading} />
        </Panel>

        <Panel
          title="Risk distribution"
          subtitle="How your scans are distributed by risk level."
          icon={BarChart3}
        >
          <RiskDistribution counts={riskCounts} total={scans.length} />
        </Panel>
      </section>

      <section className="grid gap-6 xl:grid-cols-3">
        <SummaryPanel
          title="Business Summary"
          value={latest?.executiveSummary}
          fallback="Run a scan to generate a business summary for the latest assessment."
        />
        <SummaryPanel
          title="Risk Explanation"
          value={latest?.riskSummary}
          fallback="Risk explanation will appear after a scan result is available."
        />
        <SummaryPanel
          title="Assessment Coverage"
          value={latest?.detectionSummary}
          fallback="Assessment coverage will show which security areas were evaluated."
        />
      </section>

      <section className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
        <Panel
          title="Latest priority findings"
          subtitle="Top deductions from the most recent risk assessment."
          icon={AlertTriangle}
        >
          <div className="space-y-3">
            {!latest?.deductions.length && (
              <EmptyState message="No deductions were reported in the latest scan." />
            )}

            {latest?.deductions.slice(0, 6).map((finding, index) => (
              <div
                key={`${finding.rule_id ?? "finding"}-${index}`}
                className="rounded-2xl border border-border bg-background/60 p-4"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`rounded-full px-2 py-1 text-xs font-semibold ${severityClass(finding.severity)}`}>
                    {toTitle(finding.severity ?? "info")}
                  </span>
                  <span className="text-xs font-medium text-muted-foreground">
                    {finding.rule_id ?? "RULE"}
                  </span>
                  <span className="text-xs font-semibold text-muted-foreground">
                    -{finding.deduction ?? 0}
                  </span>
                </div>
                <div className="mt-2 font-semibold">
                  {finding.title ?? "Security finding"}
                </div>
                {finding.evidence && (
                  <p className="mt-1 text-xs leading-5 text-muted-foreground">
                    Evidence: {finding.evidence}
                  </p>
                )}
              </div>
            ))}
          </div>
        </Panel>

        <Panel
          title="Recent scans"
          subtitle="Most recent authorized website assessments for this account."
          icon={Globe2}
        >
          <div className="overflow-hidden rounded-2xl border border-border">
            <table className="w-full text-left text-sm">
              <thead className="bg-muted/50 text-xs uppercase tracking-wide text-muted-foreground">
                <tr>
                  <th className="px-4 py-3">Target</th>
                  <th className="px-4 py-3">Score</th>
                  <th className="px-4 py-3">Rating</th>
                  <th className="px-4 py-3">Risk</th>
                  <th className="px-4 py-3">Date</th>
                </tr>
              </thead>
              <tbody>
                {!scans.length && (
                  <tr>
                    <td className="px-4 py-6 text-muted-foreground" colSpan={5}>
                      No scan history yet. Run your first authorized website scan.
                    </td>
                  </tr>
                )}

                {scans.slice(0, 8).map((scan) => (
                  <tr key={scan.id} className="border-t border-border">
                    <td className="px-4 py-3 font-medium">{scan.target}</td>
                    <td className="px-4 py-3">
                      {scan.score !== null ? `${scan.score}/100` : "—"}
                    </td>
                    <td className="px-4 py-3">{scan.rating}</td>
                    <td className="px-4 py-3">
                      <span className={`rounded-full px-2 py-1 text-xs font-semibold ${riskClass(scan.riskLevel)}`}>
                        {toTitle(scan.riskLevel)} Risk
                      </span>
                    </td>
                    <td className="px-4 py-3 text-muted-foreground">
                      {scan.scannedAt ? formatDate(scan.scannedAt) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </section>
    </div>
  );
}

function MetricCard({
  label,
  value,
  description,
  icon: Icon,
}: {
  label: string;
  value: string;
  description: string;
  icon: LucideIcon;
}) {
  return (
    <div className="rounded-3xl border border-border bg-card p-5 shadow-sm">
      <div className="flex items-center justify-between gap-3">
        <div className="rounded-2xl bg-primary/10 p-3 text-primary">
          <Icon className="h-5 w-5" />
        </div>
      </div>
      <div className="mt-5 text-xs uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div className="mt-2 text-3xl font-bold tracking-tight">{value}</div>
      <p className="mt-2 text-sm leading-5 text-muted-foreground">{description}</p>
    </div>
  );
}

function Panel({
  title,
  subtitle,
  icon: Icon,
  children,
}: {
  title: string;
  subtitle: string;
  icon: LucideIcon;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-3xl border border-border bg-card p-6 shadow-sm">
      <div className="mb-5 flex items-start gap-3">
        <div className="rounded-2xl bg-primary/10 p-3 text-primary">
          <Icon className="h-5 w-5" />
        </div>
        <div>
          <h2 className="font-semibold">{title}</h2>
          <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>
        </div>
      </div>
      {children}
    </div>
  );
}

function SummaryPanel({
  title,
  value,
  fallback,
}: {
  title: string;
  value?: string;
  fallback: string;
}) {
  return (
    <div className="rounded-3xl border border-border bg-card p-6 shadow-sm">
      <div className="text-xs uppercase tracking-wide text-muted-foreground">
        {title}
      </div>
      <p className="mt-3 text-sm leading-6 text-foreground/90">
        {value || fallback}
      </p>
    </div>
  );
}

function ScoreTrendChart({
  scans,
  loading,
}: {
  scans: NormalizedScan[];
  loading: boolean;
}) {
  if (loading) {
    return <EmptyState message="Loading score trend..." />;
  }

  if (scans.length < 2) {
    return <EmptyState message="At least two scored scans are needed to show a trend." />;
  }

  const width = 720;
  const height = 240;
  const paddingX = 36;
  const paddingY = 28;
  const minScore = Math.min(...scans.map((scan) => scan.score ?? 0), 60);
  const maxScore = Math.max(...scans.map((scan) => scan.score ?? 100), 100);
  const scoreRange = Math.max(maxScore - minScore, 10);

  const points = scans.map((scan, index) => {
    const x =
      scans.length === 1
        ? width / 2
        : paddingX + (index / (scans.length - 1)) * (width - paddingX * 2);

    const y =
      height -
      paddingY -
      (((scan.score ?? 0) - minScore) / scoreRange) * (height - paddingY * 2);

    return { x, y, scan };
  });

  const linePoints = points.map((point) => `${point.x},${point.y}`).join(" ");

  return (
    <div className="space-y-4">
      <div className="overflow-hidden rounded-2xl border border-border bg-background/60 p-4">
        <svg viewBox={`0 0 ${width} ${height}`} className="h-64 w-full">
          <line
            x1={paddingX}
            y1={height - paddingY}
            x2={width - paddingX}
            y2={height - paddingY}
            className="stroke-muted-foreground/30"
          />
          <line
            x1={paddingX}
            y1={paddingY}
            x2={paddingX}
            y2={height - paddingY}
            className="stroke-muted-foreground/30"
          />
          <polyline
            points={linePoints}
            fill="none"
            stroke="currentColor"
            strokeWidth="4"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="text-primary"
          />
          {points.map((point) => (
            <g key={`${point.scan.id}-${point.x}`}>
              <circle
                cx={point.x}
                cy={point.y}
                r="6"
                className="fill-background stroke-primary"
                strokeWidth="3"
              />
              <text
                x={point.x}
                y={point.y - 12}
                textAnchor="middle"
                className="fill-foreground text-[11px] font-semibold"
              >
                {point.scan.score}
              </text>
            </g>
          ))}
        </svg>
      </div>

      <div className="grid gap-2 text-xs text-muted-foreground sm:grid-cols-2 lg:grid-cols-3">
        {scans.slice(-6).map((scan) => (
          <div key={scan.id} className="truncate">
            {scan.scannedAt ? formatShortDate(scan.scannedAt) : "Unknown date"} ·{" "}
            <span className="font-semibold text-foreground">{scan.score}/100</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function RiskDistribution({
  counts,
  total,
}: {
  counts: Record<string, number>;
  total: number;
}) {
  if (!total) {
    return <EmptyState message="Risk distribution will appear after scans are available." />;
  }

  const max = Math.max(...Object.values(counts), 1);

  return (
    <div className="space-y-4">
      {RISK_ORDER.map((risk) => {
        const count = counts[risk] ?? 0;
        const width = `${Math.max((count / max) * 100, count ? 12 : 0)}%`;

        return (
          <div key={risk}>
            <div className="mb-1 flex items-center justify-between text-sm">
              <span className="font-medium">{toTitle(risk)} Risk</span>
              <span className="text-muted-foreground">{count}</span>
            </div>
            <div className="h-3 overflow-hidden rounded-full bg-muted">
              <div
                className={`h-full rounded-full ${riskBarClass(risk)}`}
                style={{ width }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="rounded-2xl border border-dashed border-border bg-background/50 p-6 text-sm text-muted-foreground">
      {message}
    </div>
  );
}

function extractScanRows(payload: unknown): unknown[] {
  if (Array.isArray(payload)) return payload;

  const record = asRecord(payload);
  if (!record) return [];

  for (const key of ["items", "scans", "history", "results", "data"]) {
    const value = record[key];
    if (Array.isArray(value)) return value;
  }

  return [];
}

function normalizeScan(row: unknown, index: number): NormalizedScan {
  const score = numberValue(
    firstDefined(
      readPath(row, ["security_score"]),
      readPath(row, ["risk_assessment", "security_score"]),
      readPath(row, ["result", "security_score"]),
      readPath(row, ["result", "risk_assessment", "security_score"]),
      readPath(row, ["raw", "security_score"])
    )
  );

  const scannedAt = stringValue(
    firstDefined(
      readPath(row, ["completed_at"]),
      readPath(row, ["scanned_at"]),
      readPath(row, ["created_at"]),
      readPath(row, ["result", "scanned_at"]),
      readPath(row, ["result", "created_at"])
    )
  );

  const riskAssessment =
    firstRecord(
      readPath(row, ["risk_assessment"]),
      readPath(row, ["result", "risk_assessment"]),
      readPath(row, ["raw", "risk_assessment"])
    ) ?? {};

  const metadata =
    firstRecord(readPath(row, ["metadata"]), readPath(row, ["result", "metadata"])) ??
    {};

  const deductions = extractDeductions(riskAssessment);

  return {
    id:
      stringValue(firstDefined(readPath(row, ["id"]), readPath(row, ["scan_id"]))) ??
      `scan-${index}`,
    target:
      stringValue(
        firstDefined(
          readPath(row, ["target_url"]),
          readPath(row, ["target"]),
          readPath(row, ["domain"]),
          readPath(row, ["result", "target_url"]),
          readPath(row, ["result", "original_url"])
        )
      ) ?? "Unknown target",
    score,
    rating:
      stringValue(
        firstDefined(
          readPath(row, ["grade"]),
          riskAssessment.grade,
          readPath(row, ["result", "grade"])
        )
      ) ?? ratingForScore(score),
    riskLevel:
      stringValue(
        firstDefined(
          readPath(row, ["risk_level"]),
          riskAssessment.risk_level,
          readPath(row, ["result", "risk_level"])
        )
      ) ?? riskForScore(score),
    scannedAt,
    timestamp: scannedAt ? Date.parse(scannedAt) || 0 : 0,
    executiveSummary:
      stringValue(
        firstDefined(
          readPath(row, ["executive_summary"]),
          riskAssessment.executive_summary,
          metadata.executive_summary
        )
      ) ?? "",
    riskSummary:
      stringValue(
        firstDefined(
          readPath(row, ["risk_engine_summary"]),
          riskAssessment.risk_engine_summary,
          metadata.risk_engine_summary
        )
      ) ?? buildRiskExplanation(riskAssessment),
    detectionSummary:
      stringValue(
        firstDefined(
          readPath(row, ["detection_summary"]),
          riskAssessment.detection_summary,
          metadata.detection_summary
        )
      ) ?? "",
    findingsCount:
      numberValue(
        firstDefined(
          readPath(row, ["findings_count"]),
          readPath(row, ["result", "findings_count"]),
          deductions.length
        )
      ) ?? deductions.length,
    deductions,
  };
}


function buildRiskExplanation(riskAssessment: AnyRecord): string {
  const drivers = Array.isArray(riskAssessment.key_risk_drivers)
    ? riskAssessment.key_risk_drivers.map(String).filter(Boolean)
    : [];

  const actions = Array.isArray(riskAssessment.priority_actions)
    ? riskAssessment.priority_actions.map(String).filter(Boolean)
    : [];

  if (drivers.length && actions.length) {
    return `Main risk drivers: ${drivers.slice(0, 3).join("; ")}. Recommended priority: ${actions[0]}`;
  }

  if (drivers.length) {
    return `Main risk drivers: ${drivers.slice(0, 3).join("; ")}`;
  }

  if (actions.length) {
    return `Recommended priority: ${actions[0]}`;
  }

  return "";
}

function extractDeductions(riskAssessment: AnyRecord): ScanDeduction[] {
  const value = riskAssessment.scoring_deductions;
  if (!Array.isArray(value)) return [];

  return value
    .map((item) => asRecord(item))
    .filter((item): item is AnyRecord => Boolean(item))
    .map((item) => ({
      rule_id: stringValue(item.rule_id),
      title: stringValue(item.title),
      severity: stringValue(item.severity),
      deduction: numberValue(item.deduction) ?? 0,
      evidence: stringValue(item.evidence),
      business_impact: stringValue(item.business_impact),
      recommendation: stringValue(item.recommendation),
    }));
}

function asRecord(value: unknown): AnyRecord | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as AnyRecord)
    : null;
}

function firstRecord(...values: unknown[]): AnyRecord | null {
  for (const value of values) {
    const record = asRecord(value);
    if (record) return record;
  }

  return null;
}

function readPath(source: unknown, path: string[]): unknown {
  let current: unknown = source;

  for (const key of path) {
    const record = asRecord(current);
    if (!record || !(key in record)) return undefined;
    current = record[key];
  }

  return current;
}

function firstDefined(...values: unknown[]): unknown {
  return values.find((value) => value !== undefined && value !== null && value !== "");
}

function stringValue(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text || undefined;
}

function numberValue(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return Math.round(value);
  if (typeof value === "string") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return Math.round(parsed);
  }
  return null;
}

function ratingForScore(score: number | null): string {
  if (score === null) return "Not Rated";
  if (score >= 90) return "Excellent";
  if (score >= 80) return "Strong";
  if (score >= 65) return "Moderate";
  if (score >= 40) return "Weak";
  return "Critical";
}

function riskForScore(score: number | null): string {
  if (score === null) return "unknown";
  if (score >= 90) return "minimal";
  if (score >= 80) return "low";
  if (score >= 65) return "moderate";
  if (score >= 40) return "high";
  return "critical";
}

function normalizeRiskKey(value: string): string {
  const key = value.toLowerCase().trim();
  return RISK_ORDER.includes(key) ? key : "moderate";
}

function toTitle(value: string): string {
  const cleaned = value.replace(/[_-]/g, " ").trim().toLowerCase();
  if (!cleaned) return "Unknown";
  return cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
}

function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function formatShortDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
  }).format(date);
}

function riskClass(value: string): string {
  switch (normalizeRiskKey(value)) {
    case "minimal":
      return "bg-emerald-500/10 text-emerald-600";
    case "low":
      return "bg-sky-500/10 text-sky-600";
    case "moderate":
      return "bg-amber-500/10 text-amber-600";
    case "high":
      return "bg-orange-500/10 text-orange-600";
    case "critical":
      return "bg-red-500/10 text-red-600";
    default:
      return "bg-muted text-muted-foreground";
  }
}

function severityClass(value: string | undefined): string {
  switch (String(value ?? "").toLowerCase()) {
    case "critical":
      return "bg-red-500/10 text-red-600";
    case "high":
      return "bg-orange-500/10 text-orange-600";
    case "medium":
      return "bg-amber-500/10 text-amber-600";
    case "low":
      return "bg-sky-500/10 text-sky-600";
    default:
      return "bg-muted text-muted-foreground";
  }
}

function riskBarClass(value: string): string {
  switch (normalizeRiskKey(value)) {
    case "minimal":
      return "bg-emerald-500";
    case "low":
      return "bg-sky-500";
    case "moderate":
      return "bg-amber-500";
    case "high":
      return "bg-orange-500";
    case "critical":
      return "bg-red-500";
    default:
      return "bg-muted-foreground";
  }
}
