import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CalendarClock,
  Globe2,
  Inbox,
  Mail,
  Paperclip,
  ShieldCheck,
  TrendingUp,
} from "lucide-react";

import {
  apiFetch,
  fetchEmailAnalysisHistory,
  type EmailThreatHistoryItem,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { canUseWebsiteFeatures } from "@/lib/access";

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

type EmailThreatMetrics = {
  total: number;
  suspicious: number;
  highConfidenceDetections: number;
  links: number;
  attachments: number;
  headersProvided: number;
  safe: number;
};

const RISK_ORDER = ["minimal", "low", "moderate", "high", "critical"];

export function Overview({ onLaunch }: { onLaunch?: () => void }) {
  const { user } = useAuth();
  const canUseWebsite = canUseWebsiteFeatures(user);

  if (!canUseWebsite) {
    return <PersonalEmailDashboard onAnalyze={onLaunch} />;
  }

  return <UnifiedSecurityDashboard />;
}

function UnifiedSecurityDashboard() {
  const [websiteLoading, setWebsiteLoading] = useState(true);
  const [websiteError, setWebsiteError] = useState<string | null>(null);
  const [scans, setScans] = useState<NormalizedScan[]>([]);

  const {
    loading: emailLoading,
    error: emailError,
    items: emailItems,
    latest: latestEmail,
    metrics: emailMetrics,
  } = useEmailThreatDashboardData();

  useEffect(() => {
    let mounted = true;

    async function loadHistory() {
      setWebsiteLoading(true);
      setWebsiteError(null);

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
          setWebsiteError(
            err instanceof Error
              ? err.message
              : "Failed to load website security history."
          );
        }
      } finally {
        if (mounted) {
          setWebsiteLoading(false);
        }
      }
    }

    loadHistory();

    return () => {
      mounted = false;
    };
  }, []);

  const latest = scans[0] ?? null;

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
        <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/10 px-3 py-1 text-xs font-semibold text-primary">
              <ShieldCheck className="h-3.5 w-3.5" />
              Unified Security Dashboard
            </div>
            <h1 className="mt-4 text-3xl font-bold tracking-tight">
              Website and email security overview
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
              A focused business dashboard showing the most important website posture
              and phishing email activity without overwhelming your team.
            </p>
          </div>

          <div className="grid gap-3 sm:grid-cols-2 xl:min-w-[520px]">
            <HeroStatusCard
              label="Latest website"
              title={latest?.target ?? "No website scans yet"}
              description={
                latest?.scannedAt
                  ? `${latest.score ?? "—"}/100 · ${toTitle(latest.riskLevel)} Risk`
                  : "Run an authorized website scan"
              }
              icon={Globe2}
            />

            <HeroStatusCard
              label="Latest email verdict"
              title={latestEmail?.verdict ?? "No email analyses yet"}
              description={
                latestEmail
                  ? `${latestEmail.confidence} confidence · ${formatShortDate(latestEmail.created_at)}`
                  : "Analyze suspicious emails"
              }
              icon={Mail}
            />
          </div>
        </div>
      </section>

      {(websiteError || emailError) && (
        <div className="space-y-3">
          {websiteError && (
            <div className="rounded-2xl border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
              Website dashboard: {websiteError}
            </div>
          )}
          {emailError && (
            <div className="rounded-2xl border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
              Email dashboard: {emailError}
            </div>
          )}
        </div>
      )}

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Website Score"
          value={latest?.score !== null && latest?.score !== undefined ? `${latest.score}/100` : "—"}
          description={
            averageScore !== null
              ? `Average website score: ${averageScore}/100`
              : "No website score yet"
          }
          icon={Activity}
        />

        <MetricCard
          label="Website Risk"
          value={latest ? `${toTitle(latest.riskLevel)} Risk` : "—"}
          description={
            latestHighPriorityCount
              ? `${latestHighPriorityCount} high-priority website item(s)`
              : "No high-priority website items"
          }
          icon={AlertTriangle}
        />

        <MetricCard
          label="Email Analyses"
          value={emailLoading ? "…" : String(emailMetrics.total)}
          description="Suspicious emails reviewed by the analyzer"
          icon={Inbox}
        />

        <MetricCard
          label="Suspicious Emails"
          value={emailLoading ? "…" : String(emailMetrics.suspicious)}
          description={`High-confidence detections: ${emailMetrics.highConfidenceDetections}`}
          icon={Mail}
        />
      </section>

      <section className="grid gap-6 xl:grid-cols-2">
        <Panel
          title="Website Security Posture"
          subtitle="Latest authorized website assessment and key posture signals."
          icon={Globe2}
        >
          <WebsitePostureSummary
            latest={latest}
            scans={scans}
            riskCounts={riskCounts}
            loading={websiteLoading}
          />
        </Panel>

        <Panel
          title="Email Threat Protection"
          subtitle="Latest phishing email activity and reviewed indicators."
          icon={Mail}
        >
          <EmailThreatSummary
            latest={latestEmail}
            metrics={emailMetrics}
            loading={emailLoading}
          />
        </Panel>
      </section>

      <section className="grid gap-6 xl:grid-cols-2">
        <Panel
          title="Recent website scans"
          subtitle="Latest authorized website assessments."
          icon={CalendarClock}
        >
          <RecentWebsiteScansTable scans={scans} />
        </Panel>

        <Panel
          title="Recent email analyses"
          subtitle="Latest suspicious emails reviewed by the analyzer."
          icon={Inbox}
        >
          <RecentEmailAnalysesTable items={emailItems} />
        </Panel>
      </section>

      <Panel
        title="Priority actions"
        subtitle="Most important next steps from website and email security activity."
        icon={ShieldCheck}
      >
        <div className="grid gap-5 lg:grid-cols-2">
          <WebsitePriorityActions latest={latest} />
          <EmailSafeActions />
        </div>
      </Panel>
    </div>
  );
}

function PersonalEmailDashboard({ onAnalyze }: { onAnalyze?: () => void }) {
  const {
    loading,
    error,
    items,
    latest,
    metrics,
  } = useEmailThreatDashboardData();

  return (
    <div className="space-y-6">
      <section className="rounded-3xl border border-border/70 bg-card/80 p-6 shadow-sm">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/10 px-3 py-1 text-xs font-semibold text-primary">
              <Mail className="h-3.5 w-3.5" />
              Personal Email Threat Dashboard
            </div>

            <h1 className="mt-4 text-3xl font-bold tracking-tight">
              Email threat protection
            </h1>

            <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
              A simple dashboard for checking suspicious emails before you click,
              reply, download, or share sensitive information.
            </p>
          </div>

          <button
            type="button"
            onClick={onAnalyze}
            className="inline-flex items-center justify-center gap-2 rounded-2xl bg-gradient-to-r from-cyan to-accent-blue px-5 py-3 text-sm font-semibold text-[#021016] glow-cyan transition hover:brightness-110"
          >
            <Mail className="h-4 w-4" />
            Analyze suspicious email
          </button>
        </div>
      </section>

      {error && (
        <div className="rounded-2xl border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          {error}
        </div>
      )}

      <section className="grid gap-4 md:grid-cols-3">
        <MetricCard
          label="Emails Analyzed"
          value={loading ? "…" : String(metrics.total)}
          description="Suspicious emails checked in your account"
          icon={Inbox}
        />

        <MetricCard
          label="Suspicious Emails"
          value={loading ? "…" : String(metrics.suspicious)}
          description={`High-confidence detections: ${metrics.highConfidenceDetections}`}
          icon={AlertTriangle}
        />

        <MetricCard
          label="Links / Attachments"
          value={loading ? "…" : `${metrics.links} / ${metrics.attachments}`}
          description="Reviewed links and attachment indicators"
          icon={Paperclip}
        />
      </section>

      <section className="grid gap-6 xl:grid-cols-[0.85fr_1.15fr]">
        <Panel
          title="Latest email verdict"
          subtitle="Most recent suspicious email analysis."
          icon={Mail}
        >
          <EmailThreatSummary latest={latest} metrics={metrics} loading={loading} />
        </Panel>

        <Panel
          title="Recent email analyses"
          subtitle="Your latest suspicious email checks."
          icon={Inbox}
        >
          <RecentEmailAnalysesTable items={items} />
        </Panel>
      </section>

      <Panel
        title="Safe handling and next actions"
        subtitle="Practical steps for normal users when an email looks suspicious."
        icon={ShieldCheck}
      >
        <EmailSafeActions />
      </Panel>
    </div>
  );
}

function useEmailThreatDashboardData(limit = 100) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [items, setItems] = useState<EmailThreatHistoryItem[]>([]);

  useEffect(() => {
    let mounted = true;

    async function loadEmailHistory() {
      setLoading(true);
      setError(null);

      try {
        const response = await fetchEmailAnalysisHistory(limit, 0);
        const history = Array.isArray(response.history) ? response.history : [];

        const sorted = [...history].sort((a, b) => {
          const at = Date.parse(a.created_at || "") || 0;
          const bt = Date.parse(b.created_at || "") || 0;
          return bt - at;
        });

        if (mounted) {
          setItems(sorted);
        }
      } catch (err) {
        if (mounted) {
          setError(
            err instanceof Error
              ? err.message
              : "Failed to load email threat analysis history."
          );
        }
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    }

    loadEmailHistory();

    return () => {
      mounted = false;
    };
  }, [limit]);

  const latest = items[0] ?? null;

  const metrics = useMemo<EmailThreatMetrics>(() => {
    const suspiciousItems = items.filter(isSuspiciousEmail);

    return {
      total: items.length,
      suspicious: suspiciousItems.length,
      highConfidenceDetections: suspiciousItems.filter(
        (item) => item.confidence.toLowerCase() === "high"
      ).length,
      links: items.reduce((sum, item) => sum + Number(item.links_count || 0), 0),
      attachments: items.reduce(
        (sum, item) => sum + Number(item.attachments_count || 0),
        0
      ),
      headersProvided: items.filter((item) => Boolean(item.headers_provided)).length,
      safe: items.filter((item) => !isSuspiciousEmail(item)).length,
    };
  }, [items]);

  return {
    loading,
    error,
    items,
    latest,
    metrics,
  };
}

function WebsitePostureSummary({
  latest,
  scans,
  riskCounts,
  loading,
}: {
  latest: NormalizedScan | null;
  scans: NormalizedScan[];
  riskCounts: Record<string, number>;
  loading: boolean;
}) {
  if (loading) {
    return <EmptyState message="Loading website posture..." />;
  }

  if (!latest) {
    return <EmptyState message="No website scans yet. Run an authorized scan to populate this area." />;
  }

  return (
    <div className="space-y-5">
      <div className="grid gap-3 sm:grid-cols-2">
        <MiniMetric label="Latest target" value={latest.target} />
        <MiniMetric label="Latest scan" value={latest.scannedAt ? formatDate(latest.scannedAt) : "Unknown"} />
        <MiniMetric label="Rating" value={latest.rating} />
        <MiniMetric label="Recorded scans" value={String(scans.length)} />
      </div>

      <div className="rounded-2xl border border-border bg-background/60 p-4">
        <div className="mb-3 flex items-center gap-2 text-sm font-semibold">
          <BarChart3 className="h-4 w-4 text-primary" />
          Risk mix
        </div>
        <CompactRiskDistribution counts={riskCounts} total={scans.length} />
      </div>

      <div className="rounded-2xl border border-border bg-background/60 p-4">
        <div className="mb-3 flex items-center gap-2 text-sm font-semibold">
          <TrendingUp className="h-4 w-4 text-primary" />
          Score movement
        </div>
        <CompactScoreTrend scans={scans} />
      </div>

      <p className="text-sm leading-6 text-muted-foreground">
        {latest.executiveSummary ||
          latest.riskSummary ||
          "Website posture summary will appear after a complete scan result is available."}
      </p>
    </div>
  );
}

function EmailThreatSummary({
  latest,
  metrics,
  loading,
}: {
  latest: EmailThreatHistoryItem | null;
  metrics: EmailThreatMetrics;
  loading: boolean;
}) {
  if (loading) {
    return <EmptyState message="Loading email threat activity..." />;
  }

  if (!latest) {
    return <EmptyState message="No email analyses yet. Analyze a suspicious email to populate this area." />;
  }

  return (
    <div className="space-y-5">
      <div className="rounded-2xl border border-border bg-background/60 p-5">
        <div className="flex flex-wrap items-center gap-2">
          <span className={`rounded-full px-2 py-1 text-xs font-semibold ${emailVerdictClass(latest)}`}>
            {isSuspiciousEmail(latest) ? "Attention needed" : "No obvious threat"}
          </span>
          <span className="text-xs text-muted-foreground">
            {formatDate(latest.created_at)}
          </span>
        </div>

        <div className="mt-3 text-2xl font-bold leading-tight">
          {latest.verdict}
        </div>

        <p className="mt-2 text-sm leading-6 text-muted-foreground">
          {latest.summary || "No summary was saved for this analysis."}
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <MiniMetric label="Confidence" value={latest.confidence} />
        <MiniMetric label="Evidence" value={latest.evidence_strength} />
        <MiniMetric label="Links / Attachments" value={`${latest.links_count ?? 0} / ${latest.attachments_count ?? 0}`} />
      </div>

      <p className="text-sm leading-6 text-muted-foreground">
        Total reviewed: {metrics.total}. Suspicious: {metrics.suspicious}. Safe or no obvious threat:
        {" "}{metrics.safe}. Headers included: {metrics.headersProvided}.
      </p>
    </div>
  );
}

function RecentWebsiteScansTable({ scans }: { scans: NormalizedScan[] }) {
  return (
    <div className="overflow-x-auto rounded-2xl border border-border">
      <table className="w-full min-w-[660px] text-left text-sm">
        <thead className="bg-muted/50 text-xs uppercase tracking-wide text-muted-foreground">
          <tr>
            <th className="px-4 py-3">Target</th>
            <th className="px-4 py-3">Score</th>
            <th className="px-4 py-3">Risk</th>
            <th className="px-4 py-3">Date</th>
          </tr>
        </thead>
        <tbody>
          {!scans.length && (
            <tr>
              <td className="px-4 py-6 text-muted-foreground" colSpan={4}>
                No website scan history yet.
              </td>
            </tr>
          )}

          {scans.slice(0, 5).map((scan) => (
            <tr key={scan.id} className="border-t border-border">
              <td className="px-4 py-3 font-medium">{scan.target}</td>
              <td className="px-4 py-3">
                {scan.score !== null ? `${scan.score}/100` : "—"}
              </td>
              <td className="px-4 py-3">
                <span className={`rounded-full px-2 py-1 text-xs font-semibold ${riskClass(scan.riskLevel)}`}>
                  {toTitle(scan.riskLevel)}
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
  );
}

function RecentEmailAnalysesTable({ items }: { items: EmailThreatHistoryItem[] }) {
  return (
    <div className="overflow-x-auto rounded-2xl border border-border">
      <table className="w-full min-w-[680px] text-left text-sm">
        <thead className="bg-muted/50 text-xs uppercase tracking-wide text-muted-foreground">
          <tr>
            <th className="px-4 py-3">Subject</th>
            <th className="px-4 py-3">Verdict</th>
            <th className="px-4 py-3">Confidence</th>
            <th className="px-4 py-3">Date</th>
          </tr>
        </thead>
        <tbody>
          {!items.length && (
            <tr>
              <td className="px-4 py-6 text-muted-foreground" colSpan={4}>
                No email analyses yet.
              </td>
            </tr>
          )}

          {items.slice(0, 5).map((item) => (
            <tr key={item.id} className="border-t border-border align-top">
              <td className="px-4 py-3 font-medium">
                <div className="max-w-[260px] truncate">
                  {item.subject_preview || "No subject provided"}
                </div>
                <div className="mt-1 max-w-[260px] truncate text-xs text-muted-foreground">
                  {item.sender_preview || "No sender provided"}
                </div>
              </td>
              <td className="px-4 py-3">
                <span className={`rounded-full px-2 py-1 text-xs font-semibold ${emailVerdictClass(item)}`}>
                  {item.verdict}
                </span>
              </td>
              <td className="px-4 py-3">{item.confidence}</td>
              <td className="px-4 py-3 text-muted-foreground">
                {formatDate(item.created_at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function WebsitePriorityActions({ latest }: { latest: NormalizedScan | null }) {
  const findings = latest?.deductions.slice(0, 3) ?? [];

  return (
    <div className="rounded-2xl border border-border bg-background/60 p-4">
      <div className="mb-3 font-semibold">Website priorities</div>

      {!findings.length ? (
        <p className="text-sm leading-6 text-muted-foreground">
          No high-priority website findings are currently shown. Run a scan to refresh this area.
        </p>
      ) : (
        <div className="space-y-3">
          {findings.map((finding, index) => (
            <div key={`${finding.rule_id ?? "finding"}-${index}`} className="rounded-xl border border-border bg-card/70 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`rounded-full px-2 py-1 text-xs font-semibold ${severityClass(finding.severity)}`}>
                  {toTitle(finding.severity ?? "info")}
                </span>
                <span className="text-xs text-muted-foreground">
                  {finding.rule_id ?? "Security finding"}
                </span>
              </div>
              <div className="mt-2 text-sm font-semibold">
                {finding.title ?? "Security finding"}
              </div>
              {finding.recommendation && (
                <p className="mt-1 text-xs leading-5 text-muted-foreground">
                  {finding.recommendation}
                </p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function EmailSafeActions() {
  return (
    <div className="rounded-2xl border border-border bg-background/60 p-4">
      <div className="mb-3 font-semibold">Email safety actions</div>
      <div className="space-y-2 text-sm leading-6 text-muted-foreground">
        <p>Do not click links or open attachments from suspicious messages.</p>
        <p>Do not share passwords, verification codes, payment details, or private documents.</p>
        <p>Confirm urgent requests through a trusted contact method before taking action.</p>
        <p>Keep only necessary email details in analysis to protect privacy.</p>
      </div>
    </div>
  );
}

function CompactRiskDistribution({
  counts,
  total,
}: {
  counts: Record<string, number>;
  total: number;
}) {
  if (!total) {
    return <EmptyState message="Risk mix will appear after scans are available." />;
  }

  const max = Math.max(...Object.values(counts), 1);

  return (
    <div className="space-y-3">
      {RISK_ORDER.map((risk) => {
        const count = counts[risk] ?? 0;
        const width = `${Math.max((count / max) * 100, count ? 12 : 0)}%`;

        return (
          <div key={risk}>
            <div className="mb-1 flex items-center justify-between text-xs">
              <span className="font-medium">{toTitle(risk)}</span>
              <span className="text-muted-foreground">{count}</span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-muted">
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

function CompactScoreTrend({ scans }: { scans: NormalizedScan[] }) {
  const scored = [...scans]
    .filter((scan) => typeof scan.score === "number")
    .sort((a, b) => a.timestamp - b.timestamp)
    .slice(-5);

  if (scored.length < 2) {
    return (
      <p className="text-sm text-muted-foreground">
        At least two scored scans are needed to show movement.
      </p>
    );
  }

  return (
    <div className="grid gap-2 sm:grid-cols-2">
      {scored.map((scan) => (
        <div key={scan.id} className="rounded-xl border border-border bg-card/70 p-3 text-sm">
          <div className="font-semibold">{scan.score}/100</div>
          <div className="mt-1 text-xs text-muted-foreground">
            {scan.scannedAt ? formatShortDate(scan.scannedAt) : "Unknown date"}
          </div>
        </div>
      ))}
    </div>
  );
}

function HeroStatusCard({
  label,
  title,
  description,
  icon: Icon,
}: {
  label: string;
  title: string;
  description: string;
  icon: LucideIcon;
}) {
  return (
    <div className="rounded-2xl border border-border bg-background/70 p-4 text-sm">
      <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-muted-foreground">
        <Icon className="h-4 w-4 text-primary" />
        {label}
      </div>
      <div className="mt-2 truncate font-semibold">{title}</div>
      <div className="mt-1 text-xs leading-5 text-muted-foreground">{description}</div>
    </div>
  );
}

function MiniMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-border bg-background/60 p-4">
      <div className="text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-2 truncate font-semibold">{value}</div>
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
      <div className="rounded-2xl bg-primary/10 p-3 text-primary w-fit">
        <Icon className="h-5 w-5" />
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
  children: ReactNode;
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

function EmptyState({ message }: { message: string }) {
  return (
    <div className="rounded-2xl border border-dashed border-border bg-background/50 p-6 text-sm text-muted-foreground">
      {message}
    </div>
  );
}

function isSuspiciousEmail(item: EmailThreatHistoryItem): boolean {
  const verdict = String(item.verdict || "").toLowerCase();
  if (!verdict) return false;
  return !verdict.includes("safe") && !verdict.includes("no obvious threat");
}

function emailVerdictClass(item: EmailThreatHistoryItem): string {
  if (!isSuspiciousEmail(item)) {
    return "bg-emerald-500/10 text-emerald-600";
  }

  const confidence = item.confidence.toLowerCase();

  if (confidence === "high") {
    return "bg-red-500/10 text-red-600";
  }

  if (confidence === "medium") {
    return "bg-amber-500/10 text-amber-600";
  }

  return "bg-sky-500/10 text-sky-600";
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
