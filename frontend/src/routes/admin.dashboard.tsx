import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Globe2,
  Inbox,
  ListChecks,
  Mail,
  ShieldCheck,
  Users as UsersIcon,
} from "lucide-react";

import { apiFetch } from "@/lib/api";

export const Route = createFileRoute("/admin/dashboard")({
  component: AdminDashboard,
});

type DistributionInput =
  | Record<string, number>
  | Array<{ label?: string; name?: string; key?: string; value?: number; count?: number; total?: number }>
  | null
  | undefined;

interface ScanRow {
  id?: number | string;
  target?: string | null;
  target_url?: string | null;
  url?: string | null;
  status?: string | null;
  security_score?: number | null;
  average_security_score?: number | null;
  grade?: string | null;
  security_rating?: string | null;
  risk_level?: string | null;
  created_at?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  user_email?: string | null;
  user_full_name?: string | null;
}

interface EmailAnalysisRow {
  id?: number | string;
  user_id?: number | string | null;
  user_email?: string | null;
  user_full_name?: string | null;
  subject_preview?: string | null;
  sender_preview?: string | null;
  verdict?: string | null;
  confidence?: string | null;
  evidence_strength?: string | null;
  summary?: string | null;
  links_count?: number | null;
  attachments_count?: number | null;
  headers_provided?: boolean | null;
  created_at?: string | null;
}

interface ActiveUserRow {
  id?: number | string;
  email?: string | null;
  full_name?: string | null;
  scan_count?: number;
  total_scans?: number;
  email_analysis_count?: number;
  total_email_analyses?: number;
}

interface DashboardAnalysis {
  total_users?: number;
  active_users?: number;
  inactive_users?: number;
  total_admins?: number;
  active_admins?: number;

  total_scans?: number;
  completed_scans?: number;
  failed_scans?: number;
  average_security_score?: number | null;
  high_critical_risk_scan_count?: number;
  high_risk_scans?: number;

  total_email_analyses?: number;
  suspicious_email_count?: number;
  high_confidence_email_count?: number;
  email_links_reviewed?: number;
  email_attachments_reviewed?: number;
  email_headers_provided?: number;

  security_rating_distribution?: DistributionInput;
  rating_distribution?: DistributionInput;
  risk_level_distribution?: DistributionInput;
  scan_status_distribution?: DistributionInput;
  status_distribution?: DistributionInput;
  email_verdict_distribution?: DistributionInput;

  recent_scans?: ScanRow[];
  recent_email_analyses?: EmailAnalysisRow[];
  riskiest_targets?: ScanRow[];
  most_active_users?: ActiveUserRow[];
  most_active_email_users?: ActiveUserRow[];
}

interface NormalizedDistribution {
  label: string;
  value: number;
}

function formatNumber(value: unknown): string {
  const number = Number(value ?? 0);
  if (!Number.isFinite(number)) return "0";
  return new Intl.NumberFormat().format(number);
}

function formatScore(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  return `${Math.round(number)}/100`;
}

function formatDate(value?: string | null): string {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return value;

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function normalizeDistribution(input: DistributionInput): NormalizedDistribution[] {
  if (!input) return [];

  if (Array.isArray(input)) {
    return input
      .map((item) => ({
        label: String(item.label ?? item.name ?? item.key ?? "Unknown"),
        value: Number(item.value ?? item.count ?? item.total ?? 0),
      }))
      .filter((item) => item.value > 0);
  }

  return Object.entries(input)
    .map(([label, value]) => ({
      label,
      value: Number(value ?? 0),
    }))
    .filter((item) => item.value > 0);
}

function isSuspiciousVerdict(verdict?: string | null): boolean {
  const value = String(verdict || "").toLowerCase();
  if (!value) return false;
  return !value.includes("safe") && !value.includes("no obvious threat");
}

function toneForVerdict(verdict?: string | null): string {
  if (!isSuspiciousVerdict(verdict)) return "border-green-800/60 bg-green-950/40 text-green-300";

  const value = String(verdict || "").toLowerCase();

  if (value.includes("malicious") || value.includes("credential") || value.includes("fraud")) {
    return "border-red-800/60 bg-red-950/40 text-red-300";
  }

  return "border-yellow-800/60 bg-yellow-950/40 text-yellow-300";
}

function riskTone(value?: string | null): string {
  const risk = String(value || "").toLowerCase();

  if (risk.includes("critical")) return "text-danger";
  if (risk.includes("high")) return "text-warning";
  if (risk.includes("medium") || risk.includes("moderate")) return "text-warning";
  return "text-success";
}

function targetOf(scan: ScanRow): string {
  return scan.target || scan.target_url || scan.url || "Unknown target";
}

function scanDate(scan: ScanRow): string {
  return formatDate(scan.created_at || scan.completed_at || scan.started_at);
}

function KpiCard({
  label,
  value,
  helper,
  icon: Icon,
  tone = "text-cyan",
  loading,
}: {
  label: string;
  value: string;
  helper: string;
  icon: any;
  tone?: string;
  loading: boolean;
}) {
  return (
    <section className="glass min-w-0 rounded-3xl p-4 sm:p-5">
      <div className="flex min-w-0 items-start justify-between gap-3 sm:gap-4">
        <div className="min-w-0">
          <div className="text-xs uppercase tracking-wider text-muted-foreground">
            {label}
          </div>

          <div className={`mt-4 break-words text-2xl font-semibold sm:text-3xl ${tone}`}>
            {loading ? "…" : value}
          </div>

          <p className="mt-3 text-sm text-muted-foreground">{helper}</p>
        </div>

        <div className="grid h-11 w-11 shrink-0 place-items-center rounded-2xl border border-border bg-secondary/60">
          <Icon className={`h-5 w-5 ${tone}`} />
        </div>
      </div>
    </section>
  );
}

function DistributionCard({
  title,
  description,
  items,
}: {
  title: string;
  description: string;
  items: NormalizedDistribution[];
}) {
  const total = items.reduce((sum, item) => sum + item.value, 0);

  return (
    <section className="glass min-w-0 rounded-3xl p-4 sm:p-5">
      <div className="mb-4 flex flex-col gap-3 sm:mb-5 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
        <div className="min-w-0">
          <h2 className="break-words text-base font-semibold">{title}</h2>
          <p className="text-xs text-muted-foreground">{description}</p>
        </div>

        <BarChart3 className="h-5 w-5 text-accent-blue" />
      </div>

      {items.length === 0 ? (
        <EmptyState message="No data available yet." />
      ) : (
        <div className="space-y-4">
          {items.slice(0, 6).map((item) => {
            const percentage = total ? Math.round((item.value / total) * 100) : 0;

            return (
              <div key={item.label} className="space-y-2">
                <div className="flex flex-col gap-1 text-sm sm:flex-row sm:items-center sm:justify-between sm:gap-3">
                  <span className="break-words font-medium">{item.label}</span>
                  <span className="text-muted-foreground">
                    {formatNumber(item.value)} · {percentage}%
                  </span>
                </div>

                <div className="h-2 overflow-hidden rounded-full bg-white/10">
                  <div
                    className="h-full rounded-full bg-accent-blue"
                    style={{ width: `${Math.max(percentage, 4)}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

function RecentWebsiteScans({ scans }: { scans: ScanRow[] }) {
  return (
    <section className="glass min-w-0 rounded-3xl p-4 sm:p-5">
      <div className="mb-4 flex flex-col gap-3 sm:mb-5 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
        <div className="min-w-0">
          <h2 className="text-base font-semibold">Recent Website Scans</h2>
          <p className="text-xs text-muted-foreground">
            Latest authorized website assessments across users.
          </p>
        </div>

        <Globe2 className="h-5 w-5 text-accent-blue" />
      </div>

      {scans.length === 0 ? (
        <EmptyState message="No recent website scans available yet." />
      ) : (
        <>
          <div className="space-y-3 md:hidden">
            {scans.slice(0, 6).map((scan, index) => (
              <div
                key={`${scan.id ?? index}`}
                className="min-w-0 rounded-2xl border border-border bg-secondary/30 p-3"
              >
                <div className="break-all text-sm font-semibold">{targetOf(scan)}</div>
                <div className="mt-1 break-all text-xs text-muted-foreground">
                  {scan.user_email || scan.user_full_name || "Unknown user"}
                </div>

                <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
                  <div className="rounded-xl border border-border/70 bg-background/30 px-3 py-2">
                    <div className="uppercase tracking-wider text-muted-foreground">Score</div>
                    <div className="mt-1 font-semibold">{formatScore(scan.security_score)}</div>
                  </div>

                  <div className="rounded-xl border border-border/70 bg-background/30 px-3 py-2">
                    <div className="uppercase tracking-wider text-muted-foreground">Risk</div>
                    <div className={`mt-1 break-words font-semibold ${riskTone(scan.risk_level)}`}>
                      {scan.risk_level || scan.grade || scan.security_rating || "—"}
                    </div>
                  </div>
                </div>

                <div className="mt-3 text-xs text-muted-foreground">{scanDate(scan)}</div>
              </div>
            ))}
          </div>

          <div className="hidden max-w-full overflow-x-auto md:block">
            <table className="w-full min-w-[620px] text-sm">
              <thead className="text-xs uppercase tracking-wider text-muted-foreground">
                <tr className="border-b border-border">
                  <th className="py-3 pr-4 text-left">Target</th>
                  <th className="py-3 pr-4 text-left">User</th>
                  <th className="py-3 pr-4 text-left">Score</th>
                  <th className="py-3 pr-4 text-left">Risk</th>
                  <th className="py-3 text-left">When</th>
                </tr>
              </thead>

              <tbody>
                {scans.slice(0, 6).map((scan, index) => (
                  <tr key={`${scan.id ?? index}`} className="border-b border-border/60 last:border-0">
                    <td className="break-all py-3 pr-4 font-medium">{targetOf(scan)}</td>
                    <td className="break-all py-3 pr-4 text-muted-foreground">
                      {scan.user_email || scan.user_full_name || "—"}
                    </td>
                    <td className="py-3 pr-4">{formatScore(scan.security_score)}</td>
                    <td className={`py-3 pr-4 font-medium ${riskTone(scan.risk_level)}`}>
                      {scan.risk_level || scan.grade || scan.security_rating || "—"}
                    </td>
                    <td className="py-3 text-muted-foreground">{scanDate(scan)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}

function RecentEmailAnalyses({ items }: { items: EmailAnalysisRow[] }) {
  return (
    <section className="glass min-w-0 rounded-3xl p-4 sm:p-5">
      <div className="mb-4 flex flex-col gap-3 sm:mb-5 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
        <div className="min-w-0">
          <h2 className="text-base font-semibold">Recent Email Analyses</h2>
          <p className="text-xs text-muted-foreground">
            Latest AI Email Threat Analyzer activity across users.
          </p>
        </div>

        <Mail className="h-5 w-5 text-cyan" />
      </div>

      {items.length === 0 ? (
        <EmptyState message="No email analyses available yet." />
      ) : (
        <div className="space-y-3">
          {items.slice(0, 6).map((item, index) => (
            <div
              key={`${item.id ?? index}`}
              className="min-w-0 rounded-2xl border border-border bg-secondary/30 p-3 sm:p-4"
            >
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div className="min-w-0">
                  <div className="break-words font-medium">
                    {item.subject_preview || "No subject provided"}
                  </div>

                  <div className="mt-1 break-all text-xs text-muted-foreground">
                    {item.user_email || "Unknown user"} · {item.sender_preview || "No sender provided"}
                  </div>

                  <p className="mt-2 line-clamp-2 text-xs leading-5 text-muted-foreground">
                    {item.summary || "No summary saved."}
                  </p>
                </div>

                <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:flex-wrap sm:items-center sm:shrink-0">
                  <span
                    className={`inline-flex w-full items-center justify-center rounded-2xl border px-3 py-1.5 text-center text-xs font-semibold sm:w-auto sm:rounded-full ${toneForVerdict(
                      item.verdict,
                    )}`}
                  >
                    {item.verdict || "Unknown"}
                  </span>

                  <span className="break-words rounded-2xl border border-border bg-background/40 px-3 py-1.5 text-center text-xs text-muted-foreground sm:rounded-full">
                    {item.confidence || "—"} confidence
                  </span>
                </div>
              </div>

              <div className="mt-3 flex min-w-0 flex-wrap gap-2 text-xs text-muted-foreground sm:gap-3">
                <span>{item.links_count ?? 0} link(s)</span>
                <span>{item.attachments_count ?? 0} attachment(s)</span>
                <span>Headers: {item.headers_provided ? "Provided" : "Not provided"}</span>
                <span>{formatDate(item.created_at)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function ActiveUsersPanel({
  websiteUsers,
  emailUsers,
}: {
  websiteUsers: ActiveUserRow[];
  emailUsers: ActiveUserRow[];
}) {
  return (
    <section className="glass min-w-0 rounded-3xl p-4 sm:p-5">
      <div className="mb-4 flex flex-col gap-3 sm:mb-5 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
        <div className="min-w-0">
          <h2 className="text-base font-semibold">Most Active Users</h2>
          <p className="text-xs text-muted-foreground">
            User activity across website scans and email analyses.
          </p>
        </div>

        <UsersIcon className="h-5 w-5 text-cyan" />
      </div>

      <div className="grid gap-3 sm:gap-4 lg:grid-cols-2">
        <UserActivityList
          title="Website scanning"
          emptyText="No website scan user activity yet."
          users={websiteUsers}
          countKey="scan_count"
          fallbackKey="total_scans"
        />

        <UserActivityList
          title="Email analysis"
          emptyText="No email analysis user activity yet."
          users={emailUsers}
          countKey="email_analysis_count"
          fallbackKey="total_email_analyses"
        />
      </div>
    </section>
  );
}

function UserActivityList({
  title,
  users,
  countKey,
  fallbackKey,
  emptyText,
}: {
  title: string;
  users: ActiveUserRow[];
  countKey: keyof ActiveUserRow;
  fallbackKey: keyof ActiveUserRow;
  emptyText: string;
}) {
  return (
    <div className="min-w-0 rounded-2xl border border-border bg-secondary/30 p-3 sm:p-4">
      <div className="mb-3 text-sm font-semibold">{title}</div>

      {users.length === 0 ? (
        <p className="text-xs text-muted-foreground">{emptyText}</p>
      ) : (
        <div className="space-y-3">
          {users.slice(0, 5).map((user, index) => {
            const count = Number(user[countKey] ?? user[fallbackKey] ?? 0);

            return (
              <div key={`${user.id ?? user.email ?? index}`} className="flex min-w-0 flex-col gap-2 rounded-2xl border border-border/70 bg-background/30 p-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0">
                  <div className="break-words text-sm font-medium">
                    {user.full_name || user.email || "Unknown user"}
                  </div>
                  <div className="break-all text-xs text-muted-foreground">
                    {user.email || "No email"}
                  </div>
                </div>

                <div className="break-words rounded-2xl border border-border bg-background/40 px-3 py-1.5 text-center text-xs text-muted-foreground sm:rounded-full">
                  {formatNumber(count)}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="rounded-2xl border border-dashed border-border bg-secondary/30 p-4 text-sm text-muted-foreground sm:p-5">
      {message}
    </div>
  );
}

function AdminDashboard() {
  const [analysis, setAnalysis] = useState<DashboardAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;

    async function loadDashboard() {
      setLoading(true);

      try {
        const data = await apiFetch<DashboardAnalysis>("/api/v1/admin/dashboard/analysis");

        if (isMounted) {
          setAnalysis(data || {});
          setError(null);
        }
      } catch (err: any) {
        if (isMounted) {
          setError(err?.message || "Failed to load admin dashboard analysis.");
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    }

    void loadDashboard();

    return () => {
      isMounted = false;
    };
  }, []);

  const highCriticalCount =
    analysis?.high_critical_risk_scan_count ?? analysis?.high_risk_scans ?? 0;

  const securityRatingDistribution = normalizeDistribution(
    analysis?.security_rating_distribution || analysis?.rating_distribution,
  );

  const emailVerdictDistribution = normalizeDistribution(analysis?.email_verdict_distribution);

  const recentScans = Array.isArray(analysis?.recent_scans) ? analysis.recent_scans : [];
  const recentEmailAnalyses = Array.isArray(analysis?.recent_email_analyses)
    ? analysis.recent_email_analyses
    : [];

  const mostActiveWebsiteUsers = Array.isArray(analysis?.most_active_users)
    ? analysis.most_active_users
    : [];

  const mostActiveEmailUsers = Array.isArray(analysis?.most_active_email_users)
    ? analysis.most_active_email_users
    : [];

  const cards = [
    {
      label: "Total Users",
      value: formatNumber(analysis?.total_users),
      helper: `${formatNumber(analysis?.active_users)} active · ${formatNumber(
        analysis?.inactive_users,
      )} inactive`,
      icon: UsersIcon,
      tone: "text-cyan",
    },
    {
      label: "Website Scans",
      value: formatNumber(analysis?.total_scans),
      helper: `${formatNumber(analysis?.completed_scans)} completed · ${formatNumber(
        highCriticalCount,
      )} high/critical`,
      icon: Globe2,
      tone: "text-accent-blue",
    },
    {
      label: "Email Analyses",
      value: formatNumber(analysis?.total_email_analyses),
      helper: `${formatNumber(analysis?.suspicious_email_count)} suspicious email result(s)`,
      icon: Mail,
      tone: "text-cyan",
    },
    {
      label: "High Confidence Email",
      value: formatNumber(analysis?.high_confidence_email_count),
      helper: `${formatNumber(analysis?.email_links_reviewed)} links · ${formatNumber(
        analysis?.email_attachments_reviewed,
      )} attachments reviewed`,
      icon: ShieldCheck,
      tone: "text-success",
    },
    {
      label: "Average Website Score",
      value: formatScore(analysis?.average_security_score),
      helper: "Average score across website scan history",
      icon: Activity,
      tone: "text-success",
    },
    {
      label: "Priority Security Items",
      value: formatNumber(
        Number(highCriticalCount || 0) + Number(analysis?.suspicious_email_count || 0),
      ),
      helper: "Website high/critical + suspicious email results",
      icon: AlertTriangle,
      tone: "text-warning",
    },
  ];

  return (
    <div className="space-y-5 sm:space-y-6">
      <header className="flex min-w-0 flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div className="min-w-0">
          <div className="inline-flex items-center gap-2 rounded-full border border-cyan/25 bg-cyan/10 px-3 py-1 text-xs font-semibold text-cyan">
            <ShieldCheck className="h-3.5 w-3.5" />
            Unified Admin Security Console
          </div>

          <h1 className="mt-3 break-words text-xl font-semibold tracking-tight sm:text-2xl">
            Admin Security Overview
          </h1>

          <p className="text-sm text-muted-foreground">
            Website scanner activity, AI email threat analysis, and user security visibility from live SecureSight360 backend data.
          </p>
        </div>

        <div className="break-words rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-xs text-muted-foreground sm:px-4">
          Live backend security analytics
        </div>
      </header>

      {error && (
        <div className="rounded-2xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:gap-4 xl:grid-cols-3">
        {cards.map((card) => (
          <KpiCard key={card.label} {...card} loading={loading} />
        ))}
      </div>

      <div className="grid gap-3 sm:gap-4 xl:grid-cols-2">
        <DistributionCard
          title="Website Security Rating Distribution"
          description="Professional rating split across completed website scans."
          items={securityRatingDistribution}
        />

        <DistributionCard
          title="Email Verdict Distribution"
          description="AI Email Threat Analyzer verdicts across saved analyses."
          items={emailVerdictDistribution}
        />
      </div>

      <div className="grid gap-3 sm:gap-4 xl:grid-cols-2">
        <RecentWebsiteScans scans={recentScans} />
        <RecentEmailAnalyses items={recentEmailAnalyses} />
      </div>

      <ActiveUsersPanel
        websiteUsers={mostActiveWebsiteUsers}
        emailUsers={mostActiveEmailUsers}
      />

      <section className="glass min-w-0 rounded-3xl p-4 sm:p-5">
        <div className="mb-4 flex flex-col gap-3 sm:mb-5 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
          <div className="min-w-0">
            <h2 className="break-words text-base font-semibold">Admin Notes</h2>
            <p className="text-xs text-muted-foreground">
              Simple operational interpretation for the current admin view.
            </p>
          </div>

          <CheckCircle2 className="h-5 w-5 text-success" />
        </div>

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <div className="min-w-0 rounded-2xl border border-border bg-secondary/30 p-3 sm:p-4">
            <div className="text-sm font-semibold">Website posture</div>
            <p className="mt-2 text-xs leading-5 text-muted-foreground">
              Continue using scan history and reports for full website evidence. This dashboard only summarizes activity.
            </p>
          </div>

          <div className="min-w-0 rounded-2xl border border-border bg-secondary/30 p-3 sm:p-4">
            <div className="text-sm font-semibold">Email threats</div>
            <p className="mt-2 text-xs leading-5 text-muted-foreground">
              Suspicious email verdicts help admins see phishing activity without exposing full mailbox content.
            </p>
          </div>

          <div className="min-w-0 rounded-2xl border border-border bg-secondary/30 p-3 sm:p-4">
            <div className="text-sm font-semibold">User oversight</div>
            <p className="mt-2 text-xs leading-5 text-muted-foreground">
              User management remains separate so admin actions stay controlled and auditable.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
