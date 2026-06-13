import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Crown,
  ListChecks,
  ShieldAlert,
  ShieldCheck,
  Target,
  UserCheck,
  UserX,
  Users as UsersIcon,
  XCircle,
} from "lucide-react";

import { apiFetch } from "@/lib/api";

type DistributionInput =
  | Record<string, number>
  | Array<{ label?: string; name?: string; key?: string; value?: number; count?: number }>
  | null
  | undefined;

interface ScanRow {
  id?: number | string;
  target?: string;
  target_url?: string;
  url?: string;
  status?: string;
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
  scan_count?: number;
}

interface ActiveUserRow {
  id?: number | string;
  email?: string | null;
  full_name?: string | null;
  role?: string | null;
  scan_count?: number;
  total_scans?: number;
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
  security_rating_distribution?: DistributionInput;
  rating_distribution?: DistributionInput;
  risk_level_distribution?: DistributionInput;
  scan_status_distribution?: DistributionInput;
  status_distribution?: DistributionInput;
  recent_scans?: ScanRow[];
  riskiest_targets?: ScanRow[];
  most_active_users?: ActiveUserRow[];
  [key: string]: unknown;
}

interface DistributionItem {
  label: string;
  value: number;
}

export const Route = createFileRoute("/admin/dashboard")({
  component: AdminDashboard,
});

function numberValue(value: unknown, fallback = 0): number {
  const parsed = Number(value);

  if (!Number.isFinite(parsed)) {
    return fallback;
  }

  return parsed;
}

function formatNumber(value: unknown): string {
  const parsed = Number(value);

  if (!Number.isFinite(parsed)) {
    return "0";
  }

  return parsed.toLocaleString();
}

function formatScore(value: unknown): string {
  const parsed = Number(value);

  if (!Number.isFinite(parsed)) {
    return "—";
  }

  return `${Math.round(parsed)}/100`;
}

function formatDate(value: unknown): string {
  if (!value) {
    return "—";
  }

  const date = new Date(String(value));

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}

function cleanLabel(value: unknown): string {
  const raw = String(value || "Unknown").trim();

  if (!raw) {
    return "Unknown";
  }

  return raw
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function getTarget(row: ScanRow): string {
  return String(row.target_url || row.target || row.url || "Unknown target");
}

function getRating(row: ScanRow): string {
  return cleanLabel(row.security_rating || row.grade || "Unrated");
}

function getRisk(row: ScanRow): string {
  return cleanLabel(row.risk_level || "Unknown");
}

function getScanDate(row: ScanRow): string {
  return formatDate(row.created_at || row.completed_at || row.started_at);
}

function normalizeDistribution(input: DistributionInput): DistributionItem[] {
  if (!input) {
    return [];
  }

  const merged = new Map<string, number>();

  const addItem = (labelValue: unknown, numericValue: unknown) => {
    const label = cleanLabel(labelValue);
    const value = numberValue(numericValue);

    if (value <= 0) {
      return;
    }

    merged.set(label, (merged.get(label) ?? 0) + value);
  };

  if (Array.isArray(input)) {
    input.forEach((item) => {
      addItem(item.label || item.name || item.key || "Unknown", item.value ?? item.count);
    });
  } else {
    Object.entries(input).forEach(([label, value]) => {
      addItem(label, value);
    });
  }

  return Array.from(merged.entries())
    .map(([label, value]) => ({ label, value }))
    .sort((a, b) => b.value - a.value);
}

function statusTone(value: unknown): string {
  const normalized = String(value || "").toLowerCase();

  if (normalized.includes("complete")) {
    return "border-success/30 bg-success/10 text-success";
  }

  if (normalized.includes("fail") || normalized.includes("error")) {
    return "border-destructive/30 bg-destructive/10 text-destructive";
  }

  return "border-accent-blue/30 bg-accent-blue/10 text-accent-blue";
}

function ratingTone(value: unknown): string {
  const normalized = String(value || "").toLowerCase();

  if (normalized.includes("excellent") || normalized.includes("strong")) {
    return "border-success/30 bg-success/10 text-success";
  }

  if (normalized.includes("moderate")) {
    return "border-warning/30 bg-warning/10 text-warning";
  }

  if (normalized.includes("weak") || normalized.includes("critical")) {
    return "border-destructive/30 bg-destructive/10 text-destructive";
  }

  return "border-white/10 bg-white/5 text-muted-foreground";
}

function riskTone(value: unknown): string {
  const normalized = String(value || "").toLowerCase();

  if (normalized.includes("critical") || normalized.includes("high")) {
    return "border-destructive/30 bg-destructive/10 text-destructive";
  }

  if (normalized.includes("medium") || normalized.includes("moderate")) {
    return "border-warning/30 bg-warning/10 text-warning";
  }

  if (normalized.includes("low")) {
    return "border-success/30 bg-success/10 text-success";
  }

  return "border-white/10 bg-white/5 text-muted-foreground";
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.03] px-4 py-8 text-center text-sm text-muted-foreground">
      {message}
    </div>
  );
}

function KpiCard({
  label,
  value,
  helper,
  icon: Icon,
  tone,
  loading,
}: {
  label: string;
  value: string;
  helper?: string;
  icon: React.ComponentType<{ className?: string }>;
  tone: string;
  loading: boolean;
}) {
  return (
    <div className="glass rounded-2xl p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-xs uppercase tracking-wider text-muted-foreground">
            {label}
          </div>
          <div className={`mt-3 text-3xl font-semibold ${tone}`}>
            {loading ? "…" : value}
          </div>
        </div>

        <div className="rounded-xl border border-white/10 bg-white/5 p-2">
          <Icon className={`h-5 w-5 ${tone}`} />
        </div>
      </div>

      {helper && (
        <div className="mt-3 text-xs text-muted-foreground">
          {helper}
        </div>
      )}
    </div>
  );
}

function DistributionCard({
  title,
  description,
  items,
}: {
  title: string;
  description: string;
  items: DistributionItem[];
}) {
  const total = useMemo(
    () => items.reduce((sum, item) => sum + item.value, 0),
    [items],
  );

  return (
    <section className="glass rounded-2xl p-5">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold">{title}</h2>
          <p className="text-xs text-muted-foreground">{description}</p>
        </div>
        <BarChart3 className="h-5 w-5 text-accent-blue" />
      </div>

      {items.length === 0 ? (
        <EmptyState message="No distribution data available yet." />
      ) : (
        <div className="space-y-4">
          {items.map((item) => {
            const percentage = total > 0 ? Math.round((item.value / total) * 100) : 0;

            return (
              <div key={item.label} className="space-y-2">
                <div className="flex items-center justify-between gap-4 text-sm">
                  <span className="font-medium">{item.label}</span>
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

function AdminDashboard() {
  const [analysis, setAnalysis] = useState<DashboardAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;

    (async () => {
      try {
        const data = await apiFetch<DashboardAnalysis>("/api/v1/admin/dashboard/analysis");

        if (isMounted) {
          setAnalysis(data || {});
          setError(null);
        }
      } catch (e: any) {
        if (isMounted) {
          setError(e?.message || "Failed to load admin dashboard analysis.");
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    })();

    return () => {
      isMounted = false;
    };
  }, []);

  const securityRatingDistribution = normalizeDistribution(
    analysis?.security_rating_distribution || analysis?.rating_distribution,
  );

  const riskLevelDistribution = normalizeDistribution(analysis?.risk_level_distribution);

  const scanStatusDistribution = normalizeDistribution(
    analysis?.scan_status_distribution || analysis?.status_distribution,
  );

  const recentScans = Array.isArray(analysis?.recent_scans) ? analysis.recent_scans : [];
  const riskiestTargets = Array.isArray(analysis?.riskiest_targets)
    ? analysis.riskiest_targets
    : [];
  const mostActiveUsers = Array.isArray(analysis?.most_active_users)
    ? analysis.most_active_users
    : [];

  const highCriticalCount =
    analysis?.high_critical_risk_scan_count ?? analysis?.high_risk_scans ?? 0;

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
      label: "Active Users",
      value: formatNumber(analysis?.active_users),
      helper: "Currently enabled accounts",
      icon: UserCheck,
      tone: "text-success",
    },
    {
      label: "Inactive Users",
      value: formatNumber(analysis?.inactive_users),
      helper: "Disabled or removed from access",
      icon: UserX,
      tone: "text-warning",
    },
    {
      label: "Admins",
      value: formatNumber(analysis?.total_admins),
      helper: `${formatNumber(analysis?.active_admins)} active admins`,
      icon: Crown,
      tone: "text-accent-blue",
    },
    {
      label: "Total Scans",
      value: formatNumber(analysis?.total_scans),
      helper: `${formatNumber(analysis?.completed_scans)} completed`,
      icon: ListChecks,
      tone: "text-accent-blue",
    },
    {
      label: "Failed Scans",
      value: formatNumber(analysis?.failed_scans),
      helper: "Scans requiring review",
      icon: XCircle,
      tone: "text-destructive",
    },
    {
      label: "Average Score",
      value: formatScore(analysis?.average_security_score),
      helper: "Average website security score",
      icon: ShieldCheck,
      tone: "text-success",
    },
    {
      label: "High/Critical Risk",
      value: formatNumber(highCriticalCount),
      helper: "Priority scan results",
      icon: AlertTriangle,
      tone: "text-warning",
    },
  ];

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            Admin Dashboard Analysis
          </h1>
          <p className="text-sm text-muted-foreground">
            Security, user, and scan intelligence from live SecureSight360 backend data.
          </p>
        </div>

        <div className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-xs text-muted-foreground">
          Source: /api/v1/admin/dashboard/analysis
        </div>
      </header>

      {error && (
        <div className="rounded-xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {cards.map((card) => (
          <KpiCard key={card.label} {...card} loading={loading} />
        ))}
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <DistributionCard
          title="Security Rating Distribution"
          description="Professional rating split across completed scans."
          items={securityRatingDistribution}
        />

        <DistributionCard
          title="Risk Level Distribution"
          description="Risk exposure view across saved scan records."
          items={riskLevelDistribution}
        />

        <DistributionCard
          title="Scan Status Distribution"
          description="Operational status breakdown for scan processing."
          items={scanStatusDistribution}
        />
      </div>

      <section className="glass rounded-2xl p-5">
        <div className="mb-5 flex items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold">Recent Scans</h2>
            <p className="text-xs text-muted-foreground">
              Latest assessment records retained for operational visibility.
            </p>
          </div>
          <Activity className="h-5 w-5 text-accent-blue" />
        </div>

        {recentScans.length === 0 ? (
          <EmptyState message="No recent scans available yet." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-sm">
              <thead>
                <tr className="border-b border-white/10 text-xs uppercase tracking-wider text-muted-foreground">
                  <th className="py-3 pr-4 font-medium">Target</th>
                  <th className="py-3 pr-4 font-medium">User</th>
                  <th className="py-3 pr-4 font-medium">Status</th>
                  <th className="py-3 pr-4 font-medium">Score</th>
                  <th className="py-3 pr-4 font-medium">Security Rating</th>
                  <th className="py-3 pr-4 font-medium">Risk</th>
                  <th className="py-3 font-medium">Date</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map((scan, index) => (
                  <tr key={`${scan.id || getTarget(scan)}-${index}`} className="border-b border-white/5">
                    <td className="py-3 pr-4 font-medium">{getTarget(scan)}</td>
                    <td className="py-3 pr-4 text-muted-foreground">
                      {scan.user_email || scan.user_full_name || "—"}
                    </td>
                    <td className="py-3 pr-4">
                      <span className={`rounded-full border px-2.5 py-1 text-xs ${statusTone(scan.status)}`}>
                        {cleanLabel(scan.status || "Unknown")}
                      </span>
                    </td>
                    <td className="py-3 pr-4">{formatScore(scan.security_score)}</td>
                    <td className="py-3 pr-4">
                      <span className={`rounded-full border px-2.5 py-1 text-xs ${ratingTone(getRating(scan))}`}>
                        {getRating(scan)}
                      </span>
                    </td>
                    <td className="py-3 pr-4">
                      <span className={`rounded-full border px-2.5 py-1 text-xs ${riskTone(getRisk(scan))}`}>
                        {getRisk(scan)}
                      </span>
                    </td>
                    <td className="py-3 text-muted-foreground">{getScanDate(scan)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <div className="grid gap-4 xl:grid-cols-2">
        <section className="glass rounded-2xl p-5">
          <div className="mb-5 flex items-start justify-between gap-4">
            <div>
              <h2 className="text-base font-semibold">Riskiest Targets</h2>
              <p className="text-xs text-muted-foreground">
                Targets that should be reviewed first based on risk and score.
              </p>
            </div>
            <ShieldAlert className="h-5 w-5 text-warning" />
          </div>

          {riskiestTargets.length === 0 ? (
            <EmptyState message="No risky targets available yet." />
          ) : (
            <div className="space-y-3">
              {riskiestTargets.map((target, index) => (
                <div
                  key={`${getTarget(target)}-${index}`}
                  className="rounded-xl border border-white/10 bg-white/[0.03] p-4"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="font-medium">{getTarget(target)}</div>
                      <div className="mt-1 text-xs text-muted-foreground">
                        {target.user_email || target.user_full_name || "No owner recorded"}
                      </div>
                    </div>

                    <Target className="h-4 w-4 text-warning" />
                  </div>

                  <div className="mt-3 flex flex-wrap gap-2">
                    <span className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-xs">
                      Score: {formatScore(target.security_score ?? target.average_security_score)}
                    </span>
                    <span className={`rounded-full border px-2.5 py-1 text-xs ${ratingTone(getRating(target))}`}>
                      {getRating(target)}
                    </span>
                    <span className={`rounded-full border px-2.5 py-1 text-xs ${riskTone(getRisk(target))}`}>
                      {getRisk(target)}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="glass rounded-2xl p-5">
          <div className="mb-5 flex items-start justify-between gap-4">
            <div>
              <h2 className="text-base font-semibold">Most Active Users</h2>
              <p className="text-xs text-muted-foreground">
                Users with the highest number of saved scan records.
              </p>
            </div>
            <CheckCircle2 className="h-5 w-5 text-success" />
          </div>

          {mostActiveUsers.length === 0 ? (
            <EmptyState message="No user scan activity available yet." />
          ) : (
            <div className="space-y-3">
              {mostActiveUsers.map((user, index) => {
                const scanCount = user.scan_count ?? user.total_scans ?? 0;

                return (
                  <div
                    key={`${user.id || user.email || index}`}
                    className="flex items-center justify-between gap-4 rounded-xl border border-white/10 bg-white/[0.03] p-4"
                  >
                    <div>
                      <div className="font-medium">
                        {user.full_name || user.email || "Unknown user"}
                      </div>
                      <div className="mt-1 text-xs text-muted-foreground">
                        {user.email || "No email recorded"}
                      </div>
                    </div>

                    <div className="text-right">
                      <div className="text-xl font-semibold text-accent-blue">
                        {formatNumber(scanCount)}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        scans
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
