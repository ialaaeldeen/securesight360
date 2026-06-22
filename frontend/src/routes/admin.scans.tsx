import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Calendar,
  Globe2,
  Inbox,
  Mail,
  RefreshCw,
  Search,
  ShieldCheck,
} from "lucide-react";

import { apiFetch } from "@/lib/api";

export const Route = createFileRoute("/admin/scans")({
  component: AdminSecurityActivityPage,
});

type ActivityTab = "website" | "email";

interface AdminWebsiteScan {
  id?: number | string;
  domain?: string | null;
  url?: string | null;
  target?: string | null;
  score?: number | string | null;
  security_score?: number | string | null;
  grade?: string | null;
  risk?: string | null;
  risk_level?: string | null;
  status?: string | null;
  user_id?: number | string | null;
  user_email?: string | null;
  created_at?: string | null;
}

interface AdminEmailAnalysis {
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
  analyzer_version?: string | null;
  created_at?: string | null;
}

function formatDate(value?: string | null): string {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return String(value);

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function toNumber(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;

  const number = Number(value);

  return Number.isFinite(number) ? number : null;
}

function formatScore(scan: AdminWebsiteScan): string {
  const score = toNumber(scan.score ?? scan.security_score);

  return score === null ? "—" : `${Math.round(score)}/100`;
}

function targetOf(scan: AdminWebsiteScan): string {
  return scan.domain || scan.target || scan.url || "Unknown target";
}

function riskFromScore(scan: AdminWebsiteScan): string {
  const score = toNumber(scan.score ?? scan.security_score);

  if (score === null) return "—";
  if (score >= 95) return "Minimal";
  if (score >= 85) return "Low";
  if (score >= 70) return "Moderate";
  if (score >= 50) return "High";
  return "Critical";
}

function riskOf(scan: AdminWebsiteScan): string {
  const directRisk =
    scan.risk ||
    scan.risk_level ||
    (scan as any).riskLevel ||
    (scan as any).security_risk ||
    (scan as any).risk_rating ||
    (scan as any).riskLevelLabel;

  if (directRisk && String(directRisk).trim() && String(directRisk).trim() !== "—") {
    return String(directRisk);
  }

  return riskFromScore(scan);
}

function riskClass(value?: string | null): string {
  const risk = String(value || "").toLowerCase();

  if (risk.includes("critical")) return "border-red-800/60 bg-red-950/40 text-red-300";
  if (risk.includes("high")) return "border-orange-800/60 bg-orange-950/40 text-orange-300";
  if (risk.includes("medium") || risk.includes("moderate")) return "border-yellow-800/60 bg-yellow-950/40 text-yellow-300";
  if (risk.includes("low")) return "border-green-800/60 bg-green-950/40 text-green-300";

  return "border-border bg-secondary/60 text-muted-foreground";
}

function statusClass(value?: string | null): string {
  const status = String(value || "").toLowerCase();

  if (status.includes("completed")) return "border-green-800/60 bg-green-950/40 text-green-300";
  if (status.includes("failed")) return "border-red-800/60 bg-red-950/40 text-red-300";
  if (status.includes("running") || status.includes("pending")) return "border-yellow-800/60 bg-yellow-950/40 text-yellow-300";

  return "border-border bg-secondary/60 text-muted-foreground";
}

function isSuspiciousVerdict(verdict?: string | null): boolean {
  const value = String(verdict || "").toLowerCase();

  if (!value) return false;

  return !value.includes("safe") && !value.includes("no obvious threat");
}

function verdictClass(verdict?: string | null): string {
  const value = String(verdict || "").toLowerCase();

  if (!isSuspiciousVerdict(verdict)) {
    return "border-green-800/60 bg-green-950/40 text-green-300";
  }

  if (
    value.includes("malicious") ||
    value.includes("credential") ||
    value.includes("fraud") ||
    value.includes("compromise")
  ) {
    return "border-red-800/60 bg-red-950/40 text-red-300";
  }

  return "border-yellow-800/60 bg-yellow-950/40 text-yellow-300";
}

function confidenceClass(value?: string | null): string {
  const confidence = String(value || "").toLowerCase();

  if (confidence === "high") return "text-red-300";
  if (confidence === "medium") return "text-yellow-300";

  return "text-green-300";
}

function StatCard({
  label,
  value,
  helper,
  icon: Icon,
  tone,
}: {
  label: string;
  value: string;
  helper: string;
  icon: any;
  tone: string;
}) {
  return (
    <section className="glass min-w-0 rounded-3xl p-4 sm:p-5">
      <div className="flex min-w-0 items-start justify-between gap-4">
        <div>
          <div className="text-xs uppercase tracking-wider text-muted-foreground">
            {label}
          </div>
          <div className={`mt-3 break-words text-2xl font-semibold sm:text-3xl ${tone}`}>{value}</div>
          <p className="mt-2 text-xs text-muted-foreground">{helper}</p>
        </div>

        <div className="grid h-11 w-11 shrink-0 place-items-center rounded-2xl border border-border bg-secondary/60">
          <Icon className={`h-5 w-5 ${tone}`} />
        </div>
      </div>
    </section>
  );
}

function TabButton({
  active,
  icon: Icon,
  label,
  count,
  onClick,
}: {
  active: boolean;
  icon: any;
  label: string;
  count: number;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex min-h-[44px] w-full items-center justify-center gap-2 rounded-2xl border px-4 py-2 text-sm font-medium transition sm:w-auto ${
        active
          ? "border-cyan/40 bg-cyan/10 text-cyan"
          : "border-border bg-secondary/50 text-muted-foreground hover:border-cyan/30 hover:text-cyan"
      }`}
    >
      <Icon className="h-4 w-4" />
      {label}
      <span className="rounded-full border border-border bg-background/50 px-2 py-0.5 text-xs">
        {count}
      </span>
    </button>
  );
}

function WebsiteTable({ scans }: { scans: AdminWebsiteScan[] }) {
  if (scans.length === 0) {
    return (
      <EmptyState message="No website scan history matched your search." />
    );
  }

  return (
    <div className="max-w-full overflow-x-auto">
      <table className="w-full min-w-[860px] text-left text-sm">
        <thead className="bg-surface/70 text-xs uppercase tracking-wider text-muted-foreground">
          <tr>
            <th className="px-5 py-4">ID</th>
            <th className="px-5 py-4">Website Target</th>
            <th className="px-5 py-4">User</th>
            <th className="px-5 py-4">Score</th>
            <th className="px-5 py-4">Risk</th>
            <th className="px-5 py-4">Status</th>
            <th className="px-5 py-4">When</th>
          </tr>
        </thead>

        <tbody>
          {scans.map((scan, index) => (
            <tr
              key={`${scan.id ?? index}`}
              className="border-t border-border/70 transition hover:bg-surface/40"
            >
              <td className="break-all px-5 py-4 text-muted-foreground">
                {scan.id ?? "—"}
              </td>
              <td className="break-all px-5 py-4 font-semibold">
                {targetOf(scan)}
              </td>
              <td className="break-all px-5 py-4 text-muted-foreground">
                {scan.user_email || "—"}
              </td>
              <td className="px-5 py-4">
                {formatScore(scan)}
              </td>
              <td className="px-5 py-4">
                <span
                  className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${riskClass(
                    riskOf(scan)
                  )}`}
                >
                  {riskOf(scan)}
                </span>
              </td>
              <td className="px-5 py-4">
                <span
                  className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${statusClass(
                    scan.status
                  )}`}
                >
                  {scan.status || "Unknown"}
                </span>
              </td>
              <td className="break-all px-5 py-4 text-muted-foreground">
                {formatDate(scan.created_at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EmailTable({ emails }: { emails: AdminEmailAnalysis[] }) {
  if (emails.length === 0) {
    return (
      <EmptyState message="No email analysis history matched your search." />
    );
  }

  return (
    <div className="space-y-3">
      {emails.map((item, index) => (
        <article
          key={`${item.id ?? index}`}
          className="min-w-0 rounded-3xl border border-border bg-surface/50 p-4 transition hover:bg-surface/70"
        >
          <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs text-muted-foreground">
                  #{item.id ?? "—"}
                </span>

                <span
                  className={`inline-flex rounded-2xl border px-3 py-1.5 text-xs font-semibold sm:rounded-full ${verdictClass(
                    item.verdict
                  )}`}
                >
                  {item.verdict || "Unknown verdict"}
                </span>

                <span className={`text-xs font-semibold ${confidenceClass(item.confidence)}`}>
                  {item.confidence || "—"} confidence
                </span>
              </div>

              <h3 className="mt-3 break-all font-semibold">
                {item.subject_preview || "No subject provided"}
              </h3>

              <p className="mt-1 break-all text-xs text-muted-foreground">
                User: {item.user_email || "Unknown user"} · Sender:{" "}
                {item.sender_preview || "No sender provided"}
              </p>

              <p className="mt-3 line-clamp-2 text-sm leading-6 text-muted-foreground">
                {item.summary || "No summary saved for this email analysis."}
              </p>
            </div>

            <div className="w-full rounded-2xl border border-border bg-secondary/40 p-3 text-xs text-muted-foreground xl:w-auto xl:min-w-[240px] xl:shrink-0">
              <div className="flex items-center gap-2">
                <Calendar className="h-3.5 w-3.5 text-cyan" />
                {formatDate(item.created_at)}
              </div>

              <div className="mt-2">
                Links: {item.links_count ?? 0} · Attachments:{" "}
                {item.attachments_count ?? 0}
              </div>

              <div className="mt-2">
                Headers: {item.headers_provided ? "Provided" : "Not provided"}
              </div>
            </div>
          </div>
        </article>
      ))}
    </div>
  );
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="rounded-2xl border border-dashed border-border bg-secondary/30 p-6 text-center text-sm text-muted-foreground sm:p-10">
      {message}
    </div>
  );
}

function AdminSecurityActivityPage() {
  const [tab, setTab] = useState<ActivityTab>("website");
  const [websiteScans, setWebsiteScans] = useState<AdminWebsiteScan[]>([]);
  const [emailAnalyses, setEmailAnalyses] = useState<AdminEmailAnalysis[]>([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadData(mode: "initial" | "refresh" = "initial") {
    if (mode === "initial") setLoading(true);
    else setRefreshing(true);

    setError(null);

    try {
      const [scansResponse, emailResponse] = await Promise.all([
        apiFetch<AdminWebsiteScan[]>("/api/v1/admin/scans"),
        apiFetch<AdminEmailAnalysis[]>("/api/v1/admin/email-analyses?limit=200"),
      ]);

      setWebsiteScans(Array.isArray(scansResponse) ? scansResponse : []);
      setEmailAnalyses(Array.isArray(emailResponse) ? emailResponse : []);
    } catch (err: any) {
      setError(err?.message || "Could not load admin security activity.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    void loadData("initial");
  }, []);

  const filteredWebsiteScans = useMemo(() => {
    const search = query.trim().toLowerCase();

    if (!search) return websiteScans;

    return websiteScans.filter((scan) => {
      return (
        String(scan.id || "").toLowerCase().includes(search) ||
        targetOf(scan).toLowerCase().includes(search) ||
        String(scan.user_email || "").toLowerCase().includes(search) ||
        String(riskOf(scan) || "").toLowerCase().includes(search) ||
        String(scan.status || "").toLowerCase().includes(search)
      );
    });
  }, [query, websiteScans]);

  const filteredEmailAnalyses = useMemo(() => {
    const search = query.trim().toLowerCase();

    if (!search) return emailAnalyses;

    return emailAnalyses.filter((item) => {
      return (
        String(item.id || "").toLowerCase().includes(search) ||
        String(item.user_email || "").toLowerCase().includes(search) ||
        String(item.subject_preview || "").toLowerCase().includes(search) ||
        String(item.sender_preview || "").toLowerCase().includes(search) ||
        String(item.verdict || "").toLowerCase().includes(search) ||
        String(item.confidence || "").toLowerCase().includes(search)
      );
    });
  }, [query, emailAnalyses]);

  const stats = useMemo(() => {
    const highCriticalWebsite = websiteScans.filter((scan) => {
      const risk = riskOf(scan).toLowerCase();
      return risk.includes("high") || risk.includes("critical");
    }).length;

    const suspiciousEmail = emailAnalyses.filter((item) =>
      isSuspiciousVerdict(item.verdict)
    ).length;

    const highConfidenceEmail = emailAnalyses.filter(
      (item) => String(item.confidence || "").toLowerCase() === "high"
    ).length;

    return {
      websiteTotal: websiteScans.length,
      highCriticalWebsite,
      emailTotal: emailAnalyses.length,
      suspiciousEmail,
      highConfidenceEmail,
    };
  }, [websiteScans, emailAnalyses]);

  return (
    <div className="space-y-5 sm:space-y-6">
      <section className="glass min-w-0 rounded-3xl p-4 sm:p-6 md:p-8">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex min-w-0 items-start gap-3 sm:gap-4">
            <div className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl border border-border bg-gradient-to-br from-cyan/20 to-accent-blue/10">
              <ShieldCheck className="h-6 w-6 text-cyan" />
            </div>

            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-cyan/25 bg-cyan/10 px-3 py-1 text-xs font-semibold text-cyan">
                <Inbox className="h-3.5 w-3.5" />
                Unified admin activity
              </div>

              <h1 className="mt-3 break-words text-xl font-semibold tracking-tight sm:text-2xl">
                Security Activity History
              </h1>

              <p className="text-sm text-muted-foreground">
                Review website scan history and AI email analysis activity across SecureSight360 users.
              </p>
            </div>
          </div>

          <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row">
            <div className="flex min-h-[44px] min-w-0 items-center gap-2 rounded-2xl border border-border bg-surface/60 px-3 py-2 focus-within:border-cyan/60">
              <Search className="h-4 w-4 text-muted-foreground" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search activity..."
                className="min-w-0 w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground/60 sm:w-64"
              />
            </div>

            <button
              type="button"
              onClick={() => loadData("refresh")}
              disabled={refreshing || loading}
              className="inline-flex min-h-[44px] w-full items-center justify-center gap-2 rounded-2xl border border-border bg-secondary/60 px-4 py-2 text-sm transition hover:border-cyan/40 hover:text-cyan disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto"
            >
              <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>
        </div>
      </section>

      <section className="grid gap-3 sm:grid-cols-2 lg:gap-4 xl:grid-cols-5">
        <StatCard
          label="Website Scans"
          value={String(stats.websiteTotal)}
          helper="Authorized website assessments"
          icon={Globe2}
          tone="text-accent-blue"
        />
        <StatCard
          label="High/Critical Website"
          value={String(stats.highCriticalWebsite)}
          helper="Website records needing review"
          icon={AlertTriangle}
          tone="text-warning"
        />
        <StatCard
          label="Email Analyses"
          value={String(stats.emailTotal)}
          helper="AI email checks saved"
          icon={Mail}
          tone="text-cyan"
        />
        <StatCard
          label="Suspicious Emails"
          value={String(stats.suspiciousEmail)}
          helper="Email verdicts needing attention"
          icon={AlertTriangle}
          tone="text-red-300"
        />
        <StatCard
          label="High Confidence Email"
          value={String(stats.highConfidenceEmail)}
          helper="High-confidence email results"
          icon={ShieldCheck}
          tone="text-green-300"
        />
      </section>

      {error && (
        <div className="rounded-3xl border border-red-800/50 bg-red-950/30 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      <section className="glass min-w-0 rounded-3xl p-4 sm:p-5">
        <div className="mb-5 flex min-w-0 flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="grid gap-2 sm:flex sm:flex-wrap">
            <TabButton
              active={tab === "website"}
              icon={Globe2}
              label="Website Scan History"
              count={filteredWebsiteScans.length}
              onClick={() => setTab("website")}
            />

            <TabButton
              active={tab === "email"}
              icon={Mail}
              label="Email Analysis History"
              count={filteredEmailAnalyses.length}
              onClick={() => setTab("email")}
            />
          </div>

          <div className="text-xs text-muted-foreground">
            {loading
              ? "Loading activity..."
              : tab === "website"
                ? `Showing ${filteredWebsiteScans.length} website record(s)`
                : `Showing ${filteredEmailAnalyses.length} email record(s)`}
          </div>
        </div>

        {loading ? (
          <div className="flex items-center justify-center gap-3 p-6 text-sm text-muted-foreground sm:p-10">
            <RefreshCw className="h-5 w-5 animate-spin text-cyan" />
            Loading admin security activity...
          </div>
        ) : tab === "website" ? (
          <WebsiteTable scans={filteredWebsiteScans} />
        ) : (
          <EmailTable emails={filteredEmailAnalyses} />
        )}
      </section>
    </div>
  );
}
