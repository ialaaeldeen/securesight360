import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Award,
  BarChart3,
  Calendar,
  CheckCircle,
  Download,
  Eye,
  FileText,
  Globe,
  Loader2,
  Lock,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Sparkles,
  X,
} from "lucide-react";

import { API_BASE, apiFetch, getToken } from "@/lib/api";
import { AssessmentScopeCard } from "@/components/AssessmentScopeCard";

type ReportRecord = {
  id: string;
  domain: string;
  target_url?: string;
  created_at: string;
  score: number;
  grade: string;
  risk_level: string;
  profile: string;
  findings_count: number;
  status: string;
  raw: any;
};

type EvidenceRow = [string, any];

function safeNumber(value: any, fallback = 0): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function hostnameFromUrl(value: string): string {
  try {
    return new URL(value).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return String(value || "unknown")
      .replace(/^https?:\/\//, "")
      .split("/")[0]
      .replace(/^www\./, "")
      .toLowerCase();
  }
}

function normalizeReport(row: any): ReportRecord {
  const target =
    row?.target_url ||
    row?.url ||
    row?.target ||
    row?.result?.final_url ||
    row?.result?.original_url ||
    row?.raw?.target_url ||
    "unknown";

  const domain =
    row?.domain ||
    row?.result?.domain ||
    row?.raw?.domain ||
    hostnameFromUrl(target);

  const score = safeNumber(
    row?.score ??
      row?.security_score ??
      row?.overall_score ??
      row?.risk_score ??
      row?.risk_assessment?.security_score ??
      row?.result?.security_score ??
      row?.raw?.security_score,
    0
  );

  const findingsCount = safeNumber(
    row?.findings_count ??
      row?.total_findings ??
      (Array.isArray(row?.findings) ? row.findings.length : undefined) ??
      (Array.isArray(row?.raw?.findings) ? row.raw.findings.length : undefined),
    0
  );

  return {
    id: String(row?.id || row?.scan_id || `${domain}-${Date.now()}`),
    domain: String(domain || "unknown").replace(/^www\./, "").toLowerCase(),
    target_url: String(target || ""),
    created_at: String(
      row?.created_at ||
        row?.completed_at ||
        row?.started_at ||
        row?.scanned_at ||
        row?.timestamp ||
        new Date().toISOString()
    ),
    score,
    grade: String(
      row?.grade ||
        row?.security_rating ||
        (score >= 85 ? "Excellent" : score >= 70 ? "Strong" : score >= 50 ? "Moderate" : score >= 30 ? "Weak" : "Critical")
    ),
    risk_level: String(
      row?.risk_level ||
        row?.risk ||
        (score >= 85 ? "Low" : score >= 65 ? "Medium" : score >= 30 ? "High" : "Critical")
    ),
    profile: String(row?.profile || row?.scan_profile || "Basic"),
    findings_count: findingsCount,
    status: String(row?.status || row?.scan_status || "completed"),
    raw: row,
  };
}

function levelClass(level: string): string {
  const value = level.toLowerCase();

  if (value.includes("low")) return "bg-success/15 text-success border-success/30";
  if (value.includes("medium")) return "bg-warning/15 text-warning border-warning/30";
  if (value.includes("high")) return "bg-danger/15 text-danger border-danger/30";

  return "bg-red-950/60 text-red-300 border-red-800/60";
}

function scoreTone(score: number): string {
  if (score >= 85) return "text-success";
  if (score >= 65) return "text-warning";
  return "text-danger";
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value || "Unknown date" : date.toLocaleString();
}

function safeFilenamePart(value: string): string {
  return value.replace(/[^a-z0-9.-]+/gi, "-").replace(/^-+|-+$/g, "");
}

function isUseful(value: any): boolean {
  if (value === null || value === undefined) return false;

  const text = String(value).trim();

  if (!text) return false;

  return ![
    "not available",
    "unknown",
    "undefined",
    "null",
    "{}",
    "[]",
  ].includes(text.toLowerCase());
}

function formatContentType(value: string): string {
  const raw = value.trim();
  const lower = raw.toLowerCase();

  const parts = raw.split(";").map((part) => part.trim()).filter(Boolean);
  const mime = parts[0] || raw;
  const charsetPart = parts.find((part) => part.toLowerCase().startsWith("charset="));
  const charset = charsetPart
    ? charsetPart.split("=")[1]?.replace(/["']/g, "").toUpperCase()
    : "";

  let label = mime;

  if (lower.includes("text/html")) label = "HTML document";
  else if (lower.includes("application/json")) label = "JSON response";
  else if (lower.includes("text/plain")) label = "Plain text";
  else if (lower.includes("application/xml") || lower.includes("text/xml")) label = "XML document";

  return charset ? `${label} (${mime}, Charset: ${charset})` : `${label} (${mime})`;
}

function formatMilliseconds(value: any): string {
  const n = Number(value);

  if (!Number.isFinite(n)) return displayValue(value);

  if (n >= 1000) {
    return `${n} ms (${(n / 1000).toFixed(2)} seconds)`;
  }

  return `${n} ms`;
}

function displayValue(value: any, label?: string): string {
  if (value === true) return "Yes";
  if (value === false) return "No";

  if (typeof value === "number") {
    if (label?.toLowerCase().includes("response time")) {
      return formatMilliseconds(value);
    }

    return String(value);
  }

  if (typeof value === "string") {
    const trimmed = value.trim();

    if (!trimmed) return "";

    const labelText = (label || "").toLowerCase();

    if (labelText.includes("content type")) {
      return formatContentType(trimmed);
    }

    if (labelText.includes("response time")) {
      return formatMilliseconds(trimmed);
    }

    if (labelText.includes("dkim")) {
      return trimmed
        .replace(/\s+/g, " ")
        .replace("Verify DKIM", "Verify DKIM");
    }

    if (["present", "enabled", "valid", "true"].includes(trimmed.toLowerCase())) {
      return "Yes";
    }

    if (["missing", "disabled", "invalid", "false"].includes(trimmed.toLowerCase())) {
      return "No";
    }

    return trimmed;
  }

  if (Array.isArray(value)) {
    return value.map((item) => displayValue(item, label)).filter(isUseful).join(", ");
  }

  if (typeof value === "object" && value) {
    const status = value.status || value.value || value.present || value.enabled || value.detected;
    if (isUseful(status)) return displayValue(status, label);

    try {
      return Object.entries(value)
        .slice(0, 4)
        .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
        .join(" · ");
    } catch {
      return "";
    }
  }

  return "";
}
function getContainer(detail: any): any {
  if (!detail) return {};
  return detail;
}

function getScan(detail: any): any {
  return detail?.scan || detail?.item || detail?.data?.scan || {};
}

function getWebsiteCheck(detail: any): any {
  const root = getContainer(detail);

  const firstCheck = Array.isArray(root?.website_checks)
    ? root.website_checks[0]
    : undefined;

  return (
    root?.website_check_payload ||
    root?.report_website_check ||
    root?.website_check ||
    firstCheck ||
    root?.raw_website_check ||
    {}
  );
}

function deepFind(source: any, keys: string[]): any {
  const wanted = keys.map((k) => k.toLowerCase());

  function visit(value: any, depth: number): any {
    if (!value || depth > 8) return undefined;

    if (Array.isArray(value)) {
      for (const item of value) {
        const found = visit(item, depth + 1);
        if (isUseful(found)) return found;
      }

      return undefined;
    }

    if (typeof value !== "object") return undefined;

    for (const [key, val] of Object.entries(value)) {
      if (wanted.includes(key.toLowerCase()) && isUseful(val)) {
        return val;
      }
    }

    for (const val of Object.values(value)) {
      const found = visit(val, depth + 1);
      if (isUseful(found)) return found;
    }

    return undefined;
  }

  return visit(source, 0);
}

function getHeaderStatus(detail: any, headerName: string): any {
  const check = getWebsiteCheck(detail);
  const possibleContainers = [
    check?.headers,
    check?.security_headers,
    check?.raw_database_check?.security_headers,
    check,
  ];

  const lower = headerName.toLowerCase();

  for (const container of possibleContainers) {
    if (!container || typeof container !== "object") continue;

    const checkedHeaders =
      container.checked_headers ||
      container.checkedHeaders ||
      container;

    for (const [key, value] of Object.entries(checkedHeaders)) {
      if (key.toLowerCase() === lower && isUseful(value)) {
        return value;
      }
    }
  }

  return undefined;
}

function rowsOnlyUseful(rows: EvidenceRow[]): EvidenceRow[] {
  return rows.filter(([label, value]) => isUseful(displayValue(value, label)));
}

export function Reports() {
  const [reports, setReports] = useState<ReportRecord[]>([]);
  const [query, setQuery] = useState("");
  const [userRole, setUserRole] = useState("user");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [selectedReport, setSelectedReport] = useState<ReportRecord | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<any | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function loadReports(mode: "initial" | "refresh" = "initial") {
    if (mode === "initial") setLoading(true);
    else setRefreshing(true);

    setError(null);

    try {
      const currentUser = (await apiFetch("/api/v1/auth/me")) as any;
      const role = String(currentUser?.role || "user").toLowerCase();
      setUserRole(role);

      const historyEndpoint =
        role === "admin"
          ? "/api/v1/website/history?limit=100"
          : "/api/v1/website/history/me?limit=100";

      const response = (await apiFetch(historyEndpoint)) as any;

      const items = Array.isArray(response?.items)
        ? response.items
        : Array.isArray(response?.history)
          ? response.history
          : [];

      const normalized = items.map(normalizeReport);

      normalized.sort((a: ReportRecord, b: ReportRecord) => {
        return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
      });

      setReports(normalized);
    } catch (err: any) {
      setReports([]);
      setError(err?.message || "Could not load reports from the backend.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    void loadReports("initial");
  }, []);

  const filteredReports = useMemo(() => {
    const q = query.trim().toLowerCase();

    if (!q) return reports;

    return reports.filter((report) => {
      return (
        report.domain.toLowerCase().includes(q) ||
        String(report.target_url || "").toLowerCase().includes(q) ||
        String(report.id).toLowerCase().includes(q)
      );
    });
  }, [reports, query]);

  const latestReport = reports[0] || null;

  const highRiskCount = useMemo(() => {
    return reports.filter((report) => {
      const level = report.risk_level.toLowerCase();
      return level.includes("high") || level.includes("critical");
    }).length;
  }, [reports]);

  async function downloadPdfReport(report: ReportRecord) {
    const token = getToken();

    if (!token) {
      alert("You must be logged in to download the PDF report.");
      return;
    }

    setDownloadingId(report.id);

    try {
      const baseUrl = API_BASE.replace(/\/$/, "");
      const url = `${baseUrl}/api/v1/website/reports/${encodeURIComponent(report.id)}/pdf`;

      const response = await fetch(url, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/pdf",
        },
      });

      if (!response.ok) {
        let message = response.statusText || `Request failed (${response.status})`;

        try {
          const text = await response.text();

          if (text) {
            try {
              const parsed = JSON.parse(text);
              message = parsed?.detail || parsed?.message || message;
            } catch {
              message = text;
            }
          }
        } catch {}

        throw new Error(message);
      }

      const blob = await response.blob();

      if (!blob || blob.size === 0) {
        throw new Error("The PDF report download was empty.");
      }

      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");

      link.href = objectUrl;
      link.download = `securesight360-report-${safeFilenamePart(report.domain)}-scan-${report.id}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();

      URL.revokeObjectURL(objectUrl);
    } catch (err: any) {
      alert(err?.message || "Could not download PDF report.");
    } finally {
      setDownloadingId(null);
    }
  }

  async function viewReportDetails(report: ReportRecord) {
    setSelectedReport(report);
    setSelectedDetail(null);
    setDetailError(null);
    setDetailLoading(true);

    setTimeout(() => {
      document.getElementById("report-detail-panel")?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }, 50);

    try {
      const endpoints =
        userRole === "admin"
          ? [`/api/v1/website/history/${report.id}`, `/api/v1/website/history/me/${report.id}`]
          : [`/api/v1/website/history/me/${report.id}`];

      let loadedDetail: any = null;
      let lastError: any = null;

      for (const endpoint of endpoints) {
        try {
          loadedDetail = await apiFetch(endpoint);
          break;
        } catch (err) {
          lastError = err;
        }
      }

      if (!loadedDetail) {
        throw lastError || new Error("Could not load report details.");
      }

      setSelectedDetail(loadedDetail);
    } catch (err: any) {
      setDetailError(err?.message || "Could not load scan details.");
    } finally {
      setDetailLoading(false);
    }
  }

  return (
    <div className="space-y-8">
      <section className="relative overflow-hidden rounded-3xl border border-border">
        <div className="absolute inset-0 bg-gradient-to-br from-[#0b1530] via-[#0a1226] to-[#04101c]" />
        <div className="absolute -top-24 -right-24 h-80 w-80 rounded-full bg-cyan/20 blur-3xl" />
        <div className="absolute -bottom-24 -left-10 h-80 w-80 rounded-full bg-accent-blue/20 blur-3xl" />

        <div className="relative grid gap-6 p-8 md:grid-cols-[1.35fr_1fr] md:p-12">
          <div className="space-y-5">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan/30 bg-cyan/10 px-2.5 py-1 text-xs uppercase tracking-wider text-cyan">
              <Sparkles className="h-3.5 w-3.5" />
              Official Evidence-Based Reports
            </div>

            <div>
              <h1 className="text-3xl font-semibold tracking-tight md:text-5xl">
                Client-ready reports from authorized external assessment evidence.
              </h1>

              <p className="mt-4 max-w-2xl text-muted-foreground">
                Generate official SecureSight360 PDF reports directly from saved external posture assessment data.
                The details view stays concise; the full PDF includes scope, limitations, evidence, findings, and recommendations.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => latestReport && downloadPdfReport(latestReport)}
                disabled={!latestReport || downloadingId === latestReport?.id}
                className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan to-accent-blue px-5 py-3 text-sm font-medium text-[#021016] glow-cyan transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {downloadingId === latestReport?.id ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Download className="h-4 w-4" />
                )}
                Export Latest PDF Report
              </button>

              <button
                type="button"
                onClick={() => loadReports("refresh")}
                disabled={refreshing}
                className="inline-flex items-center gap-2 rounded-xl border border-border bg-secondary/60 px-5 py-3 text-sm transition hover:border-cyan/40 hover:text-cyan disabled:cursor-not-allowed disabled:opacity-50"
              >
                <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
                Refresh Reports
              </button>
            </div>

            <div className="flex flex-wrap items-center gap-4 pt-2 text-xs text-muted-foreground">
              <div className="flex items-center gap-1.5">
                <ShieldCheck className="h-3.5 w-3.5 text-success" />
                Authorization-verified scope
              </div>
              <div className="flex items-center gap-1.5">
                <Award className="h-3.5 w-3.5 text-cyan" />
                Backend-owned evidence
              </div>
              <div className="flex items-center gap-1.5">
                <FileText className="h-3.5 w-3.5 text-accent-blue" />
                Official PDF endpoint
              </div>
            </div>
          </div>

          <LatestReportCard report={latestReport} />
        </div>
      </section>

      <AssessmentScopeCard compact />

      <section className="grid gap-3 md:grid-cols-3">
        <SummaryTile icon={FileText} label="Total Reports" value={String(reports.length)} />
        <SummaryTile icon={AlertTriangle} label="High/Critical Reports" value={String(highRiskCount)} />
        <SummaryTile icon={CheckCircle} label="Report Source" value="Backend" />
      </section>

      <section className="space-y-4">
        <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div>
            <h2 className="text-lg font-semibold">Generated Reports</h2>
            <p className="text-sm text-muted-foreground">
              Real reports generated from authorized external posture assessment history.
            </p>
          </div>

          <div className="flex items-center gap-2 rounded-xl border border-border bg-surface/60 px-3 py-2 focus-within:border-cyan/60">
            <Search className="h-4 w-4 text-muted-foreground" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search report..."
              className="w-56 bg-transparent text-sm outline-none placeholder:text-muted-foreground/60"
            />
          </div>
        </div>

        {error && (
          <div className="rounded-2xl border border-warning/30 bg-warning/10 p-4 text-warning">
            <div className="flex items-start gap-3">
              <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
              <div>
                <div className="font-medium">Could not load reports</div>
                <div className="text-sm opacity-90">{error}</div>
              </div>
            </div>
          </div>
        )}

        {loading ? (
          <LoadingBox text="Loading official reports…" />
        ) : filteredReports.length === 0 ? (
          <EmptyBox />
        ) : (
          <div className="grid gap-3 md:grid-cols-2">
            {filteredReports.map((report) => (
              <ReportCard
                key={report.id}
                report={report}
                downloading={downloadingId === report.id}
                onView={() => viewReportDetails(report)}
                onDownload={() => downloadPdfReport(report)}
              />
            ))}
          </div>
        )}
      </section>

      {selectedReport && (
        <ReportDetailsPanel
          report={selectedReport}
          detail={selectedDetail}
          loading={detailLoading}
          error={detailError}
          downloading={downloadingId === selectedReport.id}
          onClose={() => {
            setSelectedReport(null);
            setSelectedDetail(null);
            setDetailError(null);
          }}
          onDownload={() => downloadPdfReport(selectedReport)}
        />
      )}

      <footer className="flex flex-col gap-3 rounded-2xl border border-border bg-gradient-to-r from-surface/80 to-surface-2/80 px-6 py-5 md:flex-row md:items-center md:justify-between">
        <div className="flex items-center gap-3 text-sm">
          <ShieldCheck className="h-4 w-4 text-cyan" />
          <span className="text-soft/90">
            SecureSight360 — Professional External Security Posture Reporting
          </span>
        </div>

        <div className="text-xs text-muted-foreground">
          Reports are confidential and generated only from authorized, non-invasive saved assessment data.
        </div>
      </footer>
    </div>
  );
}

function LatestReportCard({ report }: { report: ReportRecord | null }) {
  return (
    <div className="glass rounded-2xl p-5 backdrop-blur-xl">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm">
          <FileText className="h-4 w-4 text-cyan" />
          Latest Official Report
        </div>

        <span className="rounded-full border border-success/30 bg-success/10 px-2.5 py-1 text-[10px] uppercase tracking-wider text-success">
          Dynamic
        </span>
      </div>

      {report ? (
        <>
          <div className="mt-4 min-w-0">
            <div className="truncate text-xl font-semibold">{report.domain}</div>
            <div className="mt-1 text-xs text-muted-foreground">
              Scan #{report.id} • {formatDate(report.created_at)}
            </div>
          </div>

          <div className="mt-4 grid grid-cols-3 gap-2">
            <Mini v={String(report.score)} l="Score" tone={scoreTone(report.score)} />
            <Mini v={report.grade} l="Rating" tone="text-cyan" />
            <Mini v={String(report.findings_count)} l="Findings" tone="text-soft" />
          </div>

          <div className="mt-4 rounded-xl border border-border bg-surface/60 p-3">
            <div className="flex items-center justify-between gap-3">
              <span className="text-xs text-muted-foreground">Risk level</span>
              <span className={`rounded-lg border px-2.5 py-1 text-xs font-medium capitalize ${levelClass(report.risk_level)}`}>
                {report.risk_level}
              </span>
            </div>
          </div>
        </>
      ) : (
        <div className="mt-6 rounded-xl border border-border bg-surface/60 p-5 text-sm text-muted-foreground">
          Run a website scan first. Your official PDF reports will appear here automatically.
        </div>
      )}
    </div>
  );
}

function ReportCard({
  report,
  downloading,
  onView,
  onDownload,
}: {
  report: ReportRecord;
  downloading: boolean;
  onView: () => void;
  onDownload: () => void;
}) {
  return (
    <div className="glass rounded-2xl p-5">
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-border bg-secondary">
            <Globe className="h-4 w-4 text-cyan" />
          </div>

          <div className="min-w-0">
            <div className="truncate font-medium">{report.domain}</div>
            <div className="mt-1 flex items-center gap-1.5 text-xs text-muted-foreground">
              <Calendar className="h-3.5 w-3.5" />
              {formatDate(report.created_at)}
            </div>
          </div>
        </div>

        <span className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium capitalize ${levelClass(report.risk_level)}`}>
          {report.risk_level}
        </span>
      </div>

      <div className="mt-4 grid grid-cols-3 gap-2">
        <Mini v={String(report.score)} l="Score" tone={scoreTone(report.score)} />
        <Mini v={report.grade} l="Rating" tone="text-cyan" />
        <Mini v={String(report.findings_count)} l="Findings" tone="text-soft" />
      </div>

      <div className="mt-4 rounded-xl border border-border bg-surface/50 p-3 text-xs text-muted-foreground">
        <div className="flex flex-wrap gap-x-4 gap-y-1">
          <span>Scan ID: <span className="text-soft">{report.id}</span></span>
          <span>Assessment: <span className="text-soft">Basic External</span></span>
          <span>Status: <span className="text-soft capitalize">{report.status}</span></span>
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={onView}
          className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-secondary/50 px-3 py-1.5 text-xs transition hover:border-cyan/40 hover:text-cyan"
        >
          <Eye className="h-3.5 w-3.5" />
          View Details
        </button>

        <button
          type="button"
          onClick={onDownload}
          disabled={downloading}
          className="inline-flex items-center gap-1.5 rounded-lg border border-cyan/30 bg-cyan/10 px-3 py-1.5 text-xs font-medium text-cyan transition hover:bg-cyan/15 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {downloading ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Download className="h-3.5 w-3.5" />
          )}
          {downloading ? "Preparing PDF..." : "Download PDF Report"}
        </button>
      </div>
    </div>
  );
}

function ReportDetailsPanel({
  report,
  detail,
  loading,
  error,
  downloading,
  onClose,
  onDownload,
}: {
  report: ReportRecord;
  detail: any;
  loading: boolean;
  error: string | null;
  downloading: boolean;
  onClose: () => void;
  onDownload: () => void;
}) {
  const activeDetail = detail || report.raw || {};
  const scan = getScan(activeDetail);
  const check = getWebsiteCheck(activeDetail);

  const score = safeNumber(scan?.security_score ?? report.score, report.score);
  const rating = String(scan?.security_rating || scan?.grade || report.grade);
  const risk = String(scan?.risk_level || report.risk_level);
  const findings = safeNumber(activeDetail?.findings_count ?? scan?.findings_count ?? report.findings_count, report.findings_count);

  const evidenceSource = {
    detail: activeDetail,
    scan,
    check,
    raw: check?.raw_database_check || activeDetail?.raw_website_check || {},
  };

  const availabilityRows = rowsOnlyUseful([
    ["Target", report.target_url || report.domain],
    ["Scan Status", scan?.status || report.status],
    ["HTTP Status", deepFind(evidenceSource, ["status_code", "http_status", "http_status_code"])],
    ["Final URL", deepFind(evidenceSource, ["final_url", "effective_url", "checked_url"])],
    ["Response Time", deepFind(evidenceSource, ["response_time_ms", "response_time", "response_time_seconds"])],
  ]);

  const tlsRows = rowsOnlyUseful([
    ["HTTPS Enabled", deepFind(evidenceSource, ["https_enabled", "tls_enabled", "enabled"])],
    ["Certificate Valid", deepFind(evidenceSource, ["certificate_valid", "cert_valid", "tls_certificate_valid", "valid"])],
    ["Issuer", deepFind(evidenceSource, ["issuer", "certificate_issuer", "tls_issuer"])],
    ["Days Until Expiry", deepFind(evidenceSource, ["days_until_expiry", "expiry_days", "tls_days_until_expiry"])],
    ["Protocol", deepFind(evidenceSource, ["protocol", "tls_version", "ssl_protocol"])],
  ]);

  const headerRows = rowsOnlyUseful([
    ["Content-Security-Policy", getHeaderStatus(activeDetail, "Content-Security-Policy")],
    ["X-Frame-Options", getHeaderStatus(activeDetail, "X-Frame-Options")],
    ["X-Content-Type-Options", getHeaderStatus(activeDetail, "X-Content-Type-Options")],
    ["Strict-Transport-Security", getHeaderStatus(activeDetail, "Strict-Transport-Security")],
    ["Referrer-Policy", getHeaderStatus(activeDetail, "Referrer-Policy")],
    ["Permissions-Policy", getHeaderStatus(activeDetail, "Permissions-Policy")],
  ]);

  const dnsRows = rowsOnlyUseful([
    ["SPF Present", deepFind(evidenceSource, ["spf_present", "has_spf"])],
    ["DMARC Present", deepFind(evidenceSource, ["dmarc_present", "has_dmarc"])],
    ["MX Records Present", deepFind(evidenceSource, ["mx_present", "mx_records_present", "has_mx"])],
    ["CAA Present", deepFind(evidenceSource, ["caa_present", "has_caa"])],
    ["DKIM Guidance", deepFind(evidenceSource, ["dkim_guidance", "dkim_note"])],
  ]);

  const technologyRows = rowsOnlyUseful([
    ["Server", deepFind(evidenceSource, ["server"])],
    ["Powered By", deepFind(evidenceSource, ["x_powered_by", "x-powered-by"])],
    ["Content Type", deepFind(evidenceSource, ["content_type", "content-type"])],
  ]);

  return (
    <section id="report-detail-panel" className="glass rounded-3xl border border-cyan/20 p-5 md:p-7">
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div>
          <div className="inline-flex items-center gap-2 rounded-full border border-cyan/30 bg-cyan/10 px-2.5 py-1 text-xs uppercase tracking-wider text-cyan">
            <ShieldCheck className="h-3.5 w-3.5" />
            Assessment Evidence View
          </div>

          <h2 className="mt-3 text-2xl font-semibold tracking-tight">
            {report.domain}
          </h2>

          <p className="mt-1 text-sm text-muted-foreground">
            Concise technical view from saved assessment evidence. Download the PDF for the full executive summary, evidence, scope, limitations, recommendations, and legal notice.
          </p>

          <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted-foreground">
            <span className="rounded-lg border border-border bg-surface/50 px-2.5 py-1">
              Scan ID: <span className="text-soft">{report.id}</span>
            </span>
            <span className="rounded-lg border border-border bg-surface/50 px-2.5 py-1">
              Target: <span className="text-soft">{report.target_url || report.domain}</span>
            </span>
            <span className="rounded-lg border border-border bg-surface/50 px-2.5 py-1">
              Date: <span className="text-soft">{formatDate(report.created_at)}</span>
            </span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={onDownload}
            disabled={downloading}
            className="inline-flex items-center gap-2 rounded-xl border border-cyan/30 bg-cyan/10 px-4 py-2 text-xs font-medium text-cyan transition hover:bg-cyan/15 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {downloading ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Download className="h-3.5 w-3.5" />
            )}
            {downloading ? "Preparing PDF..." : "Download PDF Report"}
          </button>

          <button
            type="button"
            onClick={onClose}
            className="inline-flex items-center gap-2 rounded-xl border border-border bg-secondary/60 px-4 py-2 text-xs transition hover:border-danger/40 hover:text-danger"
          >
            <X className="h-3.5 w-3.5" />
            Close
          </button>
        </div>
      </div>

      {loading ? (
        <LoadingBox text="Loading scanner evidence…" />
      ) : error ? (
        <div className="mt-6 rounded-2xl border border-danger/30 bg-danger/10 p-5 text-danger">
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
            <div>
              <div className="font-medium">Could not load scan details</div>
              <div className="text-sm opacity-90">{error}</div>
            </div>
          </div>
        </div>
      ) : (
        <div className="mt-6 space-y-6">
          <div className="grid gap-3 md:grid-cols-4">
            <MetricCard label="Security Score" value={`${score}/100`} tone={scoreTone(score)} />
            <MetricCard label="Security Rating" value={rating} tone="text-cyan" />
            <MetricCard label="Risk Level" value={risk} tone="text-danger" />
            <MetricCard label="Findings" value={String(findings)} tone="text-soft" />
          </div>

          <div>
            <h3 className="mb-3 text-lg font-semibold">Technical Evidence</h3>

            <div className="grid gap-4 lg:grid-cols-2">
              <EvidenceBox title="Website Availability" icon={Server} rows={availabilityRows} />
              <EvidenceBox title="HTTPS / TLS" icon={Lock} rows={tlsRows} />
              <EvidenceBox title="Security Headers" icon={ShieldCheck} rows={headerRows} />
              <EvidenceBox title="DNS / Email Security" icon={Globe} rows={dnsRows} />
              <EvidenceBox title="Detected Technologies" icon={Server} rows={technologyRows} />
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

function EvidenceBox({
  title,
  icon: Icon,
  rows,
}: {
  title: string;
  icon: any;
  rows: EvidenceRow[];
}) {
  return (
    <div className="rounded-2xl border border-border bg-surface/50 p-5">
      <div className="mb-4 flex items-center gap-2 font-medium">
        <Icon className="h-4 w-4 text-cyan" />
        {title}
      </div>

      {rows.length === 0 ? (
        <div className="rounded-xl border border-border/70 bg-background/30 px-3 py-3 text-sm text-muted-foreground">
          No evidence recorded for this section in the saved scan. The PDF report includes the same assessment scope and limitations.
        </div>
      ) : (
        <div className="space-y-2">
          {rows.map(([label, value]) => (
            <div
              key={label}
              className="flex flex-col gap-1 rounded-xl border border-border/70 bg-background/30 px-3 py-2 text-sm sm:flex-row sm:items-start sm:justify-between"
            >
              <span className="text-muted-foreground">{label}</span>
              <span className="whitespace-pre-wrap break-words text-left leading-relaxed text-soft sm:max-w-[64%] sm:text-right">
                {displayValue(value, label)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SummaryTile({
  icon: Icon,
  label,
  value,
}: {
  icon: any;
  label: string;
  value: string;
}) {
  return (
    <div className="glass rounded-2xl p-5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-xs uppercase tracking-wider text-muted-foreground">
            {label}
          </div>
          <div className="mt-2 text-2xl font-semibold">{value}</div>
        </div>

        <div className="grid h-10 w-10 place-items-center rounded-xl border border-border bg-secondary">
          <Icon className="h-4 w-4 text-cyan" />
        </div>
      </div>
    </div>
  );
}

function MetricCard({ label, value, tone }: { label: string; value: string; tone: string }) {
  return (
    <div className="rounded-2xl border border-border bg-surface/50 p-5">
      <div className="text-xs uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className={`mt-2 text-2xl font-semibold ${tone}`}>{value}</div>
    </div>
  );
}

function LoadingBox({ text }: { text: string }) {
  return (
    <div className="glass rounded-2xl p-10 text-center">
      <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl border border-border bg-secondary">
        <Loader2 className="h-6 w-6 animate-spin text-cyan" />
      </div>

      <div className="mt-4 font-medium">{text}</div>
      <p className="mt-1 text-sm text-muted-foreground">
        Reading saved data from the backend.
      </p>
    </div>
  );
}

function EmptyBox() {
  return (
    <div className="glass rounded-2xl p-10 text-center">
      <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl border border-border bg-secondary">
        <FileText className="h-6 w-6 text-cyan" />
      </div>

      <div className="mt-4 font-medium">No reports available</div>
      <p className="mt-1 text-sm text-muted-foreground">
        Run a website scan first. Each saved scan can generate an official PDF report.
      </p>
    </div>
  );
}

function Mini({ v, l, tone }: { v: string; l: string; tone: string }) {
  return (
    <div className="rounded-lg border border-border bg-surface/60 p-2.5 text-center">
      <div className={`text-lg font-semibold ${tone}`}>{v}</div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
        {l}
      </div>
    </div>
  );
}





