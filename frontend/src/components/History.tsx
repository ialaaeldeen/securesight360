import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  BarChart3,
  Calendar,
  Eye,
  Globe,
  History as HistoryIcon,
  Loader2,
  Lock,
  Mail,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  X,
} from "lucide-react";

import { apiFetch } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { canUseWebsiteFeatures } from "@/lib/access";
import { EmailHistory } from "@/components/EmailHistory";
import { AssessmentScopeCard } from "@/components/AssessmentScopeCard";

type ScanRecord = {
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

function normalizeRow(row: any): ScanRecord {
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
        (score >= 85
          ? "Excellent"
          : score >= 70
            ? "Strong"
            : score >= 50
              ? "Moderate"
              : score >= 30
                ? "Weak"
                : "Critical")
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

function riskBadgeClass(risk: string): string {
  const value = risk.toLowerCase();

  if (value.includes("low")) return "bg-green-950/60 text-green-300 border-green-800/60";
  if (value.includes("medium")) return "bg-yellow-950/60 text-yellow-300 border-yellow-800/60";
  if (value.includes("high")) return "bg-orange-950/60 text-orange-300 border-orange-800/60";

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

function isUseful(value: any): boolean {
  if (value === null || value === undefined) return false;

  const text = String(value).trim();

  if (!text) return false;

  return !["not available", "unknown", "undefined", "null", "{}", "[]"].includes(
    text.toLowerCase()
  );
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

  if (!Number.isFinite(n)) return String(value);

  if (n >= 1000) {
    return `${n} ms (${(n / 1000).toFixed(2)} seconds)`;
  }

  return `${n} ms`;
}

function displayValue(value: any, label?: string): string {
  if (value === true) return "Yes";
  if (value === false) return "No";

  if (typeof value === "number") {
    if (label?.toLowerCase().includes("response time")) return formatMilliseconds(value);
    return String(value);
  }

  if (typeof value === "string") {
    const trimmed = value.trim();

    if (!trimmed) return "";

    const labelText = (label || "").toLowerCase();

    if (labelText.includes("content type")) return formatContentType(trimmed);
    if (labelText.includes("response time")) return formatMilliseconds(trimmed);

    if (["present", "enabled", "valid", "true"].includes(trimmed.toLowerCase())) return "Yes";
    if (["missing", "disabled", "invalid", "false"].includes(trimmed.toLowerCase())) return "No";

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

function getScan(detail: any): any {
  return detail?.scan || detail?.item || detail?.data?.scan || {};
}

function getWebsiteCheck(detail: any): any {
  const firstCheck = Array.isArray(detail?.website_checks) ? detail.website_checks[0] : undefined;

  return (
    detail?.website_check_payload ||
    detail?.report_website_check ||
    detail?.website_check ||
    firstCheck ||
    detail?.raw_website_check ||
    {}
  );
}

function deepFind(source: any, keys: string[]): any {
  const wanted = keys.map((key) => key.toLowerCase());

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

    const checkedHeaders = container.checked_headers || container.checkedHeaders || container;

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

function WebsiteHistoryContent() {
  const [records, setRecords] = useState<ScanRecord[]>([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedRecord, setSelectedRecord] = useState<ScanRecord | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<any | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadBackendHistory = async (mode: "initial" | "refresh" = "initial") => {
    if (mode === "initial") setLoading(true);
    else setRefreshing(true);

    setError(null);

    try {
      const response = (await apiFetch("/api/v1/website/history/me?limit=100")) as any;

      const items = Array.isArray(response?.items)
        ? response.items
        : Array.isArray(response?.history)
          ? response.history
          : [];

      setRecords(items.map(normalizeRow));
    } catch (err: any) {
      setRecords([]);
      setError(err?.message || "Could not load scan history from the backend.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    void loadBackendHistory("initial");
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();

    if (!q) return records;

    return records.filter((r) => {
      return (
        r.domain.toLowerCase().includes(q) ||
        String(r.target_url || "").toLowerCase().includes(q) ||
        String(r.id).toLowerCase().includes(q)
      );
    });
  }, [records, query]);

  const viewDetails = async (record: ScanRecord) => {
    setSelectedRecord(record);
    setSelectedDetail(null);
    setDetailError(null);
    setDetailLoading(true);

    setTimeout(() => {
      document.getElementById("history-detail-panel")?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }, 50);

    try {
      const detail = (await apiFetch(`/api/v1/website/history/me/${record.id}`)) as any;
      setSelectedDetail(detail);
    } catch (err: any) {
      setDetailError(err?.message || "Could not load scan details.");
    } finally {
      setDetailLoading(false);
    }
  };

  return (
    <div className="space-y-5 sm:space-y-6">
      <div className="glass rounded-2xl p-5 sm:p-6 md:p-8 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-r from-cyan/5 via-transparent to-accent-blue/10 pointer-events-none" />

        <div className="relative flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex min-w-0 items-start gap-3 sm:gap-4">
            <div className="grid h-12 w-12 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-cyan/20 to-accent-blue/10 border border-border">
              <HistoryIcon className="h-6 w-6 text-cyan" />
            </div>

            <div className="min-w-0">
              <h1 className="text-xl font-semibold tracking-tight sm:text-2xl">Scan History</h1>
              <p className="text-sm text-muted-foreground">
                Backend-owned history for authorized external posture assessments.
              </p>
            </div>
          </div>

          <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:items-center">
            <div className="flex min-w-0 items-center gap-2 rounded-xl border border-border bg-surface/60 px-3 py-2 focus-within:border-cyan/60">
              <Search className="h-4 w-4 text-muted-foreground" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search domain..."
                className="min-w-0 w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground/60 sm:w-56"
              />
            </div>

            <button
              type="button"
              onClick={() => loadBackendHistory("refresh")}
              disabled={refreshing}
              className="inline-flex min-h-[44px] w-full items-center justify-center gap-2 rounded-xl border border-border bg-secondary/60 px-4 py-2 text-sm hover:border-cyan/40 hover:text-cyan disabled:opacity-50 disabled:cursor-not-allowed transition sm:w-auto"
            >
              <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>
        </div>
      </div>

      <AssessmentScopeCard compact />

      {error && (
        <div className="rounded-2xl border border-warning/30 bg-warning/10 p-4 text-warning flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 mt-0.5 shrink-0" />
          <div>
            <div className="font-medium">Could not load scan history</div>
            <div className="text-sm opacity-90">{error}</div>
          </div>
        </div>
      )}

      {loading ? (
        <LoadingBox text="Loading scan history…" />
      ) : filtered.length === 0 ? (
        <EmptyHistory />
      ) : (
        <div className="grid gap-3">
          {filtered.map((r) => (
            <div
              key={r.id}
              className="glass rounded-2xl p-4 sm:p-5 flex flex-col gap-4 xl:flex-row xl:items-center"
            >
              <div className="flex min-w-0 flex-1 items-start gap-3 sm:gap-4">
                <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-secondary border border-border">
                  <Globe className="h-5 w-5 text-cyan" />
                </div>

                <div className="min-w-0">
                  <div className="break-all font-semibold">{r.domain}</div>

                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground mt-1">
                    <Calendar className="h-3.5 w-3.5" />
                    {formatDate(r.created_at)}
                  </div>
                </div>
              </div>

              <div className="grid w-full grid-cols-2 gap-2 sm:grid-cols-4 xl:w-[520px]">
                <Mini v={String(r.score)} l="Score" tone={scoreTone(r.score)} />
                <Mini v={r.grade} l="Security Rating" tone="text-accent-blue" />
                <Mini v={String(r.findings_count)} l="Findings" tone="text-soft" />
                <Mini v="Basic External" l="Assessment" tone="text-accent-blue" />
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <span className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-semibold ${riskBadgeClass(r.risk_level)}`}>
                  <ShieldCheck className="h-3.5 w-3.5" />
                  {r.risk_level}
                </span>

                <button
                  type="button"
                  onClick={() => viewDetails(r)}
                  className="inline-flex min-h-[42px] items-center justify-center gap-1.5 rounded-xl border border-cyan/30 bg-cyan/10 px-3 py-2 text-xs text-cyan hover:bg-cyan/15 transition"
                >
                  <Eye className="h-3.5 w-3.5" />
                  View Details
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {selectedRecord && (
        <HistoryDetailsPanel
          record={selectedRecord}
          detail={selectedDetail}
          loading={detailLoading}
          error={detailError}
          onClose={() => {
            setSelectedRecord(null);
            setSelectedDetail(null);
            setDetailError(null);
          }}
        />
      )}
    </div>
  );
}

export function History() {
  const [activeTab, setActiveTab] = useState<"email" | "website">("email");

  const tabBase =
    "inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2 text-sm font-medium transition-all";

  return (
    <div className="space-y-5">
      <div className="glass rounded-2xl p-2 flex flex-col gap-2 sm:flex-row">
        <button
          type="button"
          onClick={() => setActiveTab("email")}
          className={`${tabBase} ${
            activeTab === "email"
              ? "bg-cyan/10 text-cyan border border-cyan/30"
              : "text-muted-foreground hover:text-foreground hover:bg-secondary/60 border border-transparent"
          }`}
        >
          <Mail className="h-4 w-4" />
          Email Analyses
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("website")}
          className={`${tabBase} ${
            activeTab === "website"
              ? "bg-cyan/10 text-cyan border border-cyan/30"
              : "text-muted-foreground hover:text-foreground hover:bg-secondary/60 border border-transparent"
          }`}
        >
          <Globe className="h-4 w-4" />
          Website Assessments
        </button>
      </div>

      {activeTab === "email" ? <EmailHistory /> : <WebsiteHistoryContent />}
    </div>
  );
}
function HistoryDetailsPanel({
  record,
  detail,
  loading,
  error,
  onClose,
}: {
  record: ScanRecord;
  detail: any;
  loading: boolean;
  error: string | null;
  onClose: () => void;
}) {
  const activeDetail = detail || record.raw || {};
  const scan = getScan(activeDetail);
  const check = getWebsiteCheck(activeDetail);

  const score = safeNumber(scan?.security_score ?? record.score, record.score);
  const rating = String(scan?.security_rating || scan?.grade || record.grade);
  const risk = String(scan?.risk_level || record.risk_level);
  const findings = safeNumber(
    activeDetail?.findings_count ?? scan?.findings_count ?? record.findings_count,
    record.findings_count
  );

  const evidenceSource = {
    detail: activeDetail,
    scan,
    check,
    raw: check?.raw_database_check || activeDetail?.raw_website_check || {},
  };

  const availabilityRows = rowsOnlyUseful([
    ["Target", record.target_url || record.domain],
    ["Scan Status", scan?.status || record.status],
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
    <section id="history-detail-panel" className="glass rounded-3xl border border-cyan/20 p-4 sm:p-5 md:p-7">
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div>
          <div className="inline-flex items-center gap-2 rounded-full border border-cyan/30 bg-cyan/10 px-2.5 py-1 text-xs uppercase tracking-wider text-cyan">
            <ShieldCheck className="h-3.5 w-3.5" />
            Assessment Evidence View
          </div>

          <h2 className="mt-3 text-2xl font-semibold tracking-tight">{record.domain}</h2>

          <p className="mt-1 text-sm text-muted-foreground">
            Concise technical view from saved backend evidence.
          </p>

          <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted-foreground">
            <span className="rounded-lg border border-border bg-surface/50 px-2.5 py-1">
              Scan ID: <span className="text-soft">{record.id}</span>
            </span>
            <span className="rounded-lg border border-border bg-surface/50 px-2.5 py-1">
              Target: <span className="break-all text-soft">{record.target_url || record.domain}</span>
            </span>
            <span className="rounded-lg border border-border bg-surface/50 px-2.5 py-1">
              Date: <span className="text-soft">{formatDate(record.created_at)}</span>
            </span>
          </div>
        </div>

        <button
          type="button"
          onClick={onClose}
          className="inline-flex min-h-[42px] items-center justify-center gap-2 rounded-xl border border-border bg-secondary/60 px-4 py-2 text-xs transition hover:border-danger/40 hover:text-danger"
        >
          <X className="h-3.5 w-3.5" />
          Close
        </button>
      </div>

      
      <AssessmentScopeCard compact className="mt-5" />

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
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
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
    <div className="rounded-2xl border border-border bg-surface/50 p-4 sm:p-5">
      <div className="mb-4 flex items-center gap-2 font-medium">
        <Icon className="h-4 w-4 text-cyan" />
        {title}
      </div>

      {rows.length === 0 ? (
        <div className="rounded-xl border border-border/70 bg-background/30 px-3 py-3 text-sm text-muted-foreground">
          No evidence recorded for this section in the saved scan.
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

function MetricCard({ label, value, tone }: { label: string; value: string; tone: string }) {
  return (
    <div className="rounded-2xl border border-border bg-surface/50 p-4 sm:p-5">
      <div className="text-xs uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className={`mt-2 text-2xl font-semibold ${tone}`}>{value}</div>
    </div>
  );
}

function LoadingBox({ text }: { text: string }) {
  return (
    <div className="glass rounded-2xl p-6 text-center sm:p-10">
      <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-secondary border border-border">
        <Loader2 className="h-6 w-6 text-cyan animate-spin" />
      </div>

      <div className="mt-4 font-medium">{text}</div>

      <p className="text-sm text-muted-foreground mt-1">
        Reading saved data from the backend.
      </p>
    </div>
  );
}

function EmptyHistory() {
  return (
    <div className="glass rounded-2xl p-6 text-center sm:p-10">
      <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-secondary border border-border">
        <HistoryIcon className="h-6 w-6 text-cyan" />
      </div>

      <div className="mt-4 font-medium">No scan history yet</div>

      <p className="text-sm text-muted-foreground mt-1">
        Run an authorized external posture assessment to see backend-owned results stored here.
      </p>
    </div>
  );
}

function Mini({ v, l, tone }: { v: string; l: string; tone: string }) {
  return (
    <div className="rounded-xl border border-border bg-surface/60 px-4 py-3 text-center">
      <div className={`text-lg font-bold ${tone}`}>{v}</div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{l}</div>
    </div>
  );
}




