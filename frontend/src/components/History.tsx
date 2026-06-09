import { useEffect, useMemo, useState } from "react";
import {
  Calendar,
  Download,
  Eye,
  FileText,
  Globe,
  History as HistoryIcon,
  Search,
  ShieldAlert,
  Trash2,
} from "lucide-react";

type RawScanRecord = Record<string, any>;

interface CleanScanRecord {
  id: string;
  scanId?: number | string;
  domain: string;
  targetUrl: string;
  scannedAt: string;
  score: number;
  grade: string;
  riskLevel: string;
  findingsCount: number;
  status: string;
  executiveSummary?: string;
}

const STORAGE_KEY = "cs360-scan-history";

function asText(value: unknown, fallback = "—"): string {
  if (value === null || value === undefined) return fallback;

  if (typeof value === "string") return value || fallback;
  if (typeof value === "number" || typeof value === "boolean") return String(value);

  if (Array.isArray(value)) {
    const text = value.map((item) => asText(item, "")).filter(Boolean).join(", ");
    return text || fallback;
  }

  if (typeof value === "object") {
    const item = value as Record<string, any>;

    return (
      item.title ||
      item.summary ||
      item.description ||
      item.recommendation ||
      item.evidence ||
      item.category ||
      fallback
    );
  }

  return fallback;
}

function asNumber(value: unknown, fallback = 0): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;

  if (typeof value === "string") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
  }

  return fallback;
}

function formatDate(value: string): string {
  if (!value) return "Unknown date";

  const parsed = new Date(value);

  if (Number.isNaN(parsed.getTime())) return value;

  return parsed.toLocaleString();
}

function extractDomain(value: string): string {
  try {
    return new URL(value).hostname;
  } catch {
    return value.replace(/^https?:\/\//, "").replace(/\/$/, "") || "Unknown domain";
  }
}

function normalizeRecord(record: RawScanRecord): CleanScanRecord {
  const result = record.result ?? {};
  const riskAssessment = result.risk_assessment ?? {};
  const metadata = result.metadata ?? {};
  const professionalResult = metadata.professional_result ?? {};

  const targetUrl =
    record.target_url ||
    record.targetUrl ||
    result.final_url ||
    result.original_url ||
    "Unknown target";

  const findingsArray = Array.isArray(record.findings) ? record.findings : [];

  const findingsCount =
    asNumber(record.findings_count, NaN) ||
    asNumber(record.findingsCount, NaN) ||
    findingsArray.length ||
    asNumber(riskAssessment?.scoring_deductions?.length, 0);

  const riskLevel =
    record.risk_level ||
    record.risk ||
    record.level ||
    professionalResult.risk_level ||
    riskAssessment.risk_level ||
    "unknown";

  const grade =
    record.grade ||
    professionalResult.grade ||
    riskAssessment.grade ||
    "—";

  const score =
    asNumber(record.security_score, NaN) ||
    asNumber(record.score, NaN) ||
    asNumber(professionalResult.security_score, NaN) ||
    asNumber(riskAssessment.security_score, 0);

  return {
    id: asText(record.id || record.scan_id || `${targetUrl}-${record.scanned_at || Date.now()}`),
    scanId: record.scan_id,
    domain: asText(record.domain || result.domain || extractDomain(targetUrl)),
    targetUrl: asText(targetUrl),
    scannedAt: asText(record.scanned_at || record.date || record.timestamp || new Date().toISOString()),
    score,
    grade: asText(grade),
    riskLevel: asText(riskLevel).toLowerCase(),
    findingsCount,
    status: asText(record.status || "completed").toLowerCase(),
    executiveSummary:
      record.executive_summary ||
      professionalResult.executive_summary ||
      riskAssessment.executive_summary,
  };
}

function riskClass(level: string): string {
  const normalized = level.toLowerCase();

  if (normalized === "critical") {
    return "border-red-500/40 bg-red-500/10 text-red-300";
  }

  if (normalized === "high") {
    return "border-red-500/30 bg-red-500/10 text-red-300";
  }

  if (normalized === "medium") {
    return "border-amber-500/30 bg-amber-500/10 text-amber-300";
  }

  if (normalized === "low") {
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
  }

  return "border-slate-600 bg-slate-700/40 text-slate-300";
}

function scoreClass(score: number): string {
  if (score >= 85) return "text-emerald-400";
  if (score >= 65) return "text-amber-400";
  return "text-red-400";
}

export function History() {
  const [records, setRecords] = useState<CleanScanRecord[]>([]);
  const [query, setQuery] = useState("");

  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(STORAGE_KEY);
      const parsed = raw ? JSON.parse(raw) : [];

      if (!Array.isArray(parsed)) {
        setRecords([]);
        return;
      }

      setRecords(parsed.map(normalizeRecord));
    } catch {
      setRecords([]);
    }
  }, []);

  const filteredRecords = useMemo(() => {
    const search = query.trim().toLowerCase();

    if (!search) return records;

    return records.filter((record) => {
      return (
        record.domain.toLowerCase().includes(search) ||
        record.targetUrl.toLowerCase().includes(search) ||
        record.riskLevel.toLowerCase().includes(search) ||
        record.grade.toLowerCase().includes(search)
      );
    });
  }, [query, records]);

  function clearHistory() {
    if (!confirm("Clear all scan history? This cannot be undone.")) return;

    window.localStorage.removeItem(STORAGE_KEY);
    setRecords([]);
  }

  function viewRecord(record: CleanScanRecord) {
    alert(
      [
        `Target: ${record.targetUrl}`,
        `Score: ${record.score}/100`,
        `Risk: ${record.riskLevel}`,
        `Grade: ${record.grade}`,
        `Findings: ${record.findingsCount}`,
        "",
        record.executiveSummary || "No executive summary stored for this scan.",
      ].join("\n"),
    );
  }

  return (
    <div className="space-y-6">
      <section className="glass rounded-3xl p-6 md:p-8">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-4">
            <div className="rounded-2xl bg-cyan/10 p-4 text-cyan">
              <HistoryIcon className="h-7 w-7" />
            </div>

            <div>
              <h1 className="text-2xl font-semibold tracking-tight">Scan History</h1>
              <p className="mt-1 text-sm text-muted-foreground">
                Every authorized assessment, kept private and searchable.
              </p>
            </div>
          </div>

          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <div className="flex min-w-[260px] items-center gap-2 rounded-2xl border border-border bg-background/40 px-4 py-3">
              <Search className="h-4 w-4 text-muted-foreground" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search domain..."
                className="w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground"
              />
            </div>

            <button
              type="button"
              onClick={clearHistory}
              className="inline-flex items-center justify-center gap-2 rounded-2xl border border-red-500/30 px-4 py-3 text-sm font-medium text-red-300 transition hover:bg-red-500/10"
            >
              <Trash2 className="h-4 w-4" />
              Clear
            </button>
          </div>
        </div>
      </section>

      {filteredRecords.length === 0 ? (
        <section className="glass rounded-3xl p-10 text-center">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-cyan/10 text-cyan">
            <FileText className="h-7 w-7" />
          </div>

          <h2 className="mt-4 text-lg font-semibold">No scan history yet</h2>
          <p className="mt-2 text-sm text-muted-foreground">
            Run a website scan to see clean results saved here.
          </p>
        </section>
      ) : (
        <div className="space-y-4">
          {filteredRecords.map((record) => (
            <article
              key={record.id}
              className="glass rounded-3xl p-5 md:p-6"
            >
              <div className="grid gap-5 lg:grid-cols-[1.4fr_repeat(4,minmax(110px,0.45fr))_auto] lg:items-center">
                <div className="flex min-w-0 items-center gap-4">
                  <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-cyan/10 text-cyan">
                    <Globe className="h-5 w-5" />
                  </div>

                  <div className="min-w-0">
                    <h3 className="truncate font-semibold text-foreground">{record.domain}</h3>

                    <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                      <span className="inline-flex items-center gap-1">
                        <Calendar className="h-3.5 w-3.5" />
                        {formatDate(record.scannedAt)}
                      </span>

                      <span className="truncate">{record.targetUrl}</span>
                    </div>

                    {record.executiveSummary && (
                      <p className="mt-3 line-clamp-2 text-sm text-muted-foreground">
                        {record.executiveSummary}
                      </p>
                    )}
                  </div>
                </div>

                <div className="rounded-2xl border border-border bg-background/30 p-4 text-center">
                  <div className={`text-2xl font-bold ${scoreClass(record.score)}`}>
                    {record.score}
                  </div>
                  <div className="mt-1 text-xs uppercase tracking-wider text-muted-foreground">
                    Score
                  </div>
                </div>

                <div className="rounded-2xl border border-border bg-background/30 p-4 text-center">
                  <div className="text-2xl font-bold text-cyan">{record.grade}</div>
                  <div className="mt-1 text-xs uppercase tracking-wider text-muted-foreground">
                    Grade
                  </div>
                </div>

                <div className="rounded-2xl border border-border bg-background/30 p-4 text-center">
                  <div className="text-2xl font-bold text-foreground">{record.findingsCount}</div>
                  <div className="mt-1 text-xs uppercase tracking-wider text-muted-foreground">
                    Findings
                  </div>
                </div>

                <div className="rounded-2xl border border-border bg-background/30 p-4 text-center">
                  <span
                    className={`inline-flex items-center justify-center rounded-xl border px-3 py-1 text-xs font-semibold capitalize ${riskClass(record.riskLevel)}`}
                  >
                    <ShieldAlert className="mr-1.5 h-3.5 w-3.5" />
                    {record.riskLevel}
                  </span>
                  <div className="mt-2 text-xs uppercase tracking-wider text-muted-foreground">
                    Risk
                  </div>
                </div>

                <div className="flex flex-wrap justify-start gap-2 lg:justify-end">
                  <button
                    type="button"
                    onClick={() => viewRecord(record)}
                    className="inline-flex items-center gap-2 rounded-2xl border border-border bg-background/40 px-4 py-2 text-sm font-medium transition hover:bg-cyan/10 hover:text-cyan"
                  >
                    <Eye className="h-4 w-4" />
                    View
                  </button>

                  <button
                    type="button"
                    onClick={() => alert("PDF export will be connected in the report module.")}
                    className="inline-flex items-center gap-2 rounded-2xl border border-border bg-background/40 px-4 py-2 text-sm font-medium transition hover:bg-cyan/10 hover:text-cyan"
                  >
                    <Download className="h-4 w-4" />
                    PDF
                  </button>
                </div>
              </div>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
