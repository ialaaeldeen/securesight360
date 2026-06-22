import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Calendar,
  Eye,
  Inbox,
  Loader2,
  Mail,
  RefreshCw,
  ShieldCheck,
  X,
} from "lucide-react";

import {
  type EmailThreatHistoryDetail,
  type EmailThreatHistoryItem,
  fetchEmailAnalysisDetail,
  fetchEmailAnalysisHistory,
} from "@/lib/api";

function formatDate(value: string): string {
  const date = new Date(value);

  return Number.isNaN(date.getTime())
    ? value || "Unknown date"
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}

function verdictClass(verdict: string): string {
  const value = verdict.toLowerCase();

  if (value.includes("safe")) {
    return "border-green-800/60 bg-green-950/50 text-green-300";
  }

  if (value.includes("suspicious")) {
    return "border-yellow-800/60 bg-yellow-950/50 text-yellow-300";
  }

  if (
    value.includes("malicious") ||
    value.includes("credential") ||
    value.includes("fraud")
  ) {
    return "border-red-800/60 bg-red-950/50 text-red-300";
  }

  return "border-orange-800/60 bg-orange-950/50 text-orange-300";
}

function confidenceTone(value: string): string {
  if (value.toLowerCase() === "high") return "text-danger";
  if (value.toLowerCase() === "medium") return "text-warning";
  return "text-success";
}

function isSafeVerdict(verdict: string): boolean {
  const value = verdict.toLowerCase();
  return value.includes("safe") || value.includes("no obvious threat");
}

export function EmailHistory() {
  const [items, setItems] = useState<EmailThreatHistoryItem[]>([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<EmailThreatHistoryItem | null>(null);
  const [detail, setDetail] = useState<EmailThreatHistoryDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const load = async (mode: "initial" | "refresh" = "initial") => {
    if (mode === "initial") setLoading(true);
    else setRefreshing(true);

    setError(null);

    try {
      const response = await fetchEmailAnalysisHistory(100, 0);
      const history = Array.isArray(response.history) ? response.history : [];

      setItems(
        [...history].sort((a, b) => {
          const at = Date.parse(a.created_at || "") || 0;
          const bt = Date.parse(b.created_at || "") || 0;
          return bt - at;
        })
      );
    } catch (err: any) {
      setItems([]);
      setError(err?.message || "Could not load email analysis history.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    void load("initial");
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();

    if (!q) return items;

    return items.filter((item) => {
      return (
        String(item.subject_preview || "").toLowerCase().includes(q) ||
        String(item.sender_preview || "").toLowerCase().includes(q) ||
        String(item.verdict || "").toLowerCase().includes(q) ||
        item.key_indicators.some((indicator) =>
          indicator.toLowerCase().includes(q)
        )
      );
    });
  }, [items, query]);

  const summary = useMemo(() => {
    const suspicious = items.filter((item) => !isSafeVerdict(item.verdict)).length;
    const highConfidence = items.filter(
      (item) => item.confidence.toLowerCase() === "high"
    ).length;

    return {
      total: items.length,
      suspicious,
      highConfidence,
    };
  }, [items]);

  const viewDetail = async (item: EmailThreatHistoryItem) => {
    setSelected(item);
    setDetail(null);
    setDetailError(null);
    setDetailLoading(true);

    setTimeout(() => {
      document.getElementById("email-history-detail-panel")?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }, 50);

    try {
      const response = await fetchEmailAnalysisDetail(item.id);
      setDetail(response);
    } catch (err: any) {
      setDetailError(err?.message || "Could not load email analysis details.");
    } finally {
      setDetailLoading(false);
    }
  };

  return (
    <div className="space-y-5 sm:space-y-6">
      <section className="glass rounded-3xl p-4 sm:p-6 md:p-8">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex min-w-0 items-start gap-3 sm:gap-4">
            <div className="grid h-11 w-11 shrink-0 place-items-center rounded-2xl border border-border bg-gradient-to-br from-cyan/20 to-accent-blue/10 sm:h-12 sm:w-12">
              <Mail className="h-6 w-6 text-cyan" />
            </div>

            <div className="min-w-0">
              <div className="inline-flex items-center gap-2 rounded-full border border-cyan/25 bg-cyan/10 px-3 py-1 text-xs font-semibold text-cyan">
                <ShieldCheck className="h-3.5 w-3.5" />
                Privacy-safe email history
              </div>

              <h1 className="mt-3 break-words text-xl font-semibold tracking-tight sm:text-2xl">
                Email Analysis History
              </h1>

              <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
                Review saved suspicious email checks, verdicts, confidence levels,
                and recommended actions without storing full email content by default.
              </p>
            </div>
          </div>

          <div className="flex w-full flex-col gap-3 sm:w-auto sm:flex-row sm:items-center sm:justify-end">
            <div className="flex items-center gap-2 rounded-xl border border-border bg-surface/60 px-3 py-2 focus-within:border-cyan/60">
              <Inbox className="h-4 w-4 text-muted-foreground" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search history..."
                className="min-w-0 w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground/60 sm:w-56"
              />
            </div>

            <button
              type="button"
              onClick={() => load("refresh")}
              disabled={refreshing}
              className="inline-flex min-h-[44px] w-full items-center justify-center gap-2 rounded-xl border border-border bg-secondary/60 px-4 py-2 text-sm transition hover:border-cyan/40 hover:text-cyan disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto"
            >
              <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>
        </div>
      </section>

      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <SummaryCard label="Saved analyses" value={String(summary.total)} icon={Inbox} />
        <SummaryCard label="Suspicious emails" value={String(summary.suspicious)} icon={AlertTriangle} />
        <SummaryCard label="High confidence" value={String(summary.highConfidence)} icon={ShieldCheck} />
      </section>

      {error && (
        <div className="flex items-start gap-3 rounded-2xl border border-warning/30 bg-warning/10 p-4 text-warning">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
          <div>
            <div className="font-medium">Could not load email history</div>
            <div className="text-sm opacity-90">{error}</div>
          </div>
        </div>
      )}

      {loading ? (
        <LoadingBox text="Loading email analysis history…" />
      ) : filtered.length === 0 ? (
        <EmptyEmailHistory />
      ) : (
        <section className="glass min-w-0 rounded-3xl p-4 sm:p-5">
          <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between sm:gap-3">
            <div>
              <h2 className="font-semibold">Recent email checks</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                Latest saved verdicts from the email analyzer.
              </p>
            </div>

            <div className="text-xs text-muted-foreground">
              Showing {filtered.length} of {items.length}
            </div>
          </div>

          <div className="space-y-3">
            {filtered.map((item) => (
              <HistoryRow
                key={item.id}
                item={item}
                onView={() => viewDetail(item)}
              />
            ))}
          </div>
        </section>
      )}

      {selected && (
        <EmailHistoryDetailPanel
          item={selected}
          detail={detail}
          loading={detailLoading}
          error={detailError}
          onClose={() => {
            setSelected(null);
            setDetail(null);
            setDetailError(null);
          }}
        />
      )}
    </div>
  );
}

function HistoryRow({
  item,
  onView,
}: {
  item: EmailThreatHistoryItem;
  onView: () => void;
}) {
  return (
    <div className="min-w-0 rounded-3xl border border-border bg-surface/50 p-4">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
        <div className="flex min-w-0 items-start gap-4">
          <div className="grid h-10 w-10 shrink-0 place-items-center rounded-2xl border border-border bg-secondary sm:h-11 sm:w-11">
            <Mail className="h-5 w-5 text-cyan" />
          </div>

          <div className="min-w-0">
            <div className="break-words font-semibold">
              {item.subject_preview || "No subject provided"}
            </div>

            <div className="mt-1 break-all text-xs text-muted-foreground">
              {item.sender_preview || "No sender provided"}
            </div>

            <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
              <span className="inline-flex items-center gap-1.5">
                <Calendar className="h-3.5 w-3.5" />
                {formatDate(item.created_at)}
              </span>

              <span>
                {item.links_count} link(s), {item.attachments_count} attachment(s)
              </span>

              <span className={confidenceTone(item.confidence)}>
                {item.confidence} confidence
              </span>
            </div>
          </div>
        </div>

        <div className="flex w-full flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center xl:w-auto xl:justify-end">
          <span
            className={`inline-flex w-full max-w-full items-center justify-center gap-1.5 rounded-2xl border px-3 py-2 text-center text-xs font-semibold sm:w-auto sm:justify-start sm:rounded-full sm:py-1.5 ${verdictClass(
              item.verdict
            )}`}
          >
            <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
            <span className="min-w-0 break-words">{item.verdict}</span>
          </span>

          <button
            type="button"
            onClick={onView}
            className="inline-flex min-h-[42px] w-full items-center justify-center gap-1.5 rounded-xl border border-cyan/30 bg-cyan/10 px-3 py-2 text-xs font-medium text-cyan transition hover:bg-cyan/15 sm:w-auto"
          >
            <Eye className="h-3.5 w-3.5" />
            View details
          </button>
        </div>
      </div>
    </div>
  );
}

function EmailHistoryDetailPanel({
  item,
  detail,
  loading,
  error,
  onClose,
}: {
  item: EmailThreatHistoryItem;
  detail: EmailThreatHistoryDetail | null;
  loading: boolean;
  error: string | null;
  onClose: () => void;
}) {
  const active = detail || item;

  return (
    <section
      id="email-history-detail-panel"
      className="glass rounded-3xl border border-cyan/20 p-4 sm:p-5 md:p-7"
    >
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div>
          <div className="inline-flex items-center gap-2 rounded-full border border-cyan/30 bg-cyan/10 px-2.5 py-1 text-xs uppercase tracking-wider text-cyan">
            <ShieldCheck className="h-3.5 w-3.5" />
            Email threat evidence view
          </div>

          <h2 className="mt-3 break-words text-xl font-semibold tracking-tight sm:text-2xl">
            {active.subject_preview || "Email analysis detail"}
          </h2>

          <p className="mt-1 text-sm leading-6 text-muted-foreground">
            Compact saved result. Full email body, raw headers, and attachment files
            are not stored by default.
          </p>
        </div>

        <button
          type="button"
          onClick={onClose}
          className="inline-flex min-h-[42px] w-full items-center justify-center gap-2 rounded-xl border border-border bg-secondary/60 px-4 py-2 text-xs font-medium transition hover:border-danger/40 hover:text-danger md:w-auto"
        >
          <X className="h-3.5 w-3.5" />
          Close
        </button>
      </div>

      {loading ? (
        <LoadingBox text="Loading email evidence…" />
      ) : error ? (
        <div className="mt-6 rounded-2xl border border-danger/30 bg-danger/10 p-5 text-danger">
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
            <div>
              <div className="font-medium">Could not load email details</div>
              <div className="text-sm opacity-90">{error}</div>
            </div>
          </div>
        </div>
      ) : (
        <div className="mt-6 space-y-5">
          <div className="min-w-0 rounded-3xl border border-border bg-surface/50 p-4 sm:p-5">
            <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center">
              <span
                className={`inline-flex w-full max-w-full items-center justify-center gap-2 rounded-2xl border px-3 py-2 text-center text-xs font-semibold sm:w-auto sm:justify-start sm:rounded-full sm:py-1.5 ${verdictClass(
                  active.verdict
                )}`}
              >
                <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
                <span className="min-w-0 break-words">{active.verdict}</span>
              </span>

              <span
                className={`inline-flex w-full items-center justify-center rounded-2xl border border-border bg-background/40 px-3 py-2 text-center text-xs font-semibold sm:w-auto sm:rounded-full sm:py-1.5 ${confidenceTone(
                  active.confidence
                )}`}
              >
                Confidence: {active.confidence}
              </span>

              <span className="inline-flex w-full items-center justify-center rounded-2xl border border-border bg-background/40 px-3 py-2 text-center text-xs font-semibold text-accent-blue sm:w-auto sm:rounded-full sm:py-1.5">
                Evidence: {active.evidence_strength}
              </span>

              <span className="inline-flex w-full items-center justify-center break-words rounded-2xl border border-border bg-background/40 px-3 py-2 text-center text-xs font-semibold text-soft sm:w-auto sm:rounded-full sm:py-1.5">
                Headers: {active.headers_provided ? "Provided" : "Not provided"}
              </span>
            </div>

            <p className="mt-4 text-sm leading-7 text-muted-foreground">
              {active.summary || "No summary was saved for this analysis."}
            </p>
          </div>

          <div className="grid gap-4 sm:gap-5 xl:grid-cols-2">
            <InfoBox title="Key indicators" items={active.key_indicators} />
            <InfoBox title="Attachment alerts" items={active.attachment_alerts} />
            {"recommended_actions" in active && (
              <InfoBox title="Recommended actions" items={active.recommended_actions} />
            )}
            {"safety_notes" in active && (
              <InfoBox title="Safety notes" items={active.safety_notes} />
            )}
          </div>
        </div>
      )}
    </section>
  );
}

function InfoBox({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="min-w-0 rounded-3xl border border-border bg-surface/50 p-4 sm:p-5">
      <div className="mb-3 font-medium">{title}</div>

      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">No items recorded.</p>
      ) : (
        <div className="space-y-2">
          {items.map((item, index) => (
            <div
              key={`${title}-${index}`}
              className="break-words rounded-xl border border-border/70 bg-background/30 px-3 py-2 text-sm leading-relaxed text-muted-foreground"
            >
              {item}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SummaryCard({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: string;
  icon: any;
}) {
  return (
    <div className="min-w-0 rounded-3xl border border-border bg-surface/50 p-4 sm:p-5">
      <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
        <Icon className="h-4 w-4 text-cyan" />
        {label}
      </div>
      <div className="mt-2 break-words text-2xl font-semibold text-soft sm:mt-3 sm:text-3xl">{value}</div>
    </div>
  );
}

function LoadingBox({ text }: { text: string }) {
  return (
    <div className="glass rounded-3xl p-5 text-center sm:p-10">
      <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl border border-border bg-secondary">
        <Loader2 className="h-6 w-6 animate-spin text-cyan" />
      </div>
      <div className="mt-4 font-medium">{text}</div>
      <p className="mt-1 text-sm text-muted-foreground">
        Reading saved email analysis data from the backend.
      </p>
    </div>
  );
}

function EmptyEmailHistory() {
  return (
    <div className="glass rounded-3xl p-5 text-center sm:p-10">
      <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl border border-border bg-secondary">
        <Mail className="h-6 w-6 text-cyan" />
      </div>
      <div className="mt-4 font-medium">No email analyses yet</div>
      <p className="mt-1 text-sm text-muted-foreground">
        Analyze a suspicious email to see privacy-safe results stored here.
      </p>
    </div>
  );
}
