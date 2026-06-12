import { useEffect, useMemo, useState } from "react";
import {
  History as HistoryIcon,
  Globe,
  Calendar,
  Trash2,
  Download,
  Search,
  ShieldCheck,
  BarChart3,
} from "lucide-react";

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
  raw: any;
};

function safeNumber(value: any, fallback = 0): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function hostnameFromUrl(value: string): string {
  try {
    return new URL(value).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return String(value || "unknown").replace(/^https?:\/\//, "").split("/")[0].replace(/^www\./, "").toLowerCase();
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
    id: String(row?.id || row?.scan_id || `${domain}-${row?.created_at || Date.now()}`),
    domain: String(domain || "unknown").replace(/^www\./, "").toLowerCase(),
    target_url: String(target || ""),
    created_at: String(row?.created_at || row?.scanned_at || row?.timestamp || new Date().toISOString()),
    score,
    grade: String(row?.grade || (score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F")),
    risk_level: String(row?.risk_level || row?.risk || (score >= 70 ? "Medium" : "Critical")),
    profile: String(row?.profile || row?.scan_profile || "Basic"),
    findings_count: findingsCount,
    raw: row,
  };
}

function riskBadgeClass(risk: string): string {
  const value = risk.toLowerCase();

  if (value.includes("low")) {
    return "bg-green-950/60 text-green-300 border-green-800/60";
  }

  if (value.includes("medium")) {
    return "bg-yellow-950/60 text-yellow-300 border-yellow-800/60";
  }

  if (value.includes("high")) {
    return "bg-orange-950/60 text-orange-300 border-orange-800/60";
  }

  return "bg-red-950/60 text-red-300 border-red-800/60";
}

function currentIdentity() {
  const email = (window.localStorage.getItem("cs360-user-email") || "").trim().toLowerCase();
  const domainFromEmail = email.includes("@") ? email.split("@")[1] : "";
  const storedDomain = (window.localStorage.getItem("cs360-company-domain") || "").trim().toLowerCase();

  return {
    email,
    domain: (domainFromEmail || storedDomain).replace(/^www\./, ""),
  };
}

function readJsonArray(key: string): any[] {
  try {
    const value = JSON.parse(window.localStorage.getItem(key) || "[]");
    return Array.isArray(value) ? value : [];
  } catch {
    return [];
  }
}

function loadLocalHistory(): ScanRecord[] {
  const { email, domain } = currentIdentity();

  if (!email && !domain) {
    return [];
  }

  const keys = [
    email ? `cs360-scan-history:${email}` : "",
    domain ? `cs360-scan-history-domain:${domain}` : "",
    "cs360-scan-history",
  ].filter(Boolean);

  const combined = keys.flatMap((key) => readJsonArray(key));

  const unique = new Map<string, ScanRecord>();

  for (const item of combined) {
    const record = normalizeRow(item);

    if (domain) {
      const recordDomain = record.domain.replace(/^www\./, "").toLowerCase();
      const allowed =
        recordDomain === domain ||
        recordDomain.endsWith("." + domain);

      if (!allowed) continue;
    }

    unique.set(record.id, record);
  }

  return Array.from(unique.values()).sort((a, b) => {
    return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
  });
}

function downloadJson(record: ScanRecord) {
  const blob = new Blob([JSON.stringify(record.raw, null, 2)], {
    type: "application/json",
  });

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");

  a.href = url;
  a.download = `securesight360-scan-${record.domain}-${record.id}.json`;
  a.click();

  URL.revokeObjectURL(url);
}

export function History() {
  const [records, setRecords] = useState<ScanRecord[]>([]);
  const [query, setQuery] = useState("");

  const refresh = () => {
    setRecords(loadLocalHistory());
  };

  useEffect(() => {
    refresh();

    const onStorage = () => refresh();
    window.addEventListener("storage", onStorage);

    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();

    if (!q) return records;

    return records.filter((r) => {
      return (
        r.domain.toLowerCase().includes(q) ||
        String(r.target_url || "").toLowerCase().includes(q)
      );
    });
  }, [records, query]);

  const clearAll = () => {
    if (!confirm("Clear scan history for this account/domain?")) {
      return;
    }

    const { email, domain } = currentIdentity();

    if (email) {
      window.localStorage.removeItem(`cs360-scan-history:${email}`);
    }

    if (domain) {
      window.localStorage.removeItem(`cs360-scan-history-domain:${domain}`);
    }

    const shared = readJsonArray("cs360-scan-history");
    const kept = shared.filter((item) => {
      const r = normalizeRow(item);
      if (!domain) return false;
      return !(r.domain === domain || r.domain.endsWith("." + domain));
    });

    window.localStorage.setItem("cs360-scan-history", JSON.stringify(kept));
    setRecords([]);
  };

  return (
    <div className="space-y-6">
      <div className="glass rounded-2xl p-6 md:p-8 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-r from-cyan/5 via-transparent to-accent-blue/10 pointer-events-none" />

        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 relative">
          <div className="flex items-center gap-4 min-w-0">
            <div className="grid h-12 w-12 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-cyan/20 to-accent-blue/10 border border-border">
              <HistoryIcon className="h-6 w-6 text-cyan" />
            </div>

            <div className="min-w-0">
              <h1 className="text-2xl font-semibold tracking-tight">
                Scan History
              </h1>
              <p className="text-sm text-muted-foreground">
                Every authorized assessment, kept private and searchable.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center gap-2 rounded-xl border border-border bg-surface/60 px-3 py-2 focus-within:border-cyan/60">
              <Search className="h-4 w-4 text-muted-foreground" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search domain..."
                className="bg-transparent text-sm outline-none placeholder:text-muted-foreground/60 w-56"
              />
            </div>

            <button
              type="button"
              onClick={clearAll}
              className="inline-flex items-center gap-2 rounded-xl border border-danger/40 bg-danger/10 text-danger px-4 py-2 text-sm hover:bg-danger/20 transition"
            >
              <Trash2 className="h-4 w-4" />
              Clear
            </button>
          </div>
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="glass rounded-2xl p-10 text-center">
          <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-secondary border border-border">
            <HistoryIcon className="h-6 w-6 text-cyan" />
          </div>

          <div className="mt-4 font-medium">No scan history yet</div>

          <p className="text-sm text-muted-foreground mt-1">
            Run a website scan to see results stored here.
          </p>
        </div>
      ) : (
        <div className="grid gap-3">
          {filtered.map((r) => (
            <div
              key={r.id}
              className="glass rounded-2xl p-5 flex flex-col xl:flex-row xl:items-center gap-5"
            >
              <div className="flex items-center gap-4 min-w-0 flex-1">
                <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-secondary border border-border">
                  <Globe className="h-5 w-5 text-cyan" />
                </div>

                <div className="min-w-0">
                  <div className="font-semibold truncate">{r.domain}</div>

                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground mt-1">
                    <Calendar className="h-3.5 w-3.5" />
                    {new Date(r.created_at).toLocaleString()}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 xl:w-[520px]">
                <div className="rounded-xl border border-border bg-surface/60 px-4 py-3 text-center">
                  <div className="text-lg font-bold text-danger">{r.score}</div>
                  <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Score</div>
                </div>

                <div className="rounded-xl border border-border bg-surface/60 px-4 py-3 text-center">
                  <div className="text-lg font-bold text-accent-blue">{r.grade}</div>
                  <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Grade</div>
                </div>

                <div className="rounded-xl border border-border bg-surface/60 px-4 py-3 text-center">
                  <div className="text-lg font-bold">{r.findings_count}</div>
                  <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Findings</div>
                </div>

                <div className="rounded-xl border border-border bg-surface/60 px-4 py-3 text-center">
                  <div className="text-lg font-bold text-accent-blue">{r.profile}</div>
                  <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Profile</div>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <span className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-semibold ${riskBadgeClass(r.risk_level)}`}>
                  <ShieldCheck className="h-3.5 w-3.5" />
                  {r.risk_level}
                </span>

                <button
                  type="button"
                  onClick={() => alert(JSON.stringify(r.raw, null, 2))}
                  className="inline-flex items-center gap-1.5 rounded-xl border border-border bg-secondary/60 px-3 py-2 text-xs hover:border-cyan/40 hover:text-cyan transition"
                >
                  <BarChart3 className="h-3.5 w-3.5" />
                  View
                </button>

                <button
                  type="button"
                  onClick={() => downloadJson(r)}
                  className="inline-flex items-center gap-1.5 rounded-xl border border-border bg-secondary/60 px-3 py-2 text-xs hover:border-cyan/40 hover:text-cyan transition"
                >
                  <Download className="h-3.5 w-3.5" />
                  JSON
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
