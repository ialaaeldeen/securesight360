import { useEffect, useState } from "react";
import { History as HistoryIcon, Globe, Calendar, BarChart3, Trash2, Download, Search, ShieldCheck } from "lucide-react";

interface ScanRecord {
  id: string;
  domain: string;
  score: number;
  grade: string;
  risk: "Low" | "Medium" | "High" | "Critical";
  findings: number;
  profile: "Basic" | "Advanced";
  date: string; // ISO
}

const DEMO: ScanRecord[] = [
  { id: "h1", domain: "acme-corp.com", score: 92, grade: "A", risk: "Low", findings: 3, profile: "Advanced", date: "2026-06-08T10:24:00Z" },
  { id: "h2", domain: "fintrust.io", score: 74, grade: "B", risk: "Medium", findings: 9, profile: "Basic", date: "2026-06-07T15:11:00Z" },
  { id: "h3", domain: "shop.example.net", score: 58, grade: "C", risk: "High", findings: 17, profile: "Advanced", date: "2026-06-05T09:02:00Z" },
  { id: "h4", domain: "legacy.oldsite.org", score: 41, grade: "D", risk: "Critical", findings: 24, profile: "Basic", date: "2026-06-02T18:48:00Z" },
  { id: "h5", domain: "acme-corp.com", score: 88, grade: "B", risk: "Low", findings: 5, profile: "Basic", date: "2026-05-28T08:30:00Z" },
];

function riskClass(l: string) {
  const m = l.toLowerCase();
  if (m === "low") return "bg-success/15 text-success border-success/30";
  if (m === "medium") return "bg-warning/15 text-warning border-warning/30";
  if (m === "high") return "bg-danger/15 text-danger border-danger/30";
  return "bg-red-950/60 text-red-300 border-red-800/60";
}

export function History() {
  const [records, setRecords] = useState<ScanRecord[]>([]);
  const [query, setQuery] = useState("");

  useEffect(() => {
    try {
      const raw = localStorage.getItem("cs360-scan-history");
      const parsed = raw ? (JSON.parse(raw) as ScanRecord[]) : [];
      setRecords(parsed.length ? parsed : DEMO);
    } catch {
      setRecords(DEMO);
    }
  }, []);

  const filtered = records.filter(r =>
    r.domain.toLowerCase().includes(query.trim().toLowerCase())
  );

  const clearAll = () => {
    if (!confirm("Clear all scan history? This cannot be undone.")) return;
    try { localStorage.removeItem("cs360-scan-history"); } catch {}
    setRecords([]);
  };

  return (
    <div className="space-y-6">
      <section className="glass rounded-2xl p-6 relative overflow-hidden">
        <div className="absolute -right-24 -top-24 h-64 w-64 rounded-full bg-cyan/10 blur-3xl" />
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 relative">
          <div className="flex items-center gap-4 min-w-0">
            <div className="grid h-12 w-12 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-cyan/20 to-accent-blue/10 border border-border">
              <HistoryIcon className="h-6 w-6 text-cyan" />
            </div>
            <div className="min-w-0">
              <h1 className="text-2xl font-semibold tracking-tight">Scan History</h1>
              <p className="text-sm text-muted-foreground">Every authorized assessment, kept private and searchable.</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-2 rounded-xl border border-border bg-surface/60 px-3 py-2 w-full md:w-72">
              <Search className="h-4 w-4 text-muted-foreground" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search domain..."
                className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground/60"
              />
            </div>
            <button
              onClick={clearAll}
              className="inline-flex items-center gap-1.5 rounded-xl border border-danger/40 bg-danger/10 text-danger px-3 py-2 text-xs hover:bg-danger/20 transition"
            >
              <Trash2 className="h-3.5 w-3.5" /> Clear
            </button>
          </div>
        </div>
      </section>

      {filtered.length === 0 ? (
        <div className="glass rounded-2xl p-10 text-center">
          <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-secondary border border-border">
            <HistoryIcon className="h-6 w-6 text-cyan" />
          </div>
          <div className="mt-4 font-medium">No scan history yet</div>
          <p className="text-sm text-muted-foreground mt-1">Run a website scan to see results stored here.</p>
        </div>
      ) : (
        <div className="grid gap-3">
          {filtered.map((r) => (
            <div key={r.id} className="glass rounded-2xl p-4 md:p-5 flex flex-col md:flex-row md:items-center gap-4">
              <div className="flex items-center gap-3 min-w-0 md:w-1/3">
                <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-secondary border border-border">
                  <Globe className="h-4 w-4 text-cyan" />
                </div>
                <div className="min-w-0">
                  <div className="font-medium truncate">{r.domain}</div>
                  <div className="text-xs text-muted-foreground flex items-center gap-1.5">
                    <Calendar className="h-3 w-3" /> {new Date(r.date).toLocaleString()}
                  </div>
                </div>
              </div>
              <div className="grid grid-cols-4 gap-2 flex-1">
                <Mini v={String(r.score)} l="Score" tone={r.score >= 85 ? "text-success" : r.score >= 65 ? "text-warning" : "text-danger"} />
                <Mini v={r.grade} l="Grade" tone="text-cyan" />
                <Mini v={String(r.findings)} l="Findings" tone="text-soft" />
                <Mini v={r.profile} l="Profile" tone="text-accent-blue" />
              </div>
              <div className="flex items-center gap-2 md:w-auto">
                <span className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium ${riskClass(r.risk)}`}>
                  <ShieldCheck className="h-3 w-3" /> {r.risk}
                </span>
                <button className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-secondary/50 px-3 py-1.5 text-xs hover:bg-secondary transition">
                  <BarChart3 className="h-3.5 w-3.5" /> View
                </button>
                <button className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-secondary/50 px-3 py-1.5 text-xs hover:bg-secondary transition">
                  <Download className="h-3.5 w-3.5" /> PDF
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Mini({ v, l, tone }: { v: string; l: string; tone: string }) {
  return (
    <div className="rounded-lg border border-border bg-surface/60 p-2.5 text-center">
      <div className={`text-base font-semibold ${tone}`}>{v}</div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{l}</div>
    </div>
  );
}
