import { FileText, Download, Share2, Star, Sparkles, ShieldCheck, TrendingUp, Award, MessageSquare, ThumbsUp, BarChart3, Globe, ArrowRight } from "lucide-react";
import { useState } from "react";

const sampleReports = [
  { domain: "acme-corp.com", score: 92, grade: "A", level: "Low", date: "Jun 8, 2026", findings: 3 },
  { domain: "fintrust.io", score: 74, grade: "B", level: "Medium", date: "Jun 7, 2026", findings: 9 },
  { domain: "shop.example.net", score: 58, grade: "C", level: "High", date: "Jun 5, 2026", findings: 17 },
  { domain: "legacy.oldsite.org", score: 41, grade: "D", level: "Critical", date: "Jun 2, 2026", findings: 24 },
];

function levelClass(l: string) {
  const m = l.toLowerCase();
  if (m === "low") return "bg-success/15 text-success border-success/30";
  if (m === "medium") return "bg-warning/15 text-warning border-warning/30";
  if (m === "high") return "bg-danger/15 text-danger border-danger/30";
  return "bg-red-950/60 text-red-300 border-red-800/60";
}

export function Reports() {
  const [rating, setRating] = useState(0);
  const [hover, setHover] = useState(0);
  const [feedback, setFeedback] = useState("");
  const [submitted, setSubmitted] = useState(false);

  return (
    <div className="space-y-8">
      {/* Creative marketing hero */}
      <section className="relative overflow-hidden rounded-3xl border border-border">
        <div className="absolute inset-0 bg-gradient-to-br from-[#0b1530] via-[#0a1226] to-[#04101c]" />
        <div className="absolute -top-24 -right-24 h-80 w-80 rounded-full bg-cyan/25 blur-3xl" />
        <div className="absolute -bottom-24 -left-10 h-80 w-80 rounded-full bg-accent-blue/25 blur-3xl" />
        <div
          className="absolute inset-0 opacity-[0.06]"
          style={{
            backgroundImage:
              "linear-gradient(rgba(255,255,255,0.6) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.6) 1px, transparent 1px)",
            backgroundSize: "44px 44px",
          }}
        />
        <div className="relative grid md:grid-cols-[1.3fr_1fr] gap-6 p-8 md:p-12">
          <div className="space-y-5">
            <div className="inline-flex items-center gap-2 text-xs uppercase tracking-wider text-cyan border border-cyan/30 bg-cyan/10 px-2.5 py-1 rounded-full">
              <Sparkles className="h-3.5 w-3.5" /> Reports & Insights
            </div>
            <h1 className="text-3xl md:text-5xl font-semibold tracking-tight leading-tight">
              Turn raw findings into <br />
              <span className="bg-gradient-to-r from-cyan to-accent-blue bg-clip-text text-transparent">stories your clients trust.</span>
            </h1>
            <p className="text-muted-foreground max-w-xl">
              Branded, client-ready PDFs. Executive summaries written in plain English. Priority actions your team can ship this week — not next quarter.
            </p>
            <div className="flex flex-wrap items-center gap-3">
              <button className="inline-flex items-center gap-2 rounded-xl px-5 py-3 text-sm font-medium text-[#021016] bg-gradient-to-r from-cyan to-accent-blue glow-cyan hover:brightness-110 transition">
                <Download className="h-4 w-4" /> Export latest report
              </button>
              <button className="inline-flex items-center gap-2 rounded-xl border border-border bg-secondary/60 px-5 py-3 text-sm hover:bg-secondary transition">
                <Share2 className="h-4 w-4" /> Share with client
              </button>
            </div>
            <div className="flex flex-wrap items-center gap-4 pt-2 text-xs text-muted-foreground">
              <div className="flex items-center gap-1.5"><ShieldCheck className="h-3.5 w-3.5 text-success" /> Authorization-verified</div>
              <div className="flex items-center gap-1.5"><Award className="h-3.5 w-3.5 text-cyan" /> A+ Engine</div>
              <div className="flex items-center gap-1.5"><TrendingUp className="h-3.5 w-3.5 text-accent-blue" /> Trend-ready</div>
            </div>
          </div>

          <div className="relative">
            <div className="glass rounded-2xl p-5 backdrop-blur-xl">
              <div className="flex items-center justify-between">
                <div className="text-sm flex items-center gap-2"><FileText className="h-4 w-4 text-cyan" /> Q2 Security Report</div>
                <span className="text-[10px] uppercase tracking-wider text-success">Ready</span>
              </div>
              <div className="mt-4 grid grid-cols-3 gap-2">
                <Mini v="92" l="Score" tone="text-success" />
                <Mini v="A" l="Grade" tone="text-cyan" />
                <Mini v="3" l="Issues" tone="text-warning" />
              </div>
              <div className="mt-4 h-24 rounded-xl border border-border bg-surface/60 p-3">
                <div className="flex items-end gap-1.5 h-full">
                  {[40, 55, 48, 62, 70, 65, 78, 82, 88, 90, 91, 92].map((h, i) => (
                    <div key={i} className="flex-1 rounded-t bg-gradient-to-t from-cyan/30 to-cyan" style={{ height: `${h}%` }} />
                  ))}
                </div>
              </div>
              <div className="mt-3 text-[11px] text-muted-foreground flex items-center gap-1.5"><BarChart3 className="h-3 w-3" /> 12-week security score trend</div>
            </div>
          </div>
        </div>
      </section>

      {/* Reports list */}
      <section>
        <div className="flex items-end justify-between mb-3">
          <div>
            <h2 className="text-lg font-semibold">Generated reports</h2>
            <p className="text-sm text-muted-foreground">All reports stay encrypted and tied to your account.</p>
          </div>
          <span className="text-xs text-muted-foreground">{sampleReports.length} reports</span>
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          {sampleReports.map((r) => (
            <div key={r.domain} className="glass rounded-2xl p-5 flex flex-col gap-3">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="grid h-10 w-10 place-items-center rounded-xl bg-secondary border border-border shrink-0">
                    <Globe className="h-4 w-4 text-cyan" />
                  </div>
                  <div className="min-w-0">
                    <div className="font-medium truncate">{r.domain}</div>
                    <div className="text-xs text-muted-foreground">Generated {r.date}</div>
                  </div>
                </div>
                <span className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium capitalize ${levelClass(r.level)}`}>
                  {r.level}
                </span>
              </div>
              <div className="grid grid-cols-3 gap-2">
                <Mini v={String(r.score)} l="Score" tone={r.score >= 85 ? "text-success" : r.score >= 65 ? "text-warning" : "text-danger"} />
                <Mini v={r.grade} l="Grade" tone="text-cyan" />
                <Mini v={String(r.findings)} l="Findings" tone="text-soft" />
              </div>
              <div className="flex items-center gap-2 pt-1">
                <button className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-secondary/50 px-3 py-1.5 text-xs hover:bg-secondary transition">
                  <FileText className="h-3.5 w-3.5" /> View
                </button>
                <button className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-secondary/50 px-3 py-1.5 text-xs hover:bg-secondary transition">
                  <Download className="h-3.5 w-3.5" /> Download PDF
                </button>
                <button className="ml-auto inline-flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-cyan to-accent-blue px-3 py-1.5 text-xs font-medium text-[#021016] hover:brightness-110 transition">
                  Share <ArrowRight className="h-3 w-3" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Feedback */}
      <section className="glass rounded-2xl p-6 md:p-7">
        <div className="flex items-center gap-3 mb-4">
          <div className="grid h-10 w-10 place-items-center rounded-xl bg-gradient-to-br from-cyan/20 to-accent-blue/10 border border-border">
            <MessageSquare className="h-5 w-5 text-cyan" />
          </div>
          <div>
            <h2 className="text-lg font-semibold">Rate the generated report</h2>
            <p className="text-sm text-muted-foreground">Your feedback trains the risk engine to deliver clearer reports.</p>
          </div>
        </div>

        {submitted ? (
          <div className="rounded-xl border border-success/30 bg-success/10 p-5 flex items-center gap-3">
            <ThumbsUp className="h-5 w-5 text-success" />
            <div>
              <div className="font-medium">Thanks for the feedback!</div>
              <div className="text-sm text-muted-foreground">We've logged your rating to improve future reports.</div>
            </div>
          </div>
        ) : (
          <form
            onSubmit={(e) => { e.preventDefault(); if (rating > 0) setSubmitted(true); }}
            className="space-y-4"
          >
            <div className="flex items-center gap-2">
              {[1, 2, 3, 4, 5].map((n) => (
                <button
                  key={n}
                  type="button"
                  onMouseEnter={() => setHover(n)}
                  onMouseLeave={() => setHover(0)}
                  onClick={() => setRating(n)}
                  className="p-1 transition"
                  aria-label={`Rate ${n} star${n > 1 ? "s" : ""}`}
                >
                  <Star className={`h-7 w-7 ${(hover || rating) >= n ? "fill-cyan text-cyan" : "text-muted-foreground"}`} />
                </button>
              ))}
              <span className="ml-2 text-xs text-muted-foreground">{rating > 0 ? `${rating} / 5` : "Tap to rate"}</span>
            </div>
            <textarea
              value={feedback}
              onChange={(e) => setFeedback(e.target.value)}
              rows={4}
              placeholder="What worked? What could be clearer in the report?"
              className="w-full rounded-xl border border-border bg-surface/60 px-3 py-2.5 text-sm outline-none focus:border-cyan/60 focus:ring-2 focus:ring-cyan/20 placeholder:text-muted-foreground/60"
            />
            <button
              type="submit"
              disabled={rating === 0}
              className="inline-flex items-center gap-2 rounded-xl px-5 py-3 text-sm font-medium text-[#021016] bg-gradient-to-r from-cyan to-accent-blue glow-cyan disabled:opacity-40 disabled:cursor-not-allowed hover:brightness-110 transition"
            >
              Submit feedback <ArrowRight className="h-4 w-4" />
            </button>
          </form>
        )}
      </section>

      {/* Footer */}
      <footer className="rounded-2xl border border-border bg-gradient-to-r from-surface/80 to-surface-2/80 px-6 py-5 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
        <div className="flex items-center gap-3 text-sm">
          <ShieldCheck className="h-4 w-4 text-cyan" />
          <span className="text-soft/90">SecureSight360 — Professional Security Assessment Platform</span>
        </div>
        <div className="text-xs text-muted-foreground">
          © 2026 <span className="text-soft font-medium">SecureSight360</span>. All rights reserved. Reports are confidential and intended for authorized recipients only.
        </div>
      </footer>
    </div>
  );
}

function Mini({ v, l, tone }: { v: string; l: string; tone: string }) {
  return (
    <div className="rounded-lg border border-border bg-surface/60 p-2.5 text-center">
      <div className={`text-lg font-semibold ${tone}`}>{v}</div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{l}</div>
    </div>
  );
}
