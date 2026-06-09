import { Globe, Activity, ShieldCheck, FileText, Lock, Server, Radar, BarChart3, Network, Zap } from "lucide-react";

const headline = [
  { title: "Website Scanner MVP", desc: "Run authorized website security checks in seconds.", icon: Globe, tint: "from-cyan/20 to-accent-blue/10" },
  { title: "Explainable Risk Engine", desc: "Transparent scoring with reasons behind every signal.", icon: BarChart3, tint: "from-accent-blue/20 to-cyan/10" },
  { title: "Client-Friendly Security Reports", desc: "Plain-English findings ready for stakeholders.", icon: FileText, tint: "from-warning/20 to-accent-blue/10" },
];

const features = [
  { title: "Website Availability Check", icon: Activity },
  { title: "SSL/TLS Check", icon: Lock },
  { title: "Security Headers Check", icon: ShieldCheck },
  { title: "DNS & Email Security Check", icon: Server },
  { title: "Risk Scoring Engine", icon: Radar },
  { title: "Professional Feedback", icon: Zap },
];

export function Overview({ onLaunch }: { onLaunch: () => void }) {
  return (
    <div className="space-y-4">
      <div className="glass rounded-xl p-5 lg:p-6 relative overflow-hidden">
        <div className="absolute -right-20 -top-20 h-64 w-64 rounded-full bg-cyan/10 blur-3xl" />
        <div className="flex flex-col xl:flex-row xl:items-start xl:justify-between gap-4 relative">
          <div className="space-y-3 max-w-3xl">
            <div className="inline-flex items-center gap-2 text-xs uppercase tracking-wider text-cyan border border-cyan/30 bg-cyan/10 px-2.5 py-1 rounded-full">
              <Network className="h-3.5 w-3.5" /> Security Operations Console
            </div>
            <h1 className="text-2xl md:text-3xl 2xl:text-4xl font-semibold tracking-tight">
              Assess any website's security posture with confidence.
            </h1>
            <p className="text-muted-foreground">
              SecureSight360 combines availability, transport security, headers, and DNS/email checks
              into one explainable risk score with client-ready, professional reports.
            </p>
          </div>
          <button
            onClick={onLaunch}
            className="self-start inline-flex shrink-0 items-center gap-2 rounded-xl px-5 py-3 text-sm font-medium text-[#021016] bg-gradient-to-r from-cyan to-accent-blue glow-cyan hover:brightness-110 transition"
          >
            <Radar className="h-4 w-4" /> Launch Website Scanner
          </button>
        </div>
      </div>

      <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 xl:grid-cols-3">
        {headline.map(({ title, desc, icon: Icon, tint }) => (
          <div key={title} className="glass rounded-xl p-4">
            <div className={`mb-4 inline-grid h-10 w-10 place-items-center rounded-xl bg-gradient-to-br ${tint} border border-border`}>
              <Icon className="h-5 w-5 text-cyan" />
            </div>
            <div className="font-medium">{title}</div>
            <p className="text-sm text-muted-foreground mt-1">{desc}</p>
          </div>
        ))}
      </div>

      <div>
        <div className="flex items-end justify-between mb-3">
          <h2 className="text-lg font-semibold">Platform capabilities</h2>
          <span className="text-xs text-muted-foreground">6 active modules</span>
        </div>
        <div className="grid gap-3 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
          {features.map(({ title, icon: Icon }) => (
            <div key={title} className="glass rounded-xl p-3 flex items-center gap-3 min-w-0">
              <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-secondary border border-border">
                <Icon className="h-4 w-4 text-cyan" />
              </div>
              <div className="text-sm min-w-0 truncate">{title}</div>
              <span className="ml-auto shrink-0 text-[10px] uppercase tracking-wider text-success">Online</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
