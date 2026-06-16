import {
  AlertTriangle,
  CheckCircle,
  ChevronDown,
  FileText,
  Lock,
  Radar,
  ShieldCheck,
} from "lucide-react";

export const ASSESSMENT_TYPE =
  "Basic External Website Security Posture Assessment";

const COVERAGE = [
  "Availability, final URL, HTTP status, and response timing.",
  "HTTPS/TLS presence, certificate validity, issuer, protocol, and expiry evidence.",
  "Security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.",
  "DNS and email-security signals: SPF, DMARC, MX, NS, TXT, CAA, and DKIM guidance where available.",
  "Basic technology evidence from safe response headers.",
  "Evidence-based score, findings, recommendations, and PDF reporting.",
];

const LIMITATIONS = [
  "No exploitation, payload delivery, brute forcing, or destructive testing.",
  "No authenticated testing, deep crawling, port scanning, or subdomain enumeration.",
  "Not a full penetration test and not a full vulnerability assessment.",
  "Results reflect externally observable evidence at scan time.",
];

export function AssessmentScopeBadge() {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-cyan/25 bg-cyan/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan">
      <ShieldCheck className="h-3.5 w-3.5" />
      Basic External
    </span>
  );
}

export function AssessmentScopeCard({
  compact = false,
  className = "",
}: {
  compact?: boolean;
  className?: string;
}) {
  if (compact) {
    return (
      <section className={`rounded-2xl border border-cyan/15 bg-surface/45 px-4 py-3 ${className}`}>
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex min-w-0 items-center gap-3">
            <div className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-cyan/20 bg-cyan/10">
              <ShieldCheck className="h-4 w-4 text-cyan" />
            </div>

            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <AssessmentScopeBadge />
                <span className="text-sm font-semibold text-soft">
                  Safe non-invasive external assessment
                </span>
              </div>

              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                Authorized domains only. External posture evidence and reporting; not a penetration test or full vulnerability assessment.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap gap-2 text-xs">
            <MiniPill icon={Radar} text="TLS, headers, DNS/email" />
            <MiniPill icon={Lock} text="Authorized scope" />
            <MiniPill icon={AlertTriangle} text="No exploitation" />
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className={`rounded-2xl border border-cyan/15 bg-gradient-to-r from-cyan/8 via-surface/60 to-accent-blue/8 p-4 ${className}`}>
      <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
        <div className="flex min-w-0 items-center gap-3">
          <div className="grid h-11 w-11 shrink-0 place-items-center rounded-2xl border border-cyan/25 bg-cyan/10">
            <Radar className="h-5 w-5 text-cyan" />
          </div>

          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <AssessmentScopeBadge />
              <h3 className="text-base font-semibold tracking-tight">
                Safe assessment scope
              </h3>
            </div>

            <p className="mt-1 max-w-3xl text-sm leading-relaxed text-muted-foreground">
              Read-only external posture checks for authorized domains only. No exploitation, intrusive payloads, or penetration testing.
            </p>
          </div>
        </div>

        <div className="grid gap-2 sm:grid-cols-3 xl:w-[560px]">
          <ScopeChip icon={Radar} label="Coverage" value="Availability, TLS, headers, DNS/email" />
          <ScopeChip icon={FileText} label="Output" value="Score, findings, PDF report" />
          <ScopeChip icon={AlertTriangle} label="Limits" value="No exploit or deep testing" />
        </div>
      </div>

      <details className="group mt-3 rounded-xl border border-border/70 bg-background/20">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-2.5 text-xs font-medium text-muted-foreground transition hover:text-cyan">
          <span>View scope details</span>
          <ChevronDown className="h-4 w-4 transition group-open:rotate-180" />
        </summary>

        <div className="grid gap-3 border-t border-border/70 p-4 md:grid-cols-2">
          <ScopeList title="Assessment Coverage" icon={CheckCircle} items={COVERAGE} />
          <ScopeList title="Assessment Limitations" icon={AlertTriangle} items={LIMITATIONS} />
        </div>

        <div className="border-t border-border/70 px-4 py-3 text-xs leading-relaxed text-muted-foreground">
          Authorization reminder: scan only domains you own or where you have explicit written permission.
          This assessment is not a full penetration test and not a full vulnerability assessment.
        </div>
      </details>
    </section>
  );
}

function MiniPill({
  icon: Icon,
  text,
}: {
  icon: any;
  text: string;
}) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-background/25 px-2.5 py-1 text-muted-foreground">
      <Icon className="h-3.5 w-3.5 text-cyan" />
      {text}
    </span>
  );
}

function ScopeChip({
  icon: Icon,
  label,
  value,
}: {
  icon: any;
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-xl border border-border bg-background/25 px-3 py-2.5">
      <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-cyan">
        <Icon className="h-3.5 w-3.5" />
        {label}
      </div>
      <div className="mt-1 text-xs leading-relaxed text-muted-foreground">
        {value}
      </div>
    </div>
  );
}

function ScopeList({
  title,
  icon: Icon,
  items,
}: {
  title: string;
  icon: any;
  items: string[];
}) {
  return (
    <div className="rounded-xl border border-border bg-surface/50 p-4">
      <div className="flex items-center gap-2 text-sm font-medium">
        <Icon className="h-4 w-4 text-cyan" />
        {title}
      </div>

      <ul className="mt-3 grid gap-2">
        {items.map((item) => (
          <li key={item} className="flex items-start gap-2 text-xs leading-relaxed text-muted-foreground">
            <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan" />
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
