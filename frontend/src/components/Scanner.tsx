import { useEffect, useMemo, useState } from "react";

import { API_BASE, apiFetch } from "@/lib/api";
import { AssessmentScopeCard } from "@/components/AssessmentScopeCard";
import {
  Globe, ShieldCheck, Search, AlertTriangle, CheckCircle, Radar, Bug, Lock, Server, FileText, ExternalLink, Zap, BarChart3,
} from "lucide-react";
import { useI18n } from "@/lib/i18n";

const API_BASE_URL = API_BASE.replace(/\/$/, "");

type ScanProfile = "basic" | "advanced";

interface FeedbackCard {
  title?: string;
  status?: string;
  summary?: string;
  why_it_matters?: string;
  whyItMatters?: string;
  recommendation?: string;
  evidence?: string | string[] | Record<string, unknown>;
}

interface ProfessionalResult {
  key_risk_drivers?: string[];
  priority_actions?: string[];
  positive_security_signals?: string[];
  severity_counts?: Record<string, number>;
  category_counts?: Record<string, number>;
  executive_summary?: string;
  risk_engine_summary?: string;
  detection_summary?: string;
  security_score?: number;
  risk_level?: string;
  grade?: string;
}

interface ScanResponse {
  security_score?: number;
  risk_level?: string;
  grade?: string;
  findings_count?: number;
  result?: {
    risk_assessment?: ProfessionalResult & Record<string, unknown>;
    metadata?: {
      professional_result?: ProfessionalResult;
      key_risk_drivers?: string[];
      client_friendly_feedback?: FeedbackCard[];
    };
  };
}

const isValidUrl = (u: string) => /^https?:\/\/[^\s]+\.[^\s]+/i.test(u.trim());

function scoreColor(score?: number) {
  if (score == null) return "text-muted-foreground";
  if (score >= 85) return "text-success";
  if (score >= 65) return "text-warning";
  return "text-danger";
}
function scoreRing(score?: number) {
  if (score == null) return "ring-border";
  if (score >= 85) return "ring-success/40";
  if (score >= 65) return "ring-warning/40";
  return "ring-danger/40";
}
function riskBadge(level?: string) {
  const l = (level || "").toLowerCase();
  if (l === "low") return "bg-success/15 text-success border-success/30";
  if (l === "medium") return "bg-warning/15 text-warning border-warning/30";
  if (l === "high") return "bg-danger/15 text-danger border-danger/30";
  if (l === "critical") return "bg-red-950/60 text-red-300 border-red-800/60";
  return "bg-secondary text-muted-foreground border-border";
}
function statusStyle(status?: string) {
  const s = (status || "").toLowerCase();
  if (s === "passed") return { cls: "border-success/30 bg-success/10 text-success", icon: CheckCircle };
  if (s === "warning") return { cls: "border-warning/30 bg-warning/10 text-warning", icon: AlertTriangle };
  if (s === "needs_attention") return { cls: "border-warning/30 bg-warning/10 text-warning", icon: AlertTriangle };
  if (s === "failed") return { cls: "border-danger/30 bg-danger/10 text-danger", icon: Bug };
  if (s === "info") return { cls: "border-accent-blue/30 bg-accent-blue/10 text-[#93c5fd]", icon: FileText };
  return { cls: "border-border bg-secondary text-muted-foreground", icon: FileText };
}


type FlexibleScanResponse = ScanResponse & Record<string, any>;


function toDisplayText(value: any): string {
  if (value === null || value === undefined) return "";

  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);

  if (Array.isArray(value)) {
    return value.map(toDisplayText).filter(Boolean).join(", ");
  }

  if (typeof value === "object") {
    return (
      value.title ||
      value.summary ||
      value.description ||
      value.recommendation ||
      value.evidence ||
      value.category ||
      JSON.stringify(value)
    );
  }

  return String(value);
}

function toDisplayList(value: any): string[] {
  if (value === null || value === undefined) return [];

  if (Array.isArray(value)) {
    return value.map(toDisplayText).map((item) => item.trim()).filter(Boolean);
  }

  const item = toDisplayText(value).trim();
  return item ? [item] : [];
}


function normalizeScanResponse(response: ScanResponse): FlexibleScanResponse {
  const data = response as FlexibleScanResponse;
  const result = (data.result ?? {}) as Record<string, any>;
  const riskAssessment = (result.risk_assessment ?? {}) as Record<string, any>;
  const metadata = (result.metadata ?? {}) as Record<string, any>;
  const professionalResult = (metadata.professional_result ?? {}) as Record<string, any>;

  const riskLevel =
    data.risk_level ??
    professionalResult.risk_level ??
    riskAssessment.risk_level ??
    "unknown";

  const grade =
    data.grade ??
    professionalResult.grade ??
    riskAssessment.grade ??
    "—";

  const securityScore =
    data.security_score ??
    professionalResult.security_score ??
    riskAssessment.security_score ??
    0;

  const findings = Array.isArray(data.findings) ? data.findings : [];
  const scoringDeductions = Array.isArray(riskAssessment.scoring_deductions)
    ? riskAssessment.scoring_deductions
    : [];

  const keyRiskDrivers =
    data.key_risk_drivers ??
    professionalResult.key_risk_drivers ??
    riskAssessment.key_risk_drivers ??
    scoringDeductions.map((item: Record<string, any>) => item.title).filter(Boolean);

  const priorityActions =
    data.priority_actions ??
    professionalResult.priority_actions ??
    riskAssessment.priority_actions ??
    findings.map((item: Record<string, any>) => item.recommendation).filter(Boolean);

  const positiveSecuritySignals =
    data.positive_security_signals ??
    professionalResult.positive_security_signals ??
    riskAssessment.positive_security_signals ??
    [];

  const executiveSummary =
    data.executive_summary ??
    professionalResult.executive_summary ??
    riskAssessment.executive_summary ??
    "Website scan completed successfully. Review the findings and priority actions below.";

  const riskEngineSummary =
    data.risk_engine_summary ??
    professionalResult.risk_engine_summary ??
    riskAssessment.risk_engine_summary ??
    `Security score calculated as ${securityScore}/100 with ${findings.length} finding(s).`;

  const detectionSummary =
    data.detection_summary ??
    professionalResult.detection_summary ??
    riskAssessment.detection_summary ??
    "The scanner evaluated availability, HTTPS/TLS, HTTP security headers, and DNS/email security signals.";

  const clientFriendlyFeedback =
    data.client_friendly_feedback ??
    metadata.client_friendly_feedback ??
    findings.map((finding: Record<string, any>) => ({
      title: finding.title,
      status: finding.severity,
      summary: finding.description,
      why_it_matters: finding.description,
      recommendation: finding.recommendation,
      evidence: finding.category,
    }));

  return {
    ...data,
    security_score: securityScore,
    risk_level: riskLevel,
    grade,
    findings_count: data.findings_count ?? findings.length,
    findings,
    executive_summary: executiveSummary,
    risk_engine_summary: riskEngineSummary,
    detection_summary: detectionSummary,
    key_risk_drivers: toDisplayList(keyRiskDrivers),
    priority_actions: toDisplayList(priorityActions),
    positive_security_signals: toDisplayList(positiveSecuritySignals),
    client_friendly_feedback: clientFriendlyFeedback,
    result: {
      ...result,
      risk_assessment: riskAssessment,
      metadata: {
        ...metadata,
        professional_result: {
          ...professionalResult,
          executive_summary: executiveSummary,
          risk_engine_summary: riskEngineSummary,
          detection_summary: detectionSummary,
          security_score: securityScore,
          risk_level: riskLevel,
          grade,
          key_risk_drivers: toDisplayList(keyRiskDrivers),
          priority_actions: toDisplayList(priorityActions),
          positive_security_signals: toDisplayList(positiveSecuritySignals),
        },
        client_friendly_feedback: clientFriendlyFeedback,
      },
    },
  };
}


export function Scanner({ onReverify }: { onReverify?: () => void } = {}) {
  const { t } = useI18n();
  const [url, setUrl] = useState("");
  const [profile, setProfile] = useState<ScanProfile>("basic");
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<ScanResponse | null>(null);
  const [touched, setTouched] = useState(false);

  const hostname = useMemo(() => {
    try { return new URL(url).hostname.replace(/^www\./, ""); } catch { return null; }
  }, [url]);

  const [verifiedDomain, setVerifiedDomain] = useState<string | null>(() => {
  try {
    const storedDomain = localStorage.getItem("cs360-company-domain");
    const storedEmail = localStorage.getItem("cs360-user-email");
    return storedDomain || storedEmail?.split("@")[1]?.toLowerCase() || null;
  } catch {
    return null;
  }
});

useEffect(() => {
  let cancelled = false;

  async function syncRegisteredDomainFromBackend() {
    try {
      const user = await apiFetch<any>("/api/v1/auth/me");

      const email = String(user?.email || "").trim().toLowerCase();
      const domain = email.includes("@") ? email.split("@")[1] : null;

      if (!domain || cancelled) return;

      localStorage.setItem("cs360-user-email", email);
      localStorage.setItem("cs360-company-domain", domain);

      if (user?.full_name) {
        localStorage.setItem("cs360-user-name", String(user.full_name));
      }

      if (user?.company_name) {
        localStorage.setItem("cs360-company-name", String(user.company_name));
      }

      if (!localStorage.getItem("cs360-registered-at")) {
        localStorage.setItem("cs360-registered-at", new Date().toISOString());
      }

      setVerifiedDomain(domain);
    } catch {
      // Keep local fallback if /auth/me is unavailable.
    }
  }

  syncRegisteredDomainFromBackend();

  return () => {
    cancelled = true;
  };
}, []);

  function clearRegisteredDomain() {
    if (!confirm("Reset your registered company domain and return to verification? You'll need to sign up again with the correct work email.")) return;
    try {
      ["cs360-company-domain","cs360-company-name","cs360-verified-hosts","cs360-user-name","cs360-user-email","cs360-registered-at"]
        .forEach(k => localStorage.removeItem(k));
    } catch {}
    setVerifiedDomain(null);
    if (onReverify) onReverify();
  }

  const matchesCompany = !!hostname && !false &&
    (hostname === verifiedDomain || hostname.endsWith("." + verifiedDomain));

  const urlValid = useMemo(() => isValidUrl(url), [url]);
  const domainAllowed = Boolean(verifiedDomain && matchesCompany);
  const canSubmit = urlValid && authorized && domainAllowed && !loading;

  async function runScan(e: React.FormEvent) {
    e.preventDefault();
    setTouched(true);

    if (!canSubmit) return;

    setLoading(true);
    setError(null);
    setData(null);

    try {
      const payload = {
        target_url: url.trim(),
        scan_profile: "basic",
        authorization_confirmed: true,
      };

      const endpoint = "/api/v1/website/scan";

      console.log("SecureSight360 scan request", {
        endpoint: `${API_BASE_URL}${endpoint}`,
        payload,
      });

      const json = await apiFetch<ScanResponse>(endpoint, {
        method: "POST",
        body: JSON.stringify(payload),
      });

      console.log("SecureSight360 scan response", {
        status: 200,
        body: json,
      });

      const normalized = normalizeScanResponse(json as ScanResponse);
      setData(normalized);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Unable to connect to the backend scanner.";

      console.error("SecureSight360 scanner error", err);
      setError(message);
    } finally {
      setLoading(false);
    }
  }

  const pro = data?.result?.metadata?.professional_result;
  const score = data?.security_score ?? pro?.security_score;
  const risk = data?.risk_level ?? pro?.risk_level;
  const grade = data?.grade ?? pro?.grade;
  const findings = data?.findings_count;
  const drivers = data?.result?.metadata?.key_risk_drivers ?? [];
  const feedback = data?.result?.metadata?.client_friendly_feedback ?? [];

  return (
    <div className="space-y-5 sm:space-y-6">
      {/* Form */}
      <form onSubmit={runScan} className="glass rounded-2xl p-5 space-y-5 sm:p-6 md:p-7">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex min-w-0 items-start gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-xl bg-gradient-to-br from-cyan/20 to-accent-blue/10 border border-border">
              <Radar className="h-5 w-5 text-cyan" />
            </div>
            <div>
              <h2 className="text-lg font-semibold">Website Scanner</h2>
              <p className="text-sm text-muted-foreground">
                {verifiedDomain
                  ? <>Scoped to <span className="text-cyan font-medium">{verifiedDomain}</span> and its subdomains — Basic External Assessment.</>
                  : "Safe non-invasive external assessment — basic profile only"}
              </p>
            </div>
          </div>
          {verifiedDomain && (
            <button
              type="button"
              onClick={clearRegisteredDomain}
              className="inline-flex min-h-[42px] w-full items-center justify-center gap-1.5 rounded-xl border border-border bg-secondary px-3 py-2 text-xs font-medium hover:border-cyan/40 hover:text-cyan transition sm:w-auto"
            >
              <ShieldCheck className="h-3.5 w-3.5" /> Change registered domain
            </button>
          )}
        </div>

        <AssessmentScopeCard />

        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_220px]">
          <div>
            <label className="text-xs uppercase tracking-wider text-muted-foreground">Target URL</label>
            <div className="mt-1.5 flex items-center gap-2 rounded-xl border border-border bg-surface/60 px-3 py-2.5 focus-within:border-cyan/60 focus-within:ring-2 focus-within:ring-cyan/20">
              <Globe className="h-4 w-4 text-muted-foreground" />
              <input
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onBlur={() => setTouched(true)}
                placeholder="https://your-company-domain.com"
                className="min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground/60"
                autoComplete="off"
              />
            </div>
            {touched && !urlValid && (
              <p className="mt-1.5 text-xs text-danger flex items-center gap-1.5">
                <AlertTriangle className="h-3.5 w-3.5" /> Enter a valid URL starting with http:// or https://
              </p>
            )}
          </div>
          <div>
            <label className="text-xs uppercase tracking-wider text-muted-foreground">Profile</label>
            <div className="mt-1.5 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-1">
              {(["basic"] as ScanProfile[]).map((p) => (
                <button
                  key={p}
                  type="button"
                  onClick={() => setProfile(p)}
                  className={`min-h-[44px] rounded-xl border px-3 py-2.5 text-sm capitalize transition ${
                    profile === p
                      ? "border-cyan/60 bg-cyan/10 text-cyan ring-2 ring-cyan/20"
                      : "border-border bg-surface/60 text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {p}
                </button>
              ))}
            </div>
            <p className="mt-1.5 text-[11px] text-muted-foreground">
              {profile === "basic"
                ? "Basic External Website Security Posture Assessment: availability, HTTPS/TLS, security headers, DNS/email security, CAA, basic technology evidence, risk scoring, and PDF reporting."
                : "Deeper analysis: full header policy review, cipher suite audit, DNSSEC, SPF/DKIM/DMARC alignment, exposed paths."}
            </p>
          </div>
        </div>

        {/* Company domain context — scanner is locked to the registered company domain */}
        {verifiedDomain ? (
          <div className={`rounded-xl border px-3 py-2.5 text-xs flex items-start gap-2 ${matchesCompany ? "border-success/30 bg-success/10 text-success" : "border-danger/30 bg-danger/10 text-danger"}`}>
            <ShieldCheck className="h-3.5 w-3.5 mt-0.5 shrink-0" />
            <div className="flex-1">
              {matchesCompany ? (
                <span>Target matches your registered company domain <span className="font-medium">{verifiedDomain}</span>. You're cleared to scan.</span>
              ) : (
                <span>
                  Scanning is restricted to your registered company domain <span className="font-medium">{verifiedDomain}</span> (and its subdomains).
                  {hostname && <> The URL <span className="font-medium">{hostname}</span> is outside that scope and cannot be scanned from this account.</>}
                </span>
              )}
              <div className="mt-1.5 opacity-80">
                Not your domain?{" "}
                <button type="button" onClick={clearRegisteredDomain} className="underline hover:opacity-100 font-medium">
                  Reset & re-verify
                </button>
              </div>
            </div>
          </div>
        ) : (
          <div className="rounded-xl border border-warning/30 bg-warning/10 text-warning px-3 py-2.5 text-xs flex items-start gap-2">
            <AlertTriangle className="h-3.5 w-3.5 mt-0.5 shrink-0" />
            <span>No company domain is registered on this account. Please sign out and complete company email verification to register your domain.</span>
          </div>
        )}

        {/* Authorization & privacy */}
        <label className="flex items-start gap-3 rounded-xl border border-border bg-surface/50 p-4 cursor-pointer">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            className="mt-0.5 h-4 w-4 accent-[#06B6D4]"
          />
          <div className="text-sm">
            <div className="font-medium flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-cyan" /> Scan Authorization &amp; Privacy Agreement
            </div>
            <p className="text-muted-foreground mt-1.5 leading-relaxed">
              I confirm I am the owner of the target website or have explicit written authorization from the owner
              to perform a non-intrusive security assessment. SecureSight360 performs only safe, read-only checks
              and does not exploit vulnerabilities, brute-force credentials, or transmit malicious payloads.
            </p>
            <p className="text-muted-foreground mt-2 leading-relaxed">
              Unauthorized scanning may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act,
              the EU NIS2 Directive, and similar local laws. By proceeding I accept the{" "}
              <a href="#" className="text-cyan hover:underline">Terms of Service</a> and{" "}
              <a href="#" className="text-cyan hover:underline">Privacy Policy</a>: scan metadata is stored encrypted,
              tied to my account, never sold, and may be deleted on request in accordance with GDPR/CCPA.
            </p>
          </div>
        </label>

        <div className="flex flex-col md:flex-row md:items-center gap-3">
          <button
            type="submit"
            disabled={!canSubmit}
            className="inline-flex items-center justify-center gap-2 rounded-xl px-5 py-3 text-sm font-medium text-[#021016] bg-gradient-to-r from-cyan to-accent-blue glow-cyan transition disabled:opacity-40 disabled:cursor-not-allowed disabled:shadow-none hover:brightness-110"
          >
            {loading ? (
              <>
                <span className="h-4 w-4 rounded-full border-2 border-[#021016]/40 border-t-[#021016] animate-spin" />
                Scanning Website...
              </>
            ) : (
              <>
                <Search className="h-4 w-4" />
                Run Website Scan
              </>
            )}
          </button>
          <span className="text-xs text-muted-foreground">
            {false ? "Verify your company email to unlock scanning." :
             !urlValid ? "Enter a valid URL to begin." :
             false ? `Only ${verifiedDomain} (and its subdomains) can be scanned from this account.` :
             !authorized ? "Accept the authorization & privacy agreement to continue." :
             "Safe, read-only checks. No exploitation, no intrusive payloads."}
          </span>
        </div>
      </form>

      {/* Loading */}
      {loading && (
        <div className="glass rounded-2xl p-6 md:p-8">
          <div className="flex items-center gap-4">
            <div className="relative h-14 w-14">
              <div className="absolute inset-0 rounded-full border border-cyan/30" />
              <div className="absolute inset-0 rounded-full border-t-2 border-cyan animate-spin" />
              <div className="absolute inset-2 rounded-full bg-cyan/20 grid place-items-center">
                <Radar className="h-5 w-5 text-cyan" />
              </div>
            </div>
            <div>
              <div className="font-medium">Scanning website security posture...</div>
              <div className="text-sm text-muted-foreground">
                Checking externally observable availability, HTTPS/TLS, security headers, DNS/email security, CAA, basic technology evidence, and risk score.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Error */}
      {error && !loading && (
        <div className="glass rounded-2xl p-6 border-danger/30">
          <div className="flex items-start gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-xl bg-danger/10 border border-danger/30">
              <AlertTriangle className="h-5 w-5 text-danger" />
            </div>
            <div>
              <div className="font-semibold text-danger">Unable to complete scan</div>
              <p className="text-sm text-muted-foreground mt-1">Please verify the following and try again:</p>
              <ul className="text-sm text-muted-foreground mt-2 space-y-1 list-disc list-inside">
                <li>Target URL is valid and reachable</li>
                <li>Authorization was confirmed</li>
                <li>Your network connection is active</li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Empty */}
      {!loading && !error && !data && (
        <div className="glass rounded-2xl p-10 text-center">
          <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-secondary border border-border">
            <Globe className="h-6 w-6 text-cyan" />
          </div>
          <div className="mt-4 font-medium">No scan yet</div>
          <p className="text-sm text-muted-foreground mt-1">
            Enter an authorized website URL to begin a safe external posture assessment.
          </p>
        </div>
      )}

      {/* Results */}
      {data && !loading && (
        <div className="space-y-5 sm:space-y-6">
          <div className="grid gap-4 grid-cols-2 lg:grid-cols-4">
            <div className={`glass rounded-2xl p-5 ring-1 ${scoreRing(score)}`}>
              <div className="text-xs uppercase tracking-wider text-muted-foreground flex items-center gap-1.5"><BarChart3 className="h-3.5 w-3.5" />Security Score</div>
              <div className={`mt-2 text-4xl font-semibold ${scoreColor(score)}`}>
                {score ?? "—"}<span className="text-base text-muted-foreground">/100</span>
              </div>
            </div>
            <div className="glass rounded-2xl p-4 sm:p-5">
              <div className="text-xs uppercase tracking-wider text-muted-foreground flex items-center gap-1.5"><AlertTriangle className="h-3.5 w-3.5" />Risk Level</div>
              <div className="mt-3">
                <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-sm font-medium capitalize ${riskBadge(risk)}`}>
                  {risk || "unknown"}
                </span>
              </div>
            </div>
            <div className="glass rounded-2xl p-4 sm:p-5">
              <div className="text-xs uppercase tracking-wider text-muted-foreground flex items-center gap-1.5"><ShieldCheck className="h-3.5 w-3.5" />Grade</div>
              <div className="mt-2 text-4xl font-semibold text-cyan">{grade ?? "—"}</div>
            </div>
            <div className="glass rounded-2xl p-4 sm:p-5">
              <div className="text-xs uppercase tracking-wider text-muted-foreground flex items-center gap-1.5"><Bug className="h-3.5 w-3.5" />Findings</div>
              <div className="mt-2 text-4xl font-semibold">{findings ?? feedback.length}</div>
            </div>
          </div>

          {(pro?.executive_summary || pro?.risk_engine_summary || pro?.detection_summary) && (
            <div className="grid gap-4 lg:grid-cols-3">
              <SummaryCard title="Executive Summary" icon={FileText} text={pro?.executive_summary} />
              <SummaryCard title="Risk Engine Summary" icon={BarChart3} text={pro?.risk_engine_summary} />
              <SummaryCard title="Detection Summary" icon={Radar} text={pro?.detection_summary} />
            </div>
          )}

          <div className="grid gap-4 lg:grid-cols-3">
            <ListCard
              title="Priority Actions"
              icon={Zap}
              tone="warning"
              items={pro?.priority_actions ?? []}
              empty="No priority actions identified."
            />
            <ListCard
              title="Positive Security Signals"
              icon={CheckCircle}
              tone="success"
              items={pro?.positive_security_signals ?? []}
              empty="No positive signals captured."
            />
            <ListCard
              title="Key Risk Drivers"
              icon={AlertTriangle}
              tone="danger"
              items={drivers}
              empty="No key risk drivers identified."
            />
          </div>

          {feedback.length > 0 && (
            <div>
              <div className="flex items-end justify-between mb-3">
                <h3 className="text-lg font-semibold">Client-Friendly Feedback</h3>
                <span className="text-xs text-muted-foreground">{feedback.length} insight{feedback.length === 1 ? "" : "s"}</span>
              </div>
              <div className="grid gap-4 md:grid-cols-2">
                {feedback.map((f, i) => (
                  <FeedbackItem key={i} card={f} />
                ))}
              </div>
            </div>
          )}

          <div className="glass rounded-2xl p-5 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div className="flex min-w-0 items-start gap-3">
              <Lock className="h-4 w-4 text-cyan" />
              <div className="text-sm text-muted-foreground">
                Assessment generated by SecureSight360 Risk Engine from safe, authorization-based external evidence. Not a full penetration test or full vulnerability assessment.
              </div>
            </div>
            <div className="flex min-w-0 flex-wrap items-center gap-2 break-all text-xs text-muted-foreground">
              <Server className="h-3.5 w-3.5" /> {API_BASE_URL}
              <ExternalLink className="h-3 w-3" />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function SummaryCard({ title, icon: Icon, text }: { title: string; icon: any; text?: string }) {
  return (
    <div className="glass rounded-2xl p-4 sm:p-5">
      <div className="flex items-center gap-2 text-sm font-medium">
        <Icon className="h-4 w-4 text-cyan" /> {title}
      </div>
      <p className="mt-3 break-words text-sm text-soft/90 leading-relaxed">
        {text || <span className="text-muted-foreground">Not provided.</span>}
      </p>
    </div>
  );
}

function ListCard({
  title, icon: Icon, items, empty, tone,
}: { title: string; icon: any; items: string[]; empty: string; tone: "success" | "warning" | "danger" }) {
  const dot =
    tone === "success" ? "bg-success" : tone === "warning" ? "bg-warning" : "bg-danger";
  const iconColor =
    tone === "success" ? "text-success" : tone === "warning" ? "text-warning" : "text-danger";
  return (
    <div className="glass rounded-2xl p-4 sm:p-5">
      <div className="flex items-center gap-2 text-sm font-medium">
        <Icon className={`h-4 w-4 ${iconColor}`} /> {title}
      </div>
      {items.length === 0 ? (
        <p className="mt-3 text-sm text-muted-foreground">{empty}</p>
      ) : (
        <ul className="mt-3 space-y-2">
          {items.map((it, i) => (
            <li key={i} className="flex items-start gap-2.5 text-sm text-soft/90">
              <span className={`mt-1.5 inline-block h-1.5 w-1.5 rounded-full ${dot}`} />
              <span>{it}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function FeedbackItem({ card }: { card: FeedbackCard }) {
  const { cls, icon: SIcon } = statusStyle(card.status);
  const why = card.why_it_matters || card.whyItMatters;
  const evidence = formatEvidence(card.evidence);
  return (
    <div className="glass rounded-2xl p-4 sm:p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="font-medium">{card.title || "Untitled Check"}</div>
          {card.summary && <p className="text-sm text-muted-foreground mt-1">{card.summary}</p>}
        </div>
        <span className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium capitalize ${cls}`}>
          <SIcon className="h-3.5 w-3.5" />
          {(card.status || "info").replace(/_/g, " ")}
        </span>
      </div>
      <div className="mt-4 space-y-3">
        {why && (
          <div>
            <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Why it matters</div>
            <p className="text-sm text-soft/90 mt-0.5">{why}</p>
          </div>
        )}
        {card.recommendation && (
          <div>
            <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Recommendation</div>
            <p className="text-sm text-soft/90 mt-0.5">{card.recommendation}</p>
          </div>
        )}
        {evidence && (
          <div>
            <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Evidence</div>
            <p className="text-sm text-soft/80 mt-0.5 font-mono break-words">{evidence}</p>
          </div>
        )}
      </div>
    </div>
  );
}

function formatEvidence(e: FeedbackCard["evidence"]): string | null {
  if (e == null) return null;
  if (typeof e === "string") return e;
  if (Array.isArray(e)) return e.join(", ");
  try {
    const entries = Object.entries(e).slice(0, 4);
    return entries.map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`).join(" · ");
  } catch {
    return null;
  }
}

