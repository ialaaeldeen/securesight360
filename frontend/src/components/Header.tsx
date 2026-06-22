import { Activity, ShieldCheck, ArrowLeft, User } from "lucide-react";

import { useI18n } from "@/lib/i18n";
import { useAuth } from "@/lib/auth";
import { canUseWebsiteFeatures } from "@/lib/access";

interface HeaderProps {
  section: string;
  onBack?: () => void;
  canGoBack?: boolean;
}

export function Header({ section, onBack, canGoBack }: HeaderProps) {
  const { t: tr } = useI18n();
  const { user } = useAuth();
  const canUseWebsite = canUseWebsiteFeatures(user);

  const get = (key: string) => {
    try {
      return localStorage.getItem(key) || "";
    } catch {
      return "";
    }
  };

  const userName = user?.full_name || get("cs360-user-name");
  const userEmail = user?.email || get("cs360-user-email");
  const companyName = canUseWebsite ? get("cs360-company-name") : "";
  const companyDomain = canUseWebsite
    ? user?.company_domain || get("cs360-company-domain")
    : "";

  const displayName = userName || userEmail.split("@")[0] || "SecureSight360 user";
  const initials = (userName || userEmail || "?")
    .split(/[\s@.]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("");

  const historyTitle = canUseWebsite ? "Website History" : "Email History";
  const historySubtitle = canUseWebsite
    ? "Review previous website assessments and evidence."
    : "Review previous AI email threat analyses.";

  const sectionMeta: Record<string, { title: string; sub: string; eyebrow: string }> = {
    overview: {
      title:
        tr("section.overview.title") === "section.overview.title"
          ? "Overview"
          : tr("section.overview.title"),
      sub:
        tr("section.overview.sub") === "section.overview.sub"
          ? canUseWebsite
            ? "Your combined website and email security workspace."
            : "Your email-focused threat analysis workspace."
          : tr("section.overview.sub"),
      eyebrow: canUseWebsite ? "Security workspace" : "Email protection workspace",
    },
    scanner: {
      title: "Website Scanner",
      sub: "Run authorized external website security posture assessments.",
      eyebrow: "Website security",
    },
    email: {
      title: "AI Email Analyzer",
      sub: "Analyze suspicious emails without opening links or executing attachments.",
      eyebrow: "Email threat analysis",
    },
    reports: {
      title: "Reports",
      sub: "Generate evidence-backed website security reports.",
      eyebrow: "Security reporting",
    },
    history: {
      title: historyTitle,
      sub: historySubtitle,
      eyebrow: "Activity history",
    },
    privacy: {
      title: "Privacy & Policies",
      sub: "Understand data handling, safe analysis, and authorization rules.",
      eyebrow: "Trust and safety",
    },
    settings: {
      title: "Settings",
      sub: "Manage your SecureSight360 session and preferences.",
      eyebrow: "Account workspace",
    },
  };

  const current = sectionMeta[section] || sectionMeta.overview;

  return (
    <header className="glass w-full max-w-full overflow-hidden rounded-2xl border border-border/70 px-4 py-4 sm:px-5 sm:py-4">
      <div className="flex min-w-0 flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          {canGoBack && (
            <button
              onClick={onBack}
              aria-label="Back"
              className="mt-0.5 inline-flex min-h-[40px] shrink-0 items-center justify-center rounded-xl border border-border bg-secondary px-3 text-xs font-medium transition hover:bg-secondary/70 sm:gap-1.5"
            >
              <ArrowLeft className="h-4 w-4" />
              <span className="hidden sm:inline">{tr("header.back")}</span>
            </button>
          )}

          <div className="min-w-0 flex-1">
            <div className="mb-1 flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-cyan/25 bg-cyan/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-cyan sm:text-xs">
                {current.eyebrow}
              </span>
              <span className="hidden rounded-full border border-border bg-secondary/70 px-2.5 py-1 text-[10px] text-muted-foreground sm:inline-flex">
                {canUseWebsite ? "Business access" : "Personal access"}
              </span>
            </div>

            <h1 className="text-xl font-semibold leading-tight tracking-tight text-foreground sm:text-2xl lg:text-3xl">
              {current.title}
            </h1>

            <p className="mt-1 max-w-3xl text-sm leading-6 text-muted-foreground sm:text-[15px]">
              {current.sub}
            </p>
          </div>
        </div>

        <div className="hidden shrink-0 items-center gap-2 md:flex">
          <div className="hidden items-center gap-2 rounded-xl border border-border bg-secondary/70 px-3 py-2 text-xs xl:flex">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success/60" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-success" />
            </span>
            <span className="text-muted-foreground">{tr("header.engine")}</span>
            <span className="font-medium text-success">{tr("header.operational")}</span>
          </div>

          <div className="hidden items-center gap-2 rounded-xl border border-border bg-secondary/70 px-3 py-2 text-xs xl:flex">
            <Activity className="h-3.5 w-3.5 text-cyan" />
            <span className="font-medium">{tr("header.safeMode")}</span>
          </div>

          <div className="hidden items-center gap-2 rounded-xl border border-cyan/30 bg-cyan/10 px-3 py-2 text-xs text-cyan 2xl:flex">
            <ShieldCheck className="h-3.5 w-3.5" />
            {tr("header.authorized")}
          </div>

          {(userName || userEmail) && (
            <div className="flex min-w-0 items-center gap-2.5 rounded-2xl border border-border bg-secondary/60 py-1.5 pl-1.5 pr-3">
              <div className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-cyan to-accent-blue text-xs font-bold text-[#021016]">
                {initials || <User className="h-4 w-4" />}
              </div>

              <div className="min-w-0 leading-tight">
                <div className="max-w-[180px] truncate text-xs font-semibold">
                  {displayName}
                </div>
                {companyName && (
                  <div className="max-w-[180px] truncate text-[10px] text-soft/90">
                    {companyName}
                  </div>
                )}
                {companyDomain && (
                  <div className="max-w-[180px] truncate text-[10px] text-cyan">
                    @{companyDomain}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
