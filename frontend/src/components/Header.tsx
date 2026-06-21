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
  const get = (k: string) => { try { return localStorage.getItem(k) || ""; } catch { return ""; } };
  const userName = user?.full_name || get("cs360-user-name");
  const userEmail = user?.email || get("cs360-user-email");
  const companyName = canUseWebsite ? get("cs360-company-name") : "";
  const companyDomain = canUseWebsite ? (user?.company_domain || get("cs360-company-domain")) : "";
  const displayName = userName || userEmail.split("@")[0];
  const initials = (userName || userEmail || "?")
    .split(/[\s@.]+/).filter(Boolean).slice(0, 2).map(s => s[0]?.toUpperCase()).join("");
  const sectionMeta: Record<string, { title: string; sub: string }> = {
    overview: {
      title: tr("section.overview.title") === "section.overview.title" ? "Overview" : tr("section.overview.title"),
      sub: tr("section.overview.sub") === "section.overview.sub" ? "Security posture overview" : tr("section.overview.sub"),
    },
    scanner: { title: "Website Scanner", sub: "Authorized external website security posture assessment." },
    email: { title: "AI Email Analyzer", sub: "Analyze suspicious emails without opening links or executing attachments." },
    reports: { title: "Reports", sub: "Evidence-backed website security reports." },
    history: { title: "History", sub: "Email analyses and website assessment history." },
    privacy: { title: "Privacy", sub: "Data handling, safe analysis, and authorization rules." },
    settings: { title: "Settings", sub: "Manage your SecureSight360 session and preferences." },
  };

  const t = sectionMeta[section] || sectionMeta.overview;
  return (
    <header className="glass w-full max-w-full overflow-hidden rounded-2xl px-3 py-3 sm:px-4 flex items-center justify-between gap-3">
      <div className="flex items-center gap-3 min-w-0">
        {canGoBack && (
          <button
            onClick={onBack}
            aria-label="Back"
            className="shrink-0 inline-flex items-center gap-1.5 rounded-xl border border-border bg-secondary px-3 py-2 text-xs hover:bg-secondary/70 transition"
          >
            <ArrowLeft className="h-4 w-4" />
            <span className="hidden sm:inline">{tr("header.back")}</span>
          </button>
        )}
        <div className="min-w-0">
          <div className="text-[10px] sm:text-xs uppercase tracking-wider text-muted-foreground truncate">SecureSight360 / {t.title}</div>
          <h1 className="text-lg sm:text-xl font-semibold mt-0.5 truncate">{t.title}</h1>
          <p className="text-sm text-muted-foreground hidden sm:block truncate">{t.sub}</p>
        </div>
      </div>
      <div className="hidden md:flex shrink-0 items-center gap-2">
        <div className="hidden xl:flex items-center gap-2 rounded-lg border border-border bg-secondary px-3 py-1.5 text-xs">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full rounded-full bg-success/60 animate-ping" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-success" />
          </span>
          <span className="text-muted-foreground">{tr("header.engine")}</span>
          <span className="text-success font-medium">{tr("header.operational")}</span>
        </div>
        <div className="hidden xl:flex items-center gap-2 rounded-lg border border-border bg-secondary px-3 py-1.5 text-xs">
          <Activity className="h-3.5 w-3.5 text-cyan" />
          <span className="font-medium">{tr("header.safeMode")}</span>
        </div>
        <div className="hidden 2xl:flex items-center gap-2 rounded-lg border border-cyan/30 bg-cyan/10 px-3 py-1.5 text-xs text-cyan">
          <ShieldCheck className="h-3.5 w-3.5" />
          {tr("header.authorized")}
        </div>
        {(userName || userEmail) && (
          <div className="hidden md:flex items-center gap-2.5 rounded-xl border border-border bg-secondary/60 pl-1.5 pr-3 py-1.5">
            <div className="grid h-9 w-9 place-items-center rounded-lg bg-gradient-to-br from-cyan to-accent-blue text-[#021016] text-xs font-bold">
              {initials || <User className="h-4 w-4" />}
            </div>
            <div className="leading-tight">
              <div className="text-xs font-semibold truncate max-w-[180px]">{displayName}</div>
              {companyName && (
                <div className="text-[10px] text-soft/90 truncate max-w-[180px]">{companyName}</div>
              )}
              {companyDomain && (
                <div className="text-[10px] text-cyan truncate max-w-[180px]">@{companyDomain}</div>
              )}
            </div>
          </div>
        )}
      </div>
    </header>
  );
}

