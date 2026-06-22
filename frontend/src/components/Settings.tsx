import { useEffect, useState } from "react";
import {
  Sun, Moon, LogOut, User, Bell, Globe, Shield, KeyRound, Trash2,
  Save, Mail, Languages, Eye, EyeOff, Download, Database, Sparkles, Check,
} from "lucide-react";
import { useTheme } from "@/lib/theme";
import { useI18n, LANG_META, type Lang } from "@/lib/i18n";
import { useAuth } from "@/lib/auth";
import { canUseWebsiteFeatures } from "@/lib/access";

interface Props {
  onLogout: () => void;
  onBack: () => void;
}

export function Settings({ onLogout }: Props) {
  const { theme, setTheme } = useTheme();
  const { lang, setLang } = useI18n();
  const { user, refresh } = useAuth();
  const canUseWebsite = canUseWebsiteFeatures(user);
  const [tab, setTab] = useState<"profile" | "appearance" | "security" | "scanner" | "notifications" | "data">("profile");
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!canUseWebsite && tab === "scanner") {
      setTab("profile");
    }
  }, [canUseWebsite, tab]);

  const email = user?.email?.trim() ?? "";
  const name = user?.full_name?.trim() || email.split("@")[0] || "";
  const companyDomain = canUseWebsite ? (user?.company_domain?.trim() || deriveEmailDomain(email)) : "";
  const org = companyDomain ? organizationFromDomain(companyDomain) : "";
  const registeredAt = user?.created_at ? new Date(user.created_at).toLocaleString() : "";

  // security
  const [showKey, setShowKey] = useState(false);
  const [sessionTimeout, setSessionTimeout] = useState(30);
  // scanner
  const [defaultProfile, setDefaultProfile] = useState<"basic" | "advanced">("basic");
  const [autoSave, setAutoSave] = useState(true);
  const [concurrent, setConcurrent] = useState(3);
  // notifications
  const [emailAlerts, setEmailAlerts] = useState(true);
  const [criticalOnly, setCriticalOnly] = useState(false);
  const [weeklyDigest, setWeeklyDigest] = useState(true);

  const save = () => {
    try { localStorage.setItem("cs360-settings", JSON.stringify(canUseWebsite ? { lang, sessionTimeout, defaultProfile, autoSave, concurrent, emailAlerts, criticalOnly, weeklyDigest } : { lang, sessionTimeout, emailAlerts, criticalOnly, weeklyDigest })); } catch {}
    setSaved(true);
    setTimeout(() => setSaved(false), 2200);
  };

  const tabs = [
    { id: "profile", label: "Profile", icon: User },
    { id: "appearance", label: "Appearance", icon: Sun },
    { id: "security", label: "Security", icon: Shield },
    { id: "scanner", label: "Scanner", icon: Sparkles },
    { id: "notifications", label: "Notifications", icon: Bell },
    { id: "data", label: "Data & Privacy", icon: Database },
  ] as const;

  return (
    <div className="space-y-5 sm:space-y-6">
      {/* Hero */}
      <div className="glass relative min-w-0 overflow-hidden rounded-3xl p-4 sm:p-6 lg:p-8">
        <div className="absolute -top-20 -right-20 h-64 w-64 rounded-full bg-cyan/10 blur-3xl pointer-events-none" />
        <div className="relative flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="min-w-0">
            <div className="text-xs uppercase tracking-wider text-cyan font-medium">Workspace Settings</div>
            <h2 className="mt-1 break-words text-xl font-semibold sm:text-2xl">Configure your SecureSight360 experience</h2>
            <p className="text-sm text-muted-foreground mt-1">{canUseWebsite ? "Profile, appearance, security, scanner defaults, and data controls." : "Profile, appearance, account security, email analysis preferences, and privacy controls."}</p>
          </div>
          <div className="flex w-full min-w-0 flex-col gap-2 sm:w-auto sm:flex-row sm:items-center">
            <button
              onClick={save}
              className="inline-flex min-h-[44px] w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan to-accent-blue text-[#021016] px-4 py-2 text-sm font-medium glow-cyan hover:brightness-110 transition sm:w-auto"
            >
              {saved ? <><Check className="h-4 w-4" /> Saved</> : <><Save className="h-4 w-4" /> Save changes</>}
            </button>
            <button
              onClick={onLogout}
              className="inline-flex min-h-[44px] w-full items-center justify-center gap-2 rounded-xl border border-danger/40 bg-danger/10 text-danger px-4 py-2 text-sm font-medium hover:bg-danger/20 transition sm:w-auto"
            >
              <LogOut className="h-4 w-4" /> Log out
            </button>
          </div>
        </div>
      </div>

      <div className="grid min-w-0 gap-5 lg:grid-cols-[240px_minmax(0,1fr)] lg:gap-6">
        {/* Side tabs */}
        <nav className="glass flex max-w-full gap-2 overflow-x-auto rounded-3xl p-2 lg:h-fit lg:flex-col lg:overflow-visible">
          {tabs.filter((t) => canUseWebsite || t.id !== "scanner").map((t) => {
            const Icon = t.icon;
            const active = tab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`flex min-h-[44px] shrink-0 items-center justify-center gap-2 rounded-2xl px-3 py-2.5 text-sm transition-all lg:w-full lg:justify-start ${
                  active ? "bg-secondary text-foreground border border-border" : "text-muted-foreground hover:bg-secondary/60 hover:text-foreground"
                }`}
              >
                <Icon className={`h-4 w-4 ${active ? "text-cyan" : ""}`} />
                {t.label}
              </button>
            );
          })}
        </nav>

        {/* Content */}
        <div className="min-w-0 space-y-5 sm:space-y-6">
          {tab === "profile" && (
            <Card
              title="Registered account"
              desc={canUseWebsite ? "These details are loaded from your authenticated backend account. Your verified company domain controls which websites this account can scan." : "These details are loaded from your authenticated backend account. Personal accounts are configured for AI Email Analyzer and Email Analysis History."}
            >
              <div className="grid min-w-0 gap-4 lg:grid-cols-2">
                <ReadOnlyField label="Registrant name" icon={User} value={name} />
                <ReadOnlyField label="Account email" icon={Mail} value={email} />
                {canUseWebsite ? (
                  <>
                    <ReadOnlyField label="Organization" icon={Globe} value={org} />
                    <ReadOnlyField label="Verified company domain" icon={Shield} value={companyDomain} />
                  </>
                ) : (
                  <>
                    <ReadOnlyField label="Account type" icon={Mail} value="Personal Email Account" />
                    <ReadOnlyField label="Available features" icon={Shield} value="AI Email Analyzer and Email Analysis History" />
                  </>
                )}
                <ReadOnlyField
                  label="Registered on"
                  icon={Database}
                  value={registeredAt ? new Date(registeredAt).toLocaleString() : ""}
                />
                <SelectField label="Preferred language" icon={Languages} value={lang} onChange={(v) => setLang(v as Lang)} options={(Object.keys(LANG_META) as Lang[]).map(k => ({ v: k, l: `${LANG_META[k].flag} ${LANG_META[k].native}` }))} />
              </div>
              {!user && (
                <div className="mt-4 rounded-xl border border-warning/30 bg-warning/10 text-warning text-xs px-3 py-2">
                  Account details could not be loaded from the backend. Please refresh or log in again.
                </div>
              )}
            </Card>
          )}



          {tab === "appearance" && (
            <Card title="Appearance" desc="Choose how SecureSight360 looks on your device.">
              <div className="grid sm:grid-cols-2 gap-4">
                <ThemeCard
                  active={theme === "dark"}
                  onClick={() => setTheme("dark")}
                  icon={Moon}
                  label="Dark"
                  desc="Default cyber theme. Best for low-light analysis."
                  swatch="from-[#020617] to-[#0F172A]"
                />
                <ThemeCard
                  active={theme === "light"}
                  onClick={() => setTheme("light")}
                  icon={Sun}
                  label="Light"
                  desc="High-contrast theme for presentations & daytime."
                  swatch="from-[#F8FAFC] to-[#E2E8F0]"
                />
              </div>
              <div className="mt-4 text-xs text-muted-foreground">Theme syncs across sessions on this device.</div>
            </Card>
          )}

          {tab === "security" && (
            <>
              <Card title="Account security" desc="Protect your workspace with strong authentication.">
                <div className="mt-4">
                  <label className="text-xs uppercase tracking-wider text-muted-foreground">Session timeout (minutes)</label>
                  <input type="range" min={5} max={120} step={5} value={sessionTimeout} onChange={(e) => setSessionTimeout(+e.target.value)} className="w-full mt-2 accent-[var(--cyan)]" />
                  <div className="text-sm mt-1">{sessionTimeout} minutes</div>
                </div>
              </Card>
              <Card title="API access key" desc="API access is reserved for future workspace integrations. Keep account access protected and rotate credentials when API keys are enabled.">
                <div className="flex w-full min-w-0 flex-col gap-2 sm:w-auto sm:flex-row sm:items-center">
                  <div className="flex min-w-0 flex-1 items-center gap-2 rounded-xl border border-border bg-secondary px-3 py-2 font-mono text-sm">
                    <KeyRound className="h-4 w-4 text-cyan" />
                    <span className="break-all">{showKey ? "API keys are not enabled for this workspace yet." : "•••••••••••••••••••••••••••••••••••"}</span>
                  </div>
                  <button onClick={() => setShowKey(s => !s)} className="inline-flex min-h-[42px] w-full items-center justify-center rounded-xl border border-border bg-secondary p-2 hover:bg-secondary/70 sm:w-auto sm:min-w-[42px]">
                    {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
                <button className="mt-3 inline-flex min-h-[40px] w-full items-center justify-center rounded-xl border border-border bg-secondary/60 px-3 py-2 text-xs text-muted-foreground sm:w-auto">API key management coming soon</button>
              </Card>
            </>
          )}

          {tab === "scanner" && (
            <Card title="Scanner defaults" desc="Applied to every new scan you launch.">
              <div className="grid sm:grid-cols-2 gap-3">
                <button
                  onClick={() => setDefaultProfile("basic")}
                  className={`min-h-[92px] rounded-2xl border p-4 text-left transition ${defaultProfile === "basic" ? "border-cyan bg-cyan/10" : "border-border bg-secondary hover:border-cyan/40"}`}
                >
                  <div className="break-words font-medium">Basic</div>
                  <div className="mt-1 break-words text-xs text-muted-foreground">Headers, TLS, surface checks. ~30s.</div>
                </button>
                <button
                  onClick={() => setDefaultProfile("advanced")}
                  className={`min-h-[92px] rounded-2xl border p-4 text-left transition ${defaultProfile === "advanced" ? "border-cyan bg-cyan/10" : "border-border bg-secondary hover:border-cyan/40"}`}
                >
                  <div className="break-words font-medium">Advanced</div>
                  <div className="mt-1 break-words text-xs text-muted-foreground">Full risk engine + detection summary. ~2m.</div>
                </button>
              </div>
              <div className="h-px bg-border my-5" />
              <Toggle label="Auto-save reports" desc="Add every completed scan to Reports." checked={autoSave} onChange={setAutoSave} />
              <div className="mt-4">
                <label className="text-xs uppercase tracking-wider text-muted-foreground">Max concurrent scans</label>
                <input type="range" min={1} max={10} value={concurrent} onChange={(e) => setConcurrent(+e.target.value)} className="w-full mt-2 accent-[var(--cyan)]" />
                <div className="text-sm mt-1">{concurrent} parallel</div>
              </div>
            </Card>
          )}

          {tab === "notifications" && (
            <Card title="Notifications" desc={canUseWebsite ? "Control how SecureSight360 reaches out." : "Control email-analysis notifications and reminders."}>
              <Toggle label="Email alerts" desc={canUseWebsite ? "Receive an email when a scan completes." : "Receive an email when an email analysis is completed."} checked={emailAlerts} onChange={setEmailAlerts} />
              <Toggle label="Critical findings only" desc={canUseWebsite ? "Mute low/medium severity notifications." : "Notify only when an email appears suspicious, malicious, or credential-theft related."} checked={criticalOnly} onChange={setCriticalOnly} />
              <Toggle label="Weekly digest" desc={canUseWebsite ? "Sunday summary of all scans and trends." : "Weekly summary of submitted email analyses and threat patterns."} checked={weeklyDigest} onChange={setWeeklyDigest} />
            </Card>
          )}

          {tab === "data" && (
            <>
              <Card title="Danger zone" desc="Irreversible workspace actions." danger>
                <button className="inline-flex min-h-[44px] w-full items-center justify-center gap-2 rounded-xl border border-danger/40 bg-danger/10 text-danger px-4 py-2 text-sm hover:bg-danger/20 sm:w-auto">
                  <Trash2 className="h-4 w-4" /> {canUseWebsite ? "Delete all scan history" : "Delete all email analysis history"}
                </button>
              </Card>
            </>
          )}
        </div>
      </div>
    </div>
  );
}


function deriveEmailDomain(email: string): string {
  const parts = email.trim().toLowerCase().split("@");
  return parts.length === 2 ? parts[1] : "";
}

function organizationFromDomain(domain: string): string {
  const firstLabel = domain.split(".")[0] || "";
  return firstLabel ? firstLabel.toUpperCase() : "";
}

function Card({ title, desc, children, danger }: { title: string; desc?: string; children: React.ReactNode; danger?: boolean }) {
  return (
    <div className={`glass min-w-0 rounded-3xl p-4 sm:p-5 lg:p-6 ${danger ? "border-danger/30" : ""}`}>
      <div className="mb-4">
        <div className={`break-words text-base font-semibold ${danger ? "text-danger" : ""}`}>{title}</div>
        {desc && <div className="text-sm text-muted-foreground mt-0.5">{desc}</div>}
      </div>
      {children}
    </div>
  );
}

function Field({ label, icon: Icon, value, onChange }: { label: string; icon: any; value: string; onChange: (v: string) => void }) {
  return (
    <label className="block">
      <span className="text-xs uppercase tracking-wider text-muted-foreground">{label}</span>
      <div className="mt-1.5 flex items-center gap-2 rounded-xl border border-border bg-secondary px-3 py-2 focus-within:border-cyan transition">
        <Icon className="h-4 w-4 text-muted-foreground" />
        <input value={value} onChange={(e) => onChange(e.target.value)} className="flex-1 bg-transparent outline-none text-sm" />
      </div>
    </label>
  );
}

function ReadOnlyField({ label, icon: Icon, value }: { label: string; icon: any; value: string }) {
  return (
    <div className="block">
      <span className="text-xs uppercase tracking-wider text-muted-foreground">{label}</span>
      <div className="mt-1.5 flex min-w-0 items-center gap-2 rounded-xl border border-border bg-secondary/60 px-3 py-2">
        <Icon className="h-4 w-4 text-cyan" />
        <span className={`min-w-0 flex-1 break-words text-sm ${value ? "" : "text-muted-foreground italic"}`}>
          {value || "Not provided"}
        </span>
      </div>
    </div>
  );
}


function SelectField({ label, icon: Icon, value, onChange, options }: { label: string; icon: any; value: string; onChange: (v: string) => void; options: { v: string; l: string }[] }) {
  return (
    <label className="block">
      <span className="text-xs uppercase tracking-wider text-muted-foreground">{label}</span>
      <div className="mt-1.5 flex items-center gap-2 rounded-xl border border-border bg-secondary px-3 py-2 focus-within:border-cyan transition">
        <Icon className="h-4 w-4 text-muted-foreground" />
        <select value={value} onChange={(e) => onChange(e.target.value)} className="flex-1 bg-transparent outline-none text-sm">
          {options.map(o => <option key={o.v} value={o.v} className="bg-surface text-foreground">{o.l}</option>)}
        </select>
      </div>
    </label>
  );
}

function Toggle({ label, desc, checked, onChange }: { label: string; desc?: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="flex min-w-0 items-start justify-between gap-4 border-b border-border py-3 first:pt-0 last:border-0 last:pb-0">
      <div className="min-w-0">
        <div className="break-words text-sm font-medium">{label}</div>
        {desc && <div className="text-xs text-muted-foreground mt-0.5">{desc}</div>}
      </div>
      <button
        onClick={() => onChange(!checked)}
        className={`relative h-6 w-11 shrink-0 rounded-full transition ${checked ? "bg-cyan" : "bg-secondary border border-border"}`}
        aria-pressed={checked}
      >
        <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform ${checked ? "translate-x-5" : "translate-x-0.5"}`} />
      </button>
    </div>
  );
}

function ThemeCard({ active, onClick, icon: Icon, label, desc, swatch }: { active: boolean; onClick: () => void; icon: any; label: string; desc: string; swatch: string }) {
  return (
    <button
      onClick={onClick}
      className={`relative min-w-0 overflow-hidden rounded-3xl border p-4 text-left transition ${active ? "border-cyan bg-cyan/10" : "border-border bg-secondary hover:border-cyan/40"}`}
    >
      <div className={`h-20 w-full rounded-xl bg-gradient-to-br ${swatch} border border-border mb-3`} />
      <div className="flex w-full min-w-0 flex-col gap-2 sm:w-auto sm:flex-row sm:items-center">
        <Icon className="h-4 w-4 text-cyan" />
        <span className="break-words font-medium">{label}</span>
        {active && <Check className="h-4 w-4 text-cyan ml-auto" />}
      </div>
      <div className="mt-1 break-words text-xs text-muted-foreground">{desc}</div>
    </button>
  );
}
