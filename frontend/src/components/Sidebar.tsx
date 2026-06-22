import { useState } from "react";
import {
  Shield,
  LayoutDashboard,
  Globe,
  FileText,
  History,
  Settings,
  Menu,
  X,
  Radar,
  LogOut,
  Scale,
  ShieldCheck,
  Mail,
} from "lucide-react";
import { Link } from "@tanstack/react-router";

import { useI18n } from "@/lib/i18n";
import { useAuth } from "@/lib/auth";
import { canUseWebsiteFeatures } from "@/lib/access";

const items = [
  { key: "nav.overview", label: "Overview", icon: LayoutDashboard, id: "overview" },
  { key: "nav.scanner", label: "Website Scanner", icon: Globe, id: "scanner" },
  { key: "nav.emailAnalyzer", label: "Email Analyzer", icon: Mail, id: "email" },
  { key: "nav.reports", label: "Reports", icon: FileText, id: "reports" },
  { key: "nav.history", label: "History", icon: History, id: "history" },
  { key: "nav.privacy", label: "Privacy", icon: Scale, id: "privacy" },
  { key: "nav.settings", label: "Settings", icon: Settings, id: "settings" },
];

interface Props {
  active: string;
  onSelect: (id: string) => void;
  onLogout?: () => void;
}

export function Sidebar({ active, onSelect, onLogout }: Props) {
  const [open, setOpen] = useState(false);
  const { t } = useI18n();
  const { isAdmin, user } = useAuth();
  const canUseWebsite = canUseWebsiteFeatures(user);

  const accessLabel = canUseWebsite ? "Business suite" : "Email protection";
  const accessDescription = canUseWebsite
    ? "Website + email security workspace"
    : "Personal email threat analysis workspace";

  const chooseLabel = (item: (typeof items)[number]) => {
    if (item.id === "history") {
      return canUseWebsite ? "Website History" : "Email History";
    }

    const translated = t(item.key);
    return translated === item.key ? item.label : translated;
  };

  const handleSelect = (id: string) => {
    onSelect(id);
    setOpen(false);
  };

  const Nav = (
    <aside className="glass flex h-full w-80 max-w-[92vw] shrink-0 flex-col rounded-none border-r border-border/70 lg:w-64 2xl:w-72">
      <div className="border-b border-border/70 px-4 py-4">
        <div className="flex items-center gap-3">
          <div className="relative grid h-10 w-10 shrink-0 place-items-center rounded-2xl bg-gradient-to-br from-cyan to-accent-blue glow-cyan">
            <Shield className="h-5 w-5 text-[#021016]" />
          </div>

          <div className="min-w-0">
            <div className="text-base font-semibold tracking-tight text-foreground">
              SecureSight<span className="text-cyan">360</span>
            </div>
            <div className="mt-0.5 truncate text-[11px] font-medium text-muted-foreground">
              {accessDescription}
            </div>
          </div>
        </div>

        <div className="mt-4 rounded-2xl border border-cyan/20 bg-cyan/10 px-3 py-2">
          <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-cyan">
            Active access
          </div>
          <div className="mt-0.5 text-sm font-medium text-foreground">
            {accessLabel}
          </div>
        </div>
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-3">
        {items
          .filter((item) => canUseWebsite || !["scanner", "reports"].includes(item.id))
          .map((item) => {
            const Icon = item.icon;
            const isActive = active === item.id;
            const label = chooseLabel(item);

            return (
              <button
                key={item.id}
                onClick={() => handleSelect(item.id)}
                className={`group flex min-h-[46px] w-full items-center gap-3 rounded-2xl px-3 py-2.5 text-left text-sm transition-all ${
                  isActive
                    ? "border border-cyan/25 bg-cyan/10 text-foreground shadow-[0_0_0_1px_rgba(34,211,238,0.05)]"
                    : "text-muted-foreground hover:bg-secondary/70 hover:text-foreground"
                }`}
              >
                <span
                  className={`grid h-9 w-9 shrink-0 place-items-center rounded-xl ${
                    isActive ? "bg-cyan/15 text-cyan" : "bg-secondary/80"
                  }`}
                >
                  <Icon className="h-4 w-4" />
                </span>
                <span className="min-w-0 flex-1 truncate font-medium">{label}</span>
              </button>
            );
          })}

        {isAdmin && (
          <Link
            to="/admin/dashboard"
            onClick={() => setOpen(false)}
            className="mt-2 flex min-h-[46px] w-full items-center gap-3 rounded-2xl border border-cyan/30 bg-cyan/10 px-3 py-2.5 text-sm font-medium text-cyan transition hover:bg-cyan/15"
          >
            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-cyan/15">
              <ShieldCheck className="h-4 w-4" />
            </span>
            <span className="min-w-0 flex-1 truncate">Admin Console</span>
          </Link>
        )}

        {canUseWebsite && (
          <div className="mt-3 border-t border-border/70 pt-3">
            <button
              onClick={() => handleSelect("scanner")}
              className="relative flex min-h-[48px] w-full items-center gap-3 rounded-2xl bg-gradient-to-r from-cyan to-accent-blue px-3 py-3 text-left text-sm font-semibold text-[#021016] glow-cyan transition hover:brightness-110"
            >
              <Radar className="h-4 w-4 shrink-0" />
              <span className="min-w-0 flex-1 leading-snug">
                Start website scan
              </span>
              <span className="ml-auto rounded-full bg-black/20 px-2 py-0.5 text-[10px] uppercase tracking-wider">
                MVP
              </span>
            </button>
          </div>
        )}
      </nav>

      <div className="mt-auto space-y-2 border-t border-border/70 px-3 pb-4 pt-3">
        {onLogout && (
          <button
            onClick={() => {
              setOpen(false);
              onLogout();
            }}
            className="flex min-h-[46px] w-full items-center gap-3 rounded-2xl border border-danger/40 bg-danger/10 px-3 py-2.5 text-sm font-medium text-danger transition hover:bg-danger/20"
          >
            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-danger/10">
              <LogOut className="h-4 w-4" />
            </span>
            <span>{t("header.logout")}</span>
          </button>
        )}

        <div className="flex items-start gap-2 px-1 text-[11px] leading-5 text-muted-foreground">
          <Shield className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" />
          <span>
            {canUseWebsite
              ? "Authorized scanning only. Analyze only assets you own or have permission to test."
              : "Email-only workspace. Website scanning and reports are hidden for personal accounts."}
          </span>
        </div>
      </div>
    </aside>
  );

  return (
    <>
      <div className="sticky top-0 z-40 flex w-full max-w-full items-center justify-between border-b border-border/70 bg-background/95 px-4 py-3 backdrop-blur lg:hidden">
        <div className="flex min-w-0 items-center gap-3">
          <div className="grid h-10 w-10 shrink-0 place-items-center rounded-2xl bg-gradient-to-br from-cyan to-accent-blue">
            <Shield className="h-5 w-5 text-[#021016]" />
          </div>

          <div className="min-w-0">
            <div className="truncate text-sm font-semibold leading-tight">
              SecureSight<span className="text-cyan">360</span>
            </div>
            <div className="truncate text-[11px] text-muted-foreground">
              {accessLabel}
            </div>
          </div>
        </div>

        <button
          aria-label="Open navigation menu"
          onClick={() => setOpen(true)}
          className="inline-flex min-h-[44px] shrink-0 items-center gap-2 rounded-2xl border border-border bg-secondary px-3 text-sm font-medium transition hover:bg-secondary/70"
        >
          <Menu className="h-5 w-5" />
          <span>Menu</span>
        </button>
      </div>

      <div className="hidden lg:block lg:sticky lg:top-0 lg:self-start lg:h-screen">
        {Nav}
      </div>

      <div
        className={`fixed inset-0 z-50 lg:hidden ${
          open ? "pointer-events-auto" : "pointer-events-none"
        }`}
      >
        <div
          className={`absolute inset-0 bg-black/65 backdrop-blur-sm transition-opacity duration-300 ${
            open ? "opacity-100" : "opacity-0"
          }`}
          onClick={() => setOpen(false)}
        />

        <div
          className={`absolute left-0 top-0 h-full w-80 max-w-[92vw] transform transition-transform duration-300 ease-out ${
            open ? "translate-x-0" : "-translate-x-full"
          }`}
        >
          <div className="relative h-full overflow-y-auto">
            <button
              onClick={() => setOpen(false)}
              className="absolute right-3 top-3 z-10 inline-flex min-h-[40px] min-w-[40px] items-center justify-center rounded-xl border border-border bg-secondary text-foreground"
              aria-label="Close menu"
            >
              <X className="h-4 w-4" />
            </button>

            {Nav}
          </div>
        </div>
      </div>
    </>
  );
}
