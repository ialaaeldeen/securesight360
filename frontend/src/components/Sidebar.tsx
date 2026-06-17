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

  const Nav = (
    <aside className="glass flex h-full w-64 2xl:w-72 shrink-0 flex-col rounded-none border-r border-border/70">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-border/70">
        <div className="relative grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-cyan to-accent-blue glow-cyan">
          <Shield className="h-5 w-5 text-[#021016]" />
        </div>

        <div className="min-w-0">
          <div className="text-base font-semibold tracking-tight text-foreground">
            SecureSight<span className="text-cyan">360</span>
          </div>
          <div className="text-[11px] uppercase tracking-wider text-muted-foreground truncate">
            Security Assessment Platform
          </div>
        </div>
      </div>

      <nav className="flex-1 px-3 py-2 space-y-1 overflow-y-auto">
        {items
          .filter((it) => canUseWebsite || !["scanner", "reports"].includes(it.id))
          .map((it) => {
          const Icon = it.icon;
          const isActive = active === it.id;
          const translated = t(it.key);
          const label = translated === it.key ? it.label : translated;

          return (
            <button
              key={it.id}
              onClick={() => {
                onSelect(it.id);
                setOpen(false);
              }}
              className={`group flex w-full items-center gap-3 rounded-xl px-3 py-2 text-sm transition-all ${
                isActive
                  ? "bg-secondary text-foreground border border-border"
                  : "text-muted-foreground hover:text-foreground hover:bg-secondary/60"
              }`}
            >
              <Icon
                className={`h-4 w-4 shrink-0 ${
                  isActive ? "text-cyan" : ""
                }`}
              />
              <span>{label}</span>
            </button>
          );
        })}

        {isAdmin && (
          <Link
            to="/admin/dashboard"
            onClick={() => setOpen(false)}
            className="mt-2 flex w-full items-center gap-3 rounded-xl px-3 py-2 text-sm border border-cyan/30 bg-cyan/10 text-cyan hover:bg-cyan/15 transition"
          >
            <ShieldCheck className="h-4 w-4 shrink-0" />
            <span>Admin Console</span>
          </Link>
        )}

        {canUseWebsite && (
          <div className="pt-3 mt-3 border-t border-border/70">
            <button
              onClick={() => {
                onSelect("scanner");
                setOpen(false);
              }}
              className="relative flex w-full items-center gap-2 rounded-xl px-3 py-2 text-sm font-medium text-[#021016] bg-gradient-to-r from-cyan to-accent-blue glow-cyan hover:brightness-110 transition"
            >
              <Radar className="h-4 w-4 shrink-0" />
              <span className="min-w-0 flex-1 leading-snug">
                Integrated Website Scanner
              </span>
              <span className="ml-auto text-[10px] uppercase tracking-wider bg-black/20 px-1.5 py-0.5 rounded">
                MVP
              </span>
            </button>
          </div>
        )}
      </nav>

      <div className="mt-auto px-3 pt-3 pb-3 border-t border-border/70 space-y-2">
        {onLogout && (
          <button
            onClick={() => {
              setOpen(false);
              onLogout();
            }}
            className="flex w-full items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium border border-danger/40 bg-danger/10 text-danger hover:bg-danger/20 transition"
          >
            <LogOut className="h-4 w-4 shrink-0" />
            <span>{t("header.logout")}</span>
          </button>
        )}

        <div className="text-[11px] text-muted-foreground flex items-center gap-2 px-1">
          <Shield className="h-3.5 w-3.5 shrink-0 text-success" />
          {canUseWebsite ? "Safe authorized scanning only" : "Email threat analysis only"}
        </div>
      </div>
    </aside>
  );

  return (
    <>
      <div className="lg:hidden sticky top-0 z-40 flex items-center justify-between glass px-4 py-3 rounded-none">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-cyan" />
          <span className="font-semibold">
            SecureSight<span className="text-cyan">360</span>
          </span>
        </div>

        <button
          aria-label="Menu"
          onClick={() => setOpen(true)}
          className="p-2 rounded-lg bg-secondary"
        >
          <Menu className="h-5 w-5" />
        </button>
      </div>

      <div className="hidden lg:block lg:sticky lg:top-0 lg:self-start lg:h-screen">
        {Nav}
      </div>

      <div
        className={`lg:hidden fixed inset-0 z-50 transition ${
          open ? "pointer-events-auto" : "pointer-events-none"
        }`}
      >
        <div
          className={`absolute inset-0 bg-black/60 transition-opacity duration-300 ${
            open ? "opacity-100" : "opacity-0"
          }`}
          onClick={() => setOpen(false)}
        />

        <div
          className={`absolute left-0 top-0 h-full w-[19rem] max-w-[85vw] transform transition-transform duration-300 ease-out ${
            open ? "translate-x-0" : "-translate-x-full"
          }`}
        >
          <div className="relative h-full overflow-y-auto">
            <button
              onClick={() => setOpen(false)}
              className="absolute right-3 top-3 z-10 p-2 rounded-lg bg-secondary border border-border"
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
