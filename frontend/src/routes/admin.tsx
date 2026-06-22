import {
  createFileRoute,
  Link,
  Outlet,
  useNavigate,
  useRouterState,
} from "@tanstack/react-router";
import { useEffect } from "react";
import {
  Shield,
  LayoutDashboard,
  Users,
  ListChecks,
  ShieldAlert,
  LogOut,
  ArrowLeft,
} from "lucide-react";

import { ThemeProvider } from "@/lib/theme";
import { useAuth } from "@/lib/auth";

export const Route = createFileRoute("/admin")({
  component: () => (
    <ThemeProvider>
      <AdminLayout />
    </ThemeProvider>
  ),
});

function AdminLayout() {
  const { isAuthenticated, isAdmin, loading, logout, user } = useAuth();
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  useEffect(() => {
    if (loading) return;

    if (!isAuthenticated || !isAdmin) {
      navigate({ to: "/" });
    }
  }, [loading, isAuthenticated, isAdmin, navigate]);

  if (loading || !isAuthenticated || !isAdmin) {
    return (
      <div className="grid min-h-dvh place-items-center text-muted-foreground text-sm">
        Checking admin access…
      </div>
    );
  }

  const NavLink = ({
    to,
    label,
    icon: Icon,
  }: {
    to: string;
    label: string;
    icon: any;
  }) => {
    const active = pathname === to;

    return (
      <Link
        to={to}
        className={`flex min-h-[42px] shrink-0 items-center gap-2 rounded-2xl px-3 py-2 text-sm font-medium transition sm:gap-3 lg:w-full ${
          active
            ? "bg-secondary text-foreground border border-border"
            : "text-muted-foreground hover:text-foreground hover:bg-secondary/60"
        }`}
      >
        <Icon className={`h-4 w-4 shrink-0 ${active ? "text-cyan" : ""}`} />
        {label}
      </Link>
    );
  };

  return (
    <div className="min-h-dvh w-full overflow-x-hidden lg:flex lg:h-dvh lg:overflow-hidden">
      <aside className="glass hidden h-dvh w-64 shrink-0 flex-col border-r border-border/70 lg:flex">
        <div className="flex items-center gap-3 px-4 py-3 border-b border-border/70">
          <div className="grid h-9 w-9 place-items-center rounded-xl bg-gradient-to-br from-cyan to-accent-blue glow-cyan">
            <Shield className="h-5 w-5 text-[#021016]" />
          </div>

          <div className="min-w-0">
            <div className="text-base font-semibold tracking-tight">
              Admin Console
            </div>
            <div className="truncate text-[11px] uppercase tracking-wider text-muted-foreground">
              SecureSight360
            </div>
          </div>
        </div>

        <nav className="flex-1 space-y-1 px-3 py-3">
          <NavLink
            to="/admin/dashboard"
            label="Dashboard"
            icon={LayoutDashboard}
          />
          <NavLink to="/admin/users" label="Users" icon={Users} />
          <NavLink to="/admin/scans" label="Scans" icon={ListChecks} />
          <NavLink to="/admin/audit" label="Audit Logs" icon={ShieldAlert} />
        </nav>

        <div className="mt-auto px-3 pb-3 space-y-2">
          <Link
            to="/"
            className="flex min-h-[42px] items-center gap-2 rounded-xl border border-border bg-secondary/50 px-3 py-2 text-xs transition hover:bg-secondary"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Back to app
          </Link>

          <button
            onClick={() => {
              logout();
              navigate({ to: "/" });
            }}
            className="flex min-h-[42px] w-full items-center gap-2 rounded-xl border border-danger/40 bg-danger/10 px-3 py-2 text-xs text-danger transition hover:bg-danger/20"
          >
            <LogOut className="h-3.5 w-3.5" />
            Sign out
          </button>

          <div className="truncate px-1 text-[11px] text-muted-foreground">
            {user?.email}
          </div>
        </div>
      </aside>

      <main className="min-h-0 flex-1 min-w-0 overflow-y-auto overflow-x-hidden px-3 py-4 sm:px-4 sm:py-5 lg:h-dvh lg:px-8 lg:py-6">
        <Outlet />
      </main>
    </div>
  );
}
