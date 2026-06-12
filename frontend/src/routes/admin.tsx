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
        className={`flex items-center gap-3 rounded-xl px-3 py-2 text-sm transition ${
          active
            ? "bg-secondary text-foreground border border-border"
            : "text-muted-foreground hover:text-foreground hover:bg-secondary/60"
        }`}
      >
        <Icon className={`h-4 w-4 ${active ? "text-cyan" : ""}`} />
        {label}
      </Link>
    );
  };

  return (
    <div className="h-dvh w-full flex overflow-hidden">
      <aside className="glass hidden lg:flex h-dvh w-64 shrink-0 flex-col border-r border-border/70">
        <div className="flex items-center gap-3 px-4 py-3 border-b border-border/70">
          <div className="grid h-9 w-9 place-items-center rounded-xl bg-gradient-to-br from-cyan to-accent-blue glow-cyan">
            <Shield className="h-5 w-5 text-[#021016]" />
          </div>

          <div className="min-w-0">
            <div className="text-base font-semibold tracking-tight">
              Admin Console
            </div>
            <div className="text-[11px] uppercase tracking-wider text-muted-foreground truncate">
              SecureSight360
            </div>
          </div>
        </div>

        <nav className="flex-1 px-3 py-3 space-y-1">
          <NavLink
            to="/admin/dashboard"
            label="Dashboard"
            icon={LayoutDashboard}
          />
          <NavLink to="/admin/users" label="Users" icon={Users} />
          <NavLink to="/admin/scans" label="Scans" icon={ListChecks} />
        </nav>

        <div className="mt-auto px-3 pb-3 space-y-2">
          <Link
            to="/"
            className="flex items-center gap-2 rounded-xl border border-border bg-secondary/50 px-3 py-2 text-xs hover:bg-secondary transition"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Back to app
          </Link>

          <button
            onClick={() => {
              logout();
              navigate({ to: "/" });
            }}
            className="flex w-full items-center gap-2 rounded-xl border border-danger/40 bg-danger/10 text-danger px-3 py-2 text-xs hover:bg-danger/20 transition"
          >
            <LogOut className="h-3.5 w-3.5" />
            Sign out
          </button>

          <div className="text-[11px] text-muted-foreground px-1 truncate">
            {user?.email}
          </div>
        </div>
      </aside>

      <main className="flex-1 min-w-0 h-dvh overflow-y-auto px-4 py-5 lg:px-8 lg:py-6">
        <Outlet />
      </main>
    </div>
  );
}