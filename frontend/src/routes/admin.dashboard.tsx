import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import {
  Users as UsersIcon,
  ShieldCheck,
  Activity,
  ListChecks,
} from "lucide-react";

import { apiFetch } from "@/lib/api";

interface DashboardStats {
  total_users?: number;
  total_scans?: number;
  scans_today?: number;
  active_admins?: number;
  [k: string]: any;
}

export const Route = createFileRoute("/admin/dashboard")({
  component: AdminDashboard,
});

function AdminDashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const data = await apiFetch<DashboardStats>("/api/v1/admin/dashboard");
        setStats(data || {});
      } catch (e: any) {
        setError(e?.message || "Failed to load dashboard");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const cards = [
    {
      label: "Total users",
      value: stats?.total_users ?? "—",
      icon: UsersIcon,
      tone: "text-cyan",
    },
    {
      label: "Total scans",
      value: stats?.total_scans ?? "—",
      icon: ListChecks,
      tone: "text-accent-blue",
    },
    {
      label: "Scans today",
      value: stats?.scans_today ?? "—",
      icon: Activity,
      tone: "text-success",
    },
    {
      label: "Active admins",
      value: stats?.active_admins ?? "—",
      icon: ShieldCheck,
      tone: "text-warning",
    },
  ];

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">
          Admin Dashboard
        </h1>
        <p className="text-sm text-muted-foreground">
          Operational overview of SecureSight360.
        </p>
      </header>

      {error && (
        <div className="rounded-xl border border-warning/30 bg-warning/10 text-warning text-sm px-4 py-3">
          {error}
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {cards.map((c) => {
          const Icon = c.icon;

          return (
            <div key={c.label} className="glass rounded-2xl p-5">
              <div className="flex items-start justify-between">
                <div className="text-xs uppercase tracking-wider text-muted-foreground">
                  {c.label}
                </div>
                <Icon className={`h-4 w-4 ${c.tone}`} />
              </div>

              <div className={`mt-3 text-3xl font-semibold ${c.tone}`}>
                {loading ? "…" : c.value}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}