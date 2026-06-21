import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  FileSearch,
  Loader2,
  RefreshCw,
  Search,
  ShieldAlert,
  XCircle,
} from "lucide-react";

import { apiFetch } from "@/lib/api";

type AuditLogRow = {
  id: number;
  event_type: string;
  action?: string | null;
  outcome: string;
  actor_user_id?: number | null;
  actor_email?: string | null;
  actor_role?: string | null;
  target_user_id?: number | null;
  target_email?: string | null;
  target_resource_type?: string | null;
  target_resource_id?: string | null;
  ip_address?: string | null;
  user_agent?: string | null;
  details?: Record<string, unknown> | null;
  created_at?: string | null;
};

export const Route = createFileRoute("/admin/audit")({
  component: AdminAuditLogsPage,
});

function formatDate(value?: string | null): string {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}

function eventLabel(eventType: string): string {
  return eventType
    .split(".")
    .map((part) => part.replace(/_/g, " "))
    .join(" · ");
}

function outcomeBadgeClass(outcome: string): string {
  const normalized = outcome.toLowerCase();

  if (normalized === "success") {
    return "border-green-800/60 bg-green-950/50 text-green-300";
  }

  if (normalized === "blocked") {
    return "border-yellow-800/60 bg-yellow-950/50 text-yellow-300";
  }

  if (normalized === "failure" || normalized === "failed") {
    return "border-red-800/60 bg-red-950/50 text-red-300";
  }

  return "border-border bg-secondary/70 text-muted-foreground";
}

function EventIcon({ outcome }: { outcome: string }) {
  const normalized = outcome.toLowerCase();

  if (normalized === "success") {
    return <CheckCircle2 className="h-4 w-4 text-green-300" />;
  }

  if (normalized === "blocked") {
    return <ShieldAlert className="h-4 w-4 text-yellow-300" />;
  }

  if (normalized === "failure" || normalized === "failed") {
    return <XCircle className="h-4 w-4 text-red-300" />;
  }

  return <FileSearch className="h-4 w-4 text-muted-foreground" />;
}

function detailsPreview(details?: Record<string, unknown> | null): string {
  if (!details || Object.keys(details).length === 0) {
    return "—";
  }

  try {
    return JSON.stringify(details);
  } catch {
    return "Unavailable";
  }
}

function AdminAuditLogsPage() {
  const [logs, setLogs] = useState<AuditLogRow[]>([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadLogs(options?: { silent?: boolean }) {
    if (options?.silent) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }

    setError(null);

    try {
      const data = await apiFetch<AuditLogRow[]>("/api/v1/admin/audit-logs?limit=200");
      setLogs(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setError(err?.message || "Could not load audit logs.");
      setLogs([]);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    void loadLogs();
  }, []);

  const filteredLogs = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();

    if (!normalizedQuery) {
      return logs;
    }

    return logs.filter((log) => {
      const searchable = [
        log.event_type,
        log.action,
        log.outcome,
        log.actor_email,
        log.actor_role,
        log.target_email,
        log.target_resource_type,
        log.target_resource_id,
        log.ip_address,
        detailsPreview(log.details),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return searchable.includes(normalizedQuery);
    });
  }, [logs, query]);

  const stats = useMemo(() => {
    return {
      total: logs.length,
      success: logs.filter((log) => log.outcome?.toLowerCase() === "success").length,
      blocked: logs.filter((log) => log.outcome?.toLowerCase() === "blocked").length,
      failure: logs.filter((log) =>
        ["failure", "failed"].includes(log.outcome?.toLowerCase())
      ).length,
    };
  }, [logs]);

  return (
    <div className="space-y-5 sm:space-y-6">
      <div className="glass rounded-2xl p-5 sm:p-6 md:p-8 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-r from-cyan/5 via-transparent to-accent-blue/10 pointer-events-none" />

        <div className="relative flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex min-w-0 items-start gap-3 sm:gap-4">
            <div className="grid h-12 w-12 place-items-center rounded-xl border border-border bg-gradient-to-br from-cyan/20 to-accent-blue/10">
              <ShieldAlert className="h-6 w-6 text-cyan" />
            </div>

            <div>
              <h1 className="text-xl font-semibold tracking-tight sm:text-2xl">
                Audit Logs
              </h1>
              <p className="text-sm text-muted-foreground">
                Review authentication, admin actions, and scan authorization events.
              </p>
            </div>
          </div>

          <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row">
            <div className="flex min-w-0 items-center gap-2 rounded-xl border border-border bg-surface/60 px-3 py-2 focus-within:border-cyan/60">
              <Search className="h-4 w-4 text-muted-foreground" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search audit logs..."
                className="min-w-0 w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground/60 sm:w-64"
              />
            </div>

            <button
              type="button"
              onClick={() => loadLogs({ silent: true })}
              disabled={loading || refreshing}
              className="inline-flex min-h-[44px] w-full items-center justify-center gap-2 rounded-xl border border-border bg-secondary/60 px-4 py-2 text-sm transition hover:border-cyan/40 hover:text-cyan disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto"
            >
              <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="glass rounded-2xl p-4 sm:p-5">
          <div className="text-sm text-muted-foreground">Total Events</div>
          <div className="mt-2 text-2xl font-bold">{stats.total}</div>
        </div>

        <div className="glass rounded-2xl p-4 sm:p-5">
          <div className="text-sm text-muted-foreground">Success</div>
          <div className="mt-2 text-2xl font-bold text-green-300">{stats.success}</div>
        </div>

        <div className="glass rounded-2xl p-4 sm:p-5">
          <div className="text-sm text-muted-foreground">Blocked</div>
          <div className="mt-2 text-2xl font-bold text-yellow-300">{stats.blocked}</div>
        </div>

        <div className="glass rounded-2xl p-4 sm:p-5">
          <div className="text-sm text-muted-foreground">Failures</div>
          <div className="mt-2 text-2xl font-bold text-red-300">{stats.failure}</div>
        </div>
      </div>

      {error && (
        <div className="flex items-start gap-3 rounded-2xl border border-red-800/50 bg-red-950/40 p-4 text-red-300">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
          <div className="text-sm">{error}</div>
        </div>
      )}

      <div className="glass rounded-2xl overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center gap-3 p-6 text-muted-foreground sm:p-10">
            <Loader2 className="h-5 w-5 animate-spin text-cyan" />
            Loading audit logs...
          </div>
        ) : filteredLogs.length === 0 ? (
          <div className="p-6 text-center text-muted-foreground sm:p-10">
            No audit logs found.
          </div>
        ) : (
          <div className="max-w-full overflow-x-auto">
            <table className="w-full min-w-[980px] text-sm">
              <thead className="border-b border-border bg-secondary/40 text-xs uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-5 py-4 text-left">Event</th>
                  <th className="px-5 py-4 text-left">Outcome</th>
                  <th className="px-5 py-4 text-left">Actor</th>
                  <th className="px-5 py-4 text-left">Target</th>
                  <th className="px-5 py-4 text-left">IP</th>
                  <th className="px-5 py-4 text-left">Details</th>
                  <th className="px-5 py-4 text-left">When</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-border">
                {filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-secondary/20">
                    <td className="px-5 py-4">
                      <div className="flex items-start gap-3">
                        <div className="mt-0.5 grid h-8 w-8 place-items-center rounded-lg border border-border bg-secondary/70">
                          <EventIcon outcome={log.outcome || ""} />
                        </div>

                        <div>
                          <div className="font-medium">{eventLabel(log.event_type)}</div>
                          <div className="break-words text-xs text-muted-foreground">
                            {log.event_type}
                          </div>
                          {log.action && (
                            <div className="mt-1 break-words text-xs text-muted-foreground">
                              Action: {log.action}
                            </div>
                          )}
                        </div>
                      </div>
                    </td>

                    <td className="px-5 py-4">
                      <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${outcomeBadgeClass(log.outcome || "")}`}>
                        {log.outcome || "—"}
                      </span>
                    </td>

                    <td className="px-5 py-4">
                      <div className="font-medium">{log.actor_email || "—"}</div>
                      <div className="break-words text-xs text-muted-foreground">
                        {log.actor_role || "unknown role"}
                      </div>
                    </td>

                    <td className="px-5 py-4">
                      <div className="font-medium">
                        {log.target_email || log.target_resource_id || "—"}
                      </div>
                      <div className="break-words text-xs text-muted-foreground">
                        {log.target_resource_type || "—"}
                      </div>
                    </td>

                    <td className="break-all px-5 py-4 text-muted-foreground">
                      {log.ip_address || "—"}
                    </td>

                    <td className="px-5 py-4">
                      <code className="block max-w-[260px] break-all rounded-lg border border-border bg-black/20 px-2 py-1 text-xs text-muted-foreground">
                        {detailsPreview(log.details)}
                      </code>
                    </td>

                    <td className="break-all px-5 py-4 text-muted-foreground">
                      <span className="inline-flex items-center gap-1.5">
                        <Clock className="h-3.5 w-3.5" />
                        {formatDate(log.created_at)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
