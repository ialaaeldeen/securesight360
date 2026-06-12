import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { AlertTriangle, ListChecks, Loader2 } from "lucide-react";

import { apiFetch } from "@/lib/api";

interface AdminScanRow {
  id?: number | string;
  target?: string;
  domain?: string;
  target_url?: string;
  user_email?: string;
  email?: string;
  owner_email?: string;
  full_name?: string;
  user?: string;
  security_score?: number;
  score?: number;
  overall_score?: number;
  risk_score?: number;
  grade?: string;
  risk?: string;
  risk_level?: string;
  started_at?: string;
  completed_at?: string;
  created_at?: string;
  [key: string]: any;
}

export const Route = createFileRoute("/admin/scans")({
  component: AdminScansPage,
});

function scanScore(row: AdminScanRow): number {
  const value =
    row.security_score ??
    row.score ??
    row.overall_score ??
    row.risk_score ??
    0;

  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function scoreToRisk(score: number): string {
  if (score >= 85) return "Low";
  if (score >= 70) return "Medium";
  if (score >= 50) return "High";
  return "Critical";
}

function scanUser(row: AdminScanRow): string {
  return (
    row.user_email ||
    row.email ||
    row.owner_email ||
    row.full_name ||
    row.user ||
    "—"
  );
}

function scanTarget(row: AdminScanRow): string {
  return row.target || row.domain || row.target_url || "—";
}

function scanDate(row: AdminScanRow): string {
  const value = row.completed_at || row.created_at || row.started_at;
  return value ? new Date(value).toLocaleString() : "—";
}

function AdminScansPage() {
  const [scans, setScans] = useState<AdminScanRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    (async () => {
      try {
        const data = await apiFetch<AdminScanRow[] | { items: AdminScanRow[] }>(
          "/api/v1/admin/scans"
        );

        const list = Array.isArray(data) ? data : data?.items ?? [];

        if (!cancelled) {
          setScans(list);
        }
      } catch (e: any) {
        if (!cancelled) {
          setError(e?.message || "Failed to load scans");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="space-y-6">
      <header className="flex items-center gap-3">
        <ListChecks className="h-6 w-6 text-cyan" />

        <div>
          <h1 className="text-2xl font-semibold tracking-tight">All Scans</h1>
          <p className="text-sm text-muted-foreground">
            Every scan run across all SecureSight360 users.
          </p>
        </div>
      </header>

      {error && (
        <div className="flex items-center gap-2 rounded-xl border border-warning/30 bg-warning/10 text-warning text-sm px-4 py-3">
          <AlertTriangle className="h-4 w-4" />
          {error}
        </div>
      )}

      <div className="overflow-hidden rounded-2xl border border-border bg-surface/70">
        <table className="w-full text-sm">
          <thead className="bg-secondary/70 text-muted-foreground uppercase text-xs tracking-wider">
            <tr>
              <th className="px-5 py-4 text-left">ID</th>
              <th className="px-5 py-4 text-left">Domain</th>
              <th className="px-5 py-4 text-left">User</th>
              <th className="px-5 py-4 text-left">Score</th>
              <th className="px-5 py-4 text-left">Grade</th>
              <th className="px-5 py-4 text-left">Risk</th>
              <th className="px-5 py-4 text-left">When</th>
            </tr>
          </thead>

          <tbody>
            {loading ? (
              <tr>
                <td colSpan={7} className="px-5 py-10 text-center text-muted-foreground">
                  <span className="inline-flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Loading scans...
                  </span>
                </td>
              </tr>
            ) : scans.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-5 py-10 text-center text-muted-foreground">
                  No scans found.
                </td>
              </tr>
            ) : (
              scans.map((scan) => {
                const score = scanScore(scan);
                const grade = scan.grade || scoreToGrade(score);
                const risk = scan.risk || scan.risk_level || scoreToRisk(score);

                return (
                  <tr key={String(scan.id)} className="border-t border-border/70">
                    <td className="px-5 py-4">{scan.id ?? "—"}</td>
                    <td className="px-5 py-4 font-medium">{scanTarget(scan)}</td>
                    <td className="px-5 py-4">{scanUser(scan)}</td>
                    <td className="px-5 py-4">{score}</td>
                    <td className="px-5 py-4 font-semibold">{grade}</td>
                    <td className="px-5 py-4">{risk}</td>
                    <td className="px-5 py-4 text-muted-foreground">{scanDate(scan)}</td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
