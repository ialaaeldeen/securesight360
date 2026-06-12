import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Users as UsersIcon } from "lucide-react";

import { apiFetch } from "@/lib/api";

interface AdminUserRow {
  id: number;
  email: string;
  role: string;
  full_name?: string | null;
  is_active?: boolean;
  created_at?: string;
  [k: string]: any;
}

export const Route = createFileRoute("/admin/users")({
  component: AdminUsersPage,
});

function AdminUsersPage() {
  const [users, setUsers] = useState<AdminUserRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const data = await apiFetch<AdminUserRow[] | { items: AdminUserRow[] }>(
          "/api/v1/admin/users"
        );

        const list = Array.isArray(data) ? data : data?.items ?? [];
        setUsers(list);
      } catch (e: any) {
        setError(e?.message || "Failed to load users");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  return (
    <div className="space-y-6">
      <header className="flex items-center gap-3">
        <UsersIcon className="h-6 w-6 text-cyan" />
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Users</h1>
          <p className="text-sm text-muted-foreground">
            All registered SecureSight360 accounts.
          </p>
        </div>
      </header>

      {error && (
        <div className="rounded-xl border border-warning/30 bg-warning/10 text-warning text-sm px-4 py-3">
          {error}
        </div>
      )}

      <div className="glass rounded-2xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-secondary/50 text-xs uppercase tracking-wider text-muted-foreground">
            <tr>
              <th className="text-left px-4 py-3">ID</th>
              <th className="text-left px-4 py-3">Email</th>
              <th className="text-left px-4 py-3">Name</th>
              <th className="text-left px-4 py-3">Role</th>
              <th className="text-left px-4 py-3">Active</th>
              <th className="text-left px-4 py-3">Created</th>
            </tr>
          </thead>

          <tbody>
            {loading && (
              <tr>
                <td
                  colSpan={6}
                  className="px-4 py-6 text-center text-muted-foreground"
                >
                  Loading users…
                </td>
              </tr>
            )}

            {!loading && users.length === 0 && (
              <tr>
                <td
                  colSpan={6}
                  className="px-4 py-6 text-center text-muted-foreground"
                >
                  No users found.
                </td>
              </tr>
            )}

            {users.map((u) => (
              <tr key={u.id} className="border-t border-border/60">
                <td className="px-4 py-2.5">{u.id}</td>
                <td className="px-4 py-2.5">{u.email}</td>
                <td className="px-4 py-2.5">{u.full_name || "—"}</td>

                <td className="px-4 py-2.5">
                  <span
                    className={`inline-flex rounded-md border px-2 py-0.5 text-xs ${
                      u.role === "admin"
                        ? "border-cyan/40 bg-cyan/10 text-cyan"
                        : "border-border bg-secondary/40 text-muted-foreground"
                    }`}
                  >
                    {u.role}
                  </span>
                </td>

                <td className="px-4 py-2.5">
                  {u.is_active === false ? "No" : "Yes"}
                </td>

                <td className="px-4 py-2.5 text-muted-foreground">
                  {u.created_at
                    ? new Date(u.created_at).toLocaleString()
                    : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}