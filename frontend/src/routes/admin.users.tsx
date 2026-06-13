import { useEffect, useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import {
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Search,
  Shield,
  ShieldCheck,
  UserCog,
  UserX,
} from "lucide-react";

import { apiFetch } from "@/lib/api";

type AdminUser = {
  id: number;
  email: string;
  full_name?: string | null;
  role: "user" | "admin" | string;
  is_active: boolean;
  created_at?: string | null;
  updated_at?: string | null;
  last_login_at?: string | null;
};

type CurrentUser = {
  id: number;
  email: string;
  role: string;
};

function formatDate(value?: string | null): string {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}

function roleBadgeClass(role: string): string {
  return role.toLowerCase() === "admin"
    ? "border-cyan/30 bg-cyan/10 text-cyan"
    : "border-border bg-secondary/70 text-muted-foreground";
}

function statusBadgeClass(isActive: boolean): string {
  return isActive
    ? "border-green-800/60 bg-green-950/50 text-green-300"
    : "border-red-800/60 bg-red-950/50 text-red-300";
}

export const Route = createFileRoute("/admin/users")({
  component: AdminUsersPage,
});

export default function AdminUsersPage() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [currentUser, setCurrentUser] = useState<CurrentUser | null>(null);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [savingUserId, setSavingUserId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function loadUsers() {
    setLoading(true);
    setError(null);

    try {
      const [me, userList] = await Promise.all([
        apiFetch("/api/v1/auth/me"),
        apiFetch("/api/v1/admin/users"),
      ]);

      setCurrentUser(me as CurrentUser);
      setUsers(Array.isArray(userList) ? (userList as AdminUser[]) : []);
    } catch (err: any) {
      setError(err?.message || "Could not load admin users.");
      setUsers([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadUsers();
  }, []);

  const filteredUsers = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();

    if (!normalizedQuery) {
      return users;
    }

    return users.filter((user) => {
      return (
        String(user.email || "").toLowerCase().includes(normalizedQuery) ||
        String(user.full_name || "").toLowerCase().includes(normalizedQuery) ||
        String(user.role || "").toLowerCase().includes(normalizedQuery)
      );
    });
  }, [query, users]);

  const stats = useMemo(() => {
    return {
      total: users.length,
      active: users.filter((user) => user.is_active).length,
      inactive: users.filter((user) => !user.is_active).length,
      admins: users.filter((user) => String(user.role).toLowerCase() === "admin").length,
    };
  }, [users]);

  async function updateRole(user: AdminUser, role: "user" | "admin") {
    if (user.role === role) return;

    const confirmed = confirm(
      `Change ${user.email} role from ${user.role} to ${role}?`
    );

    if (!confirmed) return;

    setSavingUserId(user.id);
    setError(null);
    setNotice(null);

    try {
      const response = (await apiFetch(`/api/v1/admin/users/${user.id}/role`, {
        method: "PATCH",
        body: JSON.stringify({ role }),
      })) as { user?: AdminUser; message?: string };

      if (response.user) {
        setUsers((previous) =>
          previous.map((item) => (item.id === user.id ? response.user! : item))
        );
      } else {
        await loadUsers();
      }

      setNotice(response.message || "User role updated successfully.");
    } catch (err: any) {
      setError(err?.message || "Could not update user role.");
    } finally {
      setSavingUserId(null);
    }
  }

  async function updateStatus(user: AdminUser) {
    const nextStatus = !user.is_active;
    const action = nextStatus ? "activate" : "deactivate";

    const confirmed = confirm(`Are you sure you want to ${action} ${user.email}?`);

    if (!confirmed) return;

    setSavingUserId(user.id);
    setError(null);
    setNotice(null);

    try {
      const response = (await apiFetch(`/api/v1/admin/users/${user.id}/status`, {
        method: "PATCH",
        body: JSON.stringify({ is_active: nextStatus }),
      })) as { user?: AdminUser; message?: string };

      if (response.user) {
        setUsers((previous) =>
          previous.map((item) => (item.id === user.id ? response.user! : item))
        );
      } else {
        await loadUsers();
      }

      setNotice(response.message || "User status updated successfully.");
    } catch (err: any) {
      setError(err?.message || "Could not update user status.");
    } finally {
      setSavingUserId(null);
    }
  }


  async function deleteUser(user: AdminUser) {
    const isSelf = currentUser?.id === user.id;

    if (isSelf) {
      setError("You cannot delete your own admin account.");
      return;
    }

    const confirmed = confirm(
      `Delete ${user.email}? This will deactivate and anonymize the account while preserving historical scan records for audit integrity.`
    );

    if (!confirmed) return;

    setSavingUserId(user.id);
    setError(null);
    setNotice(null);

    try {
      const response = (await apiFetch(`/api/v1/admin/users/${user.id}`, {
        method: "DELETE",
      })) as {
        message?: string;
        deleted_user_id?: number;
        retained_scan_records?: number;
      };

      setUsers((previous) => previous.filter((item) => item.id !== user.id));

      setNotice(
        response.message ||
          "User account deleted safely. Historical scan records were retained."
      );
    } catch (err: any) {
      setError(err?.message || "Could not delete user account.");
    } finally {
      setSavingUserId(null);
    }
  }

  return (
    <div className="space-y-6">
      <div className="glass rounded-2xl p-6 md:p-8 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-r from-cyan/5 via-transparent to-accent-blue/10 pointer-events-none" />

        <div className="relative flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-4">
            <div className="grid h-12 w-12 place-items-center rounded-xl border border-border bg-gradient-to-br from-cyan/20 to-accent-blue/10">
              <UserCog className="h-6 w-6 text-cyan" />
            </div>

            <div>
              <h1 className="text-2xl font-semibold tracking-tight">
                User Management
              </h1>
              <p className="text-sm text-muted-foreground">
                Manage registered users, roles, and account activation status.
              </p>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row gap-2">
            <div className="flex items-center gap-2 rounded-xl border border-border bg-surface/60 px-3 py-2 focus-within:border-cyan/60">
              <Search className="h-4 w-4 text-muted-foreground" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search users..."
                className="w-56 bg-transparent text-sm outline-none placeholder:text-muted-foreground/60"
              />
            </div>

            <button
              type="button"
              onClick={() => loadUsers()}
              disabled={loading}
              className="inline-flex items-center justify-center gap-2 rounded-xl border border-border bg-secondary/60 px-4 py-2 text-sm transition hover:border-cyan/40 hover:text-cyan disabled:cursor-not-allowed disabled:opacity-50"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-4">
        <div className="glass rounded-2xl p-5">
          <div className="text-sm text-muted-foreground">Total Users</div>
          <div className="mt-2 text-2xl font-bold">{stats.total}</div>
        </div>

        <div className="glass rounded-2xl p-5">
          <div className="text-sm text-muted-foreground">Active</div>
          <div className="mt-2 text-2xl font-bold text-green-300">{stats.active}</div>
        </div>

        <div className="glass rounded-2xl p-5">
          <div className="text-sm text-muted-foreground">Inactive</div>
          <div className="mt-2 text-2xl font-bold text-red-300">{stats.inactive}</div>
        </div>

        <div className="glass rounded-2xl p-5">
          <div className="text-sm text-muted-foreground">Admins</div>
          <div className="mt-2 text-2xl font-bold text-cyan">{stats.admins}</div>
        </div>
      </div>

      {notice && (
        <div className="flex items-start gap-3 rounded-2xl border border-green-800/50 bg-green-950/40 p-4 text-green-300">
          <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0" />
          <div className="text-sm">{notice}</div>
        </div>
      )}

      {error && (
        <div className="flex items-start gap-3 rounded-2xl border border-red-800/50 bg-red-950/40 p-4 text-red-300">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
          <div className="text-sm">{error}</div>
        </div>
      )}

      <div className="glass rounded-2xl overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center gap-3 p-10 text-muted-foreground">
            <RefreshCw className="h-5 w-5 animate-spin text-cyan" />
            Loading users...
          </div>
        ) : filteredUsers.length === 0 ? (
          <div className="p-10 text-center text-muted-foreground">
            No users found.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1080px] text-sm">
              <thead className="border-b border-border bg-secondary/40 text-xs uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-5 py-4 text-left">User</th>
                  <th className="px-5 py-4 text-left">Role</th>
                  <th className="px-5 py-4 text-left">Status</th>
                  <th className="px-5 py-4 text-left">Created</th>
                  <th className="px-5 py-4 text-left">Last Login</th>
                  <th className="px-5 py-4 text-right">Actions</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-border">
                {filteredUsers.map((user) => {
                  const isSelf = currentUser?.id === user.id;
                  const saving = savingUserId === user.id;

                  return (
                    <tr key={user.id} className="hover:bg-secondary/20">
                      <td className="px-5 py-4">
                        <div className="flex items-center gap-3">
                          <div className="grid h-10 w-10 place-items-center rounded-xl border border-border bg-secondary/70">
                            {String(user.role).toLowerCase() === "admin" ? (
                              <ShieldCheck className="h-5 w-5 text-cyan" />
                            ) : (
                              <Shield className="h-5 w-5 text-muted-foreground" />
                            )}
                          </div>

                          <div>
                            <div className="font-medium">
                              {user.full_name || "Unnamed user"}
                              {isSelf && (
                                <span className="ml-2 rounded-full border border-cyan/30 bg-cyan/10 px-2 py-0.5 text-[10px] uppercase tracking-wider text-cyan">
                                  You
                                </span>
                              )}
                            </div>
                            <div className="text-xs text-muted-foreground">
                              {user.email}
                            </div>
                          </div>
                        </div>
                      </td>

                      <td className="px-5 py-4">
                        <div className="flex items-center gap-2">
                          <span className={`rounded-full border px-2.5 py-1 text-xs font-medium ${roleBadgeClass(user.role)}`}>
                            {user.role}
                          </span>

                          <select
                            value={String(user.role).toLowerCase()}
                            disabled={saving}
                            onChange={(event) =>
                              updateRole(user, event.target.value as "user" | "admin")
                            }
                            className="rounded-lg border border-border bg-surface px-2 py-1 text-xs outline-none hover:border-cyan/40 disabled:opacity-50"
                          >
                            <option value="user">user</option>
                            <option value="admin">admin</option>
                          </select>
                        </div>
                      </td>

                      <td className="px-5 py-4">
                        <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${statusBadgeClass(user.is_active)}`}>
                          {user.is_active ? (
                            <CheckCircle2 className="h-3.5 w-3.5" />
                          ) : (
                            <UserX className="h-3.5 w-3.5" />
                          )}
                          {user.is_active ? "Active" : "Inactive"}
                        </span>
                      </td>

                      <td className="px-5 py-4 text-muted-foreground">
                        {formatDate(user.created_at)}
                      </td>

                      <td className="px-5 py-4 text-muted-foreground">
                        {formatDate(user.last_login_at)}
                      </td>

                      <td className="px-5 py-4 text-right">
                        <button
                          type="button"
                          disabled={saving}
                          onClick={() => updateStatus(user)}
                          className={`inline-flex items-center justify-center gap-2 rounded-xl border px-3 py-2 text-xs transition disabled:cursor-not-allowed disabled:opacity-50 ${
                            user.is_active
                              ? "border-red-800/50 bg-red-950/30 text-red-300 hover:bg-red-950/50"
                              : "border-green-800/50 bg-green-950/30 text-green-300 hover:bg-green-950/50"
                          }`}
                        >
                          {saving ? (
                            <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                          ) : user.is_active ? (
                            <UserX className="h-3.5 w-3.5" />
                          ) : (
                            <CheckCircle2 className="h-3.5 w-3.5" />
                          )}

                          {user.is_active ? "Deactivate" : "Activate"}
                        </button>
                          <button
                            type="button"
                            onClick={() => deleteUser(user)}
                            disabled={saving || isSelf}
                            className="ml-2 inline-flex items-center justify-center gap-1 rounded-lg border border-red-800/50 bg-red-950/30 px-3 py-1.5 text-xs text-red-300 transition hover:bg-red-950/50 disabled:cursor-not-allowed disabled:opacity-40"
                            title={
                              isSelf
                                ? "You cannot delete your own account"
                                : "Delete user safely"
                            }
                          >
                            <UserX className="h-3.5 w-3.5" />
                            Delete
                          </button>

                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
