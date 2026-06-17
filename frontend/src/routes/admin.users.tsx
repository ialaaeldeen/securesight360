import { useEffect, useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import {
  AlertTriangle,
  Building2,
  CheckCircle2,
  Crown,
  Mail,
  RefreshCw,
  Search,
  Shield,
  ShieldCheck,
  UserCog,
  Users,
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
  company_domain?: string | null;
};

type CurrentUser = {
  id: number;
  email: string;
  role: string;
};

type AccessType = "admin" | "personal" | "business" | "deleted";

const PERSONAL_EMAIL_DOMAINS = new Set([
  "gmail.com",
  "googlemail.com",
  "yahoo.com",
  "yahoo.co.uk",
  "outlook.com",
  "hotmail.com",
  "live.com",
  "msn.com",
  "icloud.com",
  "me.com",
  "mac.com",
  "aol.com",
  "proton.me",
  "protonmail.com",
  "mail.com",
  "zoho.com",
  "yandex.com",
  "gmx.com",
]);

export const Route = createFileRoute("/admin/users")({
  component: AdminUsersPage,
});

function formatDate(value?: string | null): string {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function domainFromEmail(email: string): string {
  const normalized = String(email || "").trim().toLowerCase();

  if (!normalized.includes("@")) return "";

  return normalized.split("@").pop() || "";
}

function getAccessType(user: AdminUser): AccessType {
  const email = String(user.email || "").toLowerCase();

  if (email.startsWith("deleted-user-") || email.includes("@deleted.securesight360.local")) {
    return "deleted";
  }

  if (String(user.role || "").toLowerCase() === "admin") {
    return "admin";
  }

  const domain = domainFromEmail(email);

  if (PERSONAL_EMAIL_DOMAINS.has(domain)) {
    return "personal";
  }

  return "business";
}

function accessTypeLabel(type: AccessType): string {
  switch (type) {
    case "admin":
      return "Admin";
    case "personal":
      return "Personal Email";
    case "business":
      return "Business Domain";
    case "deleted":
      return "Deleted Account";
    default:
      return "Unknown";
  }
}

function accessTypeDescription(user: AdminUser): string {
  const type = getAccessType(user);

  if (type === "admin") return "Full admin console access";
  if (type === "personal") return "Email Analyzer only";
  if (type === "deleted") return "Anonymized account";

  const domain = user.company_domain || domainFromEmail(user.email);
  return domain ? `Website + email access · ${domain}` : "Website + email access";
}

function accessBadgeClass(type: AccessType): string {
  switch (type) {
    case "admin":
      return "border-cyan/30 bg-cyan/10 text-cyan";
    case "personal":
      return "border-blue-800/60 bg-blue-950/40 text-blue-300";
    case "business":
      return "border-green-800/60 bg-green-950/40 text-green-300";
    case "deleted":
      return "border-red-800/60 bg-red-950/40 text-red-300";
    default:
      return "border-border bg-secondary/70 text-muted-foreground";
  }
}

function statusBadgeClass(isActive: boolean): string {
  return isActive
    ? "border-green-800/60 bg-green-950/50 text-green-300"
    : "border-red-800/60 bg-red-950/50 text-red-300";
}

function StatCard({
  label,
  value,
  helper,
  icon: Icon,
  tone,
}: {
  label: string;
  value: string;
  helper: string;
  icon: any;
  tone: string;
}) {
  return (
    <section className="glass rounded-2xl p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-xs uppercase tracking-wider text-muted-foreground">
            {label}
          </div>
          <div className={`mt-3 text-3xl font-semibold ${tone}`}>{value}</div>
          <p className="mt-2 text-xs text-muted-foreground">{helper}</p>
        </div>

        <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-border bg-secondary/60">
          <Icon className={`h-5 w-5 ${tone}`} />
        </div>
      </div>
    </section>
  );
}

function UserIdentity({ user }: { user: AdminUser }) {
  const accessType = getAccessType(user);

  return (
    <div className="flex min-w-0 items-center gap-3">
      <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-border bg-secondary">
        {accessType === "admin" ? (
          <Crown className="h-5 w-5 text-cyan" />
        ) : accessType === "personal" ? (
          <Mail className="h-5 w-5 text-blue-300" />
        ) : accessType === "deleted" ? (
          <UserX className="h-5 w-5 text-red-300" />
        ) : (
          <Building2 className="h-5 w-5 text-green-300" />
        )}
      </div>

      <div className="min-w-0">
        <div className="truncate font-semibold">
          {user.full_name || "Unnamed user"}
        </div>
        <div className="truncate text-xs text-muted-foreground">{user.email}</div>
      </div>
    </div>
  );
}

function AccessTypeBadge({ user }: { user: AdminUser }) {
  const type = getAccessType(user);

  return (
    <div>
      <span
        className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold ${accessBadgeClass(
          type
        )}`}
      >
        {accessTypeLabel(type)}
      </span>

      <div className="mt-1 text-xs text-muted-foreground">
        {accessTypeDescription(user)}
      </div>
    </div>
  );
}

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
      const [userList, me] = await Promise.all([
        apiFetch<AdminUser[]>("/api/v1/admin/users"),
        apiFetch<CurrentUser>("/api/v1/auth/me"),
      ]);

      setUsers(Array.isArray(userList) ? userList : []);
      setCurrentUser(me);
    } catch (err: any) {
      setError(err?.message || "Could not load admin users.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadUsers();
  }, []);

  const filteredUsers = useMemo(() => {
    const search = query.trim().toLowerCase();

    if (!search) return users;

    return users.filter((user) => {
      const accessLabel = accessTypeLabel(getAccessType(user)).toLowerCase();
      const domain = domainFromEmail(user.email);

      return (
        String(user.full_name || "").toLowerCase().includes(search) ||
        String(user.email || "").toLowerCase().includes(search) ||
        String(user.role || "").toLowerCase().includes(search) ||
        accessLabel.includes(search) ||
        domain.includes(search)
      );
    });
  }, [query, users]);

  const stats = useMemo(() => {
    const personal = users.filter((user) => getAccessType(user) === "personal").length;
    const business = users.filter((user) => getAccessType(user) === "business").length;
    const admins = users.filter((user) => getAccessType(user) === "admin").length;
    const active = users.filter((user) => user.is_active).length;

    return {
      total: users.length,
      personal,
      business,
      admins,
      active,
    };
  }, [users]);

  async function updateRole(user: AdminUser, nextRole: string) {
    if (nextRole === user.role) return;

    setSavingUserId(user.id);
    setError(null);
    setNotice(null);

    try {
      const response = (await apiFetch(`/api/v1/admin/users/${user.id}/role`, {
        method: "PATCH",
        body: JSON.stringify({ role: nextRole }),
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

      await loadUsers();

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
      <section className="glass rounded-2xl p-6 md:p-8">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-4">
            <div className="grid h-12 w-12 place-items-center rounded-xl border border-border bg-gradient-to-br from-cyan/20 to-accent-blue/10">
              <UserCog className="h-6 w-6 text-cyan" />
            </div>

            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-cyan/25 bg-cyan/10 px-3 py-1 text-xs font-semibold text-cyan">
                <ShieldCheck className="h-3.5 w-3.5" />
                Admin Access Control
              </div>

              <h1 className="mt-3 text-2xl font-semibold tracking-tight">
                User & Access Management
              </h1>

              <p className="text-sm text-muted-foreground">
                Manage users, roles, activation status, and account access type for personal email and business-domain accounts.
              </p>
            </div>
          </div>

          <div className="flex flex-col gap-2 sm:flex-row">
            <div className="flex items-center gap-2 rounded-xl border border-border bg-surface/60 px-3 py-2 focus-within:border-cyan/60">
              <Search className="h-4 w-4 text-muted-foreground" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search users, role, account type..."
                className="w-64 bg-transparent text-sm outline-none placeholder:text-muted-foreground/60"
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
      </section>

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total Users"
          value={String(stats.total)}
          helper={`${stats.active} active account(s)`}
          icon={Users}
          tone="text-cyan"
        />
        <StatCard
          label="Personal Accounts"
          value={String(stats.personal)}
          helper="Email Analyzer only"
          icon={Mail}
          tone="text-blue-300"
        />
        <StatCard
          label="Business Accounts"
          value={String(stats.business)}
          helper="Website + email access"
          icon={Building2}
          tone="text-green-300"
        />
        <StatCard
          label="Admins"
          value={String(stats.admins)}
          helper="Admin console access"
          icon={Crown}
          tone="text-accent-blue"
        />
      </section>

      {notice && (
        <div className="flex items-start gap-3 rounded-2xl border border-green-800/50 bg-green-950/30 p-4 text-green-300">
          <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0" />
          <div className="text-sm">{notice}</div>
        </div>
      )}

      {error && (
        <div className="flex items-start gap-3 rounded-2xl border border-red-800/50 bg-red-950/30 p-4 text-red-300">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
          <div className="text-sm">{error}</div>
        </div>
      )}

      <section className="glass overflow-hidden rounded-2xl">
        {loading ? (
          <div className="flex items-center justify-center gap-3 p-10 text-muted-foreground">
            <RefreshCw className="h-5 w-5 animate-spin text-cyan" />
            Loading users...
          </div>
        ) : filteredUsers.length === 0 ? (
          <div className="p-10 text-center text-muted-foreground">
            No users matched your search.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1120px] text-left text-sm">
              <thead className="bg-surface/70 text-xs uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-5 py-4">User</th>
                  <th className="px-5 py-4">Account Type</th>
                  <th className="px-5 py-4">Role</th>
                  <th className="px-5 py-4">Status</th>
                  <th className="px-5 py-4">Created</th>
                  <th className="px-5 py-4">Last Login</th>
                  <th className="px-5 py-4 text-right">Actions</th>
                </tr>
              </thead>

              <tbody>
                {filteredUsers.map((user) => {
                  const saving = savingUserId === user.id;
                  const isSelf = currentUser?.id === user.id;

                  return (
                    <tr
                      key={user.id}
                      className="border-t border-border/70 transition hover:bg-surface/40"
                    >
                      <td className="px-5 py-4">
                        <UserIdentity user={user} />
                      </td>

                      <td className="px-5 py-4">
                        <AccessTypeBadge user={user} />
                      </td>

                      <td className="px-5 py-4">
                        <div className="flex items-center gap-2">
                          <span
                            className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${
                              String(user.role).toLowerCase() === "admin"
                                ? "border-cyan/30 bg-cyan/10 text-cyan"
                                : "border-border bg-secondary/70 text-muted-foreground"
                            }`}
                          >
                            {user.role}
                          </span>

                          <select
                            value={user.role}
                            disabled={saving}
                            onChange={(event) => updateRole(user, event.target.value)}
                            className="rounded-xl border border-border bg-background/40 px-3 py-2 text-xs outline-none transition hover:border-cyan/40 disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            <option value="user">user</option>
                            <option value="admin">admin</option>
                          </select>
                        </div>
                      </td>

                      <td className="px-5 py-4">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold ${statusBadgeClass(
                            user.is_active
                          )}`}
                        >
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
                        <div className="flex justify-end gap-2">
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
                            className="inline-flex items-center justify-center gap-1 rounded-xl border border-red-800/50 bg-red-950/30 px-3 py-2 text-xs text-red-300 transition hover:bg-red-950/50 disabled:cursor-not-allowed disabled:opacity-40"
                            title={
                              isSelf
                                ? "You cannot delete your own account"
                                : "Delete user safely"
                            }
                          >
                            <UserX className="h-3.5 w-3.5" />
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="glass rounded-2xl p-5">
        <div className="flex items-start gap-3">
          <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-border bg-secondary">
            <Shield className="h-5 w-5 text-cyan" />
          </div>

          <div>
            <h2 className="font-semibold">Access model note</h2>
            <p className="mt-1 text-sm leading-6 text-muted-foreground">
              Personal email accounts are intended for Email Analyzer and Email History.
              Business-domain accounts can use website scanning, reports, website history,
              Email Analyzer, and Email History. Admins keep full console access.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
