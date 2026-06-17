import type { BackendUser } from "@/lib/api";

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

export function emailDomain(email?: string | null): string {
  return String(email || "").trim().toLowerCase().split("@").pop() || "";
}

export function isPersonalAccount(user?: BackendUser | null): boolean {
  if (!user) return false;
  if (String(user.role || "").toLowerCase() === "admin") return false;

  const domain = emailDomain(user.email);

  return !user.company_domain && PERSONAL_EMAIL_DOMAINS.has(domain);
}

export function canUseWebsiteFeatures(user?: BackendUser | null): boolean {
  if (!user) return false;
  if (String(user.role || "").toLowerCase() === "admin") return true;

  return !isPersonalAccount(user);
}
