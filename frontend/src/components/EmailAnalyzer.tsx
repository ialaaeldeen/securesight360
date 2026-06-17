import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  FileText,
  Inbox,
  Link2,
  Loader2,
  Mail,
  Paperclip,
  ShieldCheck,
  Sparkles,
  Trash2,
  Upload,
} from "lucide-react";

import {
  analyzeSuspiciousEmail,
  fetchEmailAnalysisHistory,
  type EmailAttachmentInput,
  type EmailThreatCompactResponse,
} from "@/lib/api";

function splitLinks(value: string): string[] {
  return value
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function verdictClass(verdict: string): string {
  const value = verdict.toLowerCase();

  if (value.includes("safe")) {
    return "border-green-800/60 bg-green-950/50 text-green-300";
  }

  if (value.includes("suspicious")) {
    return "border-yellow-800/60 bg-yellow-950/50 text-yellow-300";
  }

  if (
    value.includes("malicious") ||
    value.includes("credential") ||
    value.includes("fraud")
  ) {
    return "border-red-800/60 bg-red-950/50 text-red-300";
  }

  return "border-orange-800/60 bg-orange-950/50 text-orange-300";
}

function confidenceTone(value: string): string {
  if (value.toLowerCase() === "high") return "text-danger";
  if (value.toLowerCase() === "medium") return "text-warning";
  return "text-success";
}

function mlSignalClass(
  signal?: EmailThreatCompactResponse["ml_email_signal"] | null
): string {
  if (!signal || !signal.enabled) {
    return "border-border bg-secondary/60 text-muted-foreground";
  }

  if (signal.is_phishing_signal) {
    if (String(signal.signal_strength).toLowerCase() === "high") {
      return "border-red-800/60 bg-red-950/40 text-red-300";
    }

    return "border-yellow-800/60 bg-yellow-950/40 text-yellow-300";
  }

  return "border-green-800/60 bg-green-950/40 text-green-300";
}

function formatMlPercent(value?: number | null): string {
  if (typeof value !== "number" || Number.isNaN(value)) return "—";
  return `${Math.round(value * 10000) / 100}%`;
}

function typeFromName(name: string): string {
  const lower = name.toLowerCase();

  if (lower.endsWith(".eml")) return "message/rfc822";
  if (lower.endsWith(".html") || lower.endsWith(".htm")) return "text/html";
  if (lower.endsWith(".txt")) return "text/plain";
  if (lower.endsWith(".pdf")) return "application/pdf";
  if (lower.endsWith(".docx")) {
    return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
  }
  if (lower.endsWith(".xlsx")) {
    return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
  }

  return "application/octet-stream";
}

function canReadTextPreview(file: File): boolean {
  const lower = file.name.toLowerCase();

  return (
    file.type.startsWith("text/") ||
    lower.endsWith(".txt") ||
    lower.endsWith(".eml") ||
    lower.endsWith(".html") ||
    lower.endsWith(".htm") ||
    lower.endsWith(".csv") ||
    lower.endsWith(".json")
  );
}

async function sha256File(file: File): Promise<string | null> {
  try {
    if (!crypto?.subtle) return null;

    const buffer = await file.arrayBuffer();
    const hash = await crypto.subtle.digest("SHA-256", buffer);

    return Array.from(new Uint8Array(hash))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
  } catch {
    return null;
  }
}

async function attachmentFromFile(file: File): Promise<EmailAttachmentInput> {
  let textPreview: string | null = null;

  if (canReadTextPreview(file)) {
    try {
      textPreview = (await file.text()).slice(0, 12000);
    } catch {
      textPreview = null;
    }
  }

  return {
    file_name: file.name,
    content_type: file.type || typeFromName(file.name),
    size_bytes: file.size,
    sha256: await sha256File(file),
    text_preview: textPreview,
  };
}

export function EmailAnalyzer() {
  const [showForm, setShowForm] = useState(false);
  const [subject, setSubject] = useState("");
  const [sender, setSender] = useState("");
  const [replyTo, setReplyTo] = useState("");
  const [body, setBody] = useState("");
  const [linksText, setLinksText] = useState("");
  const [headers, setHeaders] = useState("");
  const [attachments, setAttachments] = useState<EmailAttachmentInput[]>([]);
  const [result, setResult] = useState<EmailThreatCompactResponse | null>(null);
  const [recentCount, setRecentCount] = useState<number | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [readingFiles, setReadingFiles] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const links = useMemo(() => splitLinks(linksText), [linksText]);

  const loadHistoryCount = async () => {
    try {
      const history = await fetchEmailAnalysisHistory(1, 0);
      setRecentCount(history.total);
    } catch {
      setRecentCount(null);
    }
  };

  useEffect(() => {
    void loadHistoryCount();
  }, []);

  const handleFiles = async (fileList: FileList | null) => {
    const files = Array.from(fileList || []);
    if (files.length === 0) return;

    setReadingFiles(true);
    setError(null);

    try {
      const prepared = await Promise.all(files.map((file) => attachmentFromFile(file)));
      setAttachments((current) => [...current, ...prepared].slice(0, 20));
    } catch (err: any) {
      setError(err?.message || "Could not inspect selected attachment metadata.");
    } finally {
      setReadingFiles(false);
    }
  };

  const removeAttachment = (index: number) => {
    setAttachments((current) => current.filter((_, i) => i !== index));
  };

  const loadSample = () => {
    setSubject("Urgent: verify your account now");
    setSender("Microsoft Support <support@microsoft-secure-login.example>");
    setReplyTo("security-team@random-mail.example");
    setBody(
      "Your account will be suspended within 24 hours. Login to continue and confirm your password."
    );
    setLinksText("https://bit.ly/fake-login");
    setHeaders(
      "Authentication-Results: mx.example; spf=fail smtp.mailfrom=random-mail.example; dmarc=fail"
    );
    setAttachments([
      {
        file_name: "invoice_payment.html",
        content_type: "text/html",
        size_bytes: 20480,
        text_preview:
          "<html>Verify your account password at https://example.com/login</html>",
      },
    ]);
    setResult(null);
    setError(null);
    setShowForm(true);
  };

  const clearForm = () => {
    setSubject("");
    setSender("");
    setReplyTo("");
    setBody("");
    setLinksText("");
    setHeaders("");
    setAttachments([]);
    setResult(null);
    setError(null);
    setShowForm(false);
  };

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    setResult(null);

    try {
      const response = await analyzeSuspiciousEmail({
        subject,
        sender,
        reply_to: replyTo || null,
        body,
        links,
        headers: headers || null,
        attachments,
      });

      setResult(response);
      setShowForm(true);
      void loadHistoryCount();
    } catch (err: any) {
      setError(err?.message || "Email analysis failed.");
    } finally {
      setSubmitting(false);
    }
  };

  const canAnalyze =
    subject.trim() ||
    sender.trim() ||
    body.trim() ||
    links.length > 0 ||
    headers.trim() ||
    attachments.length > 0;

  return (
    <div className="space-y-6">
      <section className="glass rounded-2xl p-6 md:p-8">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex items-start gap-4 min-w-0">
            <div className="grid h-12 w-12 shrink-0 place-items-center rounded-xl border border-border bg-gradient-to-br from-cyan/20 to-accent-blue/10">
              <Mail className="h-6 w-6 text-cyan" />
            </div>

            <div className="min-w-0">
              <div className="inline-flex items-center gap-2 rounded-full border border-cyan/25 bg-cyan/10 px-3 py-1 text-xs font-semibold text-cyan">
                <ShieldCheck className="h-3.5 w-3.5" />
                Privacy-safe email review
              </div>

              <h1 className="mt-3 text-2xl font-semibold tracking-tight">
                AI Email Threat Analyzer
              </h1>

              <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
                Analyze suspicious emails for phishing, impersonation, credential theft,
                unsafe links, and attachment warning signs. Links are not opened and
                attachments are not executed.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <SmallPill icon={Inbox}>Saved analyses: {recentCount ?? "—"}</SmallPill>

            <button
              type="button"
              onClick={loadSample}
              className="inline-flex items-center gap-2 rounded-xl border border-cyan/30 bg-cyan/10 px-4 py-2 text-sm text-cyan transition hover:bg-cyan/15"
            >
              <Sparkles className="h-4 w-4" />
              Load sample
            </button>

            <button
              type="button"
              onClick={clearForm}
              className="inline-flex items-center gap-2 rounded-xl border border-border bg-secondary/60 px-4 py-2 text-sm transition hover:border-danger/40 hover:text-danger"
            >
              <Trash2 className="h-4 w-4" />
              Clear
            </button>
          </div>
        </div>
      </section>

      {!showForm && !result && (
        <OpenAnalyzerCard onOpen={() => setShowForm(true)} />
      )}

      {!showForm && result && (
        <div className="space-y-4">
          <ResultPanel result={result} submittedLinks={links} />
          <div className="flex justify-end">
            <button
              type="button"
              onClick={() => setShowForm(true)}
              className="inline-flex items-center gap-2 rounded-xl border border-cyan/30 bg-cyan/10 px-4 py-2 text-sm text-cyan transition hover:bg-cyan/15"
            >
              <Mail className="h-4 w-4" />
              Open email details form
            </button>
          </div>
        </div>
      )}

      {showForm && (
        <section className="grid gap-6 xl:grid-cols-[1fr_0.9fr]">
          <div className="glass rounded-2xl p-5 md:p-6">
            <div className="mb-5">
              <h2 className="text-lg font-semibold">Email details</h2>
              <p className="mt-1 text-sm leading-6 text-muted-foreground">
                All fields are optional. Add only the information you have.
              </p>
            </div>

            <div className="space-y-4">
              <Field label="Subject">
                <input
                  value={subject}
                  onChange={(event) => setSubject(event.target.value)}
                  placeholder="Example: Urgent invoice payment request"
                  className="w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground/60"
                />
              </Field>

              <div className="grid gap-4 md:grid-cols-2">
                <Field label="Sender">
                  <input
                    value={sender}
                    onChange={(event) => setSender(event.target.value)}
                    placeholder="Display Name <sender@example.com>"
                    className="w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground/60"
                  />
                </Field>

                <Field label="Reply-To">
                  <input
                    value={replyTo}
                    onChange={(event) => setReplyTo(event.target.value)}
                    placeholder="reply-to@example.com"
                    className="w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground/60"
                  />
                </Field>
              </div>

              <Field label="Email body">
                <textarea
                  value={body}
                  onChange={(event) => setBody(event.target.value)}
                  rows={7}
                  placeholder="Paste the suspicious email body if available..."
                  className="w-full resize-y bg-transparent text-sm outline-none placeholder:text-muted-foreground/60"
                />
              </Field>

              <div className="grid gap-4 md:grid-cols-2">
                <Field label="Suspicious links">
                  <textarea
                    value={linksText}
                    onChange={(event) => setLinksText(event.target.value)}
                    rows={4}
                    placeholder="Paste links, separated by new lines or commas..."
                    className="w-full resize-y bg-transparent text-sm outline-none placeholder:text-muted-foreground/60"
                  />
                </Field>

                <Field label="Email headers">
                  <textarea
                    value={headers}
                    onChange={(event) => setHeaders(event.target.value)}
                    rows={4}
                    placeholder="Paste Authentication-Results or headers if available..."
                    className="w-full resize-y bg-transparent text-sm outline-none placeholder:text-muted-foreground/60"
                  />
                </Field>
              </div>

              <AttachmentBox
                attachments={attachments}
                readingFiles={readingFiles}
                onUpload={handleFiles}
                onRemove={removeAttachment}
              />

              {error && (
                <div className="flex items-start gap-3 rounded-xl border border-danger/30 bg-danger/10 p-4 text-danger">
                  <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
                  <div>
                    <div className="font-medium">Analysis failed</div>
                    <div className="text-sm opacity-90">{error}</div>
                  </div>
                </div>
              )}

              <button
                type="button"
                onClick={submit}
                disabled={!canAnalyze || submitting}
                className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan to-accent-blue px-5 py-3 text-sm font-medium text-[#021016] glow-cyan transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {submitting ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Mail className="h-4 w-4" />
                )}
                {submitting ? "Analyzing email…" : "Analyze suspicious email"}
              </button>
            </div>
          </div>

          <div className="space-y-4">
            {result ? (
              <ResultPanel result={result} submittedLinks={links} />
            ) : (
              <EmptyResult linksCount={links.length} attachmentsCount={attachments.length} />
            )}
          </div>
        </section>
      )}
    </div>
  );
}

function OpenAnalyzerCard({ onOpen }: { onOpen: () => void }) {
  return (
    <section className="glass rounded-2xl p-8 text-center">
      <div className="mx-auto grid h-16 w-16 place-items-center rounded-2xl border border-cyan/25 bg-cyan/10">
        <Mail className="h-8 w-8 text-cyan" />
      </div>

      <h2 className="mt-5 text-xl font-semibold">Start a privacy-safe email analysis</h2>

      <p className="mx-auto mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
        Open the form only when you are ready to paste suspicious email details.
        SecureSight360 will analyze the submitted content without opening links or
        executing attachments.
      </p>

      <button
        type="button"
        onClick={onOpen}
        className="mt-6 inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan to-accent-blue px-5 py-3 text-sm font-semibold text-[#021016] glow-cyan transition hover:brightness-110"
      >
        <FileText className="h-4 w-4" />
        Open email details form
      </button>
    </section>
  );
}

function AttachmentBox({
  attachments,
  readingFiles,
  onUpload,
  onRemove,
}: {
  attachments: EmailAttachmentInput[];
  readingFiles: boolean;
  onUpload: (fileList: FileList | null) => void;
  onRemove: (index: number) => void;
}) {
  return (
    <div className="rounded-2xl border border-border bg-surface/50 p-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="font-medium">Attachments</div>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">
            Optional. Files are inspected for metadata and safe text preview only.
          </p>
        </div>

        <label className="inline-flex cursor-pointer items-center justify-center gap-2 rounded-xl border border-cyan/30 bg-cyan/10 px-4 py-2 text-sm text-cyan transition hover:bg-cyan/15">
          {readingFiles ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Upload className="h-4 w-4" />
          )}
          Upload
          <input
            type="file"
            multiple
            className="hidden"
            onChange={(event) => {
              onUpload(event.target.files);
              event.currentTarget.value = "";
            }}
          />
        </label>
      </div>

      {attachments.length > 0 && (
        <div className="mt-4 space-y-2">
          {attachments.map((attachment, index) => (
            <div
              key={`${attachment.file_name}-${index}`}
              className="flex items-start justify-between gap-3 rounded-xl border border-border/70 bg-background/30 px-3 py-2 text-sm"
            >
              <div className="min-w-0">
                <div className="flex items-center gap-2 font-medium">
                  <Paperclip className="h-4 w-4 text-cyan" />
                  <span className="truncate">{attachment.file_name}</span>
                </div>
                <div className="mt-1 text-xs text-muted-foreground">
                  {attachment.content_type || "Unknown type"} ·{" "}
                  {attachment.size_bytes ?? 0} bytes
                </div>
              </div>

              <button
                type="button"
                onClick={() => onRemove(index)}
                className="rounded-lg border border-border bg-secondary/60 p-2 transition hover:border-danger/40 hover:text-danger"
                aria-label="Remove attachment"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const URL_SHORTENER_DOMAINS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "cutt.ly",
  "rebrand.ly",
  "shorturl.at",
  "lnkd.in",
]);

function domainFromLink(value: string): string {
  try {
    const raw = value.startsWith("http") ? value : `https://${value}`;
    return new URL(raw).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return "";
  }
}

function buildFrontendLinkAlerts(
  result: EmailThreatCompactResponse,
  submittedLinks: string[]
): string[] {
  const alerts: string[] = [];
  const backendAlerts = Array.isArray(result.link_alerts) ? result.link_alerts : [];

  for (const alert of backendAlerts) {
    if (alert && !alerts.includes(alert)) alerts.push(alert);
  }

  const links = submittedLinks.map((link) => link.trim()).filter(Boolean);
  const domains = links.map(domainFromLink).filter(Boolean);
  const uniqueDomains = Array.from(new Set(domains));

  if (links.length > 0) {
    alerts.push(`${links.length} link(s) were submitted for review.`);
  }

  const shorteners = uniqueDomains.filter((domain) =>
    URL_SHORTENER_DOMAINS.has(domain)
  );

  if (shorteners.length > 0) {
    alerts.push(
      `Shortened link detected (${shorteners.join(", ")}). Short links can hide the real destination.`
    );
  }

  const lookalikeDomains = uniqueDomains.filter((domain) => {
    return (
      domain.includes("secure-") ||
      domain.includes("login-") ||
      domain.includes("verify-") ||
      domain.includes("-secure") ||
      domain.includes("-login") ||
      domain.includes("-verify") ||
      domain.split("-").length >= 3
    );
  });

  if (lookalikeDomains.length > 0) {
    alerts.push(
      `Suspicious-looking link domain detected: ${lookalikeDomains.join(", ")}.`
    );
  }

  if (uniqueDomains.length > 0) {
    alerts.push(`Detected link domain(s): ${uniqueDomains.join(", ")}.`);
  }

  if (links.length > 0) {
    alerts.push("Links were inspected as text only and were not opened automatically.");
  }

  return Array.from(new Set(alerts)).slice(0, 6);
}

function cleanIndicator(item: string): string {
  const lower = item.toLowerCase();

  if (lower.includes("credential harvesting")) {
    return "The email asks you to verify, reset, or enter account credentials. This is commonly used to steal passwords.";
  }

  if (lower.includes("display-name spoofing")) {
    return "The sender name appears to imitate a trusted brand or person, but the actual sending domain does not match.";
  }

  if (lower.includes("domain impersonation")) {
    return "The sender domain looks similar to a trusted brand, but it is not the official domain.";
  }

  if (lower.includes("reply-to mismatch")) {
    return "Replies would go to a different domain than the sender address, which may redirect your response to an attacker.";
  }

  if (lower.includes("dmarc fail")) {
    return "The email failed DMARC authentication, meaning the sending domain could not be properly verified.";
  }

  if (lower.includes("spf fail") || lower.includes("softfail")) {
    return "The email failed SPF authentication, meaning the sending server may not be authorized to send for that domain.";
  }

  if (lower.includes("dkim fail")) {
    return "The email failed DKIM authentication, meaning the message signature could not be verified.";
  }

  if (lower.includes("url shortener")) {
    return "The email uses a shortened link, which can hide the real destination.";
  }

  if (lower.includes("suspicious links")) {
    return "The email contains links with suspicious characteristics. Do not click them until verified.";
  }

  if (lower.includes("urgency") || lower.includes("pressure")) {
    return "The message uses urgency or pressure to make you act quickly without verifying the request.";
  }

  if (lower.includes("attachment")) {
    return "The attachment has suspicious characteristics. Do not open it unless the sender is verified.";
  }

  return item
    .replaceAll("sender_domain=", "sender domain: ")
    .replaceAll("reply_to_domain=", "reply-to domain: ")
    .replaceAll("display_name=", "display name: ");
}

function cleanAction(item: string): string {
  return item
    .replace(
      "Verify the sender through a trusted channel such as a known phone number or official portal.",
      "Verify the sender using a known phone number, official website, or trusted contact method."
    )
    .replace(
      "Report the email to your IT or security team if this is a work-related message.",
      "If this is a work email, report it to your IT or security team."
    );
}

function customerFriendlyVerdict(result: EmailThreatCompactResponse): string {
  const verdict = result.verdict.toLowerCase();

  if (verdict.includes("credential theft")) {
    return "This email is likely trying to steal login credentials or account access. Do not click links or enter any passwords.";
  }

  if (verdict.includes("payment") || verdict.includes("invoice")) {
    return "This email may be attempting payment or invoice fraud. Verify bank details and payment requests through a trusted channel.";
  }

  if (verdict.includes("business email compromise")) {
    return "This email may be an impersonation or executive-style request designed to pressure someone into taking action.";
  }

  if (verdict.includes("impersonation")) {
    return "This email appears to impersonate a trusted brand, person, or organization.";
  }

  if (verdict.includes("link-based")) {
    return "This email contains suspicious links. Do not open them until the sender and destination are verified.";
  }

  if (verdict.includes("attachment")) {
    return "This email contains an attachment with suspicious characteristics. Do not open or enable anything inside it.";
  }

  if (verdict.includes("safe")) {
    return "No obvious threat was detected from the submitted information. Still verify unexpected requests before taking action.";
  }

  return "This email contains suspicious indicators and should be handled carefully.";
}

function severityExplanation(result: EmailThreatCompactResponse): string {
  if (result.confidence === "High" && result.evidence_strength === "Strong") {
    return "Multiple strong indicators were found, so this result should be treated seriously.";
  }

  if (result.confidence === "Medium" || result.evidence_strength === "Moderate") {
    return "Some suspicious indicators were found. More details such as full headers or sender information can improve accuracy.";
  }

  return "The submitted information is limited. Add sender details, links, headers, or attachment information for a more accurate result.";
}

function MLSignalCard({
  signal,
}: {
  signal?: EmailThreatCompactResponse["ml_email_signal"] | null;
}) {
  if (!signal) return null;

  const phishingLikelihood = formatMlPercent(signal.phishing_score);
  const safeLikelihood = formatMlPercent(signal.safe_score);
  return (
    <section className={`rounded-2xl border p-4 ${mlSignalClass(signal)}`}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <div className="text-sm font-semibold">AI threat signal</div>
          <p className="mt-1 text-xs opacity-80">
            Additional AI-based email classification used with SecureSight360 evidence.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <span className="rounded-full border border-current/20 px-3 py-1 text-xs font-semibold">
            {signal.mapped_verdict}
          </span>
          <span className="rounded-full border border-current/20 px-3 py-1 text-xs font-semibold">
            Strength: {signal.signal_strength}
          </span>
        </div>
      </div>

      <p className="mt-3 text-sm leading-6 opacity-90">{signal.explanation}</p>

      <div className="mt-3 grid gap-2 sm:grid-cols-2">
        <div className="rounded-xl border border-current/15 bg-black/10 p-3">
          <div className="text-xs opacity-70">Phishing likelihood</div>
          <div className="mt-1 text-lg font-semibold">{phishingLikelihood}</div>
        </div>

        <div className="rounded-xl border border-current/15 bg-black/10 p-3">
          <div className="text-xs opacity-70">Safe likelihood</div>
          <div className="mt-1 text-lg font-semibold">{safeLikelihood}</div>
        </div>
      </div>

      {signal.error && (
        <p className="mt-3 text-xs opacity-80">ML note: {signal.error}</p>
      )}
    </section>
  );
}

function ResultPanel({
  result,
  submittedLinks,
}: {
  result: EmailThreatCompactResponse;
  submittedLinks: string[];
}) {
  const friendlyIndicators = result.key_indicators.map(cleanIndicator);
  const friendlyActions = result.recommended_actions.map(cleanAction);
  const friendlyAttachmentAlerts = result.attachment_alerts.map(cleanIndicator);
  const friendlyLinkAlerts = buildFrontendLinkAlerts(result, submittedLinks).map(
    cleanIndicator
  );

  return (
    <div className="glass rounded-2xl p-5 md:p-6 space-y-5">
      <MLSignalCard signal={result.ml_email_signal} />

      <div className="flex flex-col gap-4">
        <div className="flex flex-wrap items-center gap-2">
          <div
            className={`inline-flex max-w-full items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold ${verdictClass(
              result.verdict
            )}`}
          >
            <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
            <span className="break-words">{result.verdict}</span>
          </div>

          <span
            className={`inline-flex rounded-full border border-border bg-surface/70 px-3 py-1.5 text-xs font-semibold ${confidenceTone(
              result.confidence
            )}`}
          >
            Confidence: {result.confidence}
          </span>

          <span className="inline-flex rounded-full border border-border bg-surface/70 px-3 py-1.5 text-xs font-semibold text-accent-blue">
            Evidence: {result.evidence_strength}
          </span>
        </div>

        <div>
          <h2 className="text-xl font-semibold">Email threat evaluation</h2>

          <div className="mt-4 rounded-2xl border border-cyan/20 bg-cyan/10 p-4">
            <div className="text-sm font-semibold text-cyan">What this means</div>
            <p className="mt-2 text-sm leading-7 text-cyan/90">
              {customerFriendlyVerdict(result)}
            </p>
          </div>

          <p className="mt-4 text-sm leading-7 text-muted-foreground">
            {severityExplanation(result)}
          </p>
        </div>
      </div>

      <FriendlySection
        title="Main warning signs"
        description="These are the clearest reasons why SecureSight360 flagged this email."
        items={friendlyIndicators}
        icon={AlertTriangle}
      />

      <FriendlySection
        title="What you should do"
        description="Recommended safe actions before replying, clicking, downloading, or paying."
        items={friendlyActions}
        icon={CheckCircle2}
      />

      <FriendlySection
        title="Link Analysis"
        description="Links are checked as text indicators only. SecureSight360 does not open suspicious links automatically."
        items={friendlyLinkAlerts}
        icon={Link2}
        emptyText={
          submittedLinks.length > 0
            ? "No suspicious link indicators were found in the submitted links."
            : "No links were submitted for analysis."
        }
      />

      <FriendlySection
        title="Attachment warnings"
        description="Only metadata and safe text previews are inspected. Attachments are not executed."
        items={friendlyAttachmentAlerts}
        icon={Paperclip}
        emptyText="No attachment warnings were reported."
      />

      <FriendlySection
        title="Safety notes"
        description="How SecureSight360 handled this analysis safely."
        items={result.safety_notes}
        icon={ShieldCheck}
      />
    </div>
  );
}

function FriendlySection({
  title,
  description,
  items,
  icon: Icon,
  emptyText = "No items reported.",
}: {
  title: string;
  description: string;
  items: string[];
  icon: any;
  emptyText?: string;
}) {
  return (
    <div className="rounded-2xl border border-border bg-surface/50 p-5">
      <div className="flex items-start gap-3">
        <div className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-cyan/10 text-cyan">
          <Icon className="h-4 w-4" />
        </div>

        <div className="min-w-0 flex-1">
          <div className="font-semibold">{title}</div>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">
            {description}
          </p>

          {items.length === 0 ? (
            <p className="mt-4 rounded-xl border border-border/70 bg-background/30 px-3 py-2 text-sm text-muted-foreground">
              {emptyText}
            </p>
          ) : (
            <div className="mt-4 space-y-2">
              {items.map((item, index) => (
                <div
                  key={`${title}-${index}`}
                  className="rounded-xl border border-border/70 bg-background/30 px-3 py-2 text-sm leading-7 text-muted-foreground"
                >
                  {item}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function EmptyResult({
  linksCount,
  attachmentsCount,
}: {
  linksCount: number;
  attachmentsCount: number;
}) {
  return (
    <div className="glass rounded-2xl p-8">
      <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl border border-border bg-secondary">
        <FileText className="h-6 w-6 text-cyan" />
      </div>

      <div className="mt-4 text-center font-medium">Analysis result will appear here</div>

      <p className="mt-2 text-center text-sm leading-6 text-muted-foreground">
        The result will show verdict, confidence, evidence strength, warning signs,
        link analysis, attachment warnings, safety notes, and recommended actions.
      </p>

      <div className="mt-6 grid gap-3 sm:grid-cols-2">
        <MiniStat icon={Link2} label="Links ready" value={String(linksCount)} />
        <MiniStat
          icon={Paperclip}
          label="Attachments ready"
          value={String(attachmentsCount)}
        />
      </div>
    </div>
  );
}

function MiniStat({
  icon: Icon,
  label,
  value,
}: {
  icon: any;
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-2xl border border-border bg-surface/50 p-4">
      <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
        <Icon className="h-4 w-4 text-cyan" />
        {label}
      </div>
      <div className="mt-2 text-2xl font-semibold text-soft">{value}</div>
    </div>
  );
}

function SmallPill({
  icon: Icon,
  children,
}: {
  icon: any;
  children: ReactNode;
}) {
  return (
    <span className="inline-flex items-center gap-2 rounded-xl border border-border bg-secondary/60 px-3 py-2 text-xs text-muted-foreground">
      <Icon className="h-4 w-4 text-cyan" />
      {children}
    </span>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <div className="mb-2 text-xs uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className="rounded-xl border border-border bg-surface/60 px-3 py-2.5 transition focus-within:border-cyan/60 focus-within:ring-2 focus-within:ring-cyan/20">
        {children}
      </div>
    </label>
  );
}

