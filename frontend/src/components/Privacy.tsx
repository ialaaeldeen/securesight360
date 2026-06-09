import { ShieldCheck, Lock, FileText, Mail, Scale, Eye, Database, Globe } from "lucide-react";

export function Privacy() {
  return (
    <div className="space-y-6">
      <section className="relative overflow-hidden rounded-2xl border border-border">
        <div className="absolute inset-0 bg-gradient-to-br from-[#0b1530] via-[#0a1226] to-[#04101c]" />
        <div className="absolute -top-24 -right-24 h-64 w-64 rounded-full bg-cyan/25 blur-3xl" />
        <div className="relative p-7 md:p-10">
          <div className="inline-flex items-center gap-2 text-xs uppercase tracking-wider text-cyan border border-cyan/30 bg-cyan/10 px-2.5 py-1 rounded-full">
            <Scale className="h-3.5 w-3.5" /> Privacy Agreements & Policies
          </div>
          <h1 className="mt-4 text-3xl md:text-4xl font-semibold tracking-tight">
            Your data. <span className="bg-gradient-to-r from-cyan to-accent-blue bg-clip-text text-transparent">Your control.</span>
          </h1>
          <p className="mt-3 text-muted-foreground max-w-2xl">
            SecureSight360 only performs authorized, read-only assessments. This page summarizes how we collect, use,
            and protect information you provide while using the platform.
          </p>
          <div className="mt-4 text-xs text-muted-foreground">Last updated: June 9, 2026</div>
        </div>
      </section>

      <div className="grid gap-4 md:grid-cols-2">
        <Card icon={ShieldCheck} title="Authorization-only scanning">
          We only scan domains you have explicitly verified ownership of. Unauthorized scanning is prohibited and
          actively blocked by the platform.
        </Card>
        <Card icon={Database} title="Data we collect">
          Account: name, work email, company, verified company domain. Scan data: target URL, timestamps, technical
          findings, and generated reports. No payment data is processed by this MVP.
        </Card>
        <Card icon={Eye} title="How we use it">
          To run authorized assessments, generate reports, improve risk scoring, and contact you about your account or
          security findings. We never sell your data.
        </Card>
        <Card icon={Lock} title="Security & retention">
          Data is encrypted in transit and at rest. Reports are retained for the lifetime of your account and can be
          deleted on request. MFA is required for sign-in.
        </Card>
        <Card icon={Globe} title="Third parties">
          We use minimal infrastructure providers strictly for hosting, email delivery, and analytics. No scan content
          is shared with third parties without your consent.
        </Card>
        <Card icon={FileText} title="Your rights">
          You may request access, correction, export, or deletion of your data at any time. Reach us at
          privacy@securesight360.app.
        </Card>
      </div>

      <section className="glass rounded-2xl p-6 md:p-7 space-y-4">
        <div className="flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-xl bg-gradient-to-br from-cyan/20 to-accent-blue/10 border border-border">
            <FileText className="h-5 w-5 text-cyan" />
          </div>
          <h2 className="text-lg font-semibold">Acceptable use & scan authorization</h2>
        </div>
        <ol className="list-decimal pl-5 space-y-2 text-sm text-muted-foreground">
          <li>You confirm legal ownership of, or written authorization for, every domain you scan.</li>
          <li>Scans must be safe and read-only. No exploitation, denial of service, or data exfiltration attempts.</li>
          <li>Findings are confidential and may only be shared with parties authorized to receive them.</li>
          <li>You will not use SecureSight360 to violate any applicable law or third-party rights.</li>
          <li>Violations may result in immediate suspension and forwarding of relevant logs to authorities.</li>
        </ol>
      </section>

      <section className="glass rounded-2xl p-6 md:p-7 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div className="flex items-center gap-3">
          <Mail className="h-5 w-5 text-cyan" />
          <div>
            <div className="font-medium">Questions about privacy?</div>
            <div className="text-sm text-muted-foreground">Our team replies within 2 business days.</div>
          </div>
        </div>
        <a
          href="mailto:privacy@securesight360.app"
          className="inline-flex items-center gap-2 rounded-xl px-5 py-3 text-sm font-medium text-[#021016] bg-gradient-to-r from-cyan to-accent-blue glow-cyan hover:brightness-110 transition"
        >
          Contact privacy team
        </a>
      </section>
    </div>
  );
}

function Card({ icon: Icon, title, children }: { icon: any; title: string; children: React.ReactNode }) {
  return (
    <div className="glass rounded-2xl p-5">
      <div className="flex items-center gap-3 mb-2">
        <div className="grid h-9 w-9 place-items-center rounded-lg bg-secondary border border-border">
          <Icon className="h-4 w-4 text-cyan" />
        </div>
        <div className="font-medium">{title}</div>
      </div>
      <p className="text-sm text-muted-foreground leading-relaxed">{children}</p>
    </div>
  );
}

