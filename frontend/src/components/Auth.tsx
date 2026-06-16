import { useEffect, useState } from "react";
import {
  ShieldCheck, Lock, Mail, User, ArrowRight, KeyRound, Eye, EyeOff,
  Radar, BarChart3, Globe, CheckCircle2, Sparkles, Building2, AlertTriangle, Check, FileText, ChevronDown, Facebook, Instagram, Linkedin, Phone, MapPin, Send, Twitter, HelpCircle,
} from "lucide-react";
import cs360Logo from "@/assets/cs360-logo.png";
import { useAuth } from "@/lib/auth";

type View = "splash" | "login" | "signup";

const BASIC_EMAIL_REGEX = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

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

function getBusinessEmailError(email: string): string | null {
  const normalized = email.trim().toLowerCase();

  if (!normalized || !BASIC_EMAIL_REGEX.test(normalized)) {
    return null;
  }

  const domain = normalized.split("@").pop() || "";

  if (PERSONAL_EMAIL_DOMAINS.has(domain)) {
    return "Please use your company/work email address. Personal email providers such as Gmail, Yahoo, Outlook, and Hotmail are not allowed.";
  }

  return null;
}

function getPasswordError(password: string): string | null {
  if (!password) {
    return null;
  }

  if (password.length < 8) {
    return "Password must be at least 8 characters.";
  }

  const commonWeakPasswords = new Set([
    "password",
    "password1",
    "password12",
    "password123",
    "password1234",
    "admin",
    "admin123",
    "admin1234",
    "qwerty",
    "qwerty123",
    "welcome",
    "welcome123",
    "letmein",
    "secure123",
    "changeme",
  ]);

  if (commonWeakPasswords.has(password.toLowerCase())) {
    return "Password is too common. Please choose a stronger password.";
  }

  if (!/[a-z]/.test(password)) {
    return "Password must include at least one lowercase letter.";
  }

  if (!/[A-Z]/.test(password)) {
    return "Password must include at least one uppercase letter.";
  }
if (!/[^A-Za-z0-9]/.test(password)) {
    return "Password must include at least one special character.";
  }

  return null;
}

interface Props {
  onAuthenticated: () => void;
}

export function Auth({ onAuthenticated }: Props) {
  const [view, setView] = useState<View>("splash");

  // Whenever the auth screen mounts (fresh session / after logout), clear any
  // previously-registered company domain so the next signup binds strictly to
  // the new account's work email.
  useEffect(() => {
    try {
      ["cs360-company-domain","cs360-company-name","cs360-verified-hosts","cs360-user-name","cs360-user-email","cs360-registered-at"]
        .forEach(k => localStorage.removeItem(k));
    } catch {}
  }, []);

  // Scroll reveal: progressively reveal anything with [data-reveal]
  useEffect(() => {
    const els = document.querySelectorAll<HTMLElement>("[data-reveal]");
    if (!("IntersectionObserver" in window)) {
      els.forEach((el) => el.classList.add("is-visible"));
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const el = entry.target as HTMLElement;
            const delay = el.dataset.revealDelay;
            if (delay) el.style.transitionDelay = `${delay}ms`;
            el.classList.add("is-visible");
            io.unobserve(el);
          }
        });
      },
      { threshold: 0.12, rootMargin: "0px 0px -40px 0px" }
    );
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, [view]);




  return (
    <div className="relative min-h-screen w-full overflow-hidden">
      {/* Animated background */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -top-32 -left-32 h-[480px] w-[480px] rounded-full bg-cyan/15 blur-3xl animate-pulse" />
        <div className="absolute top-1/3 -right-32 h-[520px] w-[520px] rounded-full bg-accent-blue/15 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 h-[400px] w-[400px] rounded-full bg-cyan/10 blur-3xl" />
        <div
          className="absolute inset-0 opacity-[0.04]"
          style={{
            backgroundImage:
              "linear-gradient(rgba(255,255,255,0.6) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.6) 1px, transparent 1px)",
            backgroundSize: "44px 44px",
          }}
        />
      </div>

      <div className="relative mx-auto flex min-h-screen max-w-[1500px] flex-col px-4 lg:px-8 py-6">
        <TopBar onLogin={() => setView("login")} onSignup={() => setView("signup")} onHome={() => setView("splash")} />

        <div className="flex-1 flex items-center justify-center py-10">
          {view === "splash" && (
            <Splash onLogin={() => setView("login")} onSignup={() => setView("signup")} />
          )}
        {view === "login" && (
  <Login
    onAuthenticated={onAuthenticated}
    onSignup={() => setView("signup")}
  />
)}
{view === "signup" && (
  <Signup
    onVerified={onAuthenticated}
    onLogin={() => setView("login")}
  />
)}
        </div>

        <SiteFooter onHome={() => setView("splash")} onLogin={() => setView("login")} onSignup={() => setView("signup")} />
      </div>

      <AiAssistant onSignup={() => setView("signup")} />
    </div>
  );
}

function AiAssistant({ onSignup }: { onSignup: () => void }) {
  const [revealed, setRevealed] = useState(false);
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState("");
  const [msgs, setMsgs] = useState<{ role: "bot" | "user"; text: string }[]>([
    { role: "bot", text: "Hi! I'm Shield, the SecureSight360 AI assistant. Ask me about our services, scans, pricing, or how to get started." },
  ]);

  const reply = (q: string): string => {
    const t = q.toLowerCase();
    if (/price|cost|plan|pricing/.test(t)) return "We tailor pricing to your domain count and monitoring needs. Click 'Get Started' to request a quote.";
    if (/scan|website|security|vulnerab/.test(t)) return "Our authorized scans cover SSL/TLS, security headers, DNS, email auth (SPF/DKIM/DMARC) and produce an A–F risk grade.";
    if (/soc|monitor|24|threat/.test(t)) return "Our SOC monitors your assets 24/7 with real-time threat detection, triage, and response guidance.";
    if (/data|ai|analytic/.test(t)) return "We build data pipelines, dashboards, and ML models that turn raw security telemetry into actionable insights.";
    if (/compliance|nist|iso|owasp/.test(t)) return "Reports are mapped to OWASP, NIST CSF and ISO 27001 so auditors and stakeholders can follow along.";
    if (/sign ?up|register|account|start|get started/.test(t)) return "Tap 'Get Started' at the top to create your secure account — verification takes under 2 minutes.";
    if (/contact|email|support|help/.test(t)) return "You can reach us via the Contact Us button — our team replies within one business day.";
    if (/hello|hi|hey/.test(t)) return "Hello! How can I help secure your business today?";
    return "Great question — I'll connect you with our team. Click 'Get Started' and we'll follow up shortly.";
  };

  const send = () => {
    const q = input.trim();
    if (!q) return;
    setMsgs((m) => [...m, { role: "user", text: q }, { role: "bot", text: reply(q) }]);
    setInput("");
  };

  return (
    <div className="fixed bottom-5 right-5 z-50">
      {open && (
        <div className="mb-3 w-[340px] max-w-[calc(100vw-2.5rem)] rounded-2xl border border-border bg-surface/95 backdrop-blur-xl shadow-2xl overflow-hidden flex flex-col" style={{ height: 460 }}>
          <div className="flex items-center justify-between gap-2 px-4 py-3 border-b border-border bg-gradient-to-r from-cyan/10 to-accent-blue/10">
            <div className="flex items-center gap-2">
              <div className="grid h-8 w-8 place-items-center rounded-full bg-gradient-to-br from-cyan to-accent-blue">
                <Sparkles className="h-4 w-4 text-[#021016]" />
              </div>
              <div className="leading-tight">
                <div className="text-sm font-semibold">Shield AI</div>
                <div className="text-[10px] text-muted-foreground">Online · SecureSight360</div>
              </div>
            </div>
            <button onClick={() => setOpen(false)} className="text-muted-foreground hover:text-foreground text-lg leading-none px-2">×</button>
          </div>
          <div className="flex-1 overflow-y-auto px-3 py-3 space-y-2">
            {msgs.map((m, i) => (
              <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
                <div className={`max-w-[85%] rounded-2xl px-3 py-2 text-sm ${m.role === "user" ? "bg-gradient-to-r from-cyan to-accent-blue text-[#021016]" : "bg-secondary/70 border border-border text-foreground/90"}`}>
                  {m.text}
                </div>
              </div>
            ))}
          </div>
          <div className="border-t border-border p-2 flex items-center gap-2">
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") send(); }}
              placeholder="Ask Shield AI…"
              className="flex-1 bg-secondary/60 border border-border rounded-xl px-3 py-2 text-sm outline-none focus:border-cyan/60"
            />
            <button onClick={send} className="rounded-xl bg-gradient-to-r from-cyan to-accent-blue px-3 py-2 text-[#021016]">
              <ArrowRight className="h-4 w-4" />
            </button>
          </div>
          <button onClick={onSignup} className="text-[11px] text-cyan hover:underline pb-2 pr-3 text-right">
            Talk to a human →
          </button>
        </div>
      )}
      <div className="flex items-center justify-end gap-3">
        {/* Sparkle launcher — only appears after Inquiry is tapped */}
        <button
          onClick={() => setOpen((o) => !o)}
          aria-label="Open AI assistant"
          className={`grid h-14 w-14 place-items-center rounded-full bg-gradient-to-br from-cyan to-accent-blue glow-cyan shadow-2xl hover:brightness-110 transition-all duration-300 ${
            revealed ? "opacity-100 scale-100 translate-x-0 pointer-events-auto" : "opacity-0 scale-50 translate-x-6 pointer-events-none"
          }`}
        >
          <Sparkles className="h-6 w-6 text-[#021016]" />
        </button>

        {/* Inquiry trigger — discreet, always visible */}
        <button
          onClick={() => { setRevealed((r) => !r); if (revealed && open) setOpen(false); }}
          aria-label="Inquiry"
          title="Inquiry"
          className="group inline-flex items-center gap-2 rounded-full border border-border bg-surface/80 backdrop-blur-xl px-4 py-2.5 text-sm font-medium text-foreground/90 hover:text-cyan hover:border-cyan/40 shadow-lg transition"
        >
          <HelpCircle className="h-5 w-5 text-cyan" />
          <span className="hidden sm:inline">Inquiry</span>
        </button>
      </div>
    </div>
  );
}

function SocialDot({ children }: { children: React.ReactNode }) {
  return (
    <a href="#" className="grid h-9 w-9 place-items-center rounded-full border border-border bg-secondary/40 text-foreground/80 hover:text-cyan hover:border-cyan/40 transition">
      {children}
    </a>
  );
}

function SiteFooter({ onHome, onLogin, onSignup }: { onHome: () => void; onLogin: () => void; onSignup: () => void }) {
  const scrollTo = (id: string) => {
    onHome();
    requestAnimationFrame(() => {
      setTimeout(() => {
        const el = document.getElementById(id);
        if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
        else window.scrollTo({ top: 0, behavior: "smooth" });
      }, 80);
    });
  };
  return (
    <footer className="mt-12 border-t border-border/60 pt-10 pb-6">
      <div className="grid gap-10 md:grid-cols-3 items-start">
        {/* Brand column */}
        <div className="space-y-5 max-w-md">
          <div className="flex items-center gap-3">
            <img src={cs360Logo} alt="SecureSight360 logo" width={48} height={48} className="h-12 w-12 object-contain" />
            <div className="leading-tight">
              <div className="text-xl font-semibold tracking-tight">
                SecureSight<span className="text-cyan">360</span>
              </div>
              <div className="text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
                Smart · Reliable · Future-Ready
              </div>
            </div>
          </div>
          <p className="text-sm leading-relaxed text-muted-foreground">
            SecureSight360 secures your business with smart, reliable, and future-ready cyber security solutions — built for teams that take risk seriously.
          </p>
          <div className="flex items-center gap-3">
            <SocialDot><Facebook className="h-4 w-4" /></SocialDot>
            <SocialDot><Instagram className="h-4 w-4" /></SocialDot>
            <SocialDot><Linkedin className="h-4 w-4" /></SocialDot>
          </div>
        </div>

        {/* Explore column — centered */}
        <div className="md:justify-self-center md:text-center">
          <h3 className="text-lg font-semibold mb-5 tracking-tight">Explore</h3>
          <ul className="space-y-3 text-sm">
            <li><button onClick={() => scrollTo("home")} className="text-foreground/80 hover:text-cyan transition">Home</button></li>
            <li><button onClick={() => scrollTo("about")} className="text-foreground/80 hover:text-cyan transition">About</button></li>
            <li><button onClick={() => scrollTo("services")} className="text-foreground/80 hover:text-cyan transition">Services</button></li>
            <li><button onClick={onLogin} className="text-foreground/80 hover:text-cyan transition">Sign in</button></li>
            <li><button onClick={() => scrollTo("contact")} className="text-foreground/80 hover:text-cyan transition">Contact us</button></li>
          </ul>
        </div>

        {/* Spacer / contact column */}
        <div className="md:justify-self-end md:text-right space-y-3 text-sm">
          <h3 className="text-lg font-semibold tracking-tight mb-2">Get in touch</h3>
          <p className="text-muted-foreground">Ready to assess your security posture?</p>
          <button onClick={onSignup} className="inline-flex items-center gap-1.5 rounded-full bg-gradient-to-r from-cyan to-accent-blue px-5 py-2.5 text-sm font-semibold text-[#021016] glow-cyan hover:brightness-110 transition">
            Get Started <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      </div>

      <div className="mt-10 pt-6 border-t border-border/40 text-center text-xs text-muted-foreground">
        © 2026 <span className="text-soft font-medium">SecureSight360</span>. All rights reserved.
      </div>
    </footer>
  );
}

function TopBar({ onLogin, onSignup, onHome }: { onLogin: () => void; onSignup: () => void; onHome: () => void }) {
  const navItem = "relative text-sm font-medium text-foreground/80 hover:text-cyan transition";
  const divider = <span className="text-border/60 select-none">|</span>;
  return (
    <div className="rounded-2xl border border-border bg-surface/70 backdrop-blur-xl px-4 md:px-6 py-3 flex items-center justify-between gap-4">
      <button onClick={onHome} className="flex items-center gap-3 shrink-0">
        <img src={cs360Logo} alt="SecureSight360 logo" width={40} height={40} className="h-10 w-10 object-contain" />
        <div className="text-left leading-tight">
          <div className="text-lg font-semibold tracking-tight">
            SecureSight<span className="text-cyan">360</span>
          </div>
          <div className="text-[9px] uppercase tracking-[0.18em] text-muted-foreground">
            Smart · Reliable · Future-Ready Security
          </div>
        </div>
      </button>

      <nav className="hidden md:flex items-center gap-5">
        <button onClick={onHome} className={`${navItem} text-cyan after:absolute after:left-0 after:right-0 after:-bottom-1.5 after:h-[2px] after:bg-cyan after:rounded-full`}>Home</button>
        {divider}
        <button onClick={onHome} className={navItem}>About Us</button>
        {divider}
        <button onClick={onHome} className={`${navItem} inline-flex items-center gap-1`}>
          Services <ChevronDown className="h-3.5 w-3.5" />
        </button>
        {divider}
        <button onClick={() => { onHome(); requestAnimationFrame(() => setTimeout(() => document.getElementById("contact")?.scrollIntoView({ behavior: "smooth", block: "start" }), 80)); }} className={navItem}>Contact Us</button>
      </nav>

      <div className="flex items-center gap-2 shrink-0">
        <button onClick={onLogin} className="hidden sm:inline-flex rounded-xl border border-border bg-secondary/50 px-4 py-2 text-sm hover:bg-secondary transition">Sign in</button>
        <button onClick={onSignup} className="inline-flex items-center gap-1.5 rounded-full bg-gradient-to-r from-cyan to-accent-blue px-5 py-2.5 text-sm font-semibold text-[#021016] glow-cyan hover:brightness-110 transition">
          Get Started <ArrowRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

function Splash({ onLogin, onSignup }: { onLogin: () => void; onSignup: () => void }) {
  const services = [
    { i: Building2, t: "Project Management", d: "Strategic oversight for IT and cybersecurity projects from planning to execution. We ensure on-time, on-budget delivery while maintaining strict quality and security standards." },
    { i: Radar, t: "Cybersecurity Operations (SOC Monitoring)", d: "24/7 threat detection and response from our Security Operations Center. We monitor, analyze, and neutralize cyber threats in real time — ensuring your business stays protected around the clock." },
    { i: BarChart3, t: "Data, AI & Analytics", d: "We help organizations harness the power of data and artificial intelligence to drive smarter decisions and automation. Our solutions span data engineering, advanced analytics, and machine learning—turning raw data into actionable insights." },
    { i: Globe, t: "Website Security Scanning", d: "Availability, SSL/TLS, headers, DNS & email checks across your domains." },
    { i: ShieldCheck, t: "Compliance Alignment", d: "Reports mapped to OWASP, NIST and ISO 27001 guidance for auditors." },
    { i: Lock, t: "Authorized-Only Scans", d: "Safe, read-only checks with verified domain ownership." },
  ];

  const faqs = [
    { q: "Why is cybersecurity important for my business?", a: "Cyberattacks can disrupt operations, leak customer data, and damage trust. SecureSight360 reduces that risk with continuous monitoring, scanning, and rapid response." },
    { q: "How often do you scan my website?", a: "On-demand scans run whenever you want, and continuous monitoring re-checks your verified domains on a weekly schedule with change detection." },
    { q: "Where is my scan and report data stored?", a: "All scan results and reports stay inside your private console. We never sell or share your data with third parties." },
    { q: "Can you respond quickly to an active incident?", a: "Yes. Our SOC team is on-call 24/7 to triage incidents, contain threats, and guide your team through recovery." },
    { q: "Do you protect against ransomware and phishing?", a: "We combine email/DNS hardening checks, endpoint guidance, and live monitoring to reduce exposure to ransomware and phishing campaigns." },
    { q: "Is my data encrypted?", a: "Yes — data is encrypted in transit (TLS) and at rest, and access is gated by 2FA on every account." },
  ];
  const [openFaq, setOpenFaq] = useState<number | null>(0);

  return (
    <div className="w-full space-y-24 scroll-mt-24">
      {/* HERO — Cyber Security & IT Solutions */}
      <section id="home" className="scroll-mt-24 space-y-10 max-w-4xl">
        <div className="space-y-6">
          <div className="inline-flex items-center gap-2 text-xs uppercase tracking-wider text-cyan border border-cyan/30 bg-cyan/10 px-3 py-1.5 rounded-full">
            <Sparkles className="h-3.5 w-3.5" /> Get Started
          </div>
          <h1 className="text-4xl md:text-6xl font-semibold tracking-tight leading-[1.05]">
            Cyber Security & IT <br />
            Solutions for Your <br />
            <span className="bg-gradient-to-r from-cyan to-accent-blue bg-clip-text text-transparent">Company</span>
          </h1>
          <div id="about" className="scroll-mt-24 max-w-3xl">
            <p className="text-lg leading-relaxed text-muted-foreground">
              <span className="text-foreground font-semibold">SecureSight360</span> delivers next-generation cybersecurity and IT solutions that empower businesses to stay secure, agile, and future-ready. From endpoint protection, threat detection, and incident response to cloud security, IT support, and project management — we ensure your entire technology ecosystem runs efficiently and remains resilient against evolving digital threats.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3 pt-2">
            <button onClick={() => document.getElementById("contact")?.scrollIntoView({ behavior: "smooth", block: "start" })} className="inline-flex items-center gap-2 rounded-full px-6 py-3 text-sm font-medium text-[#021016] bg-gradient-to-r from-cyan to-accent-blue glow-cyan hover:brightness-110 transition">
              Contact Us <ArrowRight className="h-4 w-4" />
            </button>
            <button onClick={onLogin} className="inline-flex items-center gap-2 rounded-xl border border-border bg-secondary/50 px-6 py-3 text-sm hover:bg-secondary transition">
              <Lock className="h-4 w-4" /> Sign in to console
            </button>
          </div>
        </div>
      </section>

      {/* SERVICES — card grid */}
      <section id="services" className="scroll-mt-24">
        <div data-reveal className="flex flex-col items-center text-center mb-12">
          <div className="inline-flex items-center gap-2 rounded-full bg-surface/80 border border-border px-5 py-1.5 text-sm">Services</div>
          <h2 className="mt-6 text-4xl md:text-5xl font-semibold tracking-tight">Our Core Services</h2>
        </div>
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {services.map((s, idx) => (
            <div key={idx} data-reveal data-reveal-delay={idx * 100} className="group rounded-2xl border border-border bg-surface/60 p-7 hover:border-cyan/40 hover:bg-surface/80 hover:-translate-y-1 transition-all duration-300">
              <div className="grid h-14 w-14 place-items-center rounded-full bg-cyan/10 border border-cyan/20 mb-6 group-hover:scale-110 group-hover:bg-cyan/20 transition-all duration-300">
                <s.i className="h-6 w-6 text-cyan" />
              </div>
              <h3 className="text-xl font-semibold leading-tight mb-3">{s.t}</h3>
              <p className="text-sm text-muted-foreground leading-relaxed">{s.d}</p>
              <button onClick={onSignup} className="mt-5 inline-flex items-center gap-1.5 text-sm font-medium text-cyan hover:gap-2.5 transition-all">
                Learn More <ArrowRight className="h-4 w-4" />
              </button>
            </div>
          ))}
        </div>
      </section>

      {/* SECURE YOUR WEBSITE */}
      <section className="rounded-3xl border border-border bg-gradient-to-br from-surface/80 to-surface/30 p-10 md:p-14 grid lg:grid-cols-2 gap-10 items-center">
        <div data-reveal="left" className="space-y-5">

          <div className="inline-flex items-center gap-2 text-xs uppercase tracking-wider text-cyan border border-cyan/30 bg-cyan/10 px-3 py-1.5 rounded-full">
            <Globe className="h-3.5 w-3.5" /> Secure Your Website
          </div>
          <h2 className="text-3xl md:text-4xl font-semibold tracking-tight leading-tight">
            We help you <span className="bg-gradient-to-r from-cyan to-accent-blue bg-clip-text text-transparent">secure your website</span> end-to-end.
          </h2>
          <p className="text-muted-foreground leading-relaxed">
            SecureSight360 empowers your organization with continuous security monitoring, in-depth vulnerability scan analysis, and expert cybersecurity consultation. We identify weaknesses across your digital infrastructure, interpret scan results into clear, actionable insights, and guide your team with tailored recommendations — so you stay protected, compliant, and ahead of emerging threats.
          </p>
          <ul className="space-y-3 pt-2">
            {[
              "Continuous weakness monitoring across your digital infrastructure.",
              "Detailed security scan analysis with actionable insights.",
              "Expert cybersecurity consultation tailored to your business needs.",
            ].map((t, i) => (
              <li key={i} className="flex items-start gap-3 text-sm">
                <CheckCircle2 className="h-5 w-5 text-cyan shrink-0 mt-0.5" /> <span className="text-foreground/90">{t}</span>
              </li>
            ))}
          </ul>
          <button onClick={() => document.getElementById("contact")?.scrollIntoView({ behavior: "smooth", block: "start" })} className="mt-4 inline-flex items-center gap-2 rounded-full px-6 py-3 text-sm font-medium text-[#021016] bg-gradient-to-r from-cyan to-accent-blue glow-cyan hover:brightness-110 transition">
            Contact us <ArrowRight className="h-4 w-4" />
          </button>
        </div>
        <div data-reveal="right" className="relative">
          {/* Ambient glow */}
          <div className="absolute -inset-6 bg-gradient-to-tr from-cyan/10 via-transparent to-accent-blue/10 blur-3xl rounded-[2rem] -z-10" />
          <div className="glass rounded-2xl p-6 md:p-7 relative overflow-hidden">
            <div className="absolute -right-20 -top-20 h-64 w-64 rounded-full bg-cyan/20 blur-3xl animate-float" />
            <div className="absolute -left-16 -bottom-16 h-48 w-48 rounded-full bg-accent-blue/15 blur-3xl" />

            {/* Headline */}
            <div className="relative mb-5">
              <div className="inline-flex items-center gap-2 text-[11px] uppercase tracking-[0.18em] text-cyan/90">
                <Sparkles className="h-3.5 w-3.5" /> Proven Impact
              </div>
              <h3 className="mt-2 text-xl md:text-2xl font-semibold leading-tight">
                Proof that <span className="shimmer-text">protection</span> pays off.
              </h3>
            </div>

            <div className="grid grid-cols-2 gap-3 md:gap-4 relative">
              <Stat label="Risk reduction" value="-72%" sub="avg. across audits" tone="text-cyan" icon={BarChart3} />
              <Stat label="Domains protected" value="1.2k+" sub="and counting" tone="text-accent-blue" icon={Globe} />
              <Stat label="Time to detect" value="<5min" sub="real-time alerts" tone="text-success" icon={Radar} />
              <Stat label="SOC coverage" value="24/7" sub="always watching" tone="text-soft" icon={ShieldCheck} />
            </div>

            <div className="mt-5 relative flex items-center gap-3 rounded-xl border border-success/25 bg-gradient-to-r from-success/15 to-success/5 px-4 py-3 group hover:border-success/40 transition">
              <div className="relative">
                <ShieldCheck className="h-5 w-5 text-success shrink-0" />
                <span className="absolute inset-0 rounded-full bg-success/40 blur-md opacity-60 group-hover:opacity-100 transition" />
              </div>
              <div className="text-xs">
                <div className="font-semibold text-success">Trusted. Authorized. Transparent.</div>
                <div className="text-muted-foreground">Read-only scans with verified domain ownership — your data stays yours.</div>
              </div>
            </div>
          </div>
        </div>

      </section>

      {/* FAQ */}
      <section id="faq" className="scroll-mt-24">
        <div data-reveal className="flex flex-col items-center text-center mb-10">
          <div className="inline-flex items-center gap-2 rounded-full bg-surface/80 border border-border px-5 py-1.5 text-sm">FAQs</div>
          <h2 className="mt-6 text-4xl md:text-5xl font-semibold tracking-tight">Frequently Asked Questions</h2>
          <p className="mt-4 text-muted-foreground">Everything you need to know about SecureSight360 services.</p>
        </div>
        <div className="max-w-3xl mx-auto space-y-3">
          {faqs.map((f, idx) => {
            const open = openFaq === idx;
            return (
              <div key={idx} data-reveal data-reveal-delay={idx * 60} className="rounded-2xl border border-border bg-surface/60 overflow-hidden hover:border-cyan/30 transition">

                <button
                  onClick={() => setOpenFaq(open ? null : idx)}
                  className="w-full flex items-center justify-between gap-4 px-5 py-4 text-left hover:bg-surface/80 transition"
                >
                  <span className="text-sm md:text-base font-medium">{f.q}</span>
                  <ChevronDown className={`h-5 w-5 text-muted-foreground transition-transform ${open ? "rotate-180 text-cyan" : ""}`} />
                </button>
                {open && (
                  <div className="px-5 pb-5 text-sm text-muted-foreground leading-relaxed">{f.a}</div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* CONTACT */}
      <ContactSection />
    </div>
  );
}

function ContactSection() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [company, setCompany] = useState("");
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");
  const [sent, setSent] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    const n = name.trim(), em = email.trim(), msg = message.trim();
    if (n.length < 2 || n.length > 100) return setErr("Please enter your full name.");
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em) || em.length > 255) return setErr("Please enter a valid email.");
    if (msg.length < 5 || msg.length > 1000) return setErr("Message must be 5–1000 characters.");
    const to = "allouah30@outlook.com";
    const sub = encodeURIComponent(subject.trim().slice(0, 150) || "SecureSight360 — Contact request");
    const body = encodeURIComponent(
      `Name: ${n}\nEmail: ${em}\nCompany: ${company.trim().slice(0,100)}\n\n${msg}`
    );
    window.location.href = `mailto:${to}?subject=${sub}&body=${body}`;
    setSent(true);
  };

  return (
    <section id="contact" className="scroll-mt-24">
      <div className="flex flex-col items-center text-center mb-10">
        <div className="inline-flex items-center gap-2 rounded-full bg-surface/80 border border-border px-5 py-1.5 text-sm">Contact</div>
        <h2 className="mt-6 text-4xl md:text-5xl font-semibold tracking-tight">Get in touch</h2>
        <p className="mt-4 text-muted-foreground max-w-xl">Tell us about your security goals and we'll get back to you within one business day.</p>
      </div>

      <div className="grid gap-8 lg:grid-cols-5">
        {/* Info card */}
        <div className="lg:col-span-2 space-y-4">
          <div className="rounded-2xl border border-border bg-surface/60 p-6 space-y-5">
            <a href="mailto:allouah30@outlook.com" className="flex items-start gap-3 group">
              <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-cyan/10 border border-cyan/20">
                <Mail className="h-4 w-4 text-cyan" />
              </div>
              <div>
                <div className="text-xs uppercase tracking-wider text-muted-foreground">Email</div>
                <div className="text-sm font-medium group-hover:text-cyan transition">allouah30@outlook.com</div>
              </div>
            </a>
            <a href="tel:+966550166203" className="flex items-start gap-3 group">
              <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-cyan/10 border border-cyan/20">
                <Phone className="h-4 w-4 text-cyan" />
              </div>
              <div>
                <div className="text-xs uppercase tracking-wider text-muted-foreground">Phone</div>
                <div className="text-sm font-medium group-hover:text-cyan transition">+966 55 016 6203</div>
              </div>
            </a>
            <div className="flex items-start gap-3">
              <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-cyan/10 border border-cyan/20">
                <MapPin className="h-4 w-4 text-cyan" />
              </div>
              <div>
                <div className="text-xs uppercase tracking-wider text-muted-foreground">Office</div>
                <div className="text-sm font-medium">Riyadh, Saudi Arabia</div>
              </div>
            </div>
          </div>

          <div className="rounded-2xl border border-border bg-surface/60 p-6">
            <div className="text-xs uppercase tracking-wider text-muted-foreground mb-3">Follow us</div>
            <div className="flex items-center gap-3">
              {[Linkedin, Twitter, Facebook, Instagram].map((Icon, i) => (
                <a key={i} href="#" className="grid h-10 w-10 place-items-center rounded-full border border-border bg-secondary/40 text-foreground/80 hover:text-cyan hover:border-cyan/40 transition">
                  <Icon className="h-4 w-4" />
                </a>
              ))}
            </div>
          </div>
        </div>

        {/* Form */}
        <form onSubmit={submit} className="lg:col-span-3 rounded-2xl border border-border bg-surface/60 p-6 md:p-8 space-y-4">
          <div className="grid sm:grid-cols-2 gap-4">
            <Field icon={User} value={name} onChange={setName} placeholder="Your name" autoComplete="name" />
            <Field icon={Mail} type="email" value={email} onChange={setEmail} placeholder="you@company.com" autoComplete="email" />
          </div>
          <div className="grid sm:grid-cols-2 gap-4">
            <Field icon={Building2} value={company} onChange={setCompany} placeholder="Company (optional)" autoComplete="organization" />
            <Field icon={FileText} value={subject} onChange={setSubject} placeholder="Subject" />
          </div>
          <div className="flex items-start gap-2 rounded-xl border border-border bg-surface/60 px-3 py-2.5 focus-within:border-cyan/60 focus-within:ring-2 focus-within:ring-cyan/20">
            <Send className="h-4 w-4 text-muted-foreground mt-1.5" />
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              maxLength={1000}
              rows={5}
              placeholder="Tell us about your security goals…"
              className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground/60 resize-none"
            />
          </div>
          {err && (
            <div className="flex items-center gap-2 text-xs text-destructive">
              <AlertTriangle className="h-4 w-4" /> {err}
            </div>
          )}
          {sent && !err && (
            <div className="flex items-center gap-2 text-xs text-success">
              <Check className="h-4 w-4" /> Your email client opened — we'll reply within 1 business day.
            </div>
          )}
          <button type="submit" className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-full px-6 py-3 text-sm font-medium text-[#021016] bg-gradient-to-r from-cyan to-accent-blue glow-cyan hover:brightness-110 transition">
            Send message <ArrowRight className="h-4 w-4" />
          </button>
        </form>
      </div>
    </section>
  );
}

function Stat({ label, value, tone, sub, icon: Icon }: { label: string; value: string; tone: string; sub?: string; icon?: any }) {
  return (
    <div className="group relative rounded-xl border border-border bg-surface/60 p-4 overflow-hidden hover:border-cyan/40 hover:-translate-y-0.5 transition-all duration-300">
      <div className="absolute inset-0 bg-gradient-to-br from-cyan/0 via-transparent to-accent-blue/0 group-hover:from-cyan/5 group-hover:to-accent-blue/5 transition-all duration-500" />
      <div className="relative flex items-start justify-between gap-2">
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
        {Icon && <Icon className={`h-3.5 w-3.5 ${tone} opacity-70 group-hover:opacity-100 transition`} />}
      </div>
      <div className={`relative text-2xl md:text-3xl font-bold mt-1.5 ${tone} group-hover:scale-105 origin-left transition-transform duration-300`}>{value}</div>
      {sub && <div className="relative mt-0.5 text-[10px] text-muted-foreground/80">{sub}</div>}
    </div>
  );
}


function AuthShell({ icon: Icon, title, subtitle, children }: { icon: any; title: string; subtitle: string; children: React.ReactNode }) {
  return (
    <div className="w-full max-w-md">
      <div className="glass rounded-3xl p-7 md:p-8">
        <div className="flex items-center gap-3 mb-6">
          <div className="grid h-11 w-11 place-items-center rounded-xl bg-gradient-to-br from-cyan to-accent-blue glow-cyan">
            <Icon className="h-5 w-5 text-[#021016]" />
          </div>
          <div>
            <h2 className="text-xl font-semibold">{title}</h2>
            <p className="text-sm text-muted-foreground">{subtitle}</p>
          </div>
        </div>
        {children}
      </div>
    </div>
  );
}

function Field({ icon: Icon, type = "text", value, onChange, placeholder, autoComplete }: any) {
  return (
    <div className="flex items-center gap-2 rounded-xl border border-border bg-surface/60 px-3 py-2.5 focus-within:border-cyan/60 focus-within:ring-2 focus-within:ring-cyan/20">
      <Icon className="h-4 w-4 text-muted-foreground" />
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        autoComplete={autoComplete}
        className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground/60"
      />
    </div>
  );
}


function Login({
  onAuthenticated,
  onSignup,
}: {
  onAuthenticated: () => void;
  onSignup: () => void;
}) {
  const { login } = useAuth() as any;

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validEmail = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim());
  const valid = validEmail && password.length > 0;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!valid || submitting) return;

    setSubmitting(true);
    setError(null);

    try {
      await login(email.trim(), password);
      onAuthenticated();
    } catch (err: any) {
      setError(err?.message || "Login failed. Please check your email and password.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell
      icon={Lock}
      title="Sign in"
      subtitle="Access your SecureSight360 console"
    >
      <form onSubmit={submit} className="space-y-4">
        <Field
          icon={Mail}
          type="email"
          value={email}
          onChange={setEmail}
          placeholder="you@company.com"
          autoComplete="email"
        />

        {email && !validEmail && (
          <p className="mt-1.5 text-xs text-warning flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5" />
            Please enter a valid email address.
          </p>
        )}

        <div className="flex items-center gap-2 rounded-xl border border-border bg-surface/60 px-3 py-2.5 focus-within:border-cyan/60 focus-within:ring-2 focus-within:ring-cyan/20">
          <KeyRound className="h-4 w-4 text-muted-foreground" />
          <input
            type={showPassword ? "text" : "password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password"
            autoComplete="current-password"
            className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground/60"
          />
          <button
            type="button"
            onClick={() => setShowPassword((value) => !value)}
            className="text-muted-foreground hover:text-foreground transition"
            aria-label={showPassword ? "Hide password" : "Show password"}
          >
            {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </button>
        </div>

        {error && (
          <div className="rounded-lg border border-warning/30 bg-warning/10 text-warning text-xs px-3 py-2 flex items-center gap-2">
            <AlertTriangle className="h-3.5 w-3.5" />
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={!valid || submitting}
          className="w-full inline-flex items-center justify-center gap-2 rounded-xl px-5 py-3 text-sm font-medium text-[#021016] bg-gradient-to-r from-cyan to-accent-blue glow-cyan disabled:opacity-40 disabled:cursor-not-allowed hover:brightness-110 transition"
        >
          {submitting ? "Signing in…" : "Sign in"}
          <ArrowRight className="h-4 w-4" />
        </button>

        <p className="text-center text-xs text-muted-foreground">
          Do not have an account?{" "}
          <button
            type="button"
            onClick={onSignup}
            className="text-cyan hover:underline"
          >
            Create account
          </button>
        </p>
      </form>
    </AuthShell>
  );
}

function Signup({
  onVerified,
  onLogin,
}: {
  onVerified: () => void;
  onLogin: () => void;
}) {
  const { register } = useAuth() as any;

  const [name, setName] = useState("");
  const [company, setCompany] = useState("");
  const [email, setEmail] = useState("");
  const [pwd, setPwd] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [agree, setAgree] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validEmail = BASIC_EMAIL_REGEX.test(email.trim());
  const businessEmailError = getBusinessEmailError(email);
  const validBusinessEmail = validEmail && !businessEmailError;
  const businessEmailDomain = validBusinessEmail
    ? email.trim().toLowerCase().split("@").pop() || ""
    : "";
  const passwordError = getPasswordError(pwd);

  const valid =
    name.trim().length > 1 &&
    company.trim().length > 1 &&
    validBusinessEmail &&
    pwd.length >= 8 &&
    !passwordError &&
    agree;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!valid || submitting) return;

    setSubmitting(true);
    setError(null);

    try {
      const user = await register({
        email: email.trim(),
        password: pwd,
        full_name: name.trim(),
        company_name: company.trim(),
      });

      try {
        localStorage.setItem("cs360-company-name", company.trim());
        localStorage.setItem("cs360-user-name", name.trim());
        localStorage.setItem("cs360-user-email", user.email);
        localStorage.setItem("cs360-registered-at", new Date().toISOString());
      } catch {}

      onVerified();
    } catch (err: any) {
      setError(err?.message || "Account creation failed.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell
      icon={User}
      title="Create your account"
      subtitle="Create a SecureSight360 user account"
    >
      <form onSubmit={submit} className="space-y-4">
        <Field
          icon={User}
          value={name}
          onChange={setName}
          placeholder="Your full name"
          autoComplete="name"
        />

        <Field
          icon={Building2}
          value={company}
          onChange={setCompany}
          placeholder="Company name"
          autoComplete="organization"
        />

        <Field
          icon={Mail}
          type="email"
          value={email}
          onChange={setEmail}
          placeholder="you@company.com"
          autoComplete="email"
        />

        {email && !validEmail && (
          <p className="mt-1.5 text-xs text-warning flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5" />
            Please enter a valid email address.
          </p>
        )}

        {businessEmailError && (
          <p className="mt-1.5 text-xs text-warning flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5" />
            {businessEmailError}
          </p>
        )}

        {businessEmailDomain && (
          <p className="mt-1.5 text-xs text-cyan flex items-center gap-1.5">
            <CheckCircle2 className="h-3.5 w-3.5" />
            Domain detected: {businessEmailDomain}
          </p>
        )}

        <div className="flex items-center gap-2 rounded-xl border border-border bg-surface/60 px-3 py-2.5 focus-within:border-cyan/60 focus-within:ring-2 focus-within:ring-cyan/20">
          <KeyRound className="h-4 w-4 text-muted-foreground" />
          <input
            type={showPassword ? "text" : "password"}
            value={pwd}
            onChange={(e) => setPwd(e.target.value)}
            placeholder="Password (min. 8 characters)"
            autoComplete="new-password"
            className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground/60"
          />
          <button
            type="button"
            onClick={() => setShowPassword((value) => !value)}
            className="text-muted-foreground hover:text-foreground transition"
            aria-label={showPassword ? "Hide password" : "Show password"}
          >
            {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </button>
        </div>

        <label className="flex items-start gap-2.5 text-xs text-muted-foreground cursor-pointer">
          <input
            type="checkbox"
            checked={agree}
            onChange={(e) => setAgree(e.target.checked)}
            className="mt-0.5 h-4 w-4 accent-[#06B6D4]"
          />
          <span>
            I agree to the{" "}
            <a className="text-cyan hover:underline" href="#">
              Terms of Service
            </a>{" "}
            and{" "}
            <a className="text-cyan hover:underline" href="#">
              Privacy Policy
            </a>
            , and I confirm I will only run authorized security assessments.
          </span>
        </label>

        {error && (
          <div className="rounded-lg border border-warning/30 bg-warning/10 text-warning text-xs px-3 py-2 flex items-center gap-2">
            <AlertTriangle className="h-3.5 w-3.5" />
            {error}
          </div>
        )}

        {pwd && passwordError && (
          <p className="mt-1.5 text-xs text-warning flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5" />
            {passwordError}
          </p>
        )}

        <button
          type="submit"
          disabled={!valid || submitting}
          className="w-full inline-flex items-center justify-center gap-2 rounded-xl px-5 py-3 text-sm font-medium text-[#021016] bg-gradient-to-r from-cyan to-accent-blue glow-cyan disabled:opacity-40 disabled:cursor-not-allowed hover:brightness-110 transition"
        >
          {submitting ? "Creating account…" : "Create account"}
          <ArrowRight className="h-4 w-4" />
        </button>

        <p className="text-center text-xs text-muted-foreground">
          Already have an account?{" "}
          <button
            type="button"
            onClick={onLogin}
            className="text-cyan hover:underline"
          >
            Sign in
          </button>
        </p>
      </form>
    </AuthShell>
  );
}
