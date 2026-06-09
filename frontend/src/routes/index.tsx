import { useRef, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Sidebar } from "@/components/Sidebar";
import { Header } from "@/components/Header";
import { Overview } from "@/components/Overview";
import { Scanner } from "@/components/Scanner";
import { Reports } from "@/components/Reports";
import { Auth } from "@/components/Auth";
import { Settings } from "@/components/Settings";
import { History } from "@/components/History";
import { Privacy } from "@/components/Privacy";
import { ThemeProvider } from "@/lib/theme";
import { Construction } from "lucide-react";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "SecureSight360 — Security Assessment Platform" },
      { name: "description", content: "Professional cybersecurity assessment platform: authorized website scans, explainable risk scoring, and client-friendly reports." },
      { property: "og:title", content: "SecureSight360 — Security Assessment Platform" },
      { property: "og:description", content: "Authorized website security scans with an explainable risk score and client-ready reports." },
    ],
  }),
  component: () => (
    <ThemeProvider>
      <Index />
    </ThemeProvider>
  ),
});

function Placeholder({ label }: { label: string }) {
  return (
    <div className="glass rounded-2xl p-10 text-center">
      <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-secondary border border-border">
        <Construction className="h-6 w-6 text-cyan" />
      </div>
      <div className="mt-4 font-medium">{label} coming soon</div>
      <p className="text-sm text-muted-foreground mt-1">This module is on the roadmap for the next release.</p>
    </div>
  );
}

function Index() {
  const [authed, setAuthed] = useState(false);
  const [section, setSection] = useState("overview");
  const historyRef = useRef<string[]>(["overview"]);

  const navigate = (id: string) => {
    if (id !== section) {
      historyRef.current.push(id);
      setSection(id);
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  };

  const goBack = () => {
    if (historyRef.current.length > 1) {
      historyRef.current.pop();
      setSection(historyRef.current[historyRef.current.length - 1]);
    } else {
      setSection("overview");
    }
  };

  const reverify = () => {
    try {
      ["cs360-company-domain","cs360-company-name","cs360-verified-hosts","cs360-user-name","cs360-user-email","cs360-registered-at"]
        .forEach(k => localStorage.removeItem(k));
    } catch {}
    historyRef.current = ["overview"];
    setSection("overview");
    setAuthed(false);
  };

  const logout = () => {
    if (confirm("Log out of SecureSight360?")) reverify();
  };



  if (!authed) return <Auth onAuthenticated={() => setAuthed(true)} />;

  return (
    <div className="h-dvh w-full flex overflow-hidden">
      <div className="w-full flex flex-1 gap-0 overflow-hidden">
        <Sidebar active={section} onSelect={navigate} onLogout={logout} />
        <main className="flex-1 min-w-0 h-dvh space-y-4 px-3 py-3 lg:px-4 lg:py-3 w-full overflow-y-auto overflow-x-hidden">
          <Header
            section={section}
            onBack={goBack}
            canGoBack={section !== "overview"}
          />
          {section === "overview" && <Overview onLaunch={() => navigate("scanner")} />}
          {section === "scanner" && <Scanner onReverify={reverify} />}
          {section === "reports" && <Reports />}
          {section === "history" && <History />}
          {section === "privacy" && <Privacy />}
          {section === "settings" && <Settings onLogout={logout} onBack={goBack} />}
        </main>
      </div>
    </div>
  );
}
