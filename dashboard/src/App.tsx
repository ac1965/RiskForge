import { useEffect, useState } from "react";
import "./App.css";
import { OverviewPage } from "./Overview";
import { AssetsPage, ExceptionsPage, FindingsPage, PrioritiesPage, RemediationPlansPage, SettingsPage } from "./pages";

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "assets", label: "Assets" },
  { id: "findings", label: "Findings" },
  { id: "priorities", label: "Priorities" },
  { id: "remediation-plans", label: "Remediation Plans" },
  { id: "exceptions", label: "Exceptions" },
  { id: "settings", label: "Settings" },
] as const;

type TabID = (typeof TABS)[number]["id"];

function tabFromHash(): TabID {
  const hash = window.location.hash.replace("#", "");
  return (TABS.find((t) => t.id === hash)?.id ?? "overview") as TabID;
}

// App is a plain tab switcher, not a router library — with only 7
// list-scope views (ADR 0013) a routing dependency would be more
// machinery than the app itself. The hash is kept in sync so a tab is
// still bookmarkable/shareable.
export default function App() {
  const [tab, setTab] = useState<TabID>(tabFromHash());
  const [reloadToken, setReloadToken] = useState(0);

  useEffect(() => {
    const onHashChange = () => setTab(tabFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  return (
    <div className="app">
      <header>
        <h1>RiskForge Dashboard</h1>
        <nav>
          {TABS.map((t) => (
            <a
              key={t.id}
              href={`#${t.id}`}
              className={t.id === tab ? "active" : undefined}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </a>
          ))}
        </nav>
      </header>
      <main>
        {tab === "overview" && <OverviewPage reloadToken={reloadToken} />}
        {tab === "assets" && <AssetsPage reloadToken={reloadToken} />}
        {tab === "findings" && <FindingsPage reloadToken={reloadToken} />}
        {tab === "priorities" && <PrioritiesPage reloadToken={reloadToken} />}
        {tab === "remediation-plans" && <RemediationPlansPage reloadToken={reloadToken} />}
        {tab === "exceptions" && <ExceptionsPage reloadToken={reloadToken} />}
        {tab === "settings" && <SettingsPage onTokenChange={() => setReloadToken((n) => n + 1)} />}
      </main>
    </div>
  );
}
