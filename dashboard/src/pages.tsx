import { useState } from "react";
import { ResourceTable, type Column } from "./ResourceTable";
import { getToken, setToken } from "./api";
import type { Asset, Exception, Finding, PriorityDecision, RemediationPlan } from "./types";

// Each page below is a thin column config over ResourceTable
// (ADR 0013: list-only, no detail/write UI yet).

function formatTime(iso: string): string {
  if (!iso || iso.startsWith("0001-01-01")) return "-";
  return new Date(iso).toLocaleString();
}

// reloadToken forces a fresh ResourceTable instance (and thus a fresh
// fetch) via `key` when the token on the Settings page changes — see
// ResourceTable's own comment for why this beats resetting state from
// inside an effect.

export function AssetsPage({ reloadToken }: { reloadToken: number }) {
  const columns: Column<Asset>[] = [
    { header: "Hostname", render: (a) => a.Hostname || a.FQDN },
    { header: "Type", render: (a) => a.Type },
    { header: "Environment", render: (a) => a.Environment },
    { header: "Criticality", render: (a) => a.Criticality },
    { header: "Exposure", render: (a) => (a.Exposure.InternetExposed ? "internet-exposed" : a.Exposure.Level) },
    { header: "Lifecycle", render: (a) => a.LifecycleState },
  ];
  return <ResourceTable key={reloadToken} resource="assets" columns={columns} />;
}

export function FindingsPage({ reloadToken }: { reloadToken: number }) {
  const columns: Column<Finding>[] = [
    { header: "Asset", render: (f) => f.AssetID },
    { header: "Vulnerability", render: (f) => f.VulnerabilityID },
    { header: "Status", render: (f) => f.Status },
    { header: "Confidence", render: (f) => f.Confidence },
    { header: "Detected", render: (f) => formatTime(f.DetectedAt) },
    { header: "Last confirmed", render: (f) => formatTime(f.LastConfirmedAt) },
  ];
  return <ResourceTable key={reloadToken} resource="findings" columns={columns} />;
}

export function PrioritiesPage({ reloadToken }: { reloadToken: number }) {
  const columns: Column<PriorityDecision>[] = [
    { header: "Finding", render: (p) => p.FindingID },
    { header: "Rank", render: (p) => p.Rank.toFixed(1) },
    { header: "Level", render: (p) => p.Level },
    { header: "SLA deadline", render: (p) => formatTime(p.SLADeadline) },
    { header: "Policy", render: (p) => `${p.PolicyName} v${p.PolicyVersion}` },
    { header: "Decided", render: (p) => formatTime(p.DecidedAt) },
  ];
  return <ResourceTable key={reloadToken} resource="priorities" columns={columns} />;
}

export function RemediationPlansPage({ reloadToken }: { reloadToken: number }) {
  const columns: Column<RemediationPlan>[] = [
    { header: "Finding", render: (p) => p.FindingID },
    { header: "Action", render: (p) => p.ActionType },
    { header: "Status", render: (p) => p.Status },
    { header: "Proposed by", render: (p) => p.ProposedBy },
    { header: "Approved by", render: (p) => p.ApprovedBy || "-" },
    { header: "Scheduled", render: (p) => formatTime(p.ScheduledAt) },
    { header: "Executed", render: (p) => formatTime(p.ExecutedAt) },
  ];
  return <ResourceTable key={reloadToken} resource="remediation-plans" columns={columns} />;
}

export function ExceptionsPage({ reloadToken }: { reloadToken: number }) {
  const columns: Column<Exception>[] = [
    { header: "Finding", render: (e) => e.FindingID },
    { header: "Status", render: (e) => e.Status },
    { header: "Requested by", render: (e) => e.RequestedBy },
    { header: "Approved by", render: (e) => e.ApprovedBy || "-" },
    { header: "Expires", render: (e) => formatTime(e.ExpiresAt) },
    { header: "Reason", render: (e) => e.Reason },
  ];
  return <ResourceTable key={reloadToken} resource="exceptions" columns={columns} />;
}

// SettingsPage is the only place this Dashboard touches
// authentication: it never issues or revokes a token (ADR 0012/0013)
// it only stores one that `riskforge token create` already produced.
export function SettingsPage({ onTokenChange }: { onTokenChange: () => void }) {
  const [value, setValue] = useState(getToken());
  const [saved, setSaved] = useState(false);

  return (
    <div>
      <p>
        Paste a token issued by <code>riskforge token create --principal &lt;name&gt; --scope read</code>. It is
        stored only in this browser's local storage and sent as the <code>Authorization: Bearer</code> header on
        every request.
      </p>
      <input
        type="password"
        value={value}
        onChange={(e) => {
          setValue(e.target.value);
          setSaved(false);
        }}
        placeholder="rf_..."
        size={48}
      />
      <button
        onClick={() => {
          setToken(value.trim());
          onTokenChange();
          setSaved(true);
        }}
      >
        Save
      </button>
      {saved && <span> Saved.</span>}
    </div>
  );
}
