import { useState } from "react";
import { ResourceTable, type Column } from "./ResourceTable";
import { ApiError, getToken, postAction, setToken } from "./api";
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

// ExceptionActions renders the approve/reject/revoke/expire buttons for
// one Exception row (ADR 0014's write endpoints, first write UI). Which
// buttons show depends on Status: only a "requested" exception can be
// approved/rejected, only an "approved" one can be revoked/expired —
// terminal statuses (rejected/expired/revoked) get no buttons. A 403
// here (wrong token scope) is exactly as informative as any other
// failure, so it's shown the same way rather than special-cased.
//
// No detail screen or modal for entering Reason (ADR 0013 keeps this a
// list-only app) — approve/expire ask for one with a plain
// window.prompt, which is enough for this MVP without building a form
// component for two fields.
function ExceptionActions({ exception: e, onChanged }: { exception: Exception; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function act(action: "approve" | "reject" | "expire" | "revoke", reason?: string) {
    setBusy(true);
    setError(null);
    try {
      await postAction(`exceptions/${e.ID}/${action}`, reason !== undefined ? { Reason: reason } : undefined);
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  // window.prompt can throw rather than return null — some embedded/
  // automated browser contexts disable it outright — so this treats
  // that the same as the user cancelling, instead of crashing the page.
  function promptOrNull(message: string): string | null {
    try {
      return window.prompt(message);
    } catch {
      setError("This browser doesn't support prompts; approve/expire need one for the Reason.");
      return null;
    }
  }

  function approve() {
    const reason = promptOrNull("Reason for approving this exception:");
    if (reason === null) return; // cancelled, or prompt unsupported
    void act("approve", reason);
  }

  function expire() {
    const reason = promptOrNull("Reason for expiring this exception (optional):");
    if (reason === null) return;
    void act("expire", reason || undefined);
  }

  return (
    <span>
      {e.Status === "requested" && (
        <>
          <button disabled={busy} onClick={approve}>
            Approve
          </button>{" "}
          <button disabled={busy} onClick={() => void act("reject")}>
            Reject
          </button>
        </>
      )}
      {e.Status === "approved" && (
        <>
          <button disabled={busy} onClick={() => void act("revoke")}>
            Revoke
          </button>{" "}
          <button disabled={busy} onClick={expire}>
            Expire
          </button>
        </>
      )}
      {error && <span className="error"> {error}</span>}
    </span>
  );
}

export function ExceptionsPage({ reloadToken }: { reloadToken: number }) {
  // A successful action bumps localReload, which — combined with the
  // parent's reloadToken in the ResourceTable key — remounts the table
  // and refetches, the same "reset state via key" approach ResourceTable
  // already uses for the Settings-page token change.
  const [localReload, setLocalReload] = useState(0);

  const columns: Column<Exception>[] = [
    { header: "Finding", render: (e) => e.FindingID },
    { header: "Status", render: (e) => e.Status },
    { header: "Requested by", render: (e) => e.RequestedBy },
    { header: "Approved by", render: (e) => e.ApprovedBy || "-" },
    { header: "Expires", render: (e) => formatTime(e.ExpiresAt) },
    { header: "Reason", render: (e) => e.Reason },
    { header: "Actions", render: (e) => <ExceptionActions exception={e} onChanged={() => setLocalReload((n) => n + 1)} /> },
  ];
  return <ResourceTable key={`${reloadToken}-${localReload}`} resource="exceptions" columns={columns} />;
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
