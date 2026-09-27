import { useEffect, useState } from "react";
import { ApiError, fetchList } from "./api";
import type { Asset, Exception, Finding, PriorityDecision, RemediationPlan } from "./types";

// OverviewPage computes "Phase A" of AGENTS.md §41's KPI list: the
// subset answerable purely by combining data the 5 existing read
// endpoints already return, with no new backend work. The rest of §41
// (Critical Findings, Known Exploited Findings, Verified Remediations —
// need Vulnerability/Verification data this API doesn't expose yet; a
// true Overdue Remediation — needs a due-date field RemediationPlan
// doesn't have yet, §4) is deliberately not attempted here.

interface Metrics {
  totalAssets: number;
  internetExposedAssets: number;
  exceptionCount: number;
  expiredExceptions: number;
  reopenedFindings: number;
  slaEvaluated: number;
  slaCompliant: number;
}

function isSet(iso: string): boolean {
  return !!iso && !iso.startsWith("0001-01-01");
}

// computeMetrics joins PriorityDecision.SLADeadline and
// RemediationPlan.ExecutedAt by FindingID: a plan counts as SLA-compliant
// once it has actually executed, by (or before) its finding's latest
// priority deadline. Plans with no matching priority decision, or that
// haven't executed yet, aren't counted either way (there's nothing to
// judge them against, or the story isn't over).
function computeMetrics(assets: Asset[], findings: Finding[], priorities: PriorityDecision[], plans: RemediationPlan[], exceptions: Exception[]): Metrics {
  const slaDeadlineByFinding = new Map(priorities.map((p) => [p.FindingID, p.SLADeadline]));

  let slaEvaluated = 0;
  let slaCompliant = 0;
  for (const plan of plans) {
    if (!isSet(plan.ExecutedAt)) continue;
    const deadline = slaDeadlineByFinding.get(plan.FindingID);
    if (!deadline || !isSet(deadline)) continue;
    slaEvaluated++;
    if (new Date(plan.ExecutedAt).getTime() <= new Date(deadline).getTime()) slaCompliant++;
  }

  return {
    totalAssets: assets.length,
    internetExposedAssets: assets.filter((a) => a.Exposure.InternetExposed).length,
    exceptionCount: exceptions.length,
    expiredExceptions: exceptions.filter((e) => e.Status === "expired").length,
    reopenedFindings: findings.filter((f) => f.Status === "reopened").length,
    slaEvaluated,
    slaCompliant,
  };
}

type State = { metrics: Metrics } | { error: string } | null;

function Tile({ label, value }: { label: string; value: string }) {
  return (
    <div className="tile">
      <div className="tile-value">{value}</div>
      <div className="tile-label">{label}</div>
    </div>
  );
}

export function OverviewPage({ reloadToken }: { reloadToken: number }) {
  const [state, setState] = useState<State>(null);

  useEffect(() => {
    Promise.all([
      fetchList<Asset>("assets"),
      fetchList<Finding>("findings"),
      fetchList<PriorityDecision>("priorities"),
      fetchList<RemediationPlan>("remediation-plans"),
      fetchList<Exception>("exceptions"),
    ])
      .then(([assets, findings, priorities, plans, exceptions]) => {
        setState({ metrics: computeMetrics(assets, findings, priorities, plans, exceptions) });
      })
      .catch((err: unknown) => {
        if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
          setState({ error: `${err.message} — set a valid token on the Settings page.` });
        } else {
          setState({ error: err instanceof Error ? err.message : String(err) });
        }
      });
  }, [reloadToken]);

  if (state === null) return <p>Loading…</p>;
  if ("error" in state) return <p className="error">{state.error}</p>;

  const m = state.metrics;
  const slaRate = m.slaEvaluated === 0 ? "-" : `${Math.round((100 * m.slaCompliant) / m.slaEvaluated)}%`;

  return (
    <div>
      <p className="hint">
        A subset of AGENTS.md §41's KPIs, computed here from the existing list endpoints. Critical Findings, Known
        Exploited Findings, Verified Remediations, and true Overdue Remediation need data this API doesn't expose
        yet and aren't shown.
      </p>
      <div className="tiles">
        <Tile label="Total Assets" value={String(m.totalAssets)} />
        <Tile label="Internet Exposed Assets" value={String(m.internetExposedAssets)} />
        <Tile label="Exception Count" value={String(m.exceptionCount)} />
        <Tile label="Expired Exceptions" value={String(m.expiredExceptions)} />
        <Tile label="Reopened Findings" value={String(m.reopenedFindings)} />
        <Tile label="Remediation SLA" value={slaRate} />
      </div>
      {m.slaEvaluated > 0 && (
        <p className="hint">
          Remediation SLA: {m.slaCompliant} of {m.slaEvaluated} executed remediations met their finding's priority
          SLA deadline.
        </p>
      )}
    </div>
  );
}
