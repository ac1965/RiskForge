// These mirror internal/api's JSON responses exactly as
// encoding/json.Marshal produces them from the Go domain structs (no
// json tags anywhere in this codebase, so field names stay PascalCase).
// This is a read-only, list-only Dashboard (ADR 0013): these types only
// need the fields the 5 list tables actually render.

export interface Asset {
  ID: string;
  Hostname: string;
  FQDN: string;
  Type: string;
  Environment: string;
  Criticality: string;
  Exposure: {
    InternetExposed: boolean;
    Level: string;
  };
  LifecycleState: string;
  FirstSeen: string;
  LastSeen: string;
}

export interface Finding {
  ID: string;
  AssetID: string;
  VulnerabilityID: string;
  DetectionSource: string;
  DetectedAt: string;
  LastConfirmedAt: string;
  Status: string;
  Confidence: string;
}

export interface PriorityDecision {
  ID: string;
  FindingID: string;
  Rank: number;
  Level: string;
  SLADeadline: string;
  PolicyName: string;
  PolicyVersion: string;
  DecidedAt: string;
}

export interface RemediationPlan {
  ID: string;
  FindingID: string;
  ActionType: string;
  Description: string;
  ProposedBy: string;
  ApprovedBy: string;
  ScheduledAt: string;
  ExecutedAt: string;
  Status: string;
}

export interface Exception {
  ID: string;
  FindingID: string;
  Reason: string;
  RequestedBy: string;
  ApprovedBy: string;
  CreatedAt: string;
  ExpiresAt: string;
  Status: string;
}
