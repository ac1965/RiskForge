# 0003. RemediationおよびVerificationの安全性モデル

## 状態

Accepted

## 背景

AGENTS.md §13–§16および§44は、Findingを是正する際にいくつかの安全性
特性を要求している:

- 自動修復はデフォルトで無効でなければならない（§15、§47.7）。
- `accept_risk` は、成功したRemediationとして扱ってはならない
  （§13）。
- すべてのremediation actionは、可能な限りDry RunとRollbackをサポート
  すべきであり、Rollbackできない場合はその旨を明示すべきである
  （§33、§34）。
- RemediationとVerificationは別のエンティティである（§44 不変条件3）:
  remediation.Planを完了させることは変更を加えたことを意味するのであって、
  それが有効であると確認されたことを意味しない。
- 実行できなかったVerification（例: Assetに到達できなかった）は、
  脆弱性が依然として存在するものとして扱ってはならない（§20A.6.1）。

設定駆動の汎用Policy Engine（§23） — §15で述べられている
`auto_remediation_policy` を含む — はPhase 4の作業である（§45）。
Phase 3では、そのEngineの完成を待たずにこれらの特性を成立させるための
基盤となるドメインエンティティが必要である。

## 決定

- `remediation.Plan` のステータス遷移
  （`internal/domain/remediation/status.go`）は、
  `StatusProposed -> StatusInProgress` への直接遷移を許可しない:
  Planは必ず `StatusApproved`（または `StatusScheduled`）を経由しな
  ければならない。これが「自動修復はデフォルトで無効」という要件を
  ドメインレベルで実際に強制している部分であり、将来のポリシー設定が
  何であろうと、承認をスキップするコードパスは存在しない。
- `remediation.Rollback` は、§14で文字通り挙げられている単一の自由記述
  フィールド `rollback_plan` ではなく、構造体
  （`Capable bool`、`Plan string`、`Reason string`）として表現する。
  `Validate()` は `Capable` が真のとき `Plan` を、偽のとき `Reason`
  を必須とするため、「このアクションはロールバックできない」という
  事実は、空文字列から推測すべきものではなく、構造化された事実として
  表現される（§34）。
- `Plan.DryRun` は `DryRunReport`（対象Asset、Finding、Action、予定
  される変更、Rollback）を返し、それ自体はOSコマンドを一切実行しない
  — プレビューを生成することだけが唯一の役割である（§25、§33）。
  実際にremediation actionを実行すること（§32の
  `validation → structured command → allowlist → execution` という
  パイプライン）は、後続フェーズにおけるInfrastructure層の関心事で
  ある。
- `Plan.ImpliedFindingStatus()` は、`ActionAcceptRisk` に対しては
  `finding.StatusAccepted` を、それ以外のすべてのアクション種別に対
  しては `finding.StatusRemediated` を返すが、`finding.TransitionTo`
  自体を呼び出すことは決してない — Planが保持しているのは生きた
  `*Finding` ではなく `FindingID` であるため、別の集約を直接変更する
  ことはできない。これにより不変条件3は構造的に保たれる: accept_risk
  以外のPlanが暗示する `StatusRemediated` であっても、必ず
  `Finding.TransitionTo` を経由しなければならず、その遷移表
  （Phase 1、ADR 0001由来）は依然として `StatusVerified` への直接
  遷移を拒否する。
- `verification.Verification.ImpliedFindingStatus()` も同じパターンを
  踏襲する: `ResultPass` は `StatusVerified` を、`ResultFail` は
  `StatusReopened` を暗示し、`ResultInconclusive` はいかなる遷移も
  暗示しない（`apply=false`）— これは §20A.6.1 をそのまま
  コードに落としたものである。
- `AutoRemediationPolicy`（§15にある `require_approval` /
  `allowed_asset_types` / ... というオブジェクト）は、Phase 3では
  意図的に**実装しない**。上記の承認ゲートによって既に必要な安全性
  特性は得られており、設定可能なポリシーオブジェクトはPhase 4の
  Policy Engine（§23、§45）の一部として実装する。これはADR 0002が
  Risk/Priorityの設定駆動Policyを同様に先送りしたことと整合する。

## 影響

- 将来の「自動承認・自動実行」の自動化（Phase 5）は、いつ
  `Approve` を呼ぶかをシステムに代わって決めることはできても、
  必ず `Plan.Start()` の前に `Plan.Approve()` を通さなければならない
  — ドメイン自身のステートマシンを迂回することはできない。
- （まだ実装されていない）Application層のコードは、完了したPlanや
  記録されたVerificationから `ImpliedFindingStatus()` を読み取り、
  それを使って `Finding.TransitionTo` を呼び出す責任を持つ — Domain
  層はそのマッピングを公開するだけで、集約をまたぐ書き込みは行わない。
