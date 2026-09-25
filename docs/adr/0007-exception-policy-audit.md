# 0007. Exception、Policy、Auditのドメインモデル

## 状態

Accepted

## 背景

Phase 4（AGENTS.md §45）は Exception（§18）、Policy（§23）、Audit
（§30）という3つの領域をカバーするが、AGENTS.mdがどれだけ具体的に
それらを規定しているかは大きく異なる:

- §18はExceptionに完全なフィールドリストと明示的な振る舞いのルール
  （デフォルトで永続的な例外を認めない、期限切れの例外は再評価対象
  にする）を与えている。
- §30もAuditに完全なフィールドリスト（who/what/when/why/before/after）
  と、後で§20A.8によって拡張される固定の初期Actionリストを与えている。
- §23は、スキーマというよりアーキテクチャ上の指針（「ポリシーロジック
  をハードコードせず、Policy Engineを使う」）である。名指しされている
  ポリシーのうち2つ（risk_policy、priority_policy）は、既に差し替え
  可能なinterface（`risk.Policy`、`priority.Policy`、Phase 2、
  ADR 0002）として存在している。1つ（auto_remediation_policy）は
  §15に明示的なフィールドリストがあり、Phase 3から意図的にここへ
  先送りされている（ADR 0003）。残り（remediation_policy、
  exception_policy、verification_policy）にはAGENTS.md内のどこにも
  フィールドリストが存在しない。
- §29が挙げている「分離して保持すべきデータベーステーブル」の明示的な
  リストには、他のPhase 1〜4のエンティティとは異なり「policies」
  テーブルが含まれていない。

これはつまり、PolicyをExceptionやAuditと同じ方法では実装できないと
いうことである。単一のスキーマにモデル化できるものではない。汎用的で
永続化・バージョン管理された「Policyドキュメント」集約（id/name/
version/status/configブロブ/有効化ワークフロー）を作ることは、§29が
要求していない構造を勝手に発明することになり、ドメインモデリングと
いうよりは構成管理のインフラに逸れていくことになる。

## 決定

- **Exception**（`internal/domain/exception`）は、§18のフィールド
  リストをすべて実装した上で、Statusのステートマシン
  （Requested → Approved/Rejected、Approved → Expired/Revoked）を
  持つ。`Exception.ImpliedFindingStatus()` は、remediation.Planや
  verification.Verification（ADR 0003）と同じパターンを踏襲する:
  Approvedは `finding.StatusAccepted` を、Expired/Revokedは
  `finding.StatusReopened` を暗示し、Requested/Rejectedはいかなる
  遷移も暗示しない — 一度も承認されなかったリクエストはFindingを
  一切動かさない。付随する `exception.Policy{MaxDuration}` は、
  `New` が単に `ExpiresAt` の設定を要求するのとは別に、「永久的な
  例外をデフォルトにしない」を組織的な上限として強制する。
- **Audit**（`internal/domain/audit`）は、§30のフィールドリストを
  そのまま実装し、`SubjectType`/`SubjectID`（汎用的な文字列参照で
  あり、これによりこのパッケージが監査対象を名指しするために他の
  すべてのドメインパッケージをimportする必要がなくなる）を加えて
  いる。`Action` はクローズドなenumではなく、§30のアクションを
  名前付き定数として持つ素の文字列のままにしている。これは§20A.8が
  既に後続フェーズで（pownforge_importなど）追加することを前提に
  しているためである。`evidence.Evidence` 同様、`Entry` には更新用
  メソッドが存在しない。
- **Policy**（`internal/domain/policy`）は、§23が未実装かつ具体的な
  ものとして残していた部分にちょうど絞り込んでいる:
  `AutoRemediationPolicy`（§15のフィールド:
  AllowAutomaticExecution、AllowedAssetTypes、AllowedEnvironments、
  AllowedActionTypes、MaintenanceWindow、RollbackRequired）で、
  ゼロ値はすべてを拒否する — これは remediation.Plan のステートマシン
  を通じてADR 0003が既に確立したデフォルト安全側の特性と同じものを、
  明示的で検査可能な設定オブジェクトとしても利用可能にしたものである。
  `Kind` enumは§23にある6つのポリシーに（例えば audit.Entry の
  SubjectTypeとして分類するための）名前を付けるが、すべてのポリシーを
  このパッケージ内でデータとして表現することを要求するものではない。
- 明示的に**作らなかった**もの: 独自のID/version/status/有効化ワーク
  フローを持つ汎用的な永続化Policy集約、および既に存在するもの
  （remediation承認ゲート、`exception.Policy`、verificationの
  method/result検証）を超える具体的な `remediation_policy` /
  `exception_policy` / `verification_policy` のデータ構造。任意の
  ポリシー設定を保存・バージョン管理する実際の要件が生じた場合は、
  ここに投機的に組み込むのではなく、独自のADRとしてスコープを定めて
  記録すべきである（AGENTS.md §47.12）。

## 影響

- 自動修復の試行をゲートする必要があるApplication層のコードは、
  （どこから来るにせよ設定を）`AutoRemediationPolicy` の値として
  ロードし、`remediation.Plan.Approve` を呼び出す前に必ず
  `Allows(...)` を呼び出す。これを使って `Plan` 自身のステート
  マシンを迂回することはできない。
- `exception.Policy` と `priority.SLAPolicy`（Phase 2）は、意図的に
  同じ形をしている: 永続化されるエンティティではなく、
  `Validate`/`Deadline` メソッドを持つ小さな値オブジェクトであり、
  「データとしてのポリシー」をフェーズを跨いで一貫して扱う。
- Phase 5で実際に設定駆動のPolicy Engine（名前付き・バージョン管理
  されたポリシーをストアから読み込むもの）が必要になった場合は、
  Phase 2〜4で構築したEngineやエンティティのコードを一切変更せず、
  これらと同じ型（`risk.Policy`、`priority.Policy`、
  `AutoRemediationPolicy`、`exception.Policy`）を保存済みの設定から
  構築する新しいInfrastructureとして追加できる。

## 追記（2026-09-25）: 本ADRの判断を覆す条件

本ADRの「汎用的で永続化・バージョン管理されたPolicyドキュメント集約
を作らない」という決定は、以降のリファクタリング指示書でも繰り返し
参照されるガードレールとして扱う。曖昧な運用を避けるため、覆す際の
条件を以下のとおり明文化する。

**覆してよい条件（トリガー）**:

以下の両方を満たす、投機的でない具体的な要件が生じた場合に限る。

1. 複数のPolicy種別（risk_policy/priority_policy/
   auto_remediation_policy/exception_policy/verification_policy等）
   を横断して、名前付き・バージョン管理された設定を運用者が変更・
   承認・ロールバックできる必要が、実際の運用上の要求（規制対応、
   複数チームでの承認フロー等）として生じている。
2. 既存の値オブジェクト型（`risk.Policy`、`priority.Policy`、
   `AutoRemediationPolicy`、`exception.Policy`）を個別に拡張する
   のではこの要求を満たせないことが具体的に説明できる。

**新ADRが満たすべき内容**:

上記条件を満たしてPolicy集約を新設する場合、新しいADR（次の空き
番号を使用）に以下を明記すること。

- トリガーとなった具体的な要件（誰が、何のために、それを必要と
  しているか）
- なぜ既存の値オブジェクト型の拡張では不十分か
- 本ADRの「影響」節が既に示した移行方針――既存のPhase 2〜4の
  Engine/entityコード（risk.Engine、priority.Engine、
  remediation.Plan、exception.Exception等）を変更せず、保存済み
  設定からこれらの型を構築する新しいInfrastructureとして追加する
  ――に従うか、従わない場合はその理由
- 新設するPolicy集約のスキーマ（id/name/version/status/config等）

**覆してはならない例**:

- 「将来必要になるかもしれないから」という投機的な理由（AGENTS.md
  §48）。
- 1種類のPolicy（例: auto_remediation_policyのみ）の設定変更履歴を
  残したいという理由だけで、全Policy種別を横断する汎用集約を作る
  こと（必要なのはAuditへの記録であり、Policy集約ではない可能性が
  高い――§30のAudit Logは既にwho/what/when/why/before/afterを
  記録できる）。
