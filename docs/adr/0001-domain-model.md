# 0001. コアドメインモデルとレイヤリング

## 状態

Accepted

## 背景

RiskForgeは、CVSS順に並べただけのリストとしてではなく、Asset → Software →
Vulnerability → Finding → Risk → Priority → Remediation → Verification →
Evidence というライフサイクルとして管理しなければならない
（AGENTS.md §1–§2）。そのためには、後続のフェーズで（例えば
VulnerabilityとFindingのような）異なる概念が都合よく混同されてしまわない
よう、実装を始める前にドメインエンティティと不変条件を固定しておく必要が
ある。

## 決定

AGENTS.md §3–§25で定義されているドメインモデル・不変条件・レイヤリングを
そのまま採用する:

- エンティティ: `Organization`、`Asset`、`SoftwareInstallation`、
  `Vulnerability`、`Finding`、`RiskAssessment`、`PriorityDecision`、
  `RemediationPlan`、`Verification`、`Evidence`、`Exception`。
- 不変条件（§44）: Vulnerability ≠ Finding、Risk ≠ Priority、
  Remediation ≠ Verification、Finding ≠ Evidence、CVSS ≠
  Organizational Risk、Detected ≠ Verified Remediated。
- レイヤリング: UI → Application → Domain → Infrastructure（§25）。
  Domainのコードは、HTTPクライアント、データベースドライバ、CLIパッケージ、
  OSコマンド実行、クラウドSDKを直接importしない。
- リポジトリ構成: `internal/domain/<entity>`、`internal/application`、
  `internal/infrastructure/<adapter>`、`internal/api`、`internal/cli`
  とし、このレイヤリングをパッケージ構成にそのまま反映する。

## 影響

- 不変条件を曖昧にしてしまうような機能追加（例: RiskをFindingレコードに
  直接書き込む等）には、こっそりとしたコード変更ではなく新しいADRが必要
  になる（AGENTS.md §47.12）。
- Domainパッケージは外部依存を持たないため、Risk EngineとPriority Engine
  の単体テスト（AGENTS.md §25A.6）を低コストに保てる。
- Phase 1（AGENTS.md §45）では `Asset`、`Software`、`Vulnerability`、
  `Finding` のみを実装し、残りのエンティティは後続フェーズで空のパッケージ
  /テーブルとして足場だけ用意する。前倒しでは実装しない
  （AGENTS.md §47.11）。
