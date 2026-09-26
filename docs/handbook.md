# RiskForge 手引書

設計・ビルド・利用をまとめた一冊です。ドメインモデルの規範・不変条件・
実装制約の正本(source of truth)は引き続き[AGENTS.md](../AGENTS.md)であり、
個々の設計判断の背景は[docs/adr/](adr/)配下のADRに記録されています。本書は
それらを実際のコードと突き合わせ、「どう動くか」「どう使うか」を図表つきで
説明する実践的なガイドです。

## 目次

1. [はじめに](#1-はじめに)
2. [全体アーキテクチャ](#2-全体アーキテクチャ)
3. [ドメインモデル](#3-ドメインモデル)
4. [セットアップとビルド](#4-セットアップとビルド)
5. [クイックスタート](#5-クイックスタート)
6. [CLIコマンドリファレンス](#6-cliコマンドリファレンス)
7. [Risk EngineとPriority Engine](#7-risk-engineとpriority-engine)
8. [ライフサイクルと状態遷移](#8-ライフサイクルと状態遷移)
9. [Evidenceと監査ログ](#9-evidenceと監査ログ)
10. [データベーススキーマ](#10-データベーススキーマ)
11. [テスト](#11-テスト)
12. [実装状況](#12-実装状況)
13. [ADRダイジェスト(設計判断の索引)](#13-adrダイジェスト設計判断の索引)
14. [PownForgeとの関係(姉妹プロジェクト)](#14-pownforgeとの関係姉妹プロジェクト)
15. [付録: 用語集](#15-付録-用語集)

---

## 1. はじめに

RiskForgeは、単なる脆弱性スキャナではなく、

> Asset → Software → Vulnerability → Risk → Prioritization → Remediation
> → Verification → Evidence

というライフサイクル全体を管理する、防御側のVulnerability & Exposure
Management Platformです。「何が脆弱なのか」だけでなく、「何を、なぜ、
どの順番で、どの方法で是正し、どう検証・記録するか」までを扱います。

対象読者は、このプロジェクトを保守・拡張する開発者と、CLIを実際に使って
運用するユーザーの両方です。

中核となる約束は4つです。

- **CVSSだけでは優先順位を決めない**: Risk(組織内の実リスク)と
  Priority(何を先に対応するか)は別のEngineが計算する別の値であり、
  Severity・Exploitability・Asset Criticality・Exposure・Business
  Impactを独立して扱います(AGENTS.md §1–§2、§8、§12)
- **VulnerabilityとFindingは別物**: 「CVE-XXXX-YYYYが存在する」ことと
  「SERVER-001にCVE-XXXX-YYYYが検出された」ことは異なるエンティティで
  あり、混同しません(AGENTS.md §7、§44 不変条件1)
- **自動修復はデフォルトで無効**: RemediationPlanは
  `Proposed → Approved → InProgress` という承認ゲートをドメインの
  ステートマシンとして強制しており、承認を飛ばして実行される経路は
  存在しません(AGENTS.md §15、§47.7)
- **EvidenceとAuditは削除・上書きしない**: どちらのドメイン型にも
  更新用メソッドは存在せず、訂正は常に新しいレコードとして追加します
  (AGENTS.md §17、§22、§30、§47.10)

## 2. 全体アーキテクチャ

RiskForgeは、UI/CLI・Application・Domain・Infrastructureを明確に分離した
レイヤードアーキテクチャです(AGENTS.md §25)。

```mermaid
graph TD
    subgraph FrontEnds["フロントエンド"]
        CLI["riskforge CLI<br/>(internal/cli, Cobra)"]
        API["HTTP API<br/>(internal/api, net/http)<br/>骨格のみ・未実装"]
    end

    CLI --> Service
    API -. "将来" .-> Service

    subgraph App["Application層 (internal/application)"]
        Service["application.Service<br/>Named Domain API群(§26)"]
        Ports["ports.go<br/>Repository interface"]
    end

    Service --> Domain
    Service --> Ports

    subgraph Domain["Domain層 (internal/domain/*)"]
        Asset[asset]
        Software[software]
        Vulnerability[vulnerability]
        Finding[finding]
        RiskPkg["risk<br/>(Risk Engine)"]
        PriorityPkg["priority<br/>(Priority Engine)"]
        Remediation[remediation]
        Verification[verification]
        Evidence[evidence]
        Exception[exception]
        PolicyPkg[policy]
        Audit[audit]
        Explain[explainability]
    end

    Ports --> Infra

    subgraph Infra["Infrastructure層 (internal/infrastructure/postgres)"]
        PG["Repository実装<br/>(database/sql + pgx)"]
        Mig["Migrate()<br/>go:embedされた migrations/*.sql"]
    end

    PG --> DB[(PostgreSQL)]
    Mig --> DB
```

- `internal/cli` は `internal/application` にのみ依存し、
  `internal/infrastructure` を直接importしません。PostgreSQLへの接続や
  Risk/Priority Engineの組み立ては `cmd/riskforge/main.go`
  (composition root)が担います([ADR 0010](adr/0010-cli-wiring.md))。
- `internal/application` はドメインの型とport interfaceにのみ依存し、
  データベースドライバを直接importしません
  ([ADR 0008](adr/0008-application-layer.md))。
- `internal/domain/*` は外部依存を持たない純粋なドメインロジックです
  ([ADR 0001](adr/0001-domain-model.md))。

3つのバイナリを1つのコードベースから生成し、権限を物理的に分離します
(AGENTS.md §25A.3)。

| バイナリ | 役割 | 権限 | 現状 |
| --- | --- | --- | --- |
| `riskforge` | CLI / APIサーバー | 通常操作全般 | 実装済み(CLI) |
| `riskforge-agent` | 管理対象Asset上でインベントリ収集 | Scanner権限 | 未実装(スタブ) |
| `riskforge-worker` | データ取り込み・Remediation実行等のバックグラウンドジョブ | Remediation実行権限 | 未実装(スタブ) |

ドメインの実行パイプラインは次の流れです(AGENTS.md §24)。

```mermaid
flowchart TD
    A[Asset] --> S[Software]
    S --> V[Vulnerability]
    V --> F[Finding]
    F --> R["Risk Engine<br/>(risk.Assessment)"]
    R --> P["Priority Engine<br/>(priority.Decision)"]
    P --> RM[RemediationPlan]
    RM --> VF[Verification]
    VF --> EV[Evidence]
    F -.->|Exception| ACC["finding.StatusAccepted"]
    EV -.-> AU["Audit Log<br/>(who/what/when/why/before/after)"]
    RM -.-> AU
    VF -.-> AU
    ACC -.-> AU
```

## 3. ドメインモデル

最小構成のエンティティと、それをまたいで成立しなければならない不変条件
です(AGENTS.md §3、§44、[ADR 0001](adr/0001-domain-model.md))。

```mermaid
erDiagram
    ASSETS ||--o{ SOFTWARE_INSTALLATIONS : has
    ASSETS ||--o{ FINDINGS : "検出される"
    ASSETS ||--o{ EVIDENCE : "から収集される"
    VULNERABILITIES ||--o{ FINDINGS : "として識別される"
    FINDINGS ||--o| EVIDENCE : evidence_id
    FINDINGS ||--o{ RISK_ASSESSMENTS : 評価される
    FINDINGS ||--o{ PRIORITY_DECISIONS : 優先順位付けされる
    FINDINGS ||--o{ REMEDIATION_PLANS : 是正される
    FINDINGS ||--o{ VERIFICATIONS : 検証される
    FINDINGS ||--o{ EXCEPTIONS : "リスク受容される"
```

不変条件(AGENTS.md §44):

| # | 不変条件 | 意味 |
| --- | --- | --- |
| 1 | Vulnerability ≠ Finding | 「脆弱性そのもの」と「特定Asset上での検出事実」は別物 |
| 2 | Risk ≠ Priority | 「リスクの大きさ」と「対応順序」は別のEngineが計算する別の値 |
| 3 | Remediation ≠ Verification | 変更を加えたことと、それが効いたと確認できたことは別 |
| 4 | Finding ≠ Evidence | Findingという事実と、それを裏付ける証跡は別エンティティ |
| 5 | CVSS ≠ Organizational Risk | 技術的深刻度と組織内の実リスクは別軸 |
| 6 | Detected ≠ Verified Remediated | 検出されたことと、是正が検証されたことは別 |

主要エンティティの要点:

| エンティティ | パッケージ | 要点 |
| --- | --- | --- |
| `Asset` | `internal/domain/asset` | 中心エンティティ。`Criticality`は業務側から与えられる値で、技術情報から自動推定しない(§11) |
| `SoftwareInstallation` | `internal/domain/software` | Asset上のソフトウェア。`(asset_id, vendor, product, version)`がidempotencyキー |
| `Vulnerability` | `internal/domain/vulnerability` | 脆弱性そのもの。`Provenance`(source/source_id/retrieved_at等)で外部データの出典を保持(§38) |
| `Finding` | `internal/domain/finding` | 「このAssetにこのVulnerabilityがある」という事実。ステータス遷移は§8参照 |
| `risk.Assessment` | `internal/domain/risk` | Risk Engineの出力。Score/Level/Factors(説明可能性)を持つ |
| `priority.Decision` | `internal/domain/priority` | Priority Engineの出力。Rank/Level/Factors/SLADeadlineを持つ |
| `remediation.Plan` | `internal/domain/remediation` | 是正計画。Dry Run・Rollback情報・承認ゲート付きステートマシンを持つ |
| `verification.Verification` | `internal/domain/verification` | 是正が効いたかの検証結果。`Inconclusive`は`Fail`と区別する(§20A.6.1) |
| `evidence.Evidence` | `internal/domain/evidence` | 改ざん検知可能な証跡。更新メソッドを持たない |
| `exception.Exception` | `internal/domain/exception` | リスク受容の例外。デフォルトで永続化されない(必ず`ExpiresAt`が必要) |
| `audit.Entry` | `internal/domain/audit` | who/what/when/why/before/afterを記録する不変の監査ログ |
| `policy.AutoRemediationPolicy` | `internal/domain/policy` | 自動修復ポリシー。ゼロ値はすべて拒否する安全側デフォルト |

## 4. セットアップとビルド

必要なもの: Go 1.24+、Docker(PostgreSQL用)。

```bash
git clone https://github.com/ac1965/RiskForge.git
cd RiskForge

make up                # docker compose up -d でPostgreSQLを起動
export RISKFORGE_DATABASE_URL="postgres://riskforge:riskforge@localhost:5432/riskforge?sslmode=disable"

make build              # ./bin に riskforge / riskforge-agent / riskforge-worker をビルド
./bin/riskforge migrate # スキーマを適用(migrations/*.sql を go:embed 経由で実行)
```

その他のMakeターゲット:

```bash
make test              # go test ./...(Dockerは不要)
make test-integration  # go test -tags=integration ./...(testcontainers-goで実PostgreSQLコンテナを起動)
make vet                # go vet ./...
make migrate-up        # migrate CLI(別途インストール要)で $RISKFORGE_DATABASE_URL に適用
make migrate-down      # マイグレーションを1つロールバック
make down               # docker compose down
```

`riskforge migrate` は `migrate` CLIのインストールを必要とせず、埋め込んだ
SQLを直接適用します(`migrations/embed.go`)。`make migrate-up`/
`make migrate-down` は代わりに外部の`migrate`コマンドを使う形です
([migrations/README.md](../migrations/README.md))。

## 5. クイックスタート

`$RISKFORGE_DATABASE_URL` を設定し、`riskforge migrate` を実行済みである
ことが前提です。以下は「Assetを登録してから脆弱性を是正・検証するまで」
の一通りの流れです。

```bash
# 1) Assetを登録する(discover_assets)
riskforge asset discover \
  --hostname web01.internal \
  --type server --environment production \
  --criticality critical --exposure-level direct --internet-exposed \
  --owner "platform-team" --business-unit "e-commerce"
# => asset <ASSET_ID> (web01.internal) discovered

riskforge asset list
riskforge asset inspect <ASSET_ID>

# 2) Vulnerabilityを登録する(NVD/KEV/OSV連携はPhase 5。ここでは手動登録)
riskforge vulnerability add \
  --cve-id CVE-2024-00000 --title "Example remote code execution" \
  --severity critical --cvss-v3 9.8
# => vulnerability <VULN_ID> recorded

# 3) FindingとしてAssetとVulnerabilityを関連付ける(correlate_findings)
riskforge finding correlate \
  --asset <ASSET_ID> --vulnerability <VULN_ID> \
  --source "manual" --confidence confirmed
# => finding <FINDING_ID> (open) recorded

riskforge finding list
riskforge finding show <FINDING_ID>

# 4) Riskを評価し、Priorityを計算する(assess_risk → calculate_priority)
riskforge risk assess --finding <FINDING_ID>
# => finding <FINDING_ID>: risk 92.0 (critical)

riskforge priority calculate --finding <FINDING_ID>
# => finding <FINDING_ID>: priority 100.0 (critical)

riskforge priority list

# 5) Remediationを提案・承認・Dry Run・実行する
riskforge remediation propose <FINDING_ID> \
  --action-type patch --description "Apply vendor patch 1.2.3" \
  --proposed-by "alice" --rollback-capable --rollback-plan "downgrade to 1.2.2"
# => remediation plan <PLAN_ID> proposed (proposed)

riskforge remediation execute <PLAN_ID> --executed-by alice --reason test
# => エラー: 承認前は実行できない(proposed -> in_progress は不正な遷移)

riskforge remediation approve <PLAN_ID> --approved-by bob --reason "verified with vendor"
riskforge remediation preview <PLAN_ID> --target "package foo 1.2.2 -> 1.2.3"
riskforge remediation execute <PLAN_ID> --executed-by alice --reason "maintenance window"
# => Findingが remediated に遷移する

# 6) Evidenceを記録し、Verificationで検証する
riskforge evidence record \
  --type verification_result --source "manual re-check" \
  --asset <ASSET_ID> --finding <FINDING_ID> \
  --location "s3://evidence-bucket/web01/2026-09-25.txt" \
  --file ./local-check-output.txt

riskforge verify <FINDING_ID> \
  --method version_check --result pass \
  --evidence <EVIDENCE_ID> --performed-by alice --reason "post-patch check"
# => Findingが verified に遷移する
```

Exceptionのライフサイクル(例外承認 → 期限切れ再評価)は別フローです。

```bash
riskforge exception request \
  --finding <FINDING_ID> --reason "vendor patch not yet available" \
  --requested-by alice --expires-at 2026-12-31T00:00:00Z \
  --compensating-control "WAF rule #123" --max-duration-days 90

riskforge exception approve <EXCEPTION_ID> --approved-by bob --reason "acceptable short-term risk"
# => Findingが accepted に遷移する

riskforge exception list
riskforge exception expire <EXCEPTION_ID> --reason "reached expiry date"
# => Findingが reopened に遷移し、再評価の対象になる
```

## 6. CLIコマンドリファレンス

すべてのコマンドは `internal/application.Service` のNamed API
(AGENTS.md §26)を呼び出すだけで、Domain・Infrastructureへ直接アクセス
しません。`riskforge migrate` を除くすべてのコマンドは
`$RISKFORGE_DATABASE_URL` が必要です(`--help`/`--version`は不要)。

### asset

| コマンド | 必須フラグ | 説明 |
| --- | --- | --- |
| `riskforge asset discover` | `--hostname` | `discover_assets()`。同じhostnameなら新規作成ではなく既存Assetを更新(idempotent) |
| `riskforge asset list` | – | 全Assetを一覧表示 |
| `riskforge asset inspect <id>` | – | 単一Assetの詳細を表示 |

### vulnerability

| コマンド | 必須フラグ | 説明 |
| --- | --- | --- |
| `riskforge vulnerability add` | `--title` | 手動でVulnerabilityを登録。NVD/KEV/OSV連携ができるまでの暫定手段(Phase 5で置き換え予定) |

### finding

| コマンド | 必須フラグ | 説明 |
| --- | --- | --- |
| `riskforge finding correlate` | `--asset`, `--vulnerability`, `--source` | `correlate_findings()`。同じ`(asset, vulnerability)`の組は新規作成ではなく既存Findingを再確認(idempotent) |
| `riskforge finding list` | – | 全Findingを一覧表示 |
| `riskforge finding show <id>` | – | 単一Findingの詳細を表示 |

### risk / priority

| コマンド | 必須フラグ | 説明 |
| --- | --- | --- |
| `riskforge risk assess` | – (`--finding`は省略可) | `assess_risk()`。`--finding`省略時は全Findingを評価し、失敗があっても処理を継続する |
| `riskforge priority calculate` | – (`--finding`は省略可) | `calculate_priority()`。対象Findingに`risk.Assessment`が既に存在している必要がある |
| `riskforge priority list` | – | 各Findingの最新Priority Decisionを一覧表示 |

### remediation

| コマンド | 必須フラグ | 説明 |
| --- | --- | --- |
| `riskforge remediation list` | – | 全RemediationPlanを一覧表示 |
| `riskforge remediation propose <finding>` | `--action-type`, `--description`, `--proposed-by` | `create_remediation_plan()`。`--rollback-capable`が偽なら`--rollback-reason`が必要 |
| `riskforge remediation approve <plan>` | `--approved-by`, `--reason` | Proposed → Approvedへの唯一の経路。監査対象(`remediation_approval`) |
| `riskforge remediation preview <plan>` | `--target` | Dry Run(§33)。変更は一切行わない |
| `riskforge remediation execute <plan>` | `--executed-by`, `--reason` | `execute_remediation()`。承認前のPlanに対しては失敗する。監査対象(`remediation_execution`) |

### verify / evidence

| コマンド | 必須フラグ | 説明 |
| --- | --- | --- |
| `riskforge verify <finding>` | `--method`, `--result`, `--evidence`, `--performed-by`, `--reason` | `verify_remediation()`。`--result inconclusive`はFindingを動かさない(§20A.6.1) |
| `riskforge evidence record` | `--type`, `--source`, `--asset`, `--location` | `record_evidence()`。`--file`を渡すとSHA-256ハッシュを自動計算(`--content-hash`で直接指定も可) |
| `riskforge evidence show <id>` | – | 単一Evidenceの詳細を表示 |

### exception

| コマンド | 必須フラグ | 説明 |
| --- | --- | --- |
| `riskforge exception request` | `--finding`, `--reason`, `--requested-by`, `--expires-at` | 永続的な例外はデフォルトで作れない(`--expires-at`必須)。`--max-duration-days`で組織上限を強制できる |
| `riskforge exception approve <id>` | `--approved-by`, `--reason` | 承認するとFindingが`accepted`になる。監査対象(`exception_approval`) |
| `riskforge exception reject <id>` | – | 却下。Findingは動かない |
| `riskforge exception expire <id>` | – (`--reason`は省略可) | 承認済み例外を期限切れにする。Findingが`reopened`になり再評価対象になる。監査対象(`exception_expiration`) |
| `riskforge exception revoke <id>` | – | 期限前に例外を取り消す。Findingが`reopened`になる |
| `riskforge exception list` | – | 全Exceptionを一覧表示 |

### migrate

| コマンド | 説明 |
| --- | --- |
| `riskforge migrate` | `migrations/*.sql`(go:embed)を適用。`$RISKFORGE_DATABASE_URL`のみで動作し、`migrate`外部CLIは不要 |

## 7. Risk EngineとPriority Engine

RiskとPriorityは、固定の掛け算式ではなく、差し替え可能な
Provider/Policyの組み合わせとして実装されています(AGENTS.md §8、§12、
[ADR 0002](adr/0002-risk-engine.md))。

```mermaid
graph LR
    subgraph RiskEngine["risk.Engine"]
        direction TB
        SP[SeverityProvider] --> RPolicy["risk.Policy<br/>(BaselinePolicy)"]
        EP[ExploitabilityProvider] --> RPolicy
        ACP[AssetCriticalityProvider] --> RPolicy
        EXP[ExposureProvider] --> RPolicy
        BIP[BusinessImpactProvider] --> RPolicy
    end

    subgraph PriorityEngine["priority.Engine"]
        direction TB
        EP2["Exploitability/AssetCriticality/<br/>ExposureProvider (risk.*を再利用)"] --> PPolicy["priority.Policy<br/>(BaselinePolicy)"]
        RAP[RemediationAvailabilityProvider] --> PPolicy
        BCP[BusinessConstraintsProvider] --> PPolicy
        SLAP[SLAPolicy]
    end

    RPolicy --> RA["risk.Assessment<br/>Score / Level / Factors"]
    RA -->|"in.Risk"| PPolicy
    PPolicy --> PD["priority.Decision<br/>Rank / Level / Factors / SLADeadline"]
    SLAP --> PD
```

`Engine`自体はスコアを計算しません。Providerの出力を集めて`Policy.Evaluate`
に渡すだけであり、実際の計算式は`Policy`実装の中に閉じています。
`cmd/riskforge/main.go`は現時点でデフォルトのProvider
(`FromVulnerabilityProvider`/`FromAssetProvider`等、既にロード済みの
Asset/Vulnerability/Findingから読むだけの実装)と`BaselinePolicy`を配線
しています。KEV/EPSSのような外部脅威インテリジェンスや、CMDB連携の
Business Impactは、まだ実装されていないInfrastructure層のProviderに
差し替えることで導入できます。

### すべてのスコアは説明可能でなければならない(§40)

`risk.Assessment`と`priority.Decision`は、いずれも
`explainability.Factor`のリストを1件以上持たなければ生成できません
(`risk.New`/`priority.New`がゼロ件を拒否)。例えば`BaselinePolicy`が
CVSSv3 9.8・CISA KEV掲載・internet-exposed・critical Assetの
Findingを評価すると、次のようなFactorが積み上がります。

| Factor | Value | Reason |
| --- | --- | --- |
| `severity` | `critical` | Vulnerability severity is critical |
| `cvss_v3` | `9.8` | CVSSv3 base score 9.8 |
| `kev_listed` | `true` | CISA Known Exploited Vulnerabilities (KEV) listed |
| `exposure` | `internet_exposed` | Internet exposed |
| `asset_criticality` | `critical` | Asset criticality: critical |

CLIやAPIは、Risk Score/Priority Rankを単独で表示するのではなく、
常にこのFactor一覧とともに示すことを前提としています。

### Priorityは「Riskからの再重み付け」である

`priority.BaselinePolicy`はAGENTS.md §12の例をそのまま体現しています:
同じRisk Scoreから出発し、`AssetCriticality`と`Exposure`を再度加点し
(本番・internet-facing・業務クリティカルなAssetを、同じ技術的深刻度の
社内限定Assetより上位にする)、さらに`RemediationAvailability`
(是正手段が既にあるFindingは即対応可能として加点)と
`BusinessConstraints`(コンプライアンス期限が30日以内なら加点、
Change Freeze中である旨はFactorとして記録するがスコアは変えない)を
加味します。`risk.Policy`が一切関知しないこの2つの入力こそが、
「RiskとPriorityは別物」という不変条件2を実際に成立させています。

### SLA(§43)

`priority.SLAPolicy`はPriority Levelから是正期限を計算します。
`DefaultSLAPolicy`はAGENTS.md §43の例(Critical: 7日、High: 30日、
Medium: 90日、Low: 180日)をデフォルト値として提供しますが、これは
「唯一の値」ではなく組織ポリシーとして差し替え可能な設定です。

## 8. ライフサイクルと状態遷移

3つの主要エンティティは、いずれもドメイン層のステートマシンとして
不正な遷移を拒否します。Application層はこれを迂回できません。

### Finding(AGENTS.md §16)

```mermaid
stateDiagram-v2
    [*] --> open
    open --> mitigated
    open --> remediated
    open --> accepted
    open --> false_positive
    mitigated --> remediated
    mitigated --> reopened
    mitigated --> accepted
    mitigated --> false_positive
    remediated --> verified
    remediated --> reopened
    verified --> reopened
    reopened --> mitigated
    reopened --> remediated
    reopened --> accepted
    reopened --> false_positive
    accepted --> reopened
    false_positive --> reopened
```

`open`/`mitigated`から`verified`へ直接遷移できない点に注意してください。
必ず`remediated`を経由します — これが不変条件6
(「Detected ≠ Verified Remediated」)をコードレベルで強制している部分
です。

### RemediationPlan(AGENTS.md §14、§15)

```mermaid
stateDiagram-v2
    [*] --> proposed
    proposed --> approved
    proposed --> cancelled
    approved --> scheduled
    approved --> in_progress
    approved --> cancelled
    scheduled --> in_progress
    scheduled --> cancelled
    in_progress --> completed
    in_progress --> failed
    completed --> rolled_back
    failed --> rolled_back
    failed --> cancelled
    rolled_back --> [*]
    cancelled --> [*]
```

`proposed → in_progress`という直接遷移は存在しません。承認
(`remediation approve`)を経由しない実行経路はドメインに存在せず、これが
「自動修復はデフォルトで無効」(§15、§47.7)を実際に強制しています。

### Exception(AGENTS.md §18)

```mermaid
stateDiagram-v2
    [*] --> requested
    requested --> approved
    requested --> rejected
    approved --> expired
    approved --> revoked
    rejected --> [*]
    expired --> [*]
    revoked --> [*]
```

`Approved`のみが`Expired`/`Revoked`に進めます。一度も承認されなかった
`Rejected`のリクエストはFindingを一切動かしません。

### `ImpliedFindingStatus` パターン

`remediation.Plan`・`verification.Verification`・`exception.Exception`
はいずれも`ImpliedFindingStatus()`を持ちますが、どれも
`finding.TransitionTo`を直接呼び出しません。Planは`FindingID`しか
保持しておらず、別の集約を直接変更できないためです
([ADR 0003](adr/0003-remediation-safety.md))。Application層
(`internal/application`)がこの戻り値を読み取り、
`Finding.TransitionTo`を呼び出して初めて遷移が確定します。

| 発生源 | 状態 | 暗示するFinding遷移 |
| --- | --- | --- |
| RemediationPlan | 完了(`accept_risk`以外) | `remediated` |
| RemediationPlan | 完了(`accept_risk`) | `accepted` |
| Verification | `pass` | `verified` |
| Verification | `fail` | `reopened` |
| Verification | `inconclusive` | 遷移なし(§20A.6.1: 検証できなかったことは「まだ脆弱」の証拠にならない) |
| Exception | 承認 | `accepted` |
| Exception | 期限切れ/取り消し | `reopened` |

次のシーケンス図は、`riskforge remediation execute`が実際にどう流れる
かを示しています。

```mermaid
sequenceDiagram
    participant User as オペレーター (CLI)
    participant CLI as internal/cli
    participant Svc as application.Service
    participant Plan as remediation.Plan (Domain)
    participant Exec as RemediationExecutor
    participant PG as postgres Repository
    participant Audit as audit.Entry

    User->>CLI: riskforge remediation execute <plan>
    CLI->>Svc: ExecuteRemediation(ctx, planID, ...)
    Svc->>PG: RemediationPlans.FindByID(planID)
    PG-->>Svc: *remediation.Plan
    Svc->>Plan: Start(at)
    Note over Plan: Approved以外からは失敗する
    Svc->>PG: RemediationPlans.Save(plan)
    Svc->>Exec: Execute(ctx, plan, target)
    Exec-->>Svc: nil (成功) または error
    Svc->>Plan: Complete() または Fail()
    Svc->>PG: RemediationPlans.Save(plan)
    Svc->>Svc: applyFindingStatus(plan.ImpliedFindingStatus())
    Svc->>Audit: audit.New(remediation_execution)
    Svc->>PG: Audit.Save(entry)
    Svc-->>CLI: *remediation.Plan
    CLI-->>User: "remediation plan <id>: completed"
```

`riskforge remediation execute`が使う`RemediationExecutor`は、現時点
では常に成功を返すプレースホルダー実装(`manualExecutor`)です。
AGENTS.md §31/§32が要求するvalidated/structured/allowlistedなコマンド
実行パイプラインは、まだInfrastructure層に実装されていません
([ADR 0010](adr/0010-cli-wiring.md))。これは「オペレーターが既に手動で
変更を加えており、CLIはその事実を記録しているだけ」という前提の上で
成立しています。

## 9. Evidenceと監査ログ

`evidence.Evidence`と`audit.Entry`はどちらも更新用メソッドを持たない
不変(immutable)なドメイン型です。訂正が必要な場合は新しいレコードを
追加します。

```bash
# ローカルファイルからハッシュを計算して記録する
riskforge evidence record \
  --type detection_result --source "trivy image scan" \
  --asset <ASSET_ID> --finding <FINDING_ID> \
  --location "s3://evidence-bucket/scan-2026-09-25.json" \
  --file ./scan-output.json

riskforge evidence show <EVIDENCE_ID>
```

Evidenceの`Type`は例示であり、クローズドなenumではありません
(AGENTS.md §17は「など」で終わる非網羅的なリストです)。

| 定数 | 用途 |
| --- | --- |
| `detection_result` | スキャナ等による検出結果そのもの |
| `package_info` | パッケージ情報 |
| `version_info` | バージョン情報 |
| `configuration` | 設定値のスナップショット |
| `remediation_execution` | Remediation実行結果 |
| `verification_result` | Verification結果 |

Audit(`internal/domain/audit`)は、AGENTS.md §30が明示的に列挙した
アクションについてのみ記録されます([ADR 0008](adr/0008-application-layer.md))。

| Action | 記録するコマンド | Who |
| --- | --- | --- |
| `risk_change` | `risk assess` | `system`(決定論的な自動計算のため) |
| `priority_change` | `priority calculate` | `system` |
| `remediation_approval` | `remediation approve` | `--approved-by` |
| `remediation_execution` | `remediation execute` | `--executed-by` |
| `verification` | `verify` | `--performed-by` |
| `exception_creation` | `exception request` | `--requested-by` |
| `exception_approval` | `exception approve` | `--approved-by` |
| `exception_expiration` | `exception expire` | `system` |

`remediation propose`・`evidence record`・`exception reject`・
`exception revoke`は、§30のリストに含まれていないため監査対象では
ありません。より広い監査が必要になった場合は、黙って追加するのでは
なく新しいADRで扱う方針です。

## 10. データベーススキーマ

PostgreSQL 16 + golang-migrateで管理しています
([ADR 0009](adr/0009-postgres-persistence.md)、
[migrations/README.md](../migrations/README.md))。単一の巨大な
`vulnerabilities`テーブルにすべてを詰め込まず、AGENTS.md §29の方針
どおりエンティティごとにテーブルを分離しています。

| # | テーブル | 対応するドメイン型 |
| --- | --- | --- |
| 000001 | `assets` | `asset.Asset` |
| 000002 | `software_installations` | `software.Installation` |
| 000003 | `vulnerabilities` | `vulnerability.Vulnerability` |
| 000004 | `findings` | `finding.Finding` |
| 000005 | `evidence` | `evidence.Evidence` |
| 000006 | `risk_assessments` | `risk.Assessment` |
| 000007 | `priority_decisions` | `priority.Decision` |
| 000008 | `remediation_plans` | `remediation.Plan` |
| 000009 | `verifications` | `verification.Verification` |
| 000010 | `exceptions` | `exception.Exception` |
| 000011 | `audit_log` | `audit.Entry` |

設計上の要点:

- **`findings.evidence_id` ↔ `evidence.finding_id`の循環参照**は、
  まず制約なしの`evidence_id`列付きで`findings`を作成し(000004)、
  `evidence`テーブル作成後に外部キーを追加する(000005)ことで解消して
  います。
- **配列・構造化データはJSONB**に格納します(`Asset.IPAddresses`、
  `Vulnerability.CWE`、`risk.Assessment.Factors`等)。Enum
  (`asset_type`、`severity`、`status`等)はPostgres `ENUM`型ではなく
  `CHECK`制約付きの`TEXT`です — 許容値の追加が`ALTER TYPE`より軽いため
  です。
- **追記専用 vs. upsert**: `assets`/`findings`/`remediation_plans`等の
  可変な集約は`INSERT ... ON CONFLICT (id) DO UPDATE`。
  `risk_assessments`/`priority_decisions`/`verifications`は履歴として
  常に新しい行を追加する素の`INSERT`。`evidence`/`audit_log`はいずれも
  `UPDATE`を一切発行しません(ドメイン型に更新メソッドがないことと
  対応)。
- **`remediation_actions`という独立テーブルは作っていません**。
  AGENTS.md §29の図には登場しますが、ドメインモデルには
  `remediation.Plan`という1エンティティしかないためです
  ([ADR 0009](adr/0009-postgres-persistence.md)参照)。

## 11. テスト

```bash
make test              # 単体テスト。Dockerを一切使わない
make test-integration  # 統合テスト。testcontainers-goで実PostgreSQLコンテナを起動する
```

`internal/infrastructure/postgres`の統合テストは`//go:build integration`
タグの背後にあり、`go test ./...`には含まれません。CIは両方を別ジョブ
として実行します(`.github/workflows/ci.yml`)。

```mermaid
graph LR
    A["go test ./..."] -->|Docker不要| B["Domainパッケージの単体テスト<br/>(risk/priority Engineを重点的に)"]
    C["go test -tags=integration ./..."] -->|testcontainers-go| D["実PostgreSQLに対する<br/>Repository統合テスト"]
```

`go mod tidy`はビルドタグの背後にあるimportを見えないため、
`make tidy`は`GOFLAGS=-tags=integration go mod tidy`を実行して
testcontainers-go関連の依存を`go.mod`/`go.sum`から落とさないように
しています。

## 12. 実装状況

| フェーズ(AGENTS.md §45) | 内容 | 状況 |
| --- | --- | --- |
| Phase 1 | Asset / Software / Vulnerability / Finding | 実装済み |
| Phase 2 | Risk Engine / Priority Engine | 実装済み(Dashboard/フロントエンドは未着手、§25A.7どおりバックエンド優先) |
| Phase 3 | Remediation / Verification / Evidence | 実装済み(実際のコマンド実行パイプライン§31/§32は未実装、`manualExecutor`で代替) |
| Phase 4 | Exception / Policy / Audit | 実装済み(汎用の永続化Policy集約は意図的に未実装、[ADR 0007](adr/0007-exception-policy-audit.md)参照) |
| Phase 5 | Automation / AI assistance / Integrations | 未着手。PownForge連携・NVD/KEV/OSV Data Source Adapterはここに含まれる |

具体的に未実装なもの:

- `internal/api`: パッケージの骨格(`net/http`方針の宣言)のみ。ハンドラー
  実装はまだない
- `internal/infrastructure/datasource`: NVD/CISA KEV/OSV等のAdapter
  インターフェースの説明のみ。実装はまだない(§19)
- `riskforge-agent` / `riskforge-worker`: バイナリの骨格のみで、
  実行すると "not implemented yet" を返す
- `application.RemediationExecutor`の実装: `internal/cli`の
  `manualExecutor`が唯一の実装で、実際のOSコマンド実行は行わない
- PownForge連携(§20A): 両プロジェクトとも未実装。詳細は
  [第14章](#14-pownforgeとの関係姉妹プロジェクト)

## 13. ADRダイジェスト(設計判断の索引)

重要な設計判断は、本書のような要約ではなく`docs/adr/`配下のADR
(Architecture Decision Record)が正本です(AGENTS.md §49)。ADRは番号を
付けて追記し続けるものであり、本書に吸収して個別ファイルを廃止すること
はしません。ここでは全体を見渡せるよう、各ADRの決定を1〜2行に要約した
索引だけを置きます。詳細・背景(Context)・影響(Consequences)は各ADR本文
を参照してください。

| # | タイトル | 決定の要約 |
| --- | --- | --- |
| [0001](adr/0001-domain-model.md) | コアドメインモデルとレイヤリング | AGENTS.md §3–§25のエンティティ・不変条件・`UI→Application→Domain→Infrastructure`のレイヤリングをそのまま採用。Phase 1はAsset/Software/Vulnerability/Findingのみを実装し、残りは後続フェーズへ先送り |
| [0002](adr/0002-risk-engine.md) | Risk / Priority Engineの設計 | RiskとPriorityを固定の計算式ではなくProvider/Policyの組み合わせとして実装。`BaselinePolicy`は「唯一の式」ではなく差し替え可能なリファレンス実装の1つ |
| [0003](adr/0003-remediation-safety.md) | Remediation / Verificationの安全性モデル | `remediation.Plan`のステートマシンが`Proposed→InProgress`の直接遷移を禁止し、承認ゲートをドメインレベルで強制。Verificationの`Inconclusive`はFinding遷移を発生させない |
| [0004](adr/0004-evidence-model.md) | Evidenceモデル | `evidence.Evidence`は更新用メソッドを持たず、訂正は常に新しいレコードとして追加。`ContentHash`/`Location`の役割を分離 |
| 0005 | PownForge連携 | 未作成。連携はPhase 5(Integrations)で設計・記録される予定(§20A.10、[第14章](#14-pownforgeとの関係姉妹プロジェクト)参照) |
| [0006](adr/0006-api-routing.md) | APIルーティング | サードパーティルーターを使わず、標準ライブラリの`net/http`+`http.ServeMux`を採用。ルーター導入には新ADRが必要 |
| [0007](adr/0007-exception-policy-audit.md) | Exception / Policy / Auditのドメインモデル | Exception・Auditは§18/§30のフィールドリストをそのまま実装。汎用的で永続化・バージョン管理されたPolicy集約はあえて作らず、`AutoRemediationPolicy`のみを実装 |
| [0008](adr/0008-application-layer.md) | Application層: Named APIとports | Repository interfaceを`ports.go`に集約。§26に例示のない`ApproveRemediationPlan`とException操作群を追加。監査対象は§30が明示した8アクションのみに限定 |
| [0009](adr/0009-postgres-persistence.md) | PostgreSQL永続化とマイグレーション | pgx+`database/sql`を採用し、配列・構造化データはJSONBに格納。`findings`⇔`evidence`の循環参照解消手順と、追記専用/upsertの使い分けを定義 |
| [0010](adr/0010-cli-wiring.md) | CLI配線 | `cmd/riskforge/main.go`をcomposition rootとし、`internal/cli`はPostgreSQLの存在を知らない。§27に例示のないコマンド(`asset discover`等)を追加した理由と、`manualExecutor`による暫定実行を記録 |

## 14. PownForgeとの関係(姉妹プロジェクト)

[PownForge](https://github.com/ac1965/PownForge)は、RiskForgeと対になる
攻撃側のプロジェクトです(別リポジトリ、Python/Typer製)。PownForgeが
許可されたラボ・検証環境に対する発見・検証を担うのに対し、RiskForgeは
是正の計画・承認・実行管理・検証結果の記録を担います。

```mermaid
flowchart TD
    PF["PownForge (攻撃側)<br/>発見・検証スキャン"]
    RF1["RiskForge (防御側)"]
    Target["対象Asset"]
    RF2["RiskForge"]

    PF -->|"Finding / Evidence"| RF1
    RF1 -->|Remediation| Target
    Target -->|"Verification<br/>(PownForgeによる再スキャン)"| RF2
```

連携の設計制約は本書ではなく
[AGENTS.md §20A "PownForge Integration"](../AGENTS.md#20a-pownforge-integration)
が正本です。要点のみここに記します。

- **PownForgeは外部Scannerとして扱う**: PownForgeの結果は、RiskForgeの
  `Finding`にそのまま取り込まれるのではなく、AGENTS.md 第20章のScanner
  経路(RawFinding → Normalizer → Matcher → Finding)を経由する
- **CVEを持たない診断結果**(設定不備、認可・認証の欠陥等)も破棄せず、
  既知のVulnerabilityに対応付けるか、独自IDのVulnerabilityとして登録
  するか、Confidenceを下げたRawFindingとして保留する
- **PownForgeによる成立確認は`exploitation_observed`ではない**:
  「この環境で成立した」という事実と「実環境で攻撃されている」という
  外部観測は別項目として保持する
- **PownForgeはRemediationを実行しない**。RiskForgeも攻撃的なテストを
  Remediationの一部として実行しない
- **PownForgeによる再スキャンはVerificationの一種
  (`scanner_rescan`)として許可され得る**が、allowlist・承認と実行の
  分離・production環境でのDry Run必須・Audit Log記録が必須条件
- **Evidenceはコピーではなく参照とハッシュで引き継ぐ**。取り込み時に
  Evidenceを書き換えない

この連携はRiskForge側でPhase 5(Integrations)として設計されており、
**両プロジェクトとも未実装**です。どちらかのPhase実装に便乗して連携
コードを先行実装しない、という制約はAGENTS.md §20A.10に明記されて
います。連携仕様の重要な判断は`docs/adr/0005-pownforge-integration.md`
として記録される想定ですが、本書執筆時点ではまだ作成されていません。

### 14.1 ATT&CK語彙の準備状況(PownForge側からの提案、記録のみ)

**重要(コード変更なし)**: 本節はPhase 5連携の実装ではなく、PownForge側
指示書(v3 §9)・RiskForge側指示書(v5 §7)が定める「連携コードは明示的な
依頼がない限り実装しない」制約の**手前**にある、ドキュメントレベルの
記録です。ユーザーから「これは連携実装ではなく準備作業か」の確認を得た
上で(2026-09-26)、以下の記録のみを追記しました。コード変更・新規ADRの
起票は行っていません。

- PownForge側は2026-09-26、`docs/handbook.md`(第14章「`AttackOperation`
  モデル」・第18.6章)に、MITRE ATT&CK技術IDの語彙(`T1190`/`T1210`/
  `T1552.004`)を**PownForge側からの提案**として確定しました
  (PownForgeリポジトリのコミット`c8f7e93`)。
- この語彙は、`Finding`(RiskForge側)が将来ATT&CKタグを持つ場合の
  出発点になり得ますが、**RiskForge側では現時点で採用・実装しません**。
  `RawFinding`自体がまだフィールドレベルで未実装(第20章参照)のため、
  ATT&CKタグをどこに・どう保持するかはPhase 5でRawFinding/Normalizerを
  設計する際にあらためて判断します。
- PownForge側`Finding`とRiskForge側`RawFinding`(概念)の対応表は、
  PownForge側`docs/handbook.md` §18.5に整理されています。RiskForge側の
  対応表はここでは新設せず、Phase 5着手時にPownForge側の整理を出発点
  として参照する想定です。
- この記録自体は設計判断(ADR記録義務、AGENTS.md §48)には該当しない
  ため、新規ADRは起票していません。ATT&CKタグの採用方針を実際に決める
  場合は、`docs/adr/0005-pownforge-integration.md`(Phase 5着手時に作成)
  または0013以降の番号で別途ADR化してください。

## 15. 付録: 用語集

本書とAGENTS.mdで使われる用語をまとめます。定義の正本はAGENTS.mdの
該当節であり、ここでは実装(型名・値)と対応付けて簡潔に説明します。

### ライフサイクルの中核用語(AGENTS.md §3–§18)

| 用語 | 説明 |
| --- | --- |
| Asset | IT資産そのもの。システムの中心エンティティ(`asset.Asset`、§4) |
| Software Installation | Asset上にインストールされたソフトウェア(`software.Installation`、§5) |
| Vulnerability | 脆弱性そのもの。CVE等の外部識別子と技術的深刻度を持つ(`vulnerability.Vulnerability`、§6)。**Findingとは別物**(不変条件1) |
| Finding | 「特定のAssetに特定のVulnerabilityが検出された」という実環境上の事実(`finding.Finding`、§7) |
| Risk / RiskAssessment | Findingの組織内における実リスクをRisk Engineが評価した結果(`risk.Assessment`、§8)。**CVSSやPriorityとは別物**(不変条件2・5) |
| Priority / PriorityDecision | 「何を先に対応するか」をPriority Engineが決定した結果(`priority.Decision`、§12) |
| Remediation / RemediationPlan | Findingを是正するための計画。パッチ適用に限らない(`remediation.Plan`、§13–§14) |
| Verification | Remediationが実際に効いたかどうかの検証(`verification.Verification`、§16)。**Remediation完了そのものとは別物**(不変条件3) |
| Evidence | 検出結果・設定値・実行結果などを裏付ける、改ざん検知可能な証跡(`evidence.Evidence`、§17)。**Findingとは別物**(不変条件4) |
| Exception | 誤検知や期限付きのリスク受容を表す正式な状態(`exception.Exception`、§18) |
| Audit(Entry) | 重要操作のwho/what/when/why/before/afterを記録する不変の監査ログ(`audit.Entry`、§30) |

### Risk / Priority Engineの用語(AGENTS.md §8–§12、§40、§43)

| 用語 | 説明 |
| --- | --- |
| Severity | Vulnerability自体の技術的深刻度(critical/high/medium/low/none/unknown)。組織リスクとは別軸(§6、§44不変条件5) |
| Exploitability | 悪用可能性に関する脅威インテリジェンスのスナップショット。`exploit_exists`・`public_exploit`・`exploitation_observed`・`kev_listed`等を個別に保持し混同しない(`risk.Exploitability`、§9) |
| CISA KEV | CISAが公表する「実際に悪用が確認された脆弱性」のリスト(Known Exploited Vulnerabilities)。`KEVListed`として個別に保持 |
| Exploit Prediction | 悪用確率の予測値(EPSS等を想定した0〜1のスコア)。`Exploitability.ExploitPrediction` |
| Asset Criticality | Assetの業務上の重要度(critical/high/medium/low/unknown)。技術情報から自動推定せず、業務側(CMDB等)から与えられる値(§11) |
| Exposure | Assetが攻撃者からどの程度到達可能かを表す多面的な状態。単一のbooleanにしない(`asset.Exposure`、§10) |
| Business Impact | データ分類・可用性/機密性/完全性要件などの業務影響。Asset Criticalityより詳細な業務コンテキスト(`risk.BusinessImpact`、§11) |
| CVSS(v3/v4) | Common Vulnerability Scoring Systemの基本スコア。Vulnerabilityの技術的深刻度の一指標であり、Risk Scoreそのものではない(§6、§44不変条件5) |
| Explainability / Factor | Risk Score・Priority Rankを「なぜその値になったか」まで説明する仕組み。1件以上のFactorなしにAssessment/Decisionは生成できない(`explainability.Factor`、§40) |
| Provider | Severity・Exploitability・AssetCriticality等、Engineへの入力を1つずつ集めるinterface。実装は差し替え可能(§8、§12) |
| Policy | Providerの出力からScore/Rank/Levelと説明を計算するinterface。`BaselinePolicy`はリファレンス実装の1つであり「唯一の式」ではない(§8、§12、§23) |
| Engine | Provider群とPolicyを組み合わせ、Assessment/Decisionを生成する調整役。Engine自体はスコアを計算しない(`risk.Engine`/`priority.Engine`) |
| SLA(Deadline) | Priority Levelごとに定める是正期限。固定値ではなく組織ポリシーとして差し替え可能(`priority.SLAPolicy`、§43) |

### Remediationの用語(AGENTS.md §13–§15、§31–§34)

| 用語 | 説明 |
| --- | --- |
| Action Type | Remediationの種別。`patch`/`upgrade`/`configuration_change`/`disable_feature`/`disable_service`/`remove_software`/`access_control`/`network_segmentation`/`virtual_patch`/`compensating_control`/`temporary_mitigation`/`accept_risk`(§13) |
| Virtual Patch | パッチを直接適用せず、WAF等で一時的に悪用経路を遮断する対処 |
| Compensating Control | 根本的な是正の代わりに、リスクを緩和する代替的な統制 |
| Dry Run | Remediation実行前に、対象・変更内容・Rollback方法をプレビューする仕組み。変更を一切行わない(`Plan.DryRun`、§33) |
| Rollback | Remediation実行後に変更を元に戻す手順。ロールバック不能な場合はその旨を`Reason`として明示する(`remediation.Rollback`、§34) |
| Approval(承認) | RemediationPlanが`Proposed`から`InProgress`へ進む前に必ず経由する承認ゲート。自動修復をデフォルト無効にする実装上の要(§15、§47.7) |
| Auto Remediation Policy | 自動実行を許可する条件(対象種別・環境・アクション種別・保守枠等)を定める設定。ゼロ値はすべて拒否する安全側デフォルト(`policy.AutoRemediationPolicy`、§15) |

### 状態・ステータス

| 用語 | 説明 |
| --- | --- |
| Finding Status | `open`/`mitigated`/`remediated`/`verified`/`reopened`/`accepted`/`false_positive`。遷移ルールは[第8章](#8-ライフサイクルと状態遷移)参照(§16) |
| Confidence | 検出結果の確からしさ。`confirmed`/`high`/`medium`/`low`/`unknown`。バージョン推定だけでは`confirmed`にしない(§21) |
| RemediationPlan Status | `proposed`/`approved`/`scheduled`/`in_progress`/`completed`/`failed`/`rolled_back`/`cancelled`(§14) |
| Exception Status | `requested`/`approved`/`rejected`/`expired`/`revoked`(§18) |
| Verification Result | `pass`/`fail`/`inconclusive`。`inconclusive`(検証不能)は`fail`とは区別し、Finding遷移を発生させない(§16、§20A.6.1) |
| False Positive | 誤検知。削除せずEvidenceと理由を残し、Suppression/Exceptionで再検出時の重複生成を防ぐ(§22) |

### アーキテクチャ・実装用語(AGENTS.md §25–§30、§37–§38)

| 用語 | 説明 |
| --- | --- |
| Named API | CLI/APIがDomainへ直接立ち入らず呼び出す、Application層の公開関数群(`assess_risk()`等、§26) |
| Port / Repository | ApplicationとInfrastructureの間の継ぎ目となるinterface。Applicationが定義しInfrastructureが実装する(`ports.go`、§25) |
| Composition Root | PostgreSQLやEngineの実装を1箇所で組み立て、他の層へ注入するコード(`cmd/riskforge/main.go`) |
| Layering(レイヤリング) | `UI → Application → Domain → Infrastructure`という依存方向の原則。Domainは外部依存を直接importしない(§25) |
| Invariant(不変条件) | レイヤーや機能をまたいで常に成立しなければならない性質。[第3章](#3-ドメインモデル)の6項目(§44) |
| ADR(Architecture Decision Record) | 重要な設計判断とその理由を記録する文書。`docs/adr/`配下に番号付きで蓄積する正本(§49、[第13章](#13-adrダイジェスト設計判断の索引)) |
| Idempotency(冪等性) | 同じデータを繰り返し投入しても重複Findingなどを大量生成しない性質。Asset発見・Software棚卸・Finding相関等で要求される(§37) |
| Provenance(出典) | 外部データソース(NVD/KEV/OSV等)から取り込んだ情報の出所を記録する仕組み。`source`/`source_id`/`retrieved_at`等(`vulnerability.Provenance`、§38) |
| Policy Engine | 判断ロジックをコードに散らさず、設定として管理する仕組み。RiskForgeでは`risk.Policy`/`priority.Policy`/`AutoRemediationPolicy`等として部分的に実装済み(§23) |

### 組織・ガバナンス用語(AGENTS.md §4、§11、§12)

| 用語 | 説明 |
| --- | --- |
| Business Criticality | 業務側が定める重要度。Asset Criticalityより詳細な区分を持ちうる(§11) |
| Data Classification | 扱うデータの機密度分類 |
| Environment | Assetが稼働する環境。`production`/`staging`/`development`/`test`/`management`/`unknown`(§4) |
| Lifecycle State | Assetのライフサイクル上の位置。`active`/`inactive`/`decommissioned`/`unknown`(§4) |
| Change Freeze | 変更凍結期間。Priority計算のFactorとして記録されるが、スコアそのものは変えない |
| Maintenance Window | 保守作業が許可される時間帯。Auto Remediation Policyの実行条件の1つ |
| Compliance Deadline | 規制・契約上の対応期限。近づくとPriorityが加点される |

### PownForge連携の用語(AGENTS.md §20A、Phase 5予定)

| 用語 | 説明 |
| --- | --- |
| RawFinding | 外部Scanner(PownForge等)の生の診断結果。正規化前の中間表現(§20) |
| Normalizer | RawFindingを検証・正規化する処理 |
| Matcher | 正規化された結果を既知のVulnerability/Findingへ対応付ける処理 |
| source / source_ref | Evidenceの出所と、出所側(PownForge)での識別子。参照とハッシュで引き継ぎ、コピーしない(§20A.4) |
| content_hash | Evidenceの内容が改ざん・破損していないかを検証するハッシュ値 |
| scanner_rescan | Verificationの一手法。PownForge等による再スキャンで是正結果を確認する(§20A.6) |
| exploitation_observed | 実環境で実際に攻撃が観測されたという外部情報。PownForgeによる「この環境で成立確認した」という事実とは別項目(§9、§20A.3) |
