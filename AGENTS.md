# AGENTS.md

## Project: Vulnerability & Exposure Management Platform

このリポジトリは、企業・組織のIT資産について、

> **Asset → Software → Vulnerability → Risk → Prioritization → Remediation → Verification → Evidence**

という一連のライフサイクルを管理する、防御目的の Vulnerability / Exposure Management Platform を開発する。

単なる脆弱性スキャナではなく、**「何が脆弱なのか」ではなく「何を、なぜ、どの順番で、どの方法で是正すべきか」まで管理するシステム**を目標とする。

---

# 1. 最重要原則

## 1.1 本プロジェクトの目的

本システムの目的は以下である。

1. IT資産を継続的に把握する
2. 資産上で稼働するOS・ソフトウェア・サービスを把握する
3. 脆弱性を正規化して関連付ける
4. 脆弱性の技術的深刻度だけでなく、実環境におけるリスクを評価する
5. 対応すべき脆弱性を優先順位付けする
6. パッチ適用・設定変更・緩和策・Virtual Patch等の是正方法を管理する
7. 是正後に再評価する
8. 対応結果をEvidenceとして追跡可能にする

---

# 2. やってはいけないこと

## 2.1 単純なCVSSランキングにしない

以下のような実装を基本設計として採用してはならない。

```text
CVE一覧
  ↓
CVSS順にソート
  ↓
Criticalから対応
```

CVSSは脆弱性そのものの技術的特徴を表す重要な指標だが、組織内の実際のリスクを直接表すものではない。

少なくとも以下を分離して扱う。

* Vulnerability Severity
* Exploitability
* Asset Criticality
* Exposure
* Business Impact
* Compensating Controls
* Remediation Availability
* Remediation State

---

# 3. 基本ドメインモデル

最小構成として以下のエンティティを設計する。

```text
Organization
 └── Asset
      ├── NetworkInterface
      ├── Software
      ├── Service
      ├── Configuration
      └── Finding
             └── Vulnerability
                    ├── CVE
                    ├── CWE
                    ├── Exploit Intelligence
                    └── Remediation
```

さらに、

```text
RiskAssessment
PriorityDecision
RemediationAction
Verification
Evidence
Exception
```

を独立したドメインとして扱う。

---

# 4. Asset

Assetはシステムの中心的なエンティティである。

最低限以下を保持する。

```text
Asset
- id
- hostname
- fqdn
- ip_addresses
- mac_addresses
- asset_type
- operating_system
- environment
- owner
- business_unit
- criticality
- exposure
- first_seen
- last_seen
- lifecycle_state
```

## asset_type

例:

```text
server
workstation
laptop
container
virtual_machine
cloud_instance
network_device
database
application
mobile_device
iot
unknown
```

## environment

```text
production
staging
development
test
management
unknown
```

## criticality

業務上の重要度を表す。

例:

```text
critical
high
medium
low
unknown
```

これはCVSSとは別物として扱う。

---

# 5. Software Inventory

Asset上のソフトウェアを正規化して管理する。

```text
SoftwareInstallation
- asset_id
- product
- vendor
- version
- architecture
- package_manager
- install_path
- first_seen
- last_seen
```

可能な限りCPE、PURL等の標準識別子にマッピングする。

例:

```text
vendor
product
version
CPE
PURL
```

バージョン文字列だけで脆弱性判定を実装しない。

---

# 6. Vulnerability

脆弱性情報はAssetから分離する。

```text
Vulnerability
- id
- cve_id
- title
- description
- severity
- cvss_v3
- cvss_v4
- cwe
- affected_products
- published_at
- modified_at
- exploit_available
- exploitation_observed
- remediation_available
```

CVE、NVD、CISA KEV等の外部情報を利用する場合は、

* source
* retrieved_at
* source_version
* raw_reference

を記録する。

外部データの内容を無批判に内部判断として扱わない。

---

# 7. Finding

Findingは、

> 「このAssetに、このVulnerabilityが存在する」

という実環境上の事実を表す。

```text
Finding
- id
- asset_id
- vulnerability_id
- detection_source
- detected_at
- last_confirmed_at
- status
- confidence
- evidence_id
```

VulnerabilityそのものとFindingを混同しない。

例えば、

```text
CVE-XXXX-YYYY
```

はVulnerabilityであり、

```text
SERVER-001
    has
CVE-XXXX-YYYY
```

がFindingである。

---

# 8. Risk Model

本システムの重要部分。

Riskは単純なCVSS値ではない。

概念モデル:

```text
Risk =
    Vulnerability Severity
  × Exploitability
  × Asset Criticality
  × Exposure
  × Business Impact
  × Context
```

ただし、上記を機械的な掛け算として固定実装してはならない。

Risk Engineは独立したコンポーネントとして設計する。

```text
RiskEngine
 ├── SeverityProvider
 ├── ExploitabilityProvider
 ├── AssetCriticalityProvider
 ├── ExposureProvider
 ├── BusinessImpactProvider
 └── RiskPolicy
```

---

# 9. Exploit Intelligence

以下の情報を別々に保持する。

```text
exploit_exists
public_exploit
exploit_code_available
exploitation_observed
kev_listed
exploit_prediction
```

特に、

```text
exploit_exists
```

と

```text
exploitation_observed
```

を混同しない。

「PoCが存在する」と「実際に攻撃されている」は異なる。

---

# 10. Exposure

Assetが攻撃可能な状態にあるかを評価する。

例:

```text
internet_exposed
externally_accessible
public_ip
reachable_from_untrusted_network
remote_access_enabled
service_exposed
```

ExposureはBooleanだけにしない。

必要に応じて、

```text
direct
indirect
internal_only
restricted
unknown
```

などを表現できるようにする。

---

# 11. Business Criticality

Asset Criticalityは技術情報から自動推定するものではない。

可能な場合はCMDB、資産台帳、業務主管部署等の情報を利用する。

例:

```text
business_criticality
data_classification
service_criticality
availability_requirement
confidentiality_requirement
integrity_requirement
```

---

# 12. Priority

RiskとPriorityを分離する。

```text
Risk
```

は「どの程度のリスクがあるか」。

```text
Priority
```

は「何を先に対応するか」。

例えば同じRisk Scoreでも、

```text
production
internet-facing
business-critical
```

のAssetを先に対応する可能性がある。

Priority Engine:

```text
PriorityEngine
 ├── Risk
 ├── AssetCriticality
 ├── Exposure
 ├── Exploitability
 ├── RemediationAvailability
 ├── BusinessConstraints
 └── Policy
```

---

# 13. Remediation

Remediationは「パッチ適用」だけに限定しない。

以下を標準的なRemediation Actionとして扱う。

```text
patch
upgrade
configuration_change
disable_feature
disable_service
remove_software
access_control
network_segmentation
virtual_patch
compensating_control
temporary_mitigation
accept_risk
```

ただし、

```text
accept_risk
```

は自動的なRemediation成功とは扱わない。

---

# 14. Remediation Plan

Findingごとに、

```text
RemediationPlan
```

を作成できるようにする。

```text
RemediationPlan
- id
- finding_id
- action_type
- description
- proposed_by
- approved_by
- scheduled_at
- executed_at
- status
- rollback_plan
```

Status:

```text
proposed
approved
scheduled
in_progress
completed
failed
rolled_back
cancelled
```

---

# 15. Automatic Remediation

自動修復はデフォルトで無効とする。

以下のようなPolicyを設ける。

```text
auto_remediation_policy
```

例:

```text
require_approval
allowed_asset_types
allowed_environments
allowed_action_types
maintenance_window
rollback_required
```

特にproduction環境では、

```text
detect
→ assess
→ propose
→ approve
→ execute
→ verify
```

を基本フローとする。

---

# 16. Verification

Remediation完了だけではFindingをResolvedにしない。

必ずVerificationを実施する。

```text
Verification
- finding_id
- verification_method
- verified_at
- result
- evidence
```

例:

```text
version_check
configuration_check
package_check
scanner_rescan
service_check
```

基本状態:

```text
open
mitigated
remediated
verified
reopened
accepted
false_positive
```

---

# 17. Evidence

Evidenceは第一級エンティティとして扱う。

最低限、

```text
Evidence
- id
- type
- source
- collected_at
- asset_id
- finding_id
- content_hash
- location
```

を保持する。

Evidenceには、

```text
検出結果
パッケージ情報
バージョン情報
設定値
Remediation実行結果
Verification結果
```

などを保存できる。

Evidenceは後から改変されたことが分からなくてはならない。

可能ならHashを利用する。

---

# 18. Exception / Risk Acceptance

誤検知や期限付き例外を正式な状態として管理する。

```text
Exception
- finding_id
- reason
- requested_by
- approved_by
- created_at
- expires_at
- compensating_control
- status
```

永久的な例外をデフォルトにしない。

期限切れExceptionは再評価対象にする。

---

# 19. Data Sources

外部情報源はAdapterとして実装する。

```text
DataSource
 ├── NVD
 ├── CISA KEV
 ├── OSV
 ├── vendor_advisory
 └── internal_inventory
```

各Adapterは、

```text
fetch()
normalize()
validate()
store()
```

を分離する。

外部APIのレスポンス形式をドメインモデルに直接漏らさない。

---

# 20. Scanner Architecture

ScannerはCore Domainから分離する。

```text
Scanner
 ├── HostScanner
 ├── SoftwareInventoryScanner
 ├── ConfigurationScanner
 ├── ContainerScanner
 └── CloudScanner
```

ScannerはFindingを直接DBへ書き込まない。

基本フロー:

```text
Scanner
  ↓
RawFinding
  ↓
Normalizer
  ↓
Matcher
  ↓
Finding
```

---

# 20A. PownForge Integration

RiskForge は、攻撃側ツール PownForge の対となる防御側ツールである。

```text
PownForge
     │
     │ Finding / Evidence
     ▼
RiskForge
     │
     │ Remediation
     ▼
Target Asset
     │
     │ Verification
     ▼
RiskForge
```

本章は、この連携を実装する際の設計制約を定める。連携は Phase 5（Integrations）で実装する。Phase 1〜4 の設計は、本章の存在を前提に歪めてはならない。

## 20A.1 基本方針：PownForge は外部 Scanner として扱う

PownForge の診断結果は、RiskForge の Finding として直接取り込まない。第20章の Scanner 経路に従い、必ず RawFinding として受ける。

```text
PownForge
  ↓
RawFinding
  ↓
Normalizer
  ↓
Matcher
  ↓
Finding
```

* PownForge 専用の特別経路を作らない
* PownForge の出力形式をドメインモデルに漏らさない（第19章の Adapter 原則を適用する）
* Adapter は fetch() / normalize() / validate() / store() を分離する
* PownForge の Finding を、そのまま RiskForge の Finding として扱わない

## 20A.2 CVE を持たない診断結果の扱い

PownForge の結果には、CVE に紐づかないものが含まれる。

```text
設定不備
認可・認証の欠陥
手動 exploit で確認した挙動
アプリケーション固有の不具合
```

Normalizer は、これらを次のいずれかに分類する。

```text
1. 既知の Vulnerability（CVE / CWE 等）に対応付けられる
2. CVE を持たない Vulnerability として登録する（独自ID、CWE のみ等）
3. 分類できない場合は、Confidence を下げた RawFinding として保留する
```

* 分類できないことを理由に、結果を破棄しない
* 独自ID の Vulnerability は、source と source_id により出所を必ず記録する
* 自動分類の結果は、根拠（Reason）を残す

## 20A.3 Confidence と Exploit Intelligence

PownForge は攻撃を実際に試行できるため、通常のバージョン推定型 Scanner より強い根拠を持つ場合がある。ただし、以下を守る。

* 手動 exploit または攻撃シミュレーションで成立を確認した場合のみ、`confirmed` を検討できる
* PownForge が成立を確認したことは `exploitation_observed` ではない。これは「この環境で成立した」という事実であり、「実環境で攻撃されている」という外部の観測とは別に保持する
* `exploit_exists`、`exploitation_observed`、および PownForge による成立確認は、別々の項目として保持する（第9章）
* 成立確認の条件（対象、日時、手順の要約）を Evidence に残す

## 20A.4 Evidence の受け渡し

PownForge が生成した Evidence は、コピーではなく、参照とハッシュで引き継ぐ。

```text
Evidence
- id
- type
- source            (例: PownForge)
- source_ref        (PownForge 側の識別子)
- collected_at
- asset_id
- finding_id
- content_hash
- location
```

* content_hash を検証し、RiskForge 取り込み時点の内容が元の Evidence と一致することを確認する
* 取り込み時に Evidence を書き換えない
* Evidence を削除・上書きしない（第47章）
* 元の Evidence が参照できなくなった場合でも、ハッシュと出所は保持する
* Evidence に含まれる Credential・トークン等の Secret は、保存・ログ出力の前にマスクする（第31章）

## 20A.5 Remediation と PownForge の責務分離

```text
PownForge  = 発見・検証のための攻撃側の能力
RiskForge  = 是正の計画・承認・実行管理・検証結果の記録
```

* PownForge は Remediation を実行しない
* RiskForge は、攻撃的なテストを Remediation の一部として実行しない
* Remediation は第13〜15章、第32〜34章の制約（承認、Dry Run、Rollback、allowlist）に従う

## 20A.6 PownForge を用いた Verification

是正後に、PownForge が同じ診断を再実行して「もう成立しない」ことを確認する方法を、Verification の一種（`scanner_rescan`）として許可できる。

ただし、防御側から攻撃系ツールを起動することになるため、以下を必須とする。

```text
対象 Asset と実行範囲の allowlist
承認と実行の分離
production では Dry Run と承認を必須とする
実行内容を Audit Log に記録する
実行権限を Scanner 権限・Remediation 権限とは別に分離する
```

* 再実行は、元の Finding に紐づく手順・範囲に限定する。範囲を広げる場合は新しい承認を要する
* 再実行は、自動修復と同様に、デフォルトで無効とする
* 実行前に、対象・手順・想定される影響を Dry Run として表示する
* 再実行の結果は、新しい Evidence として保存する（既存の Evidence を上書きしない）
* 成立しなかったという結果だけで、Finding を即座に `verified` にしない。Verification の結果と根拠を記録し、第16章の状態遷移に従う
* 診断の失敗（接続不能、権限不足など）は、「成立しなかった」と区別して扱う

## 20A.6.1 Verification 結果の解釈

```text
攻撃が成立しなかった  → Verification の根拠になり得る
診断が実行できなかった → Verification の根拠にならない（結果: inconclusive）
攻撃が成立した        → Finding を reopened とし、Evidence を残す
```

## 20A.7 Idempotency

* 同じ PownForge の結果を何度取り込んでも、重複 Finding を生成しない（第37章）
* 重複判定には source と source_ref を用いる
* 再取り込み時に、既存の Evidence と content_hash が異なる場合は、上書きせず差異として記録する

## 20A.8 Audit

次の操作を Audit Log の対象に加える（第30章）。

```text
pownforge_import
pownforge_verification_approval
pownforge_verification_execution
```

## 20A.9 テスト

最低限、以下をテストする（第35章・第36章に追加）。

```text
CVE を持たない結果の Normalizer 分類
分類不能な結果の保留
同一結果の再取り込み（Idempotency）
Evidence の content_hash 検証と不一致の検出
Secret のマスク
PownForge 再実行の承認・allowlist 違反の拒否
診断失敗を「成立しなかった」と誤判定しないこと
```

## 20A.10 Agent への注意

* PownForge 連携を、Phase 1〜4 の実装に便乗して先行実装しない（第47章・第48章）
* PownForge 側の変更を要する場合は、別 Task とし、ADR に記録する
* 連携仕様の重要な判断は、`docs/adr/` に ADR として残す（例: `0005-pownforge-integration.md`）

---

# 21. Detection Confidence

FindingにはConfidenceを持たせる。

例:

```text
confirmed
high
medium
low
unknown
```

バージョン推定だけで確定Findingを作らない。

---

# 22. False Positive

False Positiveは削除しない。

```text
false_positive
```

としてEvidenceと理由を残す。

再検出時に同じFindingを再生成することを避けられるよう、Suppression / Exception機構を設ける。

---

# 23. Policy Engine

判断ロジックをApplication Serviceに散在させない。

```text
PolicyEngine
```

を設ける。

Policy例:

```text
risk_policy
priority_policy
remediation_policy
exception_policy
auto_remediation_policy
verification_policy
```

Policyはコードにハードコードせず、可能な限り設定として管理する。

---

# 24. Architecture

推奨構成:

```text
                    ┌──────────────────┐
                    │ External Sources │
                    │ NVD / KEV / OSV  │
                    └────────┬─────────┘
                             ↓
                    ┌──────────────────┐
                    │ Vulnerability    │
                    │ Intelligence     │
                    └────────┬─────────┘
                             │
                             ↓
┌──────────────┐     ┌──────────────────┐
│ Asset Sources│ →   │ Asset Inventory  │
└──────────────┘     └────────┬─────────┘
                              ↓
                       ┌──────────────┐
                       │ Finding      │
                       │ Correlation  │
                       └──────┬───────┘
                              ↓
                       ┌──────────────┐
                       │ Risk Engine  │
                       └──────┬───────┘
                              ↓
                       ┌──────────────┐
                       │ Priority     │
                       │ Engine       │
                       └──────┬───────┘
                              ↓
                       ┌──────────────┐
                       │ Remediation  │
                       └──────┬───────┘
                              ↓
                       ┌──────────────┐
                       │ Verification │
                       └──────┬───────┘
                              ↓
                       ┌──────────────┐
                       │ Evidence     │
                       └──────────────┘
```

---

# 25. Layering

基本的な依存方向:

```text
UI
 ↓
Application
 ↓
Domain
 ↓
Infrastructure
```

Domainから、

* HTTP Client
* Database
* CLI
* OS command
* Cloud SDK

などを直接呼び出してはならない。

---

# 25A. Technology Stack

## 25A.1 推奨スタック

```text
Backend       Go 1.24+
CLI           Go / Cobra
API           Go / net/http
Data model    Go structs
Validation    go-playground/validator
Database      PostgreSQL
Migration     golang-migrate
Frontend      TypeScript / React
API Schema    OpenAPI 3.x
Testing       go test
Integration   testcontainers-go
Container     Docker / Docker Compose
CI            GitHub Actions
```

## 25A.2 言語方針

Core は Go で実装し、Python を Core には使わない。

理由は、RiskForge が以下をすべて扱うためである。

```text
Asset discovery
Scanner
Worker
API
CLI
Remediation execution
Agent
```

単一コードベースから、以下のバイナリを生成する。

```text
riskforge          (CLI / API)
riskforge-agent
riskforge-worker
```

## 25A.3 バイナリと権限分離

バイナリを分けることで、第31章の権限分離を物理的に実現する。

* Scanner 権限、Remediation 権限、Approval を、別々に分離する
* 単一コードベースであっても、共有コードを通じて権限が混ざらないようにする
* 依存方向（第25章）を破る import は、CI で検出できるようにする

## 25A.4 データモデルと検証

* Domain の struct、API の入力・出力 DTO、DB モデルを、必要に応じて分離する（第25章・第28章）
* go-playground/validator は、Domain ではなく、API・CLI などの境界で用いる
* Domain は、HTTP Client・Database・CLI・OS command 等を直接呼び出さない（第25章）
* Database Schema は Domain Model から設計し、golang-migrate で管理する（第29章）

## 25A.5 API Schema

* API は OpenAPI 3.x で定義する
* Resource の分離は第28章に従う（Finding と Vulnerability を同一 Resource にしない）

## 25A.6 Testing

* 単体テストは go test で行う
* PostgreSQL 等を伴う Integration Test は testcontainers-go で行う
* Risk Engine と Priority Engine の Unit Test は、第35章に従い大量に用意する

## 25A.7 実装順序

Frontend（TypeScript / React）は、Phase 2（Dashboard）以降で着手する。
Phase 1 では、Backend、API、CLI を優先する。

## 25A.8 決定事項

* API ルーティングは、標準ライブラリの `net/http`（`ServeMux`）を用いる。chi 等のルーターは、ADR による変更決定なしに導入しない
* ハンドラーは `http.Handler` の形を保ち、ミドルウェア（認証、ログ、リクエストID等）も `http.Handler` のラッパーとして実装する
* CLI 名は `vulnctl` ではなく `riskforge` に統一する（第27章・第33章に反映済み）

上記の判断は、`docs/adr/0006-api-routing.md` に ADR として記録する（第47章・第49章）。

---

# 26. Domain API

重要な処理はNamed APIとして提供する。

例:

```text
discover_assets()
inventory_asset()
correlate_findings()
assess_risk()
calculate_priority()
create_remediation_plan()
execute_remediation()
verify_remediation()
record_evidence()
```

UIやCLIからDomain内部実装を直接呼び出さない。

---

# 27. CLI

CLIは以下のような構造を基本とする。

```text
riskforge asset list
riskforge asset inspect <id>

riskforge finding list
riskforge finding show <id>

riskforge risk assess
riskforge priority list

riskforge remediation list
riskforge remediation propose <finding>

riskforge verify <finding>

riskforge evidence show <id>

riskforge exception list
```

CLIはApplication LayerのAPIを利用する。

---

# 28. API

REST API等を実装する場合、Resourceを以下のように分離する。

```text
/assets
/software
/vulnerabilities
/findings
/risks
/priorities
/remediations
/verifications
/evidence
/exceptions
```

FindingとVulnerabilityを同一Resourceとして設計しない。

---

# 29. Database

Database SchemaはDomain Modelから設計する。

特に、

```text
assets
software_installations
vulnerabilities
findings
risk_assessments
priority_decisions
remediation_plans
remediation_actions
verifications
evidence
exceptions
```

を分離する。

巨大な `vulnerabilities` テーブルにすべてを詰め込まない。

---

# 30. Audit Log

重要操作はAudit Logに記録する。

対象:

```text
risk_change
priority_change
remediation_approval
remediation_execution
verification
exception_creation
exception_approval
exception_expiration
policy_change
```

少なくとも、

```text
who
what
when
why
before
after
```

を追跡可能にする。

---

# 31. Security

このシステム自体が高い権限を持つ可能性があるため、Securityを最優先する。

特に、

* Credentialをログへ出さない
* Secretをソースコードへ埋め込まない
* Command Injectionを防止する
* Shell commandを文字列連結しない
* 外部入力を信頼しない
* Scanner権限を最小化する
* Remediation権限を分離する
* ApprovalとExecutionを分離する

こと。

---

# 32. Remediation Command Safety

OSコマンドを実行する場合、

```text
user input
    ↓
validation
    ↓
structured command
    ↓
allowlist
    ↓
execution
```

という経路にする。

以下は禁止:

```text
exec("shell " + user_input)
```

またはそれと同等の文字列連結型Command Execution。

---

# 33. Dry Run

Remediationには原則としてDry Runを実装する。

```text
riskforge remediation apply --dry-run
```

Dry Runでは、

```text
対象Asset
対象Finding
実行予定Action
変更対象
Rollback方法
```

を表示する。

---

# 34. Rollback

変更を伴うRemediationは可能な限りRollbackを定義する。

例:

```text
patch
configuration_change
service_disable
package_remove
```

Rollback不能なActionについては、その事実をPlanに明示する。

---

# 35. Testing

最低限以下をテストする。

```text
Asset discovery
Software normalization
CVE matching
Finding correlation
Risk calculation
Priority calculation
Remediation planning
Remediation policy
Verification
Evidence integrity
Exception expiration
```

特にRisk EngineとPriority EngineはUnit Testを大量に用意する。

---

# 36. Test Fixtures

テストデータとして、

```text
critical asset + critical vulnerability
low asset + critical vulnerability
internet exposed + known exploited vulnerability
internal only + no exploit
patched asset
false positive
temporary mitigation
expired exception
```

などを用意する。

---

# 37. Idempotency

以下の処理は可能な限りIdempotentにする。

```text
asset discovery
software inventory
vulnerability ingestion
finding correlation
verification
```

同じデータを何度投入しても重複Findingを大量生成しない。

---

# 38. External Data Provenance

外部データを取り込む場合、必ず出典を保持する。

例:

```text
source = "NVD"
source_id = "CVE-2026-XXXX"
retrieved_at = ...
```

内部で計算したRisk Scoreと、外部SourceのSeverityを混同しない。

---

# 39. AI

AIは補助機能として利用できる。

適用可能な領域:

```text
脆弱性説明の要約
Remediation候補の生成
重複Findingの候補検出
自然言語による検索
Evidenceの要約
Risk rationaleの説明
```

ただし、

> AIの出力だけを根拠として自動的にproduction remediationを実行してはならない。

AIの判断結果には、

```text
model
prompt/version
generated_at
confidence
human_approval
```

等のProvenanceを残せる設計にする。

---

# 40. Risk Explainability

Risk Scoreだけを表示しない。

必ず、

```text
Risk Score
+
Risk Factors
+
Reason
```

を表示する。

例:

```text
Risk: High

Reasons:
- CVSS 9.8
- CISA KEV listed
- Internet exposed
- Production asset
- Business criticality: Critical
```

ユーザーが「なぜこのFindingが上位なのか」を説明できることを必須とする。

---

# 41. Dashboard

Dashboardでは単なるCVE件数を主要KPIにしない。

最低限、

```text
Total Assets
Internet Exposed Assets
Vulnerable Assets
Critical Findings
Known Exploited Findings
Overdue Remediation
Remediation SLA
Exception Count
Expired Exceptions
Verified Remediations
Reopened Findings
```

を表示できるようにする。

---

# 42. Metrics

特に以下を追跡する。

```text
MTTD
MTTR
Mean Time to Remediate
Mean Time to Verify
Open Findings
Overdue Findings
Risk Exposure
Remediation Coverage
Verification Coverage
```

「脆弱性件数が減った」だけでは改善を評価しない。

---

# 43. SLA

FindingごとにSLAを設定できるようにする。

例:

```text
Critical → 7 days
High     → 30 days
Medium   → 90 days
Low      → 180 days
```

ただし、これらの値を固定値として実装しない。

組織Policyとして変更可能にする。

---

# 44. 不変条件

以下を破壊してはならない。

### Invariant 1

```text
Vulnerability != Finding
```

### Invariant 2

```text
Risk != Priority
```

### Invariant 3

```text
Remediation != Verification
```

### Invariant 4

```text
Finding != Evidence
```

### Invariant 5

```text
CVSS != Organizational Risk
```

### Invariant 6

```text
Detected != Verified Remediated
```

---

# 45. 実装優先順位

最初から全機能を作らない。

Phase 1:

```text
Asset
Software
Vulnerability
Finding
```

Phase 2:

```text
Risk
Priority
Dashboard
```

Phase 3:

```text
Remediation
Verification
Evidence
```

Phase 4:

```text
Exception
Policy
Audit
```

Phase 5:

```text
Automation
AI assistance
Integrations
```

---

# 46. Definition of Done

機能実装はコードが動くだけでは完了としない。

最低限、

```text
Implementation
Unit Tests
Integration Tests
Error Handling
Logging
Auditability
Documentation
CLI/API
```

を確認する。

Remediation機能についてはさらに、

```text
Dry Run
Approval
Execution
Verification
Rollback
Evidence
```

を確認する。

---

# 47. Agentへの開発原則

AI Coding Agentは以下を厳守する。

1. 既存Architectureを理解してから変更する
2. Domain責務を勝手に変更しない
3. 複数Layerを跨ぐ変更では依存方向を確認する
4. 既存APIを破壊しない
5. テストなしでRisk Engineを変更しない
6. Remediationを実装するときはDry Runを先に実装する
7. 自動修復をデフォルト有効にしない
8. Security境界を曖昧にしない
9. 外部データの出典を失わせない
10. Evidenceを削除・上書きしない
11. 大規模Refactoringを機能追加に便乗して行わない
12. 必要な場合は変更前にArchitecture Decisionを記録する

---

# 48. Refactoring Policy

機能追加のために無関係なコードをリファクタリングしてはならない。

特に以下を禁止する。

```text
全体的なディレクトリ再編
命名規則の全面変更
DB Schemaの全面再設計
APIの全面変更
Framework変更
ORM変更
Logging基盤変更
Authentication基盤変更
```

必要な場合は、

```text
問題
理由
影響範囲
移行方法
Rollback
```

を記録した上で別Taskとして扱う。

---

# 49. Documentation

重要な設計判断はADRとして記録する。

例:

```text
docs/adr/
    0001-domain-model.md
    0002-risk-engine.md
    0003-remediation-safety.md
    0004-evidence-model.md
    0005-pownforge-integration.md
    0006-api-routing.md
```

---

# 50. 最終的なシステムモデル

このプロジェクトでは、以下のモデルを基本設計とする。

```text
                    ASSET
                      │
                      ▼
                  SOFTWARE
                      │
                      ▼
               VULNERABILITY
                      │
                      ▼
                   FINDING
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
       EXPOSURE               EXPLOIT
          │                       │
          └───────────┬───────────┘
                      ▼
                    RISK
                      │
                      ▼
                  PRIORITY
                      │
                      ▼
                REMEDIATION
                      │
                      ▼
                 VERIFICATION
                      │
                      ▼
                   EVIDENCE
                      │
                      ▼
                 AUDIT / KPI
```

この一連のデータフローを本システムの中心概念とする。

**「脆弱性を見つけること」ではなく、「リスクを説明可能な形で優先順位付けし、安全に是正し、その結果を検証可能なEvidenceとして残すこと」が本プロジェクトの完成条件である。**
