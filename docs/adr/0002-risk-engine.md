# 0002. RiskおよびPriority Engineの設計

## 状態

Accepted

## 背景

AGENTS.md §8と§12は、Risk・Priorityを固定の計算式（例えばCVSSに重みを
掛け合わせるだけの機械的な乗算）ではなく、独立した組み合わせ可能な
Engineによって計算することを求めており、RiskとPriorityを同一視することを
禁じている（§44 不変条件2・5）。一方で§23は、設定駆動の完全なPolicy
Engineについて述べているが、これは明示的にPhase 4の作業であり
（§45）、Phase 2の対象ではない。Phase 2で必要なのは、以下を満たす設計
である:

- RiskとPriorityのスコアリングを、呼び出し側を変更することなく後から
  差し替えられること
- Phase 4のPolicy Engine（設定の読み込み、永続化、承認ワークフロー）を
  前倒しで作り込まないこと（§47.11）

## 決定

`internal/domain/risk` と `internal/domain/priority` を、
Engine/Policy/Providerという対になった構造として実装する:

- **Provider**（Risk向けの `SeverityProvider`、`ExploitabilityProvider`、
  `AssetCriticalityProvider`、`ExposureProvider`、
  `BusinessImpactProvider`。Priority向けの
  `RemediationAvailabilityProvider`、`BusinessConstraintsProvider`、
  加えてRiskのExploitability/AssetCriticality/Exposure Providerの再利用）
  は、それぞれ1つの入力を集めるinterfaceである。CMDB、KEVフィード、
  EPSS APIを呼び出す具体的な実装は後続フェーズのInfrastructureの関心事で
  あり、現時点ではデフォルト実装（`FromVulnerabilityProvider`、
  `FromAssetProvider`、...）が既にロード済みのAsset/Vulnerability/
  Finding集約から単純に読み取るだけにとどめる。
- **Policy**（`risk.Policy`、`priority.Policy`）は、スコアリングロジック
  が存在する唯一の継ぎ目である: `Evaluate(...)` はProviderが集めた出力を
  受け取り、`Result`（スコア/ランク、レベル、`explainability.Factor` 群）
  を返す。`Engine.Assess` / `Engine.Decide` 自身はスコアを計算せず、
  入力を集めてPolicyを呼び出すだけである。
- `risk.BaselinePolicy` と `priority.BaselinePolicy` は、それぞれ
  Policyのリファレンス実装の1つであり、「唯一の」risk/priority計算式
  ではない。これらはEngineを今すぐ使用・テスト可能にするために存在して
  おり、設定駆動のPolicy Engine（§23）は、`Engine` に手を加えることなく、
  後から別の `Policy` 実装として導入できる。
- `risk.Assessment` と `priority.Decision` は別々のエンティティである。
  `priority.Engine` は複数あるPolicy入力の1つとして `*risk.Assessment`
  を受け取るが、独自のRank/Levelを計算する — RiskのLevelをそのまま読む
  わけではない（§44 不変条件2）。
- すべての `Policy.Evaluate` の結果は、少なくとも1つの
  `explainability.Factor`（§40）を含まなければならない。`risk.New` /
  `priority.New` はFactorが0件のAssessment/Decisionを拒否するため、
  説明のつかないスコアが永続化されることはない。
- `risk.Exploitability` は、`vulnerability.Vulnerability` 自体が持つ
  exploit関連フィールドとは別の値オブジェクトである。これはAssessment
  ごとに新たに収集される、時間とともに変化する脅威インテリジェンス
  （KEV掲載、exploit予測）を表しており、脆弱性の静的な記述（§9）では
  ない。

## 影響

- 実際のPolicy（例: Phase 4でYAML/DB設定から読み込むもの）を追加する
  際は、`Engine` を変更するのではなく、`Policy` を実装する新しい型を
  書くことになる。
- 実際に稼働するKEV/EPSS連携の `ExploitabilityProvider` や、CMDB連携の
  `BusinessImpactProvider` を後から差し込むのはInfrastructure側の変更
  であり、Risk/Priorityのドメインロジックからは切り離されている。
- `risk.BaselinePolicy` と `priority.BaselinePolicy` の具体的な重み付け
  は例示的なデフォルト値であり、組織のポリシーそのものではない。
  レビューなしにproductionのリスク判断の根拠として用いるべきではない。
