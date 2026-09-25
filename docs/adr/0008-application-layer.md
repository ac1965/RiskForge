# 0008. Application層: Named APIとports

## 状態

Accepted

## 背景

AGENTS.md §26は、CLI層とAPI層が `internal/domain` に直接立ち入るので
はなく、一連のNamed Domain APIを呼び出すことを要求しており、9つの例
（`discover_assets`、`inventory_asset`、`correlate_findings`、
`assess_risk`、`calculate_priority`、`create_remediation_plan`、
`execute_remediation`、`verify_remediation`、`record_evidence`）を
挙げている。これらを実装するには永続化が必要だが、
`internal/infrastructure/postgres` はまだ存在せず、§25のレイヤリング
ルール（`UI -> Application -> Domain -> Infrastructure`）は、
Applicationがデータベースドライバを直接importできないことを意味する。

§26をそのまま読むだけでは決められないことが3つあった:

1. ApplicationとまだビルドされていないInfrastructure層の間の
   port（リポジトリinterface）を何が規定するか。
2. `§26` のリストにはRemediationの承認ステップも、
   Exception（Phase 4）へのエントリーポイントも一切含まれていないが、
   どちらもそれなしでは使い物にならない。
3. `§30` は、どの操作がaudit.Entryを生成しなければならないかを正確に
   名指ししており、そのリストは「すべてのNamed API呼び出し」より
   狭い。

## 決定

- **portは `internal/application/ports.go` に置く**。集約ごとに1つの
  リポジトリinterface（`AssetRepository`、`FindingRepository`、...）
  を用意し、それぞれに `Save` と、その集約のidempotencyルールが必要
  とするlookupを持たせる。「見つからない」というlookupは
  `(nil, nil)` を返す。呼び出し側はセンチネルエラーではなくnil結果を
  チェックする。`RemediationExecutor` は、Planが表す実際の
  Infrastructureレベルの変更（AGENTS.md §31、§32のvalidated/
  structured/allowlisted commandパイプライン）のための独立したport
  である — まだ実装は存在せず、Applicationは継ぎ目を定義するだけで
  ある。`Service`（`service.go`）はすべてのportと `risk.Engine`/
  `priority.Engine` を保持し、すべてのフィールドが設定されている
  ことを検証する `NewService` によって一度だけ構築される。
- **Idempotencyキー（AGENTS.md §37）** は推測ではなく、明示的な
  リポジトリのlookupメソッドとして表現する:
  `AssetRepository.FindByHostname`、
  `SoftwareRepository.FindByNaturalKey`（asset+vendor+product+
  version）、`FindingRepository.FindByAssetAndVulnerability`。
  `DiscoverAssets`、`InventoryAsset`、`CorrelateFindings` はいずれも
  同じ「find した上で `Observe`/`Confirm` するか `New` する」という
  形を踏襲する。
- **§26のリストを超える2つのAPIを追加した**。ドメインがそれらなしでは
  使い物にならないためである: `ApproveRemediationPlan`
  （remediation.Plan自身のステートマシン、ADR 0003。Proposed ->
  InProgressへの直接遷移を拒否する）と、Exceptionの5つの操作
  （`RequestException`、`ApproveException`、`RejectException`、
  `ExpireException`、`RevokeException` — AGENTS.md §18、Phase 4には
  独自のNamed API例が一切ない）。§26は自身のリストを「例」という
  言葉で導入しているため、これは仕様を上書きするのではなく、
  抜けている部分を埋めるものである。`PreviewRemediation` も、
  Application層で `Plan.DryRun`（§33）を公開するために追加した。
- **監査エントリは§30が実際に名指ししているアクションについてのみ
  記録する**: `risk_change`、`priority_change`、
  `remediation_approval`、`remediation_execution`、`verification`、
  `exception_creation`、`exception_approval`、
  `exception_expiration`。AGENTS.md内の他のいくつかのリストとは
  異なり、§30のリストには「など」「例」といった限定が付いていない
  ため、確定的な集合として扱う。`CreateRemediationPlan`、
  `RecordEvidence`、`RejectException`、`RevokeException` は結果として
  監査エントリを生成しない — それぞれ自身のdocコメントでその旨を
  明記している。より広範な監査（例: rejection/revocationの監査）が
  必要になった場合は、黙って修正するのではなく、将来のADRで意図的に
  スコープを決めるべき事柄である。
- `AssessRisk` と `CalculatePriority` は、決定論的で自動化された計算
  であり（AGENTS.md §8、§12）名指しできる人間の行為者が存在しない
  ため、`Who: "system"` として監査エントリを記録する。`Why` はその
  結果を生成したPolicy名/バージョンを引用し、`Before`/`After` は
  `snapshot.go` の `toJSON` によって構築されたJSONスナップショットで
  ある — Domainは自分自身をシリアライズしない（AGENTS.md §25）。
- `CalculatePriority` は、対象Findingについて既に `risk.Assessment`
  が存在していることを要求する（`assess_risk` を先に実行しなければ
  ならない）。これはAGENTS.md §24のRisk → Priorityというパイプライン
  順序と整合する。

## 影響

- （将来のフェーズの）Infrastructureの仕事は、各リポジトリportを
  PostgreSQLに対して、`RemediationExecutor` を実際のコマンド実行
  パイプラインに対して実装することである — それが実現しても
  `Service` のロジックを変更する必要はないはずである。
- `Service` を呼び出すもの（CLI、API）は、実際のデータベースなしで、
  このパッケージ自身のテスト用に既に書かれているin-memoryのfake
  （`fakes_test.go`）に対してテストできる。
- portが「見つからない」場合に `(nil, nil)` を返すため、すべての
  Named APIメソッドは自分自身でnil結果をチェックしなければならない。
  将来の実際の実装は、ラップされた「not found」エラーを返すのでは
  なく、この契約を維持しなければならない。
