# 0016. Matcher: 既知CVEの突き合わせ(PownForge連携 第二弾)

## 状態

Accepted

## 背景

[ADR 0015](0015-rawfinding-domain-model.md)は、Phase 5の第一弾として
`RawFinding`エンティティとNormalizer分類(`rawfinding.Classify`)を実装し、
Matcher(既存Vulnerabilityとの実際の突き合わせ)を対象外として次のADRに
先送りした。ユーザーから改めて「RiskForge連携の実装着手」という明示的な
依頼を受け、本ADRから着手する。

AGENTS.md §47・§48に従い、本ADRもMatcherの全機能ではなく、
`rawfinding.Classify`が`known_vulnerability`と判定したケース
(§20A.2ケース1)の一本にスコープを絞る。`unknown_vulnerability`
(ケース2、独自IDでの新規Vulnerability登録)・`unclassified`(ケース3、
保留分の永続化)は、いずれも「新しいVulnerabilityレコードをどう作るか」
という別の設計判断を要するため対象外とする(下記「対象外」参照)。

## 決定

### `VulnerabilityRepository.FindByCVE`の追加

既存の`VulnerabilityRepository`ポート(`internal/application/ports.go`)
には`FindByID`のみがあり、CVE文字列からの検索経路が無かった。
[ADR 0011](0011-http-api-design.md)が`List`を「必要になった時点で追加する
(投機的に追加しない)」とした前例に倣い、今回必要になった`FindByCVE`
のみを追加する。

```go
FindByCVE(ctx context.Context, cveID string) (*vulnerability.Vulnerability, error)
```

「見つからない」は既存の規約どおり`(nil, nil)`(エラーではない)。
`migrations/000003_create_vulnerabilities_table.up.sql`には元々
`vulnerabilities_cve_id_idx`(`cve_id <> ''`の部分インデックス)が
存在しており、このスキーマは既に本ADRのクエリパターンを見越して
設計されていたことを確認した。PostgreSQL実装
(`internal/infrastructure/postgres/vulnerability_repository.go`)は
このインデックスを使う`WHERE cve_id = $1`のみで、新規マイグレーションは
不要だった。

### `Service.MatchRawFinding`(Matcher、`internal/application/rawfinding.go`)

```go
func (s *Service) MatchRawFinding(ctx context.Context, rf rawfinding.RawFinding) (*finding.Finding, MatchOutcome, error)
```

処理は次の3段階のみ:

1. `rawfinding.Classify(rf)`を呼ぶ(ADR 0015、リポジトリ非依存)
2. `ClassificationKnownVulnerability`以外は`MatchOutcomeHeld`を返し、
   何も永続化しない(下記「対象外」参照)
3. `ClassificationKnownVulnerability`なら`Vulnerabilities.FindByCVE`で
   検索。見つかれば既存の`CorrelateFindings`(AGENTS.md §26、ADR未記載だが
   `internal/application/finding.go`が実装済み)をそのまま呼び、
   `MatchOutcomeCorrelated`を返す。見つからなければ
   `MatchOutcomeUnmatched`を返し、何も永続化しない

`CorrelateFindings`を新設せず**そのまま再利用**した。これは`Finding`の
生成・`(AssetID, VulnerabilityID)`によるidempotent upsertを既に実装
済みであり(AGENTS.md §37)、Matcherが担うべきなのは「どの
Vulnerabilityと突き合わせるか」の決定だけで、Finding生成ロジック自体を
複製する理由が無いため。`AssetID`は`RawFinding`側で既に解決済みという
前提を維持する(既存`CorrelateFindings`のコメントと同じ、「Assetは
呼び出し元が解決済み」という前提を崩さない)。

`MatchOutcome`(`correlated`/`unmatched`/`held`)は、呼び出し側
(将来のAdapter/CLI/HTTPハンドラ)が「実際にFindingが作られたか」
「まだ何もしていないか」を区別できるようにするための3値。エラーとは
独立している(`unmatched`/`held`はエラーではなく、正常な分類結果)。

### `RawFinding`固有の特別経路を作らない(AGENTS.md §20A.1)

`MatchRawFinding`はPownForge固有のロジックを一切持たない。どの
Scannerが生成した`RawFinding`でも同じ経路を通る。

## 対象外(次のADRで扱う)

- `unknown_vulnerability`ケースでの新規Vulnerability自動登録:
  `vulnerability.New`は`Title`と有効な`Severity`を必須とするが、
  `RawFinding`はSeverityの概念を持たない(Confidenceのみ)。CVEを持たない
  Vulnerabilityをどんな最小フィールドで作ってよいか自体が新しい設計
  判断であり、本ADRでは決定しない
- `unclassified`ケースでの`RawFinding`永続化: 現状`RawFinding`は
  Repositoryを持たず、`Held`になったものは呼び出し元のメモリ上で消える。
  後日レビューできるようにするには`RawFindingRepository`の新設が要る
- PownForge向けAdapter(fetch/normalize/validate/store)の実装: 本ADRの
  `MatchRawFinding`を実際に呼び出す経路(CLI/HTTP)はまだ無い
- ATT&CK技術ID・CVSSフィールドをVulnerability/Finding側がどう保持するか
  (`RawFinding`は引き続き素通しするだけ)

## 影響

- `internal/application/ports.go`の`VulnerabilityRepository`に
  `FindByCVE`が追加される(既存実装は全て追随済み: PostgreSQL・
  `internal/application`のテスト用フェイク・`internal/api`のテスト用
  フェイク)
- 新規ファイル`internal/application/rawfinding.go`
  (`MatchRawFinding`/`MatchOutcome`)
- `go build`/`go vet`/`go test ./...`、および`go test -tags=integration`
  (実際のPostgreSQLコンテナ、testcontainers-go)ともにクリーン
- 次のADRでAdapter(PownForgeの実出力→`RawFinding`変換)または
  `unknown_vulnerability`/`unclassified`ケースの永続化に進める状態
  になった
