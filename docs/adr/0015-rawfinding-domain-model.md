# 0015. RawFindingドメインモデルとNormalizer分類(PownForge連携 第一弾)

## 状態

Accepted

## 背景

[ADR 0005](0005-pownforge-integration.md)は、AGENTS.md §20Aが既に定めて
いる連携制約をADRとして記録したが、実装は明示的に対象外とし、
「`RawFinding`自体のGoの構造体定義」を含む実装は「Phase 5着手時に別ADR
で扱う」としていた。ユーザーから「PownForge連携の実装に着手する」という
明示的な依頼を受け、本ADRから着手する。

`RawFinding`は`internal/application/finding.go`のコメントが指すだけの
未実装の概念で(第20章「Scanner → RawFinding → Normalizer → Matcher →
Finding」)、既存の`CorrelateFindings`はこのパイプライン全体を経由しない
簡易な代替経路(AssetID/VulnerabilityIDを直接受け取る)である。

AGENTS.md §47・§48(大きな機能を1つのPRに詰め込まない)に従い、
[ADR 0014](0014-exception-write-endpoints.md)がExceptionワークフローを
「書き込み系APIの第一弾」として切り出したのと同じ考え方で、本ADRは
Phase 5全体ではなく**`RawFinding`エンティティと、それを既知/未知/
分類不能に振り分けるNormalizerの分類ロジックのみ**をスコープとする。
実際にPownForgeの出力を取り込むAdapter、既存Vulnerabilityへの一致判定を
行うMatcher、ATT&CK/CVSSフィールドをFinding側でどう扱うかの採用判断は、
いずれも対象外とし別ADRに先送りする。

## 決定

### `internal/domain/evidence`への`SourceRef`追加

AGENTS.md §20A.4が定めるEvidenceのフィールド一覧
(`id`/`type`/`source`/`source_ref`/`collected_at`/`asset_id`/
`finding_id`/`content_hash`/`location`)と、[ADR 0004](0004-evidence-model.md)
が実装した実際の`evidence.Evidence`を突き合わせたところ、`source_ref`が
欠けていることが分かった。§20A.7「重複判定にはsourceとsource_refを
用いる」・§20A.4「取り込み時点の内容が元のEvidenceと一致することを
確認する」を満たすには、PownForge側の識別子(例:
run_id+finding_idの組)を保持できる必要があるため、`Evidence`/
`evidence.Params`に`SourceRef string`(空文字許容の任意項目、
`FindingID`と同じ「省略可」の扱い)を追加した。既存の呼び出し元は
ゼロ値のまま動作するため後方互換である。ADR 0004自体の決定を覆すもの
ではなく、追記として扱う(ADR 0012が実シグネチャ確定を追記した前例に
倣う)。

### `internal/domain/rawfinding`パッケージ

`internal/domain/evidence`と同じ「setter無し、`New`のみ」の不変
パターンで新設した。

```go
type RawFinding struct {
    ID                 ID
    Source             string           // 例: "pownforge:nuclei"
    SourceRef          string           // 任意。idempotencyに使う(§20A.7)
    AssetID            asset.ID
    EvidenceID         evidence.ID      // 任意。EvidenceのFindingIDと同じ「相関前は空でもよい」扱い
    Title              string
    Detail             string
    Confidence         finding.Confidence // 既存のfinding.Confidenceを再利用(新規型を作らない)
    CVSSScore          *float64         // 任意
    CVSSVector         string           // 任意
    NativeSeverity     string           // 任意
    AttackTechniqueIDs []string         // 任意
    CollectedAt        time.Time
}
```

- `Confidence`は`internal/domain/finding`の既存`Confidence`型
  (confirmed/high/medium/low/unknown)をそのまま再利用する。新しい
  Confidence概念をRawFinding専用に作らない(AGENTS.md §21が定める語彙を
  分裂させないため)。
- `CVSSScore`/`CVSSVector`/`NativeSeverity`/`AttackTechniqueIDs`は、
  PownForge側`Finding`のフィールド([ADR 0005](0005-pownforge-integration.md)
  の対応表参照)をそのまま素通りさせるためだけの任意項目である。
  RawFinding自身はこれらの値を一切解釈・検証しない(採用可否の判断は
  Matcher/Finding側の別ADRに委ねる、下記「対象外」参照)。
- 必須項目は`Source`/`AssetID`/`Title`/`CollectedAt`のみ。`Confidence`
  省略時は`ConfidenceUnknown`にフォールバックする(Evidenceの
  `ContentHash`/`Location`のような「無いと成立しない」項目ではなく、
  「不明」も正当な値であるため)。

### `Classify`によるNormalizer分類(§20A.2)

```go
func Classify(rf RawFinding) ClassificationResult
```

3種の`Classification`(`known_vulnerability`/`unknown_vulnerability`/
`unclassified`)に純粋関数として振り分ける。リポジトリへの問い合わせは
一切行わない(実際に既存Vulnerabilityと一致するかの判定はMatcherの仕事、
下記「対象外」参照)。

- `Title`+`Detail`から正規表現(`CVE-\d{4}-\d{4,}`、大小文字無視)でCVE IDを
  抽出できれば`known_vulnerability`とし、抽出したID(大文字正規化)を
  `ClassificationResult.VulnerabilityIdentifier`に入れる。PownForgeの
  各Scanner(trivy/grype/nuclei/vulncheck)はいずれもCVEを専用フィールド
  ではなくTitleに埋め込む形式(`"[CVE-2021-36159] ..."`等)で出力する
  ([ADR 0005](0005-pownforge-integration.md)参照)ため、これは
  Adapterが事前にパースすべき構造化フィールドではなく、緩い形式の
  Scanner結果を解釈するNormalizer自身の仕事だと判断した。
- CVEが見つからない場合、`Confidence`が`low`/`unknown`/空なら
  `unclassified`(§20A.2ケース3「分類できない場合は、Confidenceを
  下げたRawFindingとして保留する」)、それ以外(`medium`/`high`/
  `confirmed`)なら`unknown_vulnerability`(§20A.2ケース2「独自IDの
  Vulnerabilityとして登録する」、source_idは既存の`Source`+
  `SourceRef`で足りる)とする。

## 対象外(次のADRで扱う)

- PownForge向けAdapter(`fetch()`/`normalize()`/`validate()`/`store()`)
  の実装: 実際にPownForgeのCLI出力・Web API JSONを`RawFinding`へ変換
  する経路
- Matcher: `ClassificationResult.VulnerabilityIdentifier`(CVE)や
  `unknown_vulnerability`ケースを実際に`internal/domain/vulnerability`の
  既存レコードと突き合わせ、`Finding`を生成する処理。Repository依存が
  生じるため本ADRのスコープ外とした
- ATT&CK技術ID・CVSSフィールドをRiskForge側の`Finding`/`Vulnerability`が
  最終的にどう保持するか(採用可否そのもの): 本ADRは`RawFinding`が
  これらを素通しできることのみを決定し、Finding側での扱いは未決定の
  ままとする
- `scanner_rescan`(§20A.6)のVerification実装、Idempotency実装
  (§20A.7、`Source`+`SourceRef`での重複排除処理そのもの)、Audit Log
  配線(§20A.8): いずれもRepository/Application層が絡むため別ADR
- HTTP API・CLIからの実際の取り込み経路

## 影響

- `internal/domain/evidence`に`SourceRef`(任意項目)が追加される。
  既存呼び出し元はゼロ値のまま動作し、後方互換を維持する
- 新規パッケージ`internal/domain/rawfinding`が追加される
  (`RawFinding`/`Classify`)。既存パッケージへの依存は
  `asset`/`evidence`/`finding`/`id`のみで、Application層・
  Infrastructure層への配線はまだ無い(呼び出し元がまだ存在しない)
- `go build ./...`・`go test ./...`ともにクリーン
- 次のADRでAdapter/Matcherを実装する際、本ADRの`RawFinding`/`Classify`
  を土台として使う
