# 0018. Adapter(normalize)とunclassifiedケースの永続化(PownForge連携 第四弾)

## 状態

Accepted

## 背景

[ADR 0015](0015-rawfinding-domain-model.md)〜[0017](0017-unknown-vulnerability-registration.md)で
`RawFinding`→Normalizer(`Classify`)→Matcher(`MatchRawFinding`、
`known_vulnerability`/`unknown_vulnerability`の2ケース)まで実装した。
残っていたのは(1)`unclassified`ケース(§20A.2ケース3)の永続化、
(2)PownForge向けAdapter(§19・§20A.1、`fetch()`/`normalize()`/
`validate()`/`store()`)の実装で、ユーザーから両方を対象に「実装を
進めて」の依頼を受け、本ADRで着手する。

AGENTS.md §47・§48に従い、本ADRもAdapterの4段階全てではなく
**`normalize()`のみ**をスコープとする。実際にPownForgeへ到達する
`fetch()`(HTTPかファイルかCLI呼び出しか、認証をどうするか)、
入力の`validate()`、`MatchRawFinding`を呼ぶ`store()`のCLI/HTTP配線は
対象外とする(下記「対象外」参照)。

## 決定

### 副次的な修正: `Evidence.SourceRef`の永続化配線漏れ

実装前の確認で、[ADR 0015](0015-rawfinding-domain-model.md)が
`evidence.Evidence`へ追加した`SourceRef`が、実際には
`migrations/000005`(evidenceテーブル)にカラムが無く、
`internal/infrastructure/postgres/evidence_repository.go`のSQLにも
含まれていない(=保存時に静かに失われる)ことが判明した。
`migrations/000015`でカラムを追加し、`Save`/`FindByID`の両方に配線、
実PostgreSQLコンテナでの往復を確認するテストも追加した。ADR 0004の
決定自体は変更せず、追記として扱う。

### `RawFindingRepository`と`raw_findings`テーブル(unclassifiedケースの永続化)

AGENTS.md §20A.2ケース3「分類できない場合は、Confidenceを下げた
RawFindingとして保留する」の「保留する」を文字通り実装した。
`Save`/`FindByID`/`List`のみを持つ最小限のポートとし
(プログラムによる更新は想定しない、人間によるレビュー専用)、
`migrations/000016`で`raw_findings`テーブルを新設した(`RawFinding`の
全フィールドをそのまま列に対応させる、`Vulnerability`と同じく
setter無しだが`Save`はUPSERT — `RawFinding`自体には
AGENTS.md上の不変性要件は無いため)。

`MatchRawFinding`(`internal/application/rawfinding.go`)の
`ClassificationUnclassified`分岐が、`MatchOutcomeHeld`を返す前に
`RawFindings.Save`を呼ぶよう変更した。これにより`held`は「何もしない」
から「保留として確実に保存される」に変わった(`Service`構造体に
`RawFindings RawFindingRepository`を追加、`cmd/riskforge/main.go`の
composition rootと全テストフェイクに配線済み)。

### PownForge Adapter: `internal/infrastructure/scanner/pownforge`

AGENTS.md §19の`DataSource`とは別に、§20の`Scanner`用Adapterとして
新設した(既存の`internal/infrastructure/datasource`パッケージは
§19が列挙する5つのDataSource専用で、PownForgeはScanner側の概念の
ため相乗りしない)。

`Normalize(payload []byte, assetID asset.ID) ([]rawfinding.RawFinding, error)`
は、PownForgeの`RunRecord`(`src/pownforge/core/models/evidence.py`)の
JSON形状を、実際のPownForgeソースコードのフィールド名で確認した上で
パースする(`run_id`/`target`/`plugin`/`created_at`/`findings`)。各
`findings[]`要素は`Finding`(`src/pownforge/core/models/finding.py`)と
1対1で、`finding_id`/`title`/`detail`/`source`/`status`/
`attack_technique_ids`/`cvss_score`/`cvss_vector`/`native_severity`を
そのまま読む。

- **`status="false-positive"`は丸ごと除外する**: 人間が既にレビューし
  「実在しない」と判定した結果であり、`RawFinding`として分類する
  対象ですらない
- **Confidenceは`(source, status)`からマッピングする**
  (AGENTS.md §20A.3「手動exploitまたは攻撃シミュレーションで成立を
  確認した場合のみconfirmedを検討できる」に対応):
  | PownForge `status` | PownForge `source` | `finding.Confidence` |
  | --- | --- | --- |
  | `confirmed` | (問わず) | `ConfidenceConfirmed` |
  | `needs-review` | `ai` | `ConfidenceLow`(`finding.py`のdocstring「未検証のLLM出力」どおり) |
  | `needs-review` | `tool`/`manual`/その他 | `ConfidenceMedium` |
  | それ以外(未知の値含む) | - | `ConfidenceUnknown` |
- **CVSS/ATT&CK系フィールドはそのまま素通し**(ADR 0015の設計どおり、
  ここでも変換・解釈しない)
- `SourceRef`は`"<run_id>:<finding_id>"`(既存のテストで使ってきた形式
  と同じ)、`Source`は`"pownforge:<plugin>"`(pluginが空なら`"pownforge"`)
- **PownForgeの`target`(スコープ対象名の文字列)からRiskForgeの
  `asset.ID`への解決は行わない**: 呼び出し元が`assetID`を渡す前提とし、
  `AssetRepository.FindByHostname`等による解決は`fetch()`/`store()`の
  仕事として次のADRに残す(下記「対象外」参照)
- 個々の`Finding`が`rawfinding.New`の検証に失敗した場合(実運用では
  ほぼ起きない、PownForge側`title`が空文字列になるような異常系)は
  そのFindingだけをスキップし、バッチ全体は失敗させない。トップレベル
  のJSON自体が不正な場合のみエラーを返す

## 対象外(次のADRで扱う)

- `fetch()`: 実際にPownForgeへ到達する経路(HTTP経由でWeb
  APIを呼ぶか、`pownforge run show --format json`をCLI実行するか)、
  認証、設定(ベースURL等)
- `validate()`: 取り込み前の入力検証(現状は`json.Unmarshal`の
  成功/失敗のみ)
- `store()`のCLI/HTTP配線: `Normalize`の結果を`MatchRawFinding`へ
  実際に流し込む経路(`riskforge`コマンド・HTTP API)
- PownForgeの`target`名→RiskForge `asset.ID`の解決方法
- Evidenceの橋渡し: PownForgeの`RunRecord.evidence`
  (`content_hash`等)をRiskForge側`Evidence`レコードとしてどう保存し、
  `RawFinding.EvidenceID`にどう繋ぐか(AGENTS.md §20A.4)
- Normalize()とMatchRawFindingを組み合わせたend-to-endテスト:
  両者は独立してテスト済みで(前者はPownForgeの実際のJSON構造・
  Confidenceマッピング、後者は分類ロジック)、`internal/application`は
  レイヤリング上`internal/infrastructure`に依存できないため、結合
  テストは`store()`配線と合わせて次のADRで追加する

## 影響

- 新規マイグレーション`000015`(evidence.source_ref、副次的な修正)・
  `000016`(raw_findingsテーブル)
- `internal/application/ports.go`に`RawFindingRepository`、
  `Service`に`RawFindings`フィールドを追加。全ての呼び出し元
  (`cmd/riskforge/main.go`、テストフェイク3箇所)が追随済み
- 新規パッケージ`internal/infrastructure/scanner/pownforge`
  (`Normalize`)
- `internal/application/rawfinding.go`の`MatchRawFinding`が
  `unclassified`分岐で`RawFindings.Save`を呼ぶよう変更
- `go build`/`go vet`/`go test ./...`、`go test -tags=integration`
  (実PostgreSQLコンテナ、`TestMigrateIsIdempotent`・
  `TestEvidenceRepository`のSourceRef往復・`TestRawFindingRepository`
  含む)ともにクリーン
