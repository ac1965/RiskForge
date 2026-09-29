# 0022. Evidenceの橋渡し(PownForge連携 第八弾)

## 状態

Accepted

## 背景

[ADR 0021](0021-pownforge-http-api-endpoint.md)までで、ユーザーから依頼
された4点(ネットワーク経由fetch、target名の自動解決、HTTP APIエンド
ポイント、Evidenceの橋渡し)のうち3点が完了した。本ADRは最後の1点、
PownForgeの`RunRecord.evidence`をRiskForge側`Evidence`としてどう保存し
`RawFinding.EvidenceID`に繋ぐか(AGENTS.md §20A.4)を扱う。

## 決定

### `ExtractEvidence`(`internal/infrastructure/scanner/pownforge`)

```go
func ExtractEvidence(payload []byte, assetID asset.ID) (evidence.Params, error)
```

PownForgeの`Evidence`(`src/pownforge/core/models/evidence.py`、
`command`/`started_at`/`finished_at`/`returncode`/`stdout_sha256`/
`stderr_sha256`/`tool_version`)を`RunRecord`の`evidence`サブオブジェクト
として実際に確認した上で実装した。

- **`ContentHash`は`stdout_sha256`を使う**(`stderr_sha256`や両方を
  結合したハッシュではない): PownForgeのプラグイン出力(検出結果・
  生のツール出力)は標準出力側にあるため。意図的な選択であり、実行の
  完全な出力を網羅する試みではないことをコードコメントに明記した
- **`Location`は空のまま返す**: `AssetID`と違い、「このデータはどこに
  あるか」に唯一の正解が無い(ローカルファイルパスか、fetchしたURLか、
  HTTPリクエストボディ経由で来た場合は出所を示すものが無い)。呼び出し元
  (CLI/HTTP API)だけがpayloadの取得経路を知っているため、
  `Params.Location`は呼び出し元が埋める
- **1つの`RunRecord`につき1つのEvidence**: PownForgeの`evidence`は
  RunRecord全体(実行1回分)を表し、個々のFindingを表さない。このため
  `ExtractEvidence`はRunRecordごとに1回だけ呼び、結果の`evidence.ID`を
  そのRunRecordの全RawFindingが共有する(Findingごとに呼ぶのではない)

### `Normalize`のシグネチャ変更

```go
func Normalize(payload []byte, assetID asset.ID, evidenceID evidence.ID) ([]rawfinding.RawFinding, error)
```

第3引数として`evidenceID`を追加し、生成される全ての`RawFinding`に
スタンプする。Evidenceを記録しない場合(下記)は空文字列を渡す。

### CLI: `--location`は無く、モードごとに自動導出。`--skip-evidence`で無効化可能

`scanner import-pownforge`は、`<file>`モードではファイルの絶対パスから
`"file://" + 絶対パス`を、`--pownforge-url`/`--run-id`モードでは
実際にfetchしたURL(`Fetch`が組み立てるものと同じ形)を`Location`として
自動的に使う。オペレーターが明示的に指定する新しいフラグは追加せず、
`--skip-evidence`(Evidence記録自体をスキップ)のみ追加した。

`ExtractEvidence`が返す`ContentHash`が空(payloadに`evidence`サブ
オブジェクトが無い、または`stdout_sha256`が空)の場合は、
`record_evidence()`が要求する非空検証に必ず失敗するため、**Evidence
記録自体をスキップしてインポートを続行する**(全体を失敗させない)。
標準エラー出力にその旨を1行出す。

### HTTP API: `Location`はembeddedモードで必須、fetchモードでは自動導出

CLIと違い、HTTP APIの`RunRecord`埋め込みモードには「ファイルパス」も
「fetchしたURL」も存在しない(呼び出し元がどこからJSONを持ってきたかを
サーバー側は知りようがない)。このため`pownforgeImportBody`に
`Location`(embeddedモードで、`SkipEvidence`がtrueでない限り必須)と
`SkipEvidence`を追加した。`PownForgeURL`+`RunID`モードでは、CLIと同じ
形で自動導出し`Location`は無視する。

### 型注入パターンの拡張

`PownForgeEvidenceExtractor`関数型を、`PownForgeNormalizer`/
`PownForgeFetcher`と全く同じ注入パターンで追加した(`internal/cli`・
`internal/api`双方に個別に定義、`NewMux`/`HandlerFactory`の境界は
ADR 0021で確立した「無名の生の関数型」のルールをそのまま踏襲)。

**実機検証**: 実PostgreSQL(`docker compose`)+実際に`pownforge scan
nuclei`を実行して得た本物のRunRecord(`pownforge result show <id>`)を
`riskforge scanner import-pownforge`で取り込み、`riskforge evidence
show`で実際にContent Hashが本物の`stdout_sha256`
(`817e3c6465f7d1b099ab2b2019ad2754e02c6d13b682b69d893bcdf8eaa84858`)と
完全一致し、Locationが取り込んだファイルの絶対パスとして記録され、
`riskforge finding show`でそのFindingのEvidenceフィールドに正しく
繋がっていることを確認した。`--skip-evidence`でEvidence記録を省略できる
ことも確認した。

## 対象外(範囲を明示的に超えるもの)

- PownForgeの`command`/`returncode`/`tool_version`をRiskForge側
  `Evidence`のどこかに保持すること: 現在の`evidence.Evidence`は
  `Type`/`Source`/`SourceRef`/`CollectedAt`/`AssetID`/`FindingID`/
  `ContentHash`/`Location`のみで、これらを持たない。`pfEvidence`構造体
  自体はパースしているが未使用のまま残している(将来必要になれば
  `evidence.Evidence`自体の拡張が要る、これは本ADRの範囲を超える
  ドメインモデル変更)
- `stderr_sha256`の扱い: `ContentHash`は`stdout_sha256`のみを使うと
  決定した(上記「決定」参照)。両方を記録したい場合は
  `evidence.Evidence`のスキーマ拡張が要る

## 影響

- `internal/infrastructure/scanner/pownforge/adapter.go`: `pfEvidence`
  構造体、`ExtractEvidence`関数を追加。`Normalize`のシグネチャに
  `evidenceID`を追加
- `internal/cli/scanner.go`: `PownForgeEvidenceExtractor`型、
  `--skip-evidence`フラグ、Location自動導出、Evidence記録ロジックを追加
- `internal/api/scanner.go`: 同上のHTTP版。リクエストボディに
  `Location`/`SkipEvidence`を追加
- `internal/cli/root.go`/`serve.go`、`internal/api/api.go`、
  `cmd/riskforge/main.go`: 新しい関数の配線
- テスト: `adapter_test.go`に`ExtractEvidence`の単体テスト3件、
  `scanner_test.go`(HTTP API側)に`statefulEvidenceRepo`を新設し
  Evidence記録の有無を検証するテスト3件を追加
- `go build`/`go vet`/`go test ./...`はクリーン。実PostgreSQL+実際の
  `pownforge scan`実行結果に対する実機検証(Content Hashの完全一致確認
  込み)を実施済み

---

以上でユーザーから依頼された4点(ネットワーク経由fetch・target名の
自動解決・HTTP APIエンドポイント・Evidenceの橋渡し)がすべて完了した。
PownForge連携(Phase 5)はADR 0015〜0022の8枚で、Scanner→RawFinding→
Normalizer→Matcher→Adapter(fetch/normalize/evidence)→CLI/HTTP取り込み
まで一気通貫で動作する状態になっている。
