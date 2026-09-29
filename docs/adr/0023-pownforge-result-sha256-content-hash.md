# 0023. Evidence ContentHashをresult_sha256優先に変更

## 状態

Accepted

## 背景

[ADR 0022](0022-pownforge-evidence-bridging.md)は`ContentHash`に
PownForgeの`stdout_sha256`(プロセスの標準出力そのもののハッシュ)を
使うと決定した。2026-09-30の実機PoC第2弾([§14.0.1](../handbook.md#1401-実機poc-pownforgeの検知是正再検証をremediationワークフローで完結2026-09-30))
で、この選択が`container`(trivy)プラグインに対して実質的に機能しない
ことが判明した: trivyは検出結果を`-o <file>`でファイルへ書き、標準
出力には何も書かないため、`stdout_sha256`は常に空文字列のSHA256
(`e3b0c44...`)になる。2回の異なるスキャン結果でも同じハッシュに
なってしまい、改ざん検知として機能しない。ADR 0022自身の検証は
nuclei(標準出力に結果を書くプラグイン)に対して行われており、この
前提の崩れには気づいていなかった。

PownForge側で、この問題を修正する`Evidence.result_sha256`
フィールド(PownForgeリポジトリの2026-09-30の変更、`RunRecord.output`
の正規化JSONをハッシュ -- プラグインが結果をstdout/ファイルの
どちらに書くかに依存しない)が追加された。

## 決定

`ExtractEvidence`(`internal/infrastructure/scanner/pownforge/adapter.go`)の
`ContentHash`算出を、`result_sha256`優先・`stdout_sha256`フォールバックに
変更する:

```go
contentHash := run.Evidence.ResultSHA256
if contentHash == "" {
    contentHash = run.Evidence.StdoutSHA256
}
```

- **`result_sha256`が空でなければそちらを使う**: PownForge側の
  `Evidence.result_sha256`は`None`の場合JSON上`null`になり、Goの
  `encoding/json`は`string`フィールドへの`null`/欠落キーをゼロ値
  (空文字列)として扱うため、追加のnull処理コードは不要
- **`result_sha256`が空(古いPownForgeバージョン/このフィールド追加前に
  保存されたrun)なら`stdout_sha256`にフォールバック**: 後方互換。
  古いPownForgeと連携している既存の取り込みが壊れない
- **`stderr_sha256`や両方を結合したハッシュは使わない**: ADR 0022が
  既に決定した非目標をそのまま維持する

## 対象外(範囲を明示的に超えるもの)

- `evidence.Evidence`自体のスキーマ変更: `ContentHash`は引き続き単一の
  文字列フィールドで、「どのハッシュ由来か」を区別する追加フィールドは
  設けない。`ExtractEvidence`が呼び出し元に代わってどちらを使うかを
  決定する
- PownForge側`Evidence.result_sha256`の実装詳細(どのフィールドを
  ハッシュに含めるか等)はPownForgeリポジトリの責務であり、本ADRは
  RiskForge側の消費方法のみを扱う

## 影響

- `internal/infrastructure/scanner/pownforge/adapter.go`: `pfEvidence`に
  `ResultSHA256`フィールドを追加、`ExtractEvidence`のContentHash算出を
  上記のフォールバックロジックに変更
- テスト: `adapter_test.go`に
  `TestExtractEvidencePrefersResultSHA256OverStdoutSHA256`(result_sha256
  優先の確認)・`TestExtractEvidenceFallsBackToStdoutSHA256WhenResultSHA256Absent`
  (後方互換の確認)を追加。既存の`TestExtractEvidence`(サンプルJSONに
  result_sha256を含まない)は無変更のままフォールバック経路を暗黙に
  検証し続ける
- **実機検証**: 実際にPownForgeで`container`プラグインを実行して得た
  本物のRunRecord(`result_sha256`付き)を`riskforge scanner
  import-pownforge`で取り込み、`SELECT content_hash FROM evidence`で
  実際にPownForge側の`result_sha256`
  (`73cab4f6632e126c8429236586712f5253c4bd3a8121aa312fbd1b1ea93bffea`)と
  完全一致することを確認した
- `go build`/`go vet`/`go test ./...`はクリーン
