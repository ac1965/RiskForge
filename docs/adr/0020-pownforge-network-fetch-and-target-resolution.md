# 0020. ネットワーク経由fetchとtarget名の自動解決(PownForge連携 第六弾)

## 状態

Accepted

## 背景

[ADR 0019](0019-pownforge-cli-ingestion.md)は`fetch()`を最も単純な形
(事前エクスポートされたJSONファイルを読む)に限定し、実際にPownForgeへ
ネットワーク越しに到達する経路と、PownForgeのtarget名からRiskForgeの
`asset.ID`を自動解決する処理を次のADRへ先送りした。ユーザーから
「ネットワーク経由のfetch・target名の自動解決・HTTP APIエンドポイント・
Evidenceの橋渡し」の4点をまとめて依頼されたが、AGENTS.md §47・§48に
従い本ADRはこのうち最初の2点(いずれも`scanner import-pownforge`
コマンドの入力オプションを増やすだけで、Application/ドメイン層への
変更を伴わない)に絞る。残り2点(HTTP APIエンドポイント、Evidenceの
橋渡し)はそれぞれ独立したADRとして別途実施する。

## 決定

### `Fetch`(`internal/infrastructure/scanner/pownforge`)

```go
func Fetch(ctx context.Context, baseURL, runID string) ([]byte, error)
```

PownForgeの`GET /api/runs/{run_id}`(`src/pownforge/web/routers/runs.py`、
`response_model=RunRecord`)を実際に確認した上で、そのパスへの単純な
HTTP GETとして実装した。50MiB相当の読み取り上限とクライアント側の
30秒タイムアウトを設ける(PownForge自身にリクエストサイズ制限は無い
ため、こちら側での防御的な上限)。認証は行わない
(PownForgeのWeb APIはlocalhostのみにバインドする設計で、認証機構を
持たない、PownForge側`docs/handbook.md` §9参照)。

**実機検証**: 実際に`pownforge web serve`を起動し(nucleiの
robots-txt-endpointテンプレートで実スキャンを1件実行した後)、
RiskForge側の`Fetch`から`GET /api/runs/<run_id>`へ本当にHTTPリクエスト
を送って取得、`Normalize`に通して`RawFinding`へ変換できることを確認
した(`httptest.Server`によるテストに加え、実際に動いている
PownForgeプロセスに対しても検証)。

### `--target`によるAsset自動解決(`internal/cli/scanner.go`)

PownForgeのtarget名(スコープ対象名の文字列)を、既存の
`discover_assets()`(AGENTS.md §26、`Service.DiscoverAssets`)経由で
RiskForgeの`asset.ID`へ解決する。これは新しい解決ロジックではなく、
`asset discover --hostname`が既に使っている「hostnameでの
idempotentなupsert」パスをそのまま再利用しただけである
(§37の重複排除要件をそのまま享受する)。`Type`/`Environment`/
`Criticality`/`Exposure.Level`/`LifecycleState`は`asset discover`が
`--hostname`のみ与えられた場合と同じ既定値
(`TypeUnknown`/`EnvironmentUnknown`/`CriticalityUnknown`/
`LevelUnknown`/`LifecycleActive`)を使う。

既存の`--asset <id>`(ADR 0019で導入、既存Assetを直接指定)とは
互いに排他とし、どちらか一方を必須にした。

**実機で見つけたバグ**: 実装当初、`asset.Params{Hostname: targetFlag}`
だけを渡して呼んでいたところ、`asset.New`が`Type`の必須検証
(`"asset: invalid type \"\""`)で失敗することを実機確認で発見した
(`asset discover`コマンド自身は全フィールドに既定値を设定しているため
気づかれなかった潜在バグ)。`internal/cli/asset.go`の
`newAssetDiscoverCommand`と同じ既定値を明示的に埋めることで解決した。

### `<file>`と`--pownforge-url`/`--run-id`の排他制御

`scanner import-pownforge`は`[file]`を省略可能な位置引数に変更し、
`--pownforge-url`+`--run-id`(両方揃って初めて有効)との**どちらか
一方のみ**を許可する(両方指定・どちらも未指定はエラー)。
`PownForgeFetcher`関数型を`PownForgeNormalizer`と同じ注入パターンで
追加し、`cmd/riskforge/main.go`から`pownforge.Fetch`を渡す
(`internal/cli`は引き続き`internal/infrastructure`を直接importしない、
ADR 0019の解決パターンをそのまま踏襲)。

**実機検証**: 実PostgreSQL(`docker compose`)に対し、
`--target`での新規Asset自動作成・同一target名での再取り込み時の
Asset再利用(重複無し)、`--pownforge-url`のみ/`--run-id`のみ指定時の
エラーメッセージを確認した。

## 対象外(別ADRで扱う)

- HTTP APIエンドポイント(`riskforge serve`側に`scanner
  import-pownforge`相当の経路を追加すること) — 別ADR
- Evidenceの橋渡し(PownForgeの`RunRecord.evidence`をRiskForge側
  `Evidence`としてどう保存し`RawFinding.EvidenceID`に繋ぐか) — 別ADR
- PownForgeのWeb APIへの認証(現状PownForge自身が持たないため、
  RiskForge側で追加する動機も無い)
- `validate()`の強化(引き続き`json.Unmarshal`の成功/失敗のみ)

## 影響

- `internal/infrastructure/scanner/pownforge/adapter.go`に`Fetch`を
  追加(テスト: `httptest.Server`による単体テスト3件、実PownForge
  プロセスに対する実機検証)
- `internal/cli/scanner.go`: `PownForgeFetcher`型、`--target`/
  `--pownforge-url`/`--run-id`フラグ、相互排他バリデーションを追加
- `internal/cli/root.go`・`cmd/riskforge/main.go`: 新しい引数の配線
- `go build`/`go vet`/`go test ./...`はクリーン。実PostgreSQL・実
  PownForgeプロセス双方に対する実機検証を実施済み
