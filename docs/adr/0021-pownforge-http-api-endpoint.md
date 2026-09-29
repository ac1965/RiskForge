# 0021. `POST /api/v1/scanner/pownforge-import`: HTTP APIエンドポイント(PownForge連携 第七弾)

## 状態

Accepted

## 背景

[ADR 0020](0020-pownforge-network-fetch-and-target-resolution.md)までで
CLI(`scanner import-pownforge`)からの取り込みが一通り動くようになった。
ユーザーから依頼された残り2点(HTTP APIエンドポイント、Evidenceの橋渡し)
のうち、本ADRはHTTP APIエンドポイントを扱う。

## 決定

### `POST /api/v1/scanner/pownforge-import`

[ADR 0011](0011-http-api-design.md)/[0012](0012-http-api-authentication.md)/
[0014](0014-exception-write-endpoints.md)の既存の型(PascalCaseフィールド、
封筒無し、`net/http`標準`ServeMux`、bearer token認証)をそのまま踏襲した。

リクエストボディ:

```go
type pownforgeImportBody struct {
    RunRecord    json.RawMessage // PownForgeのRunRecord JSONをそのまま埋め込む
    PownForgeURL string          // または、サーバー側でfetchする場合
    RunID        string
    AssetID      string
    Target       string
}
```

`RunRecord`(CLIの`<file>`相当)と`PownForgeURL`+`RunID`(CLIの
`--pownforge-url`/`--run-id`相当)はどちらか一方のみ、`AssetID`と
`Target`もどちらか一方のみを要求する。バリデーションロジックは
CLI(`internal/cli/scanner.go`)と実質同じ内容をこちらにも実装した
(下記「対象外」に、この重複についての判断を記す)。

レスポンスは`scanner import-pownforge`のタブ区切り出力に対応する
JSON配列:

```json
[{"Title": "...", "Outcome": "correlated|registered|unmatched|held", "FindingID": "..."}]
```

### 新スコープ`scanner:import`

書き込みを伴うエンドポイントとして、既存の`exception:request`/
`exception:approve`と同じ考え方で新設した(`internal/domain/authn/
token.go`、「必要になった時点で追加する」という既存コメントの方針
どおり)。`ScopeRead`には相乗りしない。`riskforge token create
--scope`のヘルプ文字列を更新するのを忘れかけたが、実機検証
(後述)で気づいて修正した。

### `internal/api`も`internal/infrastructure`を直接importしない

`internal/cli`と同じ制約(AGENTS.md §25 Layering)を`internal/api`にも
適用し、`NewMux`に`normalizePownForge`/`fetchPownForge`を関数値として
注入する形にした(ADR 0018/0020のCLI側パターンをそのまま踏襲)。

実装時に見つけた型システム上の制約: `internal/cli`の`HandlerFactory`
(`serve.go`)は`internal/api.NewMux`をそのまま代入できる必要があるが、
`internal/cli`と`internal/api`はそれぞれ独自に
`PownForgeNormalizer`/`PownForgeFetcher`という**別々の名前付き型**を
定義している(互いをimportしないため)。Goでは同じ構造を持つ別々の
名前付き関数型は、関数シグネチャの引数位置では**相互に代入不可**
(名前付き型どうしの同一性は構造ではなく宣言そのもので決まる)。
このため`NewMux`と`HandlerFactory`は、双方とも**無名の生の関数型**
(`func([]byte, asset.ID) ([]rawfinding.RawFinding, error)`等)を
シグネチャに直接書く形にした(パッケージ内部で使う
`PownForgeNormalizer`という別名は、`NewMux`/`HandlerFactory`の
境界そのものには使わない)。これにより、どちらのパッケージも
相手の型を一切importせずに済んでいる。

**実機検証**: 実PostgreSQL(`docker compose`)+実際に`riskforge serve`
を起動し、`riskforge token create --scope scanner:import`で発行した
トークンを使い、実際にHTTP POSTで`RunRecord`を埋め込んだリクエストを
送って`registered`という結果を取得した。トークン無し(401)、
スコープ不足(403)、`AssetID`と`Target`両方指定(400)もそれぞれ実機で
確認した。

## 対象外(別ADRで扱う)

- Evidenceの橋渡し(PownForgeの`RunRecord.evidence`をRiskForge側
  `Evidence`としてどう保存し`RawFinding.EvidenceID`に繋ぐか) — 別ADR
- CLIとHTTP APIハンドラの間で重複している「`--target`/`Target`解決」
  ロジック(`resolveTargetAsset`ヘルパーとして各パッケージ内に個別実装):
  3箇所目の呼び出し元が現れた時点で共有ヘルパーの抽出を検討する
  (投機的な抽出はしない、ADR 0011の`List`追加時の判断と同じ方針)
- ネットワーク越し`fetch()`(PownForgeへの到達経路)自体の認証: 
  PownForge自身が認証を持たないため、こちら側でも追加しない
  (ADR 0020から継続)

## 影響

- `internal/domain/authn/token.go`: `ScopeScannerImport`を追加
- `internal/api/api.go`: `NewMux`のシグネチャに`normalizePownForge`/
  `fetchPownForge`(無名関数型)を追加、`POST /api/v1/scanner/
  pownforge-import`ルートを登録
- `internal/api/scanner.go`(新規): ハンドラ実装
- `internal/cli/serve.go`: `HandlerFactory`のシグネチャを同じ無名
  関数型に変更、`newServeCommand`に`normalizePownForge`/
  `fetchPownForge`を追加配線
- `internal/cli/token.go`: `--scope`のヘルプ文字列に`scanner:import`
  を追記
- テスト: `internal/api/scanner_test.go`(新規、10ケース)。実行に
  あたり、`internal/api`の既存フェイク(`assetsFake`/
  `vulnerabilitiesFake`)がstateless(Save/FindByIDが実質no-op)である
  ため、`MatchRawFinding`が要求する「保存したものを直後に見つけられる」
  という前提を満たせず、`statefulAssetsRepo`/
  `statefulVulnerabilitiesRepo`(`exceptions_test.go`の
  `statefulFindingsRepo`等と同じ様式)を新設し、`testServiceFakes`に
  `assetsRepo`/`vulnerabilitiesRepo`のオーバーライドフィールドを追加した
- `go build`/`go vet`/`go test ./...`はクリーン。実PostgreSQL・実際に
  起動した`riskforge serve`プロセスへの実機検証を実施済み
