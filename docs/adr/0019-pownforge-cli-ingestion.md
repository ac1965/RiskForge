# 0019. `riskforge scanner import-pownforge`: fetch()とCLI配線(PownForge連携 第五弾)

## 状態

Accepted

## 背景

[ADR 0018](0018-pownforge-adapter-and-unclassified-persistence.md)は
`normalize()`(`internal/infrastructure/scanner/pownforge.Normalize`)まで
実装し、「`fetch()`のCLI・HTTP配線」を対象外として次のADRに残した。
ユーザーから改めて「次のステージ」の依頼を受け、本ADRで着手する。

設計に着手した時点で、`internal/cli/root.go`の既存コメント
「Commands call into internal/application; they must not reach into
internal/domain business logic or internal/infrastructure directly
(AGENTS.md §25)」と、実際に`Normalize`をCLIコマンドから呼びたいという
要求が衝突することに気づいた。この制約は既存のCLIコード
(`internal/cli/service.go`の`ServiceFactory`、`internal/cli/serve.go`の
`HandlerFactory`)が既に解決済みのパターンを持っている:
**実体はcomposition root(`cmd/riskforge/main.go`)で組み立て、関数値
としてCLIへ注入する**。本ADRはこのパターンをそのまま踏襲した。

## 決定

### `PownForgeNormalizer`関数型(`internal/cli/scanner.go`)

```go
type PownForgeNormalizer func(payload []byte, assetID asset.ID) ([]rawfinding.RawFinding, error)
```

`ServiceFactory`/`HandlerFactory`と全く同じ形。`internal/cli`が依存する
のはこの関数シグネチャ(と`internal/domain`の値型)だけで、
`internal/infrastructure/scanner/pownforge`パッケージ自体は
`cmd/riskforge/main.go`だけがimportする。`NewRootCommand`の第4引数として
追加し、`main.go`から`pownforge.Normalize`をそのまま渡す。

### `riskforge scanner import-pownforge <file> --asset <id>`

本ADRの`fetch()`は**意図的に最も単純なもの**にした: 実行中のPownForge
インスタンスへネットワーク越しに到達するのではなく、事前にエクスポート
された JSON ファイル(例: `pownforge run show <id> --format json >
run.json`)を読む。実際にPownForgeへHTTP等で到達する経路の設計
(認証の要否、ベースURLの設定等)は次のADRへ先送りする(下記「対象外」
参照)。

`--asset`は既存の`asset.ID`を直接受け取る。`finding correlate --asset`
が既にこの流儀(target名からの自動解決はせず、オペレーターが既知のIDを
渡す)を採用しており、それに倣った。PownForgeの`target`名(スコープ対象
名の文字列)からRiskForgeの`asset.ID`を自動解決する処理
(`AssetRepository.FindByHostname`等)は、Assetを暗黙に作成すべきか
という別の設計判断を伴うため、本ADRでは行わない。

処理の流れ: ファイル読み込み→`normalizePownForge`→各`RawFinding`に
ついて`svc.MatchRawFinding`をループ呼び出し→結果(`title`/`outcome`/
`finding id`)をタブ区切りで出力。1件の`MatchRawFinding`が失敗しても
コマンド全体を中断する(部分的成功を許容する設計にはしていない -- 実運用
での挙動は今後の実績を見て判断する)。

### テスト方針

`internal/cli`パッケージは既存の慣習として(`serve_test.go`のコメント
「このパッケージは基本的にGo単体テストではなく実際の実行で検証する」)
純粋なロジック単位(`isLoopbackAddr`)以外の単体テストを持たない。
`scanner.go`にも同種の単体テスト可能なロジックが無いため、新規テスト
ファイルは追加せず、代わりに以下を実機で検証した:

1. `docker compose up -d` + `riskforge migrate`で実PostgreSQLを起動
2. `riskforge asset discover --hostname lab-web`でAssetを登録
3. PownForgeが実際に生成する形式(`finding.py`/`evidence.py`の
   フィールド名)のRunRecord JSON(nuclei風のCVEなし`info`severity
   finding、CVE付きconfirmed finding、false-positive findingの3件)を
   `riskforge scanner import-pownforge`で取り込み、
   - `false-positive`が除外されること(出力に2行のみ)
   - CVEなしfindingが`registered`(Severity=none、Confidence=medium)
     となること
   - CVE付きfindingは、対応するVulnerabilityが未登録の間は
     `unmatched`、`vulnerability add --cve-id CVE-2014-0160`で登録後に
     再実行すると`correlated`(Confidence=confirmed、PownForgeの
     `status=confirmed`どおり)に変わること
   を確認した
4. 同じファイルを再度取り込んでも同一のFinding ID(重複なし)である
   ことを確認し、idempotencyを実機で確認した

## 対象外(次のADRで扱う)

- 実際にPownForgeへネットワーク越しに到達する`fetch()`(HTTP経由での
  Web API呼び出し、認証、ベースURL設定)
- PownForgeの`target`名からRiskForge `asset.ID`への自動解決
- `validate()`: 取り込み前の入力検証の強化(現状は`json.Unmarshal`の
  成功/失敗のみ)
- HTTP API側の対応エンドポイント(現状CLIのみ)
- Evidenceの橋渡し(ADR 0018から持ち越し)
- ATT&CK/CVSSフィールドの最終採用可否(ADR 0015から持ち越し)

## 影響

- `internal/cli/scanner.go`(新規): `PownForgeNormalizer`型、
  `scanner`/`scanner import-pownforge`コマンド
- `internal/cli/root.go`: `NewRootCommand`に`normalizePownForge`引数を
  追加(既存の呼び出し元は`cmd/riskforge/main.go`のみで、他に破壊的
  影響なし)
- `cmd/riskforge/main.go`: `pownforge.Normalize`を注入
- `go build`/`go vet`/`go test ./...`はクリーン。実PostgreSQLに対する
  実機検証(上記)を実施済み
