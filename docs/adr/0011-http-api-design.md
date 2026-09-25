# 0011. HTTP APIの設計

## 状態

Accepted

## 背景

`internal/api` はこれまで package doc（`doc.go`）のみが存在し、実際の
ハンドラ・ルーティング・`ListenAndServe` は一切実装されていなかった。
Phase 2 Dashboard（AGENTS.md §41）に着手するには、まずDashboardが読み
取るHTTP APIが必要になる。

AGENTS.md §25A.8 は「APIルーティングは標準ライブラリの `net/http`
（`ServeMux`）を用いる。chi等のルーターは、ADRによる変更決定なしに
導入しない」とすでに決定しており、本ADRはこれを覆さない。本ADRが
決めるのは、その上に載せるリクエスト/レスポンス方針、認証・認可の
扱い、および `internal/api` と他レイヤーの依存方向である。

このAPI層は、AGENTS.md §47（大規模リファクタリングの禁止）に従い、
1つのPRで完結する最小スコープ（読み取り専用エンドポイントのみ）を
対象とする。書き込み系エンドポイント（Remediation実行、Exception
承認等）は本ADRの対象外とし、別途ADR/PRで扱う。

## 決定

### ルーティングとハンドラ

- `net/http` の `http.ServeMux`（Go 1.22以降のパターン付き
  `ServeMux`、本リポジトリは go.mod で Go 1.27 系を要求している）を
  用いる。`GET /api/v1/{resource}` の形でパターン登録する。
- ハンドラは `http.HandlerFunc`（＝`http.Handler`）の形を保つ。
  ミドルウェア（将来のログ・認証・リクエストID等）は
  `func(http.Handler) http.Handler` の形でラップし、ルーター固有の
  シグネチャに依存しない（AGENTS.md §25A.8 を踏襲）。
- `internal/api` は `func NewMux(svc *application.Service) http.Handler`
  を公開する。これが `internal/api` の唯一のエクスポートされた
  エントリーポイントであり、個々のハンドラ・エンコード/デコードの
  ヘルパーは非公開のままとする。

### リクエスト/レスポンス方針

- レスポンスは JSON（`Content-Type: application/json`）のみとする。
  クエリパラメータによるフォーマット切り替えは行わない。
- 正常応答は対象リソースの配列をそのまま返す（例:
  `GET /api/v1/assets` → `[{...}, {...}]`）。封筒（envelope）型の
  `{"data": [...]}` は導入しない。ページネーションが必要になった時点
  で、別ADRとして再検討する。
- エラー応答は `{"error": "<message>"}` の形の JSON ボディと、対応する
  HTTP ステータスコードを返す。本PRの読み取り専用エンドポイントでは、
  Application層のエラーはすべて `500 Internal Server Error` として
  扱う（対象リソースをID指定で取得する `GET /{resource}/{id}` は
  本ADRの対象外であり、その導入時に `404 Not Found` の扱いを別途
  決定する）。
- エラーメッセージは、CLI（`internal/cli/output.go`）と同様、内部の
  実装詳細（SQLエラー文字列等）をそのまま露出しない。Application層
  が返す `error` の `Error()` 文字列を使うが、Credential等の機微情報
  がそこに含まれないことは AGENTS.md §31 の既存の原則（ログへ
  Credentialを出さない）に従う。

### 認証・認可

- 本PRでは認証・認可を実装しない。**意図的な先送り**であり、放置では
  ない。理由は次の通り:
  1. 本PRのスコープは読み取り専用の集計データ（Asset/Finding/
     Priority/RemediationPlan/Exceptionの一覧）に限られ、状態変更
     エンドポイントは含まれない。Remediation実行やException承認等、
     Auditドメイン（§30）と連動する書き込み操作を実装する時点で、
     認証・認可の設計（誰が実行できるか）を避けて通れなくなる。その
     時点で改めてADRを起票し、認証方式を決定する。
  2. `riskforge` バイナリは元々ネットワーク境界の外（ローカルCLI /
     信頼された運用ネットワーク）で動く前提だった。HTTP APIサーバー
     を追加することで新たに露出する攻撃面であるため、デフォルトの
     bind先は `127.0.0.1`（後述）とし、運用者が明示的にネットワーク
     境界を越えて公開する場合は、その時点でリバースプロキシ等による
     認証を運用者の責任で追加することを前提とする。
  3. 上記の前提は本PRの完了条件（実DBに対する`curl`確認）にのみ
     適用される暫定的なものであり、Dashboard（P1）から一般利用者が
     アクセスする構成になった時点で、認証・認可の欠如は許容されない。
     そのため、Dashboard着手（本書P1）の前提条件として、認証方式の
     ADRを追加することを次のアクションとして明記する。

### `internal/api` の依存方向

- `internal/api` は `internal/application` にのみ依存する。
  `internal/domain` の値型（DTOへの変換元）を参照することはあるが、
  `internal/infrastructure` を直接importしない。これは
  `internal/cli`（ADR 0010）と同じ制約であり、`internal/api` と
  `internal/cli` はどちらも「UI層」として同じレイヤリングルール
  （AGENTS.md §25）に従う。
- サーバーの起動（`http.ListenAndServe` の呼び出しとPostgreSQLへの
  接続）は `cmd/riskforge/main.go`（Composition Root、ADR 0010）が
  担う。`internal/cli` に `riskforge serve` サブコマンドを追加するが、
  このコマンドは `internal/api` を直接importせず、`main.go` から
  `func(*application.Service) http.Handler` を受け取ることで、
  `internal/cli` が `internal/api` に依存しない構造を保つ
  （`internal/cli` は `net/http`（標準ライブラリ）と
  `internal/application` のみに依存する）。
- バイナリは新設しない。`riskforge` バイナリのサブコマンドとして
  実装し、AGENTS.md §25A.3 のバイナリ/権限分離（
  `riskforge` / `riskforge-agent` / `riskforge-worker`）を変更しない。

### スコープ（本PRセット = P0-2）

読み取り専用、`internal/application/query.go` の既存メソッドを薄く
ラップするだけの5エンドポイントに限定する。

```text
GET /api/v1/assets              → Service.ListAssets
GET /api/v1/findings            → Service.ListFindings
GET /api/v1/priorities          → Service.ListPriorities
GET /api/v1/remediation-plans   → Service.ListRemediationPlans
GET /api/v1/exceptions          → Service.ListExceptions
```

ID指定の `GET /{resource}/{id}`、Vulnerability一覧、Evidence一覧、
および書き込み系エンドポイントは本ADRの対象外とする（
`query.go` には `GetAsset`/`GetVulnerability`/`GetFinding`/
`GetRemediationPlan`/`GetEvidence`/`GetException` はあるが
`ListVulnerabilities`/`ListEvidence` に相当するメソッドが存在せず、
Application層への追加が必要になるため、既存メソッドの薄いラップに
限定する本PRの範囲を超える）。

### デフォルトのbindアドレスとポート

- `riskforge serve` はデフォルトで `127.0.0.1:8080` にbindする
  （`--addr` フラグで上書き可能）。ワイルドカードアドレスへの
  デフォルトbindは、上記「認証・認可」の項で述べた攻撃面拡大を
  避けるため採用しない。

## 影響

- `internal/api` に `NewMux(*application.Service) http.Handler` と、
  5つの非公開ハンドラが追加される。
- `internal/cli` に `newServeCommand` が追加され、
  `NewRootCommand` は新たに `func(*application.Service) http.Handler`
  を構築するための関数を引数に取る。
- `cmd/riskforge/main.go` が `internal/api` をimportし、
  `newServeCommand` に渡す。
- 認証・認可を実装しないため、`riskforge serve` の運用は当面
  「信頼されたネットワーク内、またはlocalhost限定」を前提とする。
  この前提はREADMEのステータスおよび `riskforge serve --help` の
  説明に明記する。Dashboard（本書P1）着手前に、認証方式を決定する
  ADRを追加することを次のアクションとする。
- OpenAPI 3.x によるスキーマ定義（AGENTS.md §25A.5）は本PRでは
  作成しない。エンドポイント数が安定した時点（書き込み系を含めた
  P0全体の完了後）で別途整備する。
