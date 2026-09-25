# 0012. HTTP APIの認証・認可方式

## 状態

Accepted

## 背景

ADR 0011（HTTP APIの設計）は、P0-2（読み取り専用エンドポイント）の
スコープでは認証・認可を意図的に実装せず、「Dashboard着手前に、
認証方式を決定するADRを追加する」ことを次のアクションとして明記
していた。本ADRはその宿題に答える。

検討にあたり、RiskForgeの導入形態を確認した: RiskForgeは複数組織に
配布する製品ではなく、**特定の1組織向けに育てる内製システム**である。
さらにその組織には、他の社内ツールが経由するSSO/OIDC IdPや社内
リバースプロキシといった認証基盤が**まだ存在しない**。RiskForgeの
ためだけにそうした基盤を新設するのは過剰投資であるという判断を得た。

検討した選択肢は3つ:

- **A. APIサーバー自体にトークン認証を持たせる**（riskforgeバイナリ
  単体で完結、追加インフラ不要）
- **B. リバースプロキシ委任**（OIDC/oauth2-proxy等の外部コンポーネント
  にAuthenticationを委任し、RiskForgeは信頼済みヘッダーを読むだけ）
- **C. mTLS**（APIサーバーがクライアント証明書を直接検証）

Bは前提となる認証基盤の新設が必要になり、上記の組織方針と矛盾する。
Cは人間がブラウザからDashboardにアクセスする用途にはクライアント
証明書配布の運用負荷が高く、機械間通信（将来のPownForge連携等）
向けの選択肢としては温存する価値があるが、Dashboard認証の第一候補
ではない。

いずれの方式でも、AGENTS.md §14/§32〜§34（Remediationの承認と実行の
分離）が要求する**認可（何をしてよいか）**は、外部のIdPやプロキシが
「これは誰か」を教えてくれるだけでは満たされない。RiskForge自身が
Principal（誰か）とScope（何をしてよいか）を保持する必要があり、
これはA/B/Cいずれを選んでも避けられない。したがって、A案の実装は
将来B案へ移行する場合の土台としても無駄にならない。

## 決定

### 認証方式: A案（APIサーバー自体のトークン認証）を採用する

- 自己完結型のopaque bearer tokenを用いる。JWTのような自己署名型
  トークンは採用しない。理由: §30（Audit）が要求する「who」の
  追跡性と、漏洩時の**即時失効**を優先するため。JWTは有効期限が
  来るまで無効化しづらく、deny-list運用という余計な複雑さを生む。
- トークン形式は `rf_<32バイトのランダム値をbase64url等でエンコード>`
  とし、発行時に一度だけ生の値をCLI標準出力に表示する。サーバー側
  には**SHA-256ハッシュ値のみ**を保存し、生トークンをログ・DB・
  Auditのいずれにも記録しない（AGENTS.md §31）。

### ドメインモデル

新規パッケージ `internal/domain/authn` を追加する。汎用IAMは作らず、
必要最小限に留める（AGENTS.md §48）。

```text
Principal
- id
- name
- kind        (human | service)
- created_at

APIToken
- id
- principal_id
- token_hash
- scopes      ([]string)
- created_at
- expires_at  (nullable)
- revoked_at  (nullable)
- last_used_at (nullable)
```

- 期限切れ・失効済みの判定はドメインロジックとして `authn` パッケージ
  に置く。バリデータ（go-playground/validator）は境界（CLI/API）側
  であり、ドメインには置かない（AGENTS.md §25A.4）。
- Application層に `AuthenticateToken(ctx context.Context, rawToken
  string) (*authn.Principal, error)` をNamed APIとして追加する。
  `internal/api` のミドルウェアはこれだけを呼び、
  `internal/infrastructure` には触れない（ADR 0011の依存方向を
  維持）。
- 永続化は `internal/infrastructure/postgres` に `principals` /
  `api_tokens` テーブルを追加し、golang-migrateのマイグレーション
  `000012`/`000013` として管理する（既存の最終番号は `000011`）。
  既存の他ドメインのテーブルと混在させない（AGENTS.md §29）。

### スコープ設計

- P0-2で実装済みの読み取り専用エンドポイントに対しては `read`
  スコープのみを用いる。Dashboard用に発行するトークンはこれだけを
  持つ。
- 将来、書き込み系エンドポイント（Remediation承認・実行、Exception
  承認）を追加する際は、AGENTS.md §14の承認/実行分離をスコープでも
  表現する。例: `remediation:propose` / `remediation:approve` /
  `remediation:execute` / `exception:approve` を分離し、1つの
  トークンに承認系と実行系の両方を持たせない運用をデフォルトとする。
  この具体設計（スコープ名の確定、ハンドラごとの要求スコープ）は、
  該当エンドポイントを実装するPRで別途決定する。本ADRは
  `APIToken.scopes` が複数のスコープ文字列を保持できるという型だけを
  今のうちに確定させる。
- HTTP APIのトークンは、`riskforge-agent`（Scanner権限）・
  `riskforge-worker`（Remediation実行権限）の権限を代替しない
  （AGENTS.md §25A.3）。Dashboardから将来Remediation実行を呼び出せる
  ようにする場合でも、HTTP API層が実行権限そのものを保持するのでは
  なく、既存のバイナリ権限境界へ委譲する設計とする。この委譲の具体
  方式は、書き込み系エンドポイントの実装時に別ADRで扱う。

### トークン発行はCLI経由のみ

Web上の自己登録・発行エンドポイントは作らない（不要な攻撃面になる
ため）。`riskforge token create --principal <name> --scope read`を
新設し、生成した生トークンをその場で一度だけ表示する。トークンの
一覧・失効も同様にCLIコマンド（`riskforge token list` /
`riskforge token revoke <id>`）として提供し、HTTP API経由では提供
しない（トークン管理コマンド自体がAPIサーバーを介さずに機能する
必要があるため。仮にAPIサーバーが停止していても、失効操作ができる
ことが望ましい）。

### ミドルウェア

ADR 0011で決めた「`http.Handler` をラップするミドルウェア」方針に
従う。

```go
func RequireScope(authn AuthnService, scope string) func(http.Handler) http.Handler
```

`Authorization: Bearer <token>` ヘッダーを読み、`AuthenticateToken`
でPrincipalとscopesを取得し、要求スコープを満たすか検証してcontextに
Principalを詰める。失敗時は `401`（未認証）または `403`
（スコープ不足）を、ADR 0011のエラー形式（`{"error": "..."}`）で返す。

### TLSの要件（ADR 0011のデフォルトbindを上書きする点）

ADR 0011はデフォルトbindを `127.0.0.1:8080`（平文HTTP）としていた。
本ADRでは、**Bearerトークンを平文HTTPで送信する運用を認めない**と
明記する。`127.0.0.1` へのbindはローカルの`curl`検証や開発時に限り
許容するが、それ以外（`--addr`でワイルドカードや非loopbackアドレス
を指定する運用）を行う場合は、TLS終端（`riskforge serve`への
`--tls-cert`/`--tls-key`フラグ追加、またはリバースプロキシでの
TLS終端）を必須とする。TLSフラグの実装自体は、認証機能を実装する
PRの中で一緒に行う（トークン認証だけ実装してTLSを後回しにすると、
平文でトークンが流れる期間が生じるため）。

### 将来のB案（リバースプロキシ委任）への移行余地

組織が将来SSO基盤を整備した場合に備え、以下の点だけ設計上考慮して
おく（今回は実装しない）:

- `Principal` は「トークンから解決される」以外の解決経路（例:
  信頼済みヘッダーから解決）を将来追加できるよう、
  `AuthenticateToken` とは別に `AuthnService` インターフェースの
  形でApplication層のportを切っておく。
- Scopeモデルは認証方式に依存しないため、B案へ移行してもそのまま
  再利用できる。

これ以上の抽象化（未使用の認証方式のためのプラグイン機構等）は
AGENTS.md §48（不要な抽象化の禁止）に反するため行わない。

## 影響

- `internal/domain/authn`（新規）、`internal/application` への
  `AuthenticateToken` Named API追加、`internal/infrastructure/postgres`
  への `principals`/`api_tokens` リポジトリ実装とマイグレーション
  `000012`/`000013` が必要になる。
- `internal/cli` に `token create`/`token list`/`token revoke` サブ
  コマンドが追加される。
- `internal/api` の `NewMux` に `RequireScope` ミドルウェアが導入され、
  P0-2で実装した5エンドポイントすべてに `read` スコープが要求される
  ようになる（既存のcurl検証手順は、認証ヘッダーを追加する形に更新
  が必要）。
- `riskforge serve` に `--tls-cert`/`--tls-key` フラグが追加される。
- この認証機能の実装自体を独立したPR（P0-4）として扱い、Dashboard
  （P1）はこのPRの完了後に着手する。
- READMEのステータスセクションに、認証方式の決定と実装状況を追記
  する。
