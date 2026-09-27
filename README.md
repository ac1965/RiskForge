# RiskForge

Vulnerability & Exposure Management Platform（脆弱性・エクスポージャー管理プラットフォーム）。

単なる脆弱性スキャナではなく、Asset → Software → Vulnerability → Risk →
Prioritization → Remediation → Verification → Evidence という一連のライフ
サイクル全体を管理する。ドメインモデル・アーキテクチャ・開発上の制約の全体像は
[AGENTS.md](AGENTS.md) を参照。本READMEは日常的なコマンドのみを扱う。

設計・ビルド・利用を図表つきでまとめた手引書は
[docs/handbook.md](docs/handbook.md) を参照。

## 関連プロジェクト

[PownForge](https://github.com/ac1965/PownForge) は姉妹プロジェクトであり、
許可を得た検証用ラボ環境に対する発見/検証スキャンを行う攻撃側CLI（別リポジト
リ、Python/Typer製）である。RiskForgeは防御側の対となる存在であり、PownForge
を外部Scannerとして扱い（RawFinding → Normalizer → Matcher → Finding）、
PownForgeからRemediationを実行することは決してなく、Verificationの一手法
（`scanner_rescan`）としてPownForgeの再スキャンを呼び出すことがある。この連携
は**両側ともまだ未実装**であり（RiskForge Phase 5 「Integrations」として計画）、
設計制約の正本は
[AGENTS.md §20A "PownForge Integration"](AGENTS.md#20a-pownforge-integration)
にある。明示的な依頼なしに、このフェーズより先んじて連携コードを実装しては
ならない。

## 技術スタック

Go 1.24+、PostgreSQL、golang-migrate、Cobra CLI、`net/http`。
[AGENTS.md §25A](AGENTS.md#25a-technology-stack) を参照。

## バイナリ

- `riskforge` — CLI / APIサーバー
- `riskforge-agent` — 管理対象Asset上で稼働（Scanner権限）
- `riskforge-worker` — バックグラウンドジョブ（Remediation実行権限）

AGENTS.md §31・§25A.3で述べた権限分離を物理的に実現するため、バイナリは
分離して保持する。

## 開発

```bash
make up               # Docker ComposeでPostgreSQLを起動
make build             # 3つのバイナリすべてを ./bin にビルド
make test              # go test ./...（Dockerは不要）
make test-integration  # go test -tags=integration ./...（testcontainers-goで実際のPostgresを起動）
make vet               # go vet ./...
make migrate-up        # $RISKFORGE_DATABASE_URL にマイグレーションを適用
make migrate-down      # マイグレーションを1つロールバック
```

データベーススキーマのマイグレーションは [migrations/](migrations/) 配下にあり、
golang-migrateで管理する。詳細は
[migrations/README.md](migrations/README.md) を参照。

## ステータス

Phase 1（AGENTS.md §45）のドメインモデル — Asset、Software、Vulnerability、
Finding — は `internal/domain/` 配下に実装済みであり、バリデーションと
Findingステータスのライフサイクルをカバーする単体テストが存在する。

Phase 2のドメインモデル — RiskとPriority — も実装済み。`internal/domain/risk`
（Risk Engine、§8）と `internal/domain/priority`（Priority Engine、§12）は
それぞれ差し替え可能なProviderとPolicyを組み合わせ、スコアリング式をハード
コードすることなく、説明可能なAssessment/Decision（§40）を生成する。Phase 2の
Dashboard部分（§41、フロントエンド）は未着手（§25A.7: フロントエンド作業は
バックエンド/CLI/APIの後に開始する）。

Phase 3のドメインモデル — Remediation、Verification、Evidence — も実装済み。
`internal/domain/remediation`（RemediationPlan、§13–§14）、
`internal/domain/verification`（§16）、`internal/domain/evidence`（§17）。
自動修復ポリシーの設定（§15の `auto_remediation_policy`）はPhase 4へ先送りした。

Phase 4のドメインモデル — Exception、Policy、Audit — も実装済み。
`internal/domain/exception`（§18、例外の実行可能期間の上限を課す
`exception.Policy` を含む）、`internal/domain/policy`（§15の
`AutoRemediationPolicy`、デフォルトで自動実行を拒否）、
`internal/domain/audit`（§30、who/what/when/why/before/afterを記録する
不変レコード）。汎用的で永続化・バージョン管理されたPolicyドキュメント集約は
意図的に作らなかった — その理由は
[docs/adr/0007-exception-policy-audit.md](docs/adr/0007-exception-policy-audit.md)
を参照。

Application層のNamed API（AGENTS.md §26）も `internal/application` に実装
済み: `DiscoverAssets`、`InventoryAsset`、`CorrelateFindings`、`AssessRisk`、
`CalculatePriority`、`CreateRemediationPlan`/`ApproveRemediationPlan`/
`PreviewRemediation`/`ExecuteRemediation`、`VerifyRemediation`、
`RecordEvidence`、および Exceptionワークフロー（`RequestException`、
`ApproveException`、`RejectException`、`ExpireException`、
`RevokeException`）。これらはリポジトリのport interface（`ports.go`）と
Phase 2のエンジンにのみ依存しており、現在は下記のPostgreSQL実装により裏付け
られている。portsの設計とどの操作が監査対象かについては
[docs/adr/0008-application-layer.md](docs/adr/0008-application-layer.md)
を参照。

PostgreSQL永続化とマイグレーションも実装済み: `internal/infrastructure/postgres`
は `internal/application/ports.go` のすべてのリポジトリを提供し
（`interfaces.go` にコンパイル時の
`var _ application.XRepository = (*XRepository)(nil)` チェックあり）、
`/migrations` 配下に埋め込んだSQLマイグレーションを適用する `Migrate(db)`
も提供する。スキーマと永続化の設計（JSONB vs. ネイティブ配列、
`findings`↔`evidence` の循環外部キー、追記専用 vs. upsertするテーブル、
独立した `remediation_actions` テーブルが存在しない理由）については
[docs/adr/0009-postgres-persistence.md](docs/adr/0009-postgres-persistence.md)
を参照。

リポジトリの挙動はtestcontainers-goを介した実際のPostgreSQLコンテナに対して
検証している（AGENTS.md §25A.6）: `make test` はDockerに一切触れず、
`make test-integration` は触れる。

CLIの配線も実装済み: `cmd/riskforge/main.go` がcomposition rootであり
（PostgreSQLへ接続し、Risk/Priority Engineを構築し、`application.Service`
を組み立てる）、`internal/cli` は `internal/application` にのみ依存し、
`internal/infrastructure` を直接参照することはない。コマンド体系は
AGENTS.md §27に加え、システムをエンドツーエンドで使用可能にするために
必要ないくつかのコマンド（`asset discover`、`vulnerability add`、
`finding correlate`、`remediation approve`/`preview`/`execute`、
`exception` ワークフロー、`evidence record`、`priority calculate`、
`migrate`）をカバーする — それぞれを追加した理由については
[docs/adr/0010-cli-wiring.md](docs/adr/0010-cli-wiring.md) を参照。
実際のPostgreSQLインスタンスに対してエンドツーエンドで検証済み: asset →
vulnerability → finding → risk → priority → remediation（propose →
approve → execute） → evidence → verify、および別途、exceptionの
request → approve → expire のライフサイクル。それぞれが期待通りの
Findingステータス遷移を駆動することを確認している。

HTTP API（読み取り専用5エンドポイント + Exceptionワークフローの書き込み
系、トークン認証付き）実装済み: `riskforge serve`（デフォルト
`127.0.0.1:8080`、`--addr`で上書き可）が`GET /api/v1/assets`・
`/findings`・`/priorities`・`/remediation-plans`・`/exceptions`を提供する。
いずれも`internal/application`の既存`List*`メソッドを薄くラップするだけで、
正常時は対象リソースの配列を、失敗時は`{"error": "..."}`(500)を返す
([ADR 0011](docs/adr/0011-http-api-design.md)、P0-2)。

これに加えて、[ADR 0014](docs/adr/0014-exception-write-endpoints.md)
どおりP0-3の第一弾として、Exceptionワークフローの書き込み系
(コマンド実行を伴わない範囲。Remediationの書き込み系は別ADRに先送り)
を実装済み: `POST /api/v1/exceptions`(request、201)、
`POST /api/v1/exceptions/{id}/{approve,reject,expire,revoke}`(200)。
`RequestedBy`/`ApprovedBy`はリクエストボディではなく認証済み
Principalの名前を使う(クライアントの自己申告を信用しない)。エラーは
対象が存在しない場合`404`、不正な状態遷移(例: 承認済みを再度承認)は
`409`、それ以外のバリデーション失敗は`400`。

認証・認可は
[docs/adr/0012-http-api-authentication.md](docs/adr/0012-http-api-authentication.md)
どおり実装済み: `riskforge token create --principal <name> --scope read`
で発行したbearerトークン(`rf_<random>`、サーバー側はSHA-256ハッシュのみ
保存)を`Authorization: Bearer <token>`で提示しないと5エンドポイントの
どれにもアクセスできない(トークン欠落/不正/期限切れ/失効は401、スコープ
不足は403)。`riskforge token list`/`token revoke <id>`はHTTP API経由では
提供せず、CLI専用(APIサーバーが落ちていても失効操作ができるようにする
ため)。`--addr`をloopback(既定の`127.0.0.1`/`::1`/`localhost`)以外に
bindする場合は`--tls-cert`/`--tls-key`が無いと起動自体を拒否する
(bearerトークンを平文HTTPで送らせないため)。

`internal/api`は`internal/application`にのみ依存し、`internal/cli`も
`internal/api`を直接importしない(`cmd/riskforge/main.go`が
`func(*application.Service) http.Handler`を注入する)。実際にPostgreSQLへ
asset(criticality/exposure付き)を登録し、`riskforge token create`で発行
した実トークンを使って、`riskforge serve`(平文HTTP・loopback、および
自己署名証明書を使ったTLS・非loopbackの両方)を起動し、トークン無し/
不正トークン/スキーム違いがいずれも401になること、正しいトークンで
5エンドポイントすべてから実データが返ること(空配列は`null`ではなく
`[]`)、`token revoke`後は同じトークンが即座に401になることを`curl`で
確認済み。書き込み系も、`exception:request`スコープのトークン(alice)で
`POST /api/v1/exceptions`を作成し、`exception:approve`スコープのトークン
(bob)で承認・再承認(409)・失効(revoke)まで一連の流れを`curl`で実行し、
`RequestedBy`/`ApprovedBy`が期待どおりトークンの持ち主の名前になること、
承認によってFindingが`accepted`へ、失効によって`reopened`へ遷移すること
(`riskforge finding list`で確認)、存在しないIDへの操作が404になること、
必須フィールド欠落が400になることを確認済み。

Dashboard実装済み: `dashboard/`(TypeScript + React + Vite、
[ADR 0013](docs/adr/0013-dashboard-bootstrap.md))が、上記5エンドポイント
をそのまま表示するタブ切り替え画面を提供する。Exceptionsタブには
Approve/Reject/Expire/Revokeボタンがあり、ADR 0014の書き込みエンドポイント
を直接呼び出す(スコープ不足は403がその場に表示される)。Overviewタブは
AGENTS.md §41のKPIのうち既存の一覧エンドポイントだけで計算できるもの
(Total Assets・Internet Exposed Assets・Exception Count・Expired
Exceptions・Reopened Findings・Remediation SLA)をクライアント側で計算
して表示する。Critical Findings等、Vulnerability/Verificationのデータが
要るKPIと、1件を掘り下げる詳細画面は対象外のまま。Dashboard自身は
トークンを発行しない(`riskforge token create`で発行したトークンを
Settings画面に貼り付け、ブラウザの`localStorage`に保存するのみ)。
`npm run dev`はViteのdevサーバープロキシで`/api`を`riskforge serve`へ
転送するため、`internal/api`側にCORS対応は追加していない。実際に
`riskforge serve`(平文HTTP・loopback)に対して起動し、ブラウザで7タブ
すべてが実データを表示すること、KPI計算値が実データ(asset 2件・実行済
remediation 1件・申請中exception 1件)と一致すること、Exceptions一覧の
Reject/Approveボタンが実際に`POST`を送りステータス更新後に再描画される
ことを確認済み。`window.prompt`が使えない環境(一部の自動化ブラウザ等)
でクラッシュせず案内メッセージを出すことも確認済み。
