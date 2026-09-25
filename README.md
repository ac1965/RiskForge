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
