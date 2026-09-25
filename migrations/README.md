# マイグレーション

スキーマのマイグレーションは
[golang-migrate](https://github.com/golang-migrate/migrate)
で管理する（AGENTS.md §25A.1、§29）。データベーススキーマはドメインモデル
から設計するのであって、その逆ではない: `assets`、`software_installations`、
`vulnerabilities`、`findings`、`evidence`、`risk_assessments`、
`priority_decisions`、`remediation_plans`、`verifications`、`exceptions`
は独立したテーブルとして保持し、すべてを詰め込む単一の `vulnerabilities`
テーブルは作らない。`audit_log` も独立したテーブルであり、AGENTS.md §29の
明示的なリストには含まれていないが、`audit.Entry`（§30、Phase 4）を永続化
するために必要である。

`§29` は `remediation_plans` とは別に `remediation_actions` テーブルも
挙げている。ドメインモデル（`internal/domain/remediation`）には §14の
フィールドリストに対応する `Plan` エンティティしか存在しないため、
`remediation_actions` は同一概念として扱い、独立したテーブルにはしていない
（詳細は
[docs/adr/0009-postgres-persistence.md](../docs/adr/0009-postgres-persistence.md)
を参照）。

`findings.evidence_id` と `evidence.finding_id` は互いを参照しており、
この循環依存は、まず（制約なしの）`evidence_id` カラムを持つ `findings`
を先に作成し（マイグレーション `000005`）、`evidence` が存在してから外部
キーを追加することで解消している。

このディレクトリの `embed.go` は `go:embed` を使ってこれらの `.sql` ファイル
を埋め込んでおり、`internal/infrastructure/postgres.Migrate` は `migrate`
CLIをインストールしなくてもマイグレーションを適用できる — いずれの経路でも
このディレクトリが唯一の正本である。

新しいマイグレーションのペアを作成する:

```bash
migrate create -ext sql -dir migrations -seq <name>
```

CLIでマイグレーションを適用する:

```bash
migrate -database "$RISKFORGE_DATABASE_URL" -path migrations up
```

またはプログラムから:

```go
db, err := postgres.Open(dsn)
// ...
err = postgres.Migrate(db)
```

`make migrate-up` / `make migrate-down` は `$RISKFORGE_DATABASE_URL` を
使ってこのCLI形式をラップしたものである。
