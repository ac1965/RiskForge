# 0009. PostgreSQL永続化とマイグレーション

## 状態

Accepted

## 背景

AGENTS.md §29はスキーマ上分離して保持すべきテーブルを挙げており、
§25A.1はPostgreSQL + golang-migrateをスタックとして名指ししている。
`internal/application/ports.go`（ADR 0008）で定義されたportに対して
これを実装するにあたり、§29が直接触れていないいくつかの事項を決定する
必要があった。

## 決定

- **ドライバ**: pgxのネイティブ（非`database/sql`）interfaceではなく、
  `github.com/jackc/pgx/v5/stdlib` をドライバとする `database/sql` を
  用いる。これにより、すべてのリポジトリが標準ライブラリのinterfaceに
  対して書かれることになり、golang-migrateの `database/postgres`
  ドライバ（`*sql.DB` をラップする）がそのまま動作する。
- **配列や構造化データはネイティブなPostgres配列やenum型ではなく
  `JSONB` に格納する。** `Asset.IPAddresses`/`MACAddresses`、
  `Vulnerability.CWE`/`AffectedProducts`、`risk.Assessment.Factors`/
  `priority.Decision.Factors` はすべてJSONBとして保存し、Go側で
  `encoding/json` でmarshal/unmarshalする。これにより、
  pgx経由の`database/sql`が持つより煩雑なネイティブ配列のスキャンを
  回避でき、すべてのカラムを素の `Scan` 呼び出しで読み取れるように
  なる。Enum（`asset_type`、`severity`、`status`、...）は、Postgresの
  `ENUM` 型ではなく `CHECK` 制約付きの `TEXT` とする。Postgres enumの
  許容値集合の変更（`ALTER TYPE ... ADD VALUE`）は、後続のマイグレー
  ションで `CHECK` 制約を更新するより破壊的だからである。オープン
  エンドなフィールド（`evidence.type`、`audit_log.action`、
  `findings.detection_source`）には `CHECK` を一切設けない。対応する
  Go側の型がクローズドなenumではなく素の文字列であることと整合させる
  ためである。
- **`findings.evidence_id` ↔ `evidence.finding_id` の循環参照**は、
  まず（マイグレーション`000004`で）`findings` を制約なしの
  `evidence_id UUID` カラム付きで作成し、`evidence` が存在してから
  マイグレーション`000005`で実際の外部キーを追加することで解消する。
  `000005` のdownマイグレーションは、テーブルをdropする前にこの制約
  をdropする。
- **§29は `remediation_plans` とは別に `remediation_actions` を挙げて
  いる**が、ドメインモデル（Phase 3、ADR 0003）には §14の正確な
  フィールドリストに対応する `remediation.Plan` という1つのエンティ
  ティしか存在せず、そこには既に `action_type`、`status`、
  `executed_at` が含まれている。§29の図に一度だけ登場するテーブル名
  を満たすためだけに新しいドメインエンティティを今導入することは、
  一度も具体的に規定されたことのない要件（§14はRemediationPlanに対して
  するようなフィールドリストをRemediationActionには一切与えていない）
  についてスキーマ設計を投機的に行うことになる。テーブルは
  `remediation_plans` の1つのみとし、もし（1つのPlanの複数回の
  リトライのような）試行単位の実行履歴が実際に必要になった場合は、
  ここで推測するのではなく、それに相応しい独自のADRを伴う新しい
  ドメイン概念とすべきである。
- **`audit_log` は§29のリストにないにもかかわらず追加する**。
  `audit.Entry`（§30、Phase 4）を永続化するにはテーブルが必要であり、
  §29内の他の名前はどれも当てはまらないためである。`subject_id` は
  外部キーではなく `TEXT` とし、`audit.Entry.SubjectType`/
  `SubjectID` が意図的に汎用的で型付けされていない参照であることと
  整合させる（ADR 0007）。
- **追記専用 vs. upsert**: `assets`、`software_installations`、
  `vulnerabilities`、`findings`、`remediation_plans`、`exceptions` は
  `INSERT ... ON CONFLICT (id) DO UPDATE` を用いる。これらのドメイン
  型は、状態変化（`Observe`、`TransitionTo`、`Approve`、...）の後に
  Application層が再保存する可変な集約だからである。
  `risk_assessments`、`priority_decisions`、`verifications` は
  `ON CONFLICT` 句のない素の `INSERT` とする。各 `risk.Engine.Assess`
  / `priority.Engine.Decide` / 記録された `Verification` 呼び出しは、
  以前の行を上書きするのではなく、新しい履歴行を生成することを意図
  しており、後で `FindLatestByFinding` の
  `ORDER BY ... DESC LIMIT 1` によって見つけられる。`evidence` と
  `audit_log` は `INSERT ... ON CONFLICT (id) DO NOTHING`（evidence）
  または素の `INSERT`（audit_log）を用いる。どちらもドメイン設計上
  不変である（`evidence.Evidence` にも `audit.Entry` にも更新用
  メソッドが存在しない）ため、`internal/infrastructure/postgres` が
  どちらのテーブルに対しても `UPDATE` を発行することはない。
- **マイグレーションは `go:embed` で埋め込む**
  （`migrations/embed.go`）。これにより `postgres.Migrate(db)` は
  `migrate` CLIのインストールを必要とせずマイグレーションを適用でき、
  `/migrations/*.sql` は（CLI形式、`make migrate-up` からも使える）
  唯一の正本のままである。
- **Integration testは `//go:build integration` タグの背後に隠す**
  （`internal/infrastructure/postgres/integration_test.go`）。
  `database/sql` をモックするのではなく、testcontainers-go
  （AGENTS.md §25A.6）を介してテストごとに実際のPostgreSQLコンテナを
  起動する。タグなしの `go test ./...` はDockerに一切触れず、
  `make test-integration`（`go test -tags=integration ./...`）は
  触れる。CIはこの2つを別々のジョブとして実行する。これらの
  integration専用のimportはbuildタグの背後にあるため、通常の
  `go mod tidy` はそれらを見つけられず、`go.mod`/`go.sum` から削って
  しまう — そのため `make tidy` は代わりに
  `GOFLAGS=-tags=integration go mod tidy` を実行する。

## 影響

- すべてのリポジトリは、port interfaceに対してコンパイルされるだけで
  なく（ADR 0008は既に `interfaces.go` にコンパイル時の
  `var _ application.XRepository = (*XRepository)(nil)` アサーション
  を持っている）、`integration_test.go` によって実際のPostgreSQLに
  対して検証される。スキーマとクエリの不一致は、productionに持ち
  越される前に `make test-integration` で検出される。
- `EvidenceRepository.Save` と `AuditRepository.Save` がそれぞれの
  テーブルへの唯一の書き込み経路であり、対応する `Update` が存在
  しないことは、「EvidenceとAuditは作成後に変更されない」という
  不変条件をDBレベルで具体的に強制するものである — これはドメイン
  型がsetterを持たないことで既にコード化しているのと同じ不変条件
  である。
- 後から本当に新しい `remediation_actions` という概念が必要になった
  場合は、新しいマイグレーション、新しいドメイン型、そしてADR 0003
  の更新（または置き換え）が必要であり、既存の `remediation_plans`
  テーブルをひそかに転用することは許されない。
