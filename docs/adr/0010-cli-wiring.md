# 0010. CLIの配線

## 状態

Accepted

## 背景

`internal/cli`（初期スキャフォールディングの時点から）は既にAGENTS.md
§27が示すコマンド体系を持っていたが、すべての `RunE` は「not
implemented yet」を返していた。これを実際の永続化に配線すると、
ADR 0008とADR 0009がApplicationとInfrastructureについて既に答えたのと
同種の疑問が生じた: §27のリストは出発点となる構造（「CLIは以下のよう
な構造を基本とする」）であって、必ずしも網羅的ではなく、そのいくつかの
コマンドは `list`/`show` が表示するためのデータを生成する手段を持たず、
あるいは前フェーズで構築した承認/実行/exception操作に到達する手段を
持っていなかった。

## 決定

- **Composition root**: `internal/cli` ではなく `cmd/riskforge/main.go`
  が `internal/infrastructure/postgres` をimportし、
  `risk.Engine`/`priority.Engine` を構築する。これは
  `internal/cli.NewRootCommand` に `ServiceFactory`
  （`func() (*application.Service, func() error, error)`）と
  `migrate func() error` を渡す。`internal/cli` 自身は
  `internal/application` と（フラグから `Params` 構造体を組み立て、
  enum定数を読み取るための）`internal/domain` の値型のみをimportし、
  `internal/infrastructure` を一切importしない — バイナリ全体として
  は明らかにPostgreSQLを必要とするにもかかわらず、レイヤリングルール
  （AGENTS.md §25）を保っている。
- **factoryは遅延評価される**: 各コマンドは `NewRootCommand` の構築
  時点ではなく、自身の `RunE` の中で `newService()` を呼び出す。
  これにより `$RISKFORGE_DATABASE_URL` が一切設定されていなくても
  `riskforge --help` や `riskforge --version` は動作し、一方で実際の
  コマンドは設定されていない場合には即座に、かつ明確に失敗する。
- **Application portsに `List`/`ListLatest` メソッドを追加した**
  （`AssetRepository.List`、`FindingRepository.List`、
  `RemediationPlanRepository.List`、`ExceptionRepository.List`、
  `PriorityDecisionRepository.ListLatest`）。これらはこのフェーズ
  以前には存在しておらず、CLIの `list` コマンドが必要とするまで誰も
  必要としていなかった。それぞれ `internal/infrastructure/postgres`
  に実装され、専用のintegration testでカバーされている。
  `PriorityDecisionRepository.ListLatest` は
  `SELECT DISTINCT ON (finding_id) ... ORDER BY finding_id, decided_at
  DESC` を用いてFindingごとの最新の決定を取得し、同一Findingに対して
  異なるランクを持つ2つの決定を含むfixtureに対して検証している。
- **§27の文字通りのリストを超えるコマンド**を追加した。既存のもの
  だけでは実用可能なシステムとして組み合わせられないためである:
  - `asset discover`、`vulnerability add`、`finding correlate`:
    CLI経由でAsset、Vulnerability、Findingを作成できる他の手段が
    ない。`vulnerability add` は明示的に手動の代替手段であり、実際の
    取り込みはNVD/KEV/OSVのData Source Adapter（§19）— これはPhase 5
    である。
  - `remediation approve`、`remediation preview`、
    `remediation execute`: `remediation propose` だけでは
    `StatusProposed` を超えて進めない（ADR 0003の承認ゲート）。
  - `exception request`/`approve`/`reject`/`expire`/`revoke`:
    §27には `exception list` しか示されておらず、Exception（§18、
    Phase 4）にはそれ以外CLIのエントリーポイントが一切ない。
  - `priority calculate`: `risk assess` と対になる、Risk → Priority
    パイプラインの書き込み側であり、これにより `priority list` は
    決定を一覧表示する副作用としてこっそり計算するのではなく、
    純粋な読み取りのままでいられる。
  - `evidence record`: `verify` と `exception request` の両方が、
    参照するためのEvidence idを必要とする。
  - `migrate`: 外部の `migrate` CLIを必要とせず、`postgres.Migrate`
    （ADR 0009）を再利用することで、`riskforge` バイナリをスキーマ
    セットアップについて自己完結させる。
- **`remediation execute` はプレースホルダーの `manualExecutor`**
  （`internal/cli/remediation.go`）を用い、常に成功を報告する。
  AGENTS.md §31/§32が実際に要求するvalidated/structured/allowlisted
  なコマンド実行はまだ存在しない（ADR 0008の `RemediationExecutor`
  portを参照）。これはオペレーターが既に手動で変更を加えており、CLIは
  その事実を記録しているに過ぎないという前提であり、実際の実行
  インフラを持たないv1のCLIが約束できることについて正直な設計である。
- **バッチコマンド（`risk assess`、`priority calculate`）は、1件の
  失敗の後も処理を継続する**。失敗ごとに `finding <id>: error: ...`
  を出力し、すべての対象を処理し終えてから非ゼロの終了コードを返す。
  これにより1件の不良なFindingが残りの評価をブロックすることはない。
- **`RISKFORGE_DATABASE_URL`** は、CLIが読み取る唯一の設定項目である
  （既にこの名前を使っているMakefileの `migrate-up`/`migrate-down`
  ターゲットと整合する）。

## 影響

- `cmd/riskforge/main.go` は、CLIを別のProviderセット（例えば実際の
  CMDB連携の `BusinessImpactProvider` が実装された場合）や別の永続化
  バックエンドに向けるために変更が必要な唯一の場所である —
  `internal/cli` 自体はPostgreSQLの存在を一切知らない。
- 単体レベルだけでなく、実際のPostgreSQLインスタンス
  （`docker compose up` + ビルド済みバイナリ）に対してもエンドツー
  エンドで検証済み: asset discover → asset list/inspect →
  vulnerability add → finding correlate → finding list/show →
  risk assess → priority calculate/list → remediation propose →
  （approve前のexecuteは正しく拒否される）→ approve → preview →
  execute → Findingが `remediated` に到達 → evidence record →
  verify → Findingが `verified` に到達。これとは別に、exception
  request（組織の期間上限を超えたものは1回拒否、その範囲内のものは
  1回受理）→ approve → Findingが `accepted` に到達 → expire →
  Findingが `reopened` に到達。
- `root.SilenceErrors` は `true` としている。`cmd/riskforge/main.go`
  が既に `Execute()` が返すエラーを出力しているためである。cobraの
  デフォルトである `false` のままにしておくと、すべてのコマンドエラー
  が二重に出力されてしまい、上記のエンドツーエンド検証で即座に発覚
  した。
