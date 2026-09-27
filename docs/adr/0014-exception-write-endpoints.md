# 0014. 書き込み系HTTP APIの第一弾: Exceptionワークフロー

## 状態

Accepted

## 背景

ADR 0011は書き込み系エンドポイントを明示的に対象外とし、「別途ADR/PRで
扱う」としていた。ADR 0012も、書き込み系エンドポイントを追加する際は
AGENTS.md §14(承認と実行の分離)をスコープでも表現すること、
具体的なスコープ名・ハンドラごとの要求スコープは「該当エンドポイントを
実装するPRで別途決定する」とし、`exception:approve`を例として挙げていた。

書き込み系として公開しうるNamed APIは、Asset discovery・Finding
correlate・Risk assess・Priority calculate・Remediation
propose/approve/preview/execute・Exception
request/approve/reject/expire/revoke・Evidence recordと幅広い。特に
Remediation executeは実際のコマンド実行に繋がる可能性があり(現状は
`manualExecutor`のみだが)、AGENTS.md 第47章の原則6「Remediationを
実装するときはDry Runを先に実装する」・原則7「自動修復をデフォルト
有効にしない」が直接関わる。これらを一度に設計・実装することは§47・§48
(大規模な機能追加を1PRに詰め込まない)に反する。

本ADRは、書き込み系APIの**第一弾**として、コマンド実行を一切伴わない
Exceptionワークフロー(§18)のみをスコープとする。Remediationの
書き込み系(propose/approve/execute)は、Dry Run・実行権限分離を
HTTP層でどう表現するかを含めて、別ADRで扱う。

## 決定

### エンドポイント

`internal/application`の既存Named API(`RequestException`/
`ApproveException`/`RejectException`/`ExpireException`/
`RevokeException`、いずれもADR 0008で導入済み)をそのまま呼び出す。
新しいApplication層のロジックは追加しない。

```text
POST /api/v1/exceptions                → RequestException  → 201
POST /api/v1/exceptions/{id}/approve   → ApproveException   → 200
POST /api/v1/exceptions/{id}/reject    → RejectException    → 200
POST /api/v1/exceptions/{id}/expire    → ExpireException    → 200
POST /api/v1/exceptions/{id}/revoke    → RevokeException    → 200
```

いずれも成功時のレスポンスボディは、更新後の`Exception`(`GET
/api/v1/exceptions`が返すのと同じ形)を返す。

### リクエストボディとフィールド名

既存の読み取り専用5エンドポイントがGoの構造体をそのまま
`json.Marshal`している(jsonタグを使わずPascalCaseのフィールド名を
そのまま公開する、ADR 0011の方針)ことと内部一貫性を保つため、
リクエストボディもPascalCaseのフィールド名を使う。snake_case/camelCase
という一般的なREST慣習より、このAPI内での一貫性を優先する。

```text
POST /api/v1/exceptions
  {"FindingID": "...", "Reason": "...", "ExpiresAt": "2026-12-31T00:00:00Z",
   "CompensatingControl": "..." (省略可)}

POST /api/v1/exceptions/{id}/approve
  {"Reason": "..."}

POST /api/v1/exceptions/{id}/expire
  {"Reason": "..."} (省略時は "reached expiry date"、CLIの既定値と同じ)

POST /api/v1/exceptions/{id}/reject
POST /api/v1/exceptions/{id}/revoke
  ボディ無し(Application側にreasonパラメータが無いため)
```

`RequestedBy`/`ApprovedBy`はリクエストボディに含めない。
`internal/api`の`RequireScope`ミドルウェアが認証済みの`authn.Principal`
をcontextに詰めているため(ADR 0012)、`PrincipalFromContext`から得た
`Principal.Name`を使う。CLIは`--requested-by`/`--approved-by`という
自由入力フラグを使っているが、HTTP経由ではクライアントが自己申告する
文字列より、トークンが紐づく認証済みIdentityの方が信頼できるため、
CLIとは意図的に異なる方式を取る。

go-playground/validator(AGENTS.md §25A.1推奨)はまだこのリポジトリの
どこでも使われていない。本PRのためだけに新規導入するのは§48が禁じる
「機能追加に便乗したFramework変更」に該当しうるため見送り、必須
フィールドの有無・`ExpiresAt`のRFC3339形式といった最小限のチェックを
ハンドラ内で手書きする。将来、書き込みエンドポイントが増えて手書き
検証が増えてきた時点で、validator導入を別ADRとして検討する。

### スコープ設計(ADR 0012の続き)

ADR 0012は`exception:approve`を例示していたが、「誰が要求してよいか」
と「誰が決定してよいか」を分けるため、Remediationの
propose/approveと同じ考え方で`exception:request`を追加する。

```text
exception:request  → POST /api/v1/exceptions (request)
exception:approve  → POST .../approve, .../reject, .../expire, .../revoke
```

reject/expire/revokeもapproveと同じスコープにまとめる。理由:
いずれも「既存のException requestの結末を決定する」操作であり、
requestを作るのとは異なる権限レベルが必要だが、この4つの操作間で
リスクの性質が大きく異なるわけではない(スコープを4分割しても
AGENTS.md §14が求める「承認と実行の分離」の実質は増えない)。将来
実際に運用上の必要が生じた時点で細分化する。

### エラーレスポンスとステータスコード

ADR 0011は読み取り専用エンドポイントについて「Application層のエラーは
すべて500として扱う」とし、ID指定エンドポイントの404の扱いは
「導入時に別途決定する」と明記していた。本PRがそれにあたる。

- リクエストボディがJSONとして不正、または必須フィールド欠落 →
  `400`
- 対象のExceptionが存在しない(`ApproveException`等が返す
  "not found"エラー) → `404`。これを`errors.Is`で判定できるよう、
  `internal/application`に`ErrNotFound`を新設し、Exception関連の
  4箇所の "not found" エラーをこれでラップする(メッセージ文字列・
  CLIの出力は変更しない、`%w`で包むだけ)
- 不正な状態遷移(`exception.ErrInvalidTransition`、例:
  すでにRejectedのExceptionをApproveしようとした) → `409`
- 上記のいずれでもないApplication層のエラー(ドメインバリデーション
  失敗、Exception Policy違反等) → `400`。真にインフラ起因の失敗
  (DB接続断等)もこの分類に落ちる可能性があるが、ADR 0011自身が
  採用した「完璧な分類より単純さを優先する」という前例を踏襲する
  (バリデーション失敗が大半を占めるため、実用上は妥当な近似)

エラーボディの形式(`{"error": "..."}`)はADR 0011を維持する。

### 依存方向・ミドルウェア

`internal/api`は引き続き`internal/application`にのみ依存する。
`RequireScope`ミドルウェア自体はADR 0012の実装をそのまま再利用し、
要求スコープだけがルートごとに変わる。

### 対象外(この後のADRで扱う)

- Remediationの書き込み系(propose/approve/preview/execute): Dry Run・
  `riskforge-worker`との実行権限分離をHTTP層でどう表現するかを含めて
  別ADR
- Asset discovery・Finding correlate・Risk assess・Priority
  calculate・Evidence record: 需要が生じた時点で別ADR/PR
- OpenAPIスキーマ定義(AGENTS.md §25A.5): 書き込み系を含めた
  エンドポイント数が安定してから整備する(ADR 0011から持ち越し)

## 影響

- `internal/application/exception.go`の4箇所に`ErrNotFound`のwrapが
  加わる(メッセージ・CLI出力は不変)。
- `internal/api`に5つの新規ハンドラと、リクエストボディのデコード・
  最小限のバリデーション・エラー分類ロジックが追加される。
- READMEのステータスセクションに、書き込み系(Exceptionワークフロー)
  実装済みであることを追記する。
