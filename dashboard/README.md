# RiskForge Dashboard

`internal/api`(読み取り専用5エンドポイント、[ADR 0011](../docs/adr/0011-http-api-design.md))
を表示するだけの、TypeScript + React + Viteのフロントエンドです。設計判断
(ディレクトリ命名・技術選定・スコープ)は
[docs/adr/0013-dashboard-bootstrap.md](../docs/adr/0013-dashboard-bootstrap.md)
を参照してください。

## 現在のスコープ

- Assets / Findings / Priorities / Remediation Plans / Exceptionsの
  一覧表示のみ。詳細画面・書き込み操作UIは含まない
- AGENTS.md §41のKPI群(Overdue Remediation等)は、対応する集計APIが
  存在しないため対象外

## 認証

このDashboard自身はトークンを発行しません([ADR 0012](../docs/adr/0012-http-api-authentication.md)
がWeb上でのトークン発行UIを明示的に禁止しています)。まずCLIでトークンを
発行してください。

```bash
riskforge token create --principal dashboard --kind service --scope read
```

表示された`rf_...`をDashboardの「Settings」画面に貼り付けると、以降の
リクエストに`Authorization: Bearer <token>`として使われます。値は
ブラウザの`localStorage`にのみ保存されます。

## 開発

```bash
npm install
npm run dev
```

`npm run dev`はViteのdevサーバープロキシで`/api`を`riskforge serve`
(既定`http://127.0.0.1:8080`)へ転送します。別アドレスの場合は
`RISKFORGE_API_URL`環境変数で上書きできます(`vite.config.ts`参照)。
あらかじめ`riskforge serve`を起動しておいてください。

```bash
npm run build   # 型チェック(tsc -b) + 本番ビルド
npm run lint    # oxlint
```
