# RiskForge Dashboard

`internal/api`(読み取り専用5エンドポイント、[ADR 0011](../docs/adr/0011-http-api-design.md)。
Exceptionワークフローの書き込み系、[ADR 0014](../docs/adr/0014-exception-write-endpoints.md))
を表示・操作する、TypeScript + React + Viteのフロントエンドです。設計判断
(ディレクトリ命名・技術選定・スコープ)は
[docs/adr/0013-dashboard-bootstrap.md](../docs/adr/0013-dashboard-bootstrap.md)
を参照してください。

## 現在のスコープ

- Assets / Findings / Priorities / Remediation Plans / Exceptionsの
  一覧表示
- Exceptionsの一覧には承認操作(Approve/Reject/Expire/Revoke)ボタンを
  付けている。トークンに対応するスコープ(`exception:request`/
  `exception:approve`)が無ければ、その場で403エラーが表示される
- Overviewタブに、AGENTS.md §41のKPIのうち既存の一覧エンドポイントだけ
  で計算できるもの(Total Assets、Internet Exposed Assets、Exception
  Count、Expired Exceptions、Reopened Findings、Remediation SLA)を
  表示する。Critical Findings等、Vulnerability/Verificationのデータが
  要るものは対象外(該当データを返すエンドポイントがまだ無い)
- 1件を掘り下げる詳細画面は無い(一覧の列でほぼ全フィールドを表示済み
  のため今のところ不要と判断)

## 認証

このDashboard自身はトークンを発行しません([ADR 0012](../docs/adr/0012-http-api-authentication.md)
がWeb上でのトークン発行UIを明示的に禁止しています)。まずCLIでトークンを
発行してください。

```bash
riskforge token create --principal dashboard --kind service --scope read,exception:request,exception:approve
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
