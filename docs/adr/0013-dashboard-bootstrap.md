# 0013. Dashboardの起動(ディレクトリ命名・技術選定・最小スコープ)

## 状態

Accepted

## 背景

ADR 0011/0012(P0-2読み取り専用HTTP API、P0-4トークン認証+TLS)が完了し、
AGENTS.md §25A.7が定める「Frontend(TypeScript/React)はPhase 2(Dashboard)
以降で着手する」の前提条件が満たされた。リファクタリング指示書v5 §2は、
Dashboard着手にあたって以下を本ADRで決定するよう求めている。

- フロントエンドディレクトリの命名
- 最小スコープの確認(P0-2の5エンドポイントの一覧表示のみ、書き込み
  操作UIは含めない)

AGENTS.md §41は将来のDashboardが表示すべきKPI群(Total Assets、Overdue
Remediation、Remediation SLA等)を挙げているが、これらの多くは現状の
読み取り専用5エンドポイント(生の一覧)からは直接算出できない集計値で
あり、専用の集計APIが別途必要になる。本ADRはそれを先取りせず、AGENTS.md
§47(大規模Refactoringの禁止、変更前のArchitecture Decision記録)・
指示書v5 §2の両方が求める「一覧表示のみのPRとして最初に完結させる」
方針を維持する。

## 決定

### ディレクトリ命名: `dashboard/`

AGENTS.md はこの機能を第41章から一貫して「Dashboard」と呼んでおり、
本書もこれに合わせて`dashboard/`とする。姉妹プロジェクトPownForgeの
フロントエンドは`webui/`という名称だが、命名規則をプロジェクト間で
機械的に揃える要件はAGENTS.mdに存在しないため、それに合わせる必然性は
ない。RiskForgeの既存ドキュメント内の呼称をそのまま使うことを優先する。

### 技術スタック: TypeScript + React + Vite

AGENTS.md §25A.1が定める「TypeScript / React」をそのまま採用する。
ビルドツール自体はAGENTS.mdに指定が無いため、現時点で軽量・高速な
デファクトスタンダードであるViteを採用する(Create React Appは
メンテナンスモードのため避ける)。パッケージ管理はnpm(`package-lock.json`)
とする。

### スコープ: P0-2の5エンドポイントの一覧表示のみ

- `GET /api/v1/{assets,findings,priorities,remediation-plans,exceptions}`
  をそのまま表として表示する一覧画面5つと、それらを切り替えるだけの
  最小限のナビゲーションのみを実装する。
- AGENTS.md §41のKPI群(Overdue Remediation等)は、対応する集計APIが
  存在しないため本PRの対象外とする。将来必要になった時点で、集計API
  設計のADRを別途起票してから着手する。
- 詳細画面(1件の対象を掘り下げる画面)・書き込み操作UI(Remediation
  承認・Exception承認等)は本PRに含めない。別PRに分割する(AGENTS.md
  §47・指示書v5 §2)。

### 認証UX: トークンはCLIで発行し、DashboardにはCLIから貼り付ける

ADR 0012は「Web上の自己登録・発行エンドポイントは作らない」と明記して
いる。本ADRもこれを踏襲し、Dashboard自身にはトークンを発行・失効する
UIを持たせない。運用者は`riskforge token create --principal <name>
--scope read`で発行した生トークンを、Dashboardの設定画面(1つの入力
フィールドのみ)に貼り付け、ブラウザの`localStorage`に保存する。以降の
API呼び出しは`Authorization: Bearer <token>`ヘッダーにこの値を使う。
トークンが未設定または401/403が返った場合は、設定画面への入力を促す。

### 開発時のAPI接続: Viteのdevサーバープロキシ

`npm run dev`時は、Viteの`server.proxy`で`/api`パス配下を
`riskforge serve`(既定`http://127.0.0.1:8080`)へ転送する。これにより
`internal/api`側にCORS対応を追加する必要がなくなる(ADR 0011/0012が
決めたレスポンス形式・認証方式には変更を加えない)。本番ビルドの静的
ファイル配信方法(`riskforge serve`自身から配信するか、別のWebサーバー
を使うか)は本ADRの対象外とし、必要になった時点で別ADRとして決定する。
本PRでの動作確認は`npm run dev` + 実際の`riskforge serve`に対する
手動確認までとする。

## 影響

- 新規ディレクトリ`dashboard/`(`package.json`・`vite.config.ts`・
  `tsconfig.json`・`src/`)が追加される。Goモジュール
  (`go.mod`/`go.sum`)には影響しない。
- READMEの「ステータス」セクションに、Dashboardの一覧表示のみが実装
  済みであることを追記する。
- 詳細画面・書き込み操作UI・§41のKPI集計APIは、それぞれ将来の別PR・
  別ADRの対象として明示的に残す。
