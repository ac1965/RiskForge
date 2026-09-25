# 0004. Evidenceモデル

## 状態

Accepted

## 背景

AGENTS.md §17は、Evidenceを改ざん検知可能な第一級エンティティとし、
Findingと混同してはならないと定めている（§44 不変条件4）。§22と
§47.10はさらに、誤検知（false positive）であってもEvidenceを削除・
上書きすることを禁じている。

## 決定

- `evidence.Evidence`（`internal/domain/evidence`）は、§17に挙げられて
  いるフィールド（`Type`、`Source`、`CollectedAt`、`AssetID`、
  `FindingID`、`ContentHash`、`Location`）に `ID` を加えたものだけを
  持ち、**更新用のメソッドは一切持たない** — 提供されるのは `New` の
  みである。このパッケージには、構築後に既存のEvidence値のフィールド
  を変更するコードパスは存在しない。訂正は常に新しいEvidenceレコード
  として行う。
- `FindingID` のみが任意項目である。Evidence（例えば生のスキャン結果）
  は、特定のFindingに紐付けられる前に収集され得る。一方 `AssetID` は
  必須である。Evidenceは常に何らかのAssetの文脈で収集されるためである。
- `ContentHash` は必須だが、空でないこと以外のフォーマットは強制しない:
  §17は「可能ならHashを利用する」と述べているため、将来ある情報源が
  別種の完全性マーカーしか提供できない場合でも、このドメイン型が使え
  なくならないようにしている。`ComputeContentHash`（SHA-256、16進数
  エンコード）と `Evidence.VerifyContent` はデフォルトの仕組みとして
  提供されており、Infrastructure側のコードが生のコンテンツを持って
  いる場合はこれを使うべきである。
- `Location` は必須であり、実際のコンテンツがどこにあるかを示す参照
  （例: URI）である — Evidenceエンティティ自体は生のコンテンツを保持
  したり読み書きしたりしない。Locationを介したコンテンツの保存・取得
  はInfrastructureの責務であり、このパッケージをストレージ/ネット
  ワーク依存から切り離している（§25）。

## 影響

- Evidenceにはsetterが存在しないため、evidenceを「更新」したいコード
  は代わりに新しいEvidenceを作成し、必要であれば新しいFinding/
  Verification/Planの参照からそれをリンクしなければならない — 型
  システムによって、誤って上書きしてしまうことが不可能になっている。
- 保存されているコンテンツが改ざんされていないことを検証するには、
  `Location` からバイト列を取得して `VerifyContent` を呼び出す必要
  がある。このパッケージは意図的にその取得処理自体は行わない。
