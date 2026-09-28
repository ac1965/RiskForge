# 0005. PownForge連携の設計方針

## 状態

Accepted

## 背景

AGENTS.md §20A「PownForge Integration」は、姉妹プロジェクト
[PownForge](https://github.com/ac1965/PownForge)(攻撃側)との連携に
関する設計制約を既に詳細に定めている。§20A.10は「連携仕様の重要な
判断は、`docs/adr/`にADRとして残す(例: `0005-pownforge-integration.md`)」
と明記しており、`docs/adr/`の番号列(0001〜0004、0006〜)も`0005`を
この連携用に予約した形で欠番にしていた。

しかし本書執筆時点(2026-09-27)まで、この`0005`は実際には作成されて
おらず、[本書§14「PownForgeとの関係」](../handbook.md#14-pownforgeとの関係姉妹プロジェクト)
にも「本書執筆時点ではまだ作成されていない」と明記されていた
(PownForge側`AGENTS.md`にも同種の記録専用の一線がある)。

PownForge側[Issue #15](https://github.com/ac1965/PownForge/issues/15)は
これを指摘し、「ADRが存在しないこと自体が、連携の設計検討を始める前提を
欠いている」として、まずこのADRを作成することを提案した。本ADRは
その提案を受けてユーザーの明示的な依頼により作成するもので、
**連携コードの実装そのものを承認するものではない**(下記「対象外」参照)。
AGENTS.md §20A.10・§47・§48が定める「Phase 1〜4の実装に便乗して
連携を先行実装しない」という制約は本ADR作成後も変わらず有効である。

本ADRの役割は、AGENTS.md §20Aと本書§14がすでに定めている設計制約を
正本として維持したまま、ADRという記録形式に落とし込み、将来Phase 5
(Integrations)に着手する際の出発点を1箇所にまとめることにある。
新しい設計判断を追加するものではない。

## 決定

### 基本方針: PownForgeは外部Scannerとして扱う(AGENTS.md §20A.1)

PownForgeの診断結果は、RiskForgeの`Finding`として直接取り込まない。
第20章のScanner経路(`RawFinding → Normalizer → Matcher → Finding`)を
必ず経由する。PownForge専用の特別経路は作らず、PownForgeの出力形式を
ドメインモデルに漏らさない(§19のAdapter原則)。Adapterは
`fetch()`/`normalize()`/`validate()`/`store()`を分離する。

### CVEを持たない診断結果の扱い(§20A.2)

PownForgeの結果(設定不備、認可・認証の欠陥、手動exploitで確認した挙動、
アプリケーション固有の不具合等)は、Normalizerが次のいずれかに分類する:
(1)既知のVulnerability(CVE/CWE等)に対応付ける、(2)CVEを持たない
Vulnerabilityとして独自IDで登録する、(3)分類できない場合はConfidence
を下げたRawFindingとして保留する。分類できないことを理由に結果を
破棄しない。

### Confidenceとexploit intelligenceの分離(§20A.3)

PownForgeが成立を確認したことは`exploitation_observed`(実環境で攻撃
されているという外部観測)ではない。`exploit_exists`・
`exploitation_observed`・PownForgeによる成立確認は、別々の項目として
保持する(第9章)。手動exploitまたは攻撃シミュレーションで成立を確認
した場合のみ`confirmed`を検討できる。

### Evidenceの受け渡し(§20A.4)

PownForgeが生成したEvidenceは、コピーではなく参照と`content_hash`で
引き継ぐ。取り込み時にEvidenceを書き換えない。`content_hash`を検証し、
取り込み時点の内容が元のEvidenceと一致することを確認する。Evidenceに
含まれるCredential・トークン等のSecretは、保存・ログ出力の前に
マスクする(§31)。

### Remediationとの責務分離(§20A.5)

```text
PownForge  = 発見・検証のための攻撃側の能力
RiskForge  = 是正の計画・承認・実行管理・検証結果の記録
```

PownForgeはRemediationを実行しない。RiskForgeも攻撃的なテストを
Remediationの一部として実行しない。

### PownForgeを用いたVerification(§20A.6・§20A.6.1)

是正後にPownForgeが同じ診断を再実行して「もう成立しない」ことを確認する
方法を、Verificationの一種(`scanner_rescan`)として許可し得る。対象Asset
と実行範囲のallowlist、承認と実行の分離、production環境でのDry Run必須、
Audit Log記録を必須とする。診断が実行できなかった場合(接続不能・権限
不足等)は`inconclusive`とし、「成立しなかった」と混同しない。

### Idempotency・Audit(§20A.7・§20A.8)

同じPownForgeの結果を何度取り込んでも重複Findingを生成しない
(source + source_refで判定)。`pownforge_import`・
`pownforge_verification_approval`・`pownforge_verification_execution`を
Audit Log対象に加える。

### 共有語彙・スキーマの現状(本書§14.1、PownForge側`docs/handbook.md`§18.5/§18.6)

- PownForge側は2026-09-26、MITRE ATT&CK技術IDの語彙
  (`T1190`/`T1210`/`T1552.004`)を**PownForge側からの提案**として
  `docs/handbook.md`に確定した(PownForgeコミット`c8f7e93`)。本書§14.1
  に参照専用として記録済みだが、RiskForge側では未採用・未実装のまま
  である。
- PownForge側`Finding`は`cvss_score`/`cvss_vector`/`native_severity`
  (いずれもオプショナル、後方互換)を持つ(PownForge側指示書v3§3)。
  PownForge側`docs/handbook.md`§18.5が、これらと本書`RawFinding`
  (概念)との対応表を整理しているが、**`RawFinding`自体がRiskForge側で
  まだフィールドレベルで未実装**なため、対応表は概念レベルに留まる。
- どちらの語彙・スキーマも、Phase 5で`RawFinding`/Normalizerを実際に
  設計する時点で採用可否・保持場所をあらためて判断する。本ADRは
  これらの語彙案の存在を記録するのみで、採用を決定するものではない。

## 対象外(Phase 5着手時に別ADRで扱う)

本ADRはAGENTS.md §20Aが既に定めている制約の記録であり、以下は
一切決定しない(§20A.10「PownForge側の変更を要する場合は、別Taskとし、
ADRに記録する」を踏襲し、実装判断は着手時の別ADRに委ねる):

- `RawFinding`自体のGoの構造体定義・フィールドスキーマ
- PownForge向けAdapter(`fetch()`/`normalize()`/`validate()`/`store()`)
  の実装
- ATT&CK技術ID・CVSSフィールドをRiskForge側でどう保持するか(採用可否
  を含む)
- Normalizer/Matcherの分類ロジックの実装
- `scanner_rescan`の承認・allowlist・Dry Run・実行権限分離の実装
- HTTP API等、実際にPownForgeの結果を取り込む経路

## 影響

- コード変更は無い。本ADRはドキュメントのみの変更である。
- `docs/adr/`の欠番だった`0005`が埋まり、AGENTS.md §20A.10が要求する
  「連携仕様の重要な判断をADRとして残す」という前提が満たされる。
- 今後Phase 5でPownForge連携の実装に着手する場合、本ADRを出発点とし、
  「対象外」に挙げた各項目を新しいADRとして順次決定する。
- 本ADR単独では、PownForge連携の実装着手をユーザーに代わって承認しない
  (PownForge側Issue #15・本書§14.1が明記する制約を維持)。
