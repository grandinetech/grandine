---
Description: セキュリティ監査コマンドのヘルプを表示します。
Usage: `/security`
Example: `/security`
Arguments: なし
---
# Security Agent Commands Help

利用可能なセキュリティ分析コマンドの一覧と使用方法です。

## 🛡️ 監査ワークフロー

### 標準的な監査フロー
1. `/01_spec <target_folder>` - プロジェクト仕様の理解
2. `/02_order <target_folder>` - 監査順序マップの生成
3. `/03_auditmap <target_folder>` - ソースコード監査の実施
4. `/04_review <target_folder>` - 監査結果のレビュー
5. `/05_poc_unit <args>` - ユニットテストPoCの作成
6. `/06_poc_integration <args>` - 統合テストPoCの作成
7. `/07_report <args>` - 最終レポートの生成

## 📋 コマンド一覧

### 01_spec - 仕様分析
- **説明**: プロジェクトの包括的な仕様書を生成
- **使用方法**: `/01_spec <target_folder>`
- **例**: `/01_spec ../contracts/docs`
- **出力**: `security-agent/outputs/01_SPEC.json`
- **内容**: アーキテクチャ、ユーザーフロー、API仕様、セキュリティ要件

### 02_order - 監査順序
- **説明**: 全関数の監査順序マップを生成
- **使用方法**: `/02_order <target_folder>`
- **例**: `/02_order ./core/`
- **出力**: `security-agent/outputs/02_ORDER.json`
- **内容**: 攻撃面から内部へのチャンク分け、トップ攻撃パス

### 03_auditmap - コード監査
- **説明**: ソースに@audit/@audit-ok注釈を追加し、脆弱性レポート生成
- **使用方法**: `/03_auditmap <target_folder>`
- **例**: `/03_auditmap ./core/`
- **入力**:
  - `security-agent/outputs/02_ORDER.json` (監査順序)
  - `security-agent/outputs/01_SPEC.json` (プロジェクト仕様)
  - `security-agent/docs/ethereum/spec_*.json` (Ethereum仕様)
  - `security-agent/docs/ethereum/bugs_*.json` (既知バグDB)
- **出力**:
  - ソースファイル内の`@audit`/`@audit-ok`注釈
  - `security-agent/outputs/03_AUDITMAP.json` (監査結果)
  - `security-agent/outputs/02_ORDER.json` (review_count更新)

### 04_review - レビュー
- **説明**: 監査結果の深層レビューと検証
- **使用方法**: `/04_review <target_folder>`
- **例**: `/04_review ./core/`
- **出力**: `security-agent/outputs/04_REVIEW.json`

### 05_poc_unit - ユニットテストPoC
- **説明**: 脆弱性のユニットテストPoCを生成
- **使用方法**: `/05_poc_unit <vuln_name> <snippet> <file:line> <output_file>`
- **例**: `/05_poc_unit Reentrancy "call{value: amount}();" core/vm/evm.go:L234 poc_reentrancy.go`
- **出力**: 指定されたPoCファイル

### 06_poc_integration - 統合テストPoC
- **説明**: 統合テスト環境でのPoCを生成
- **使用方法**: `/06_poc_integration <unit_poc> <it_path> <vuln_name>`
- **例**: `/06_poc_integration poc_reentrancy.go tests/poc_reentrancy_test.go Reentrancy`
- **出力**: 統合テストファイル

### 07_report - Bug Bountyレポート
- **説明**: 発見した脆弱性の詳細レポートを生成
- **使用方法**: `/07_report <vuln_name> <snippet> <file> <poc_file>`
- **例**: `/07_report Reentrancy "call{value: amount}();" evm.go poc_reentrancy.go`
- **出力**: `security-agent/outputs/07_REPORT_<vuln_name>.md`

## 📁 出力ファイル構造

```
security-agent/
├── outputs/
│   ├── 01_SPEC.json              # プロジェクト仕様
│   ├── 02_ORDER.json             # 監査順序マップ
│   ├── 03_AUDITMAP.json          # 監査結果マップ
│   ├── 04_REVIEW.json            # レビュー結果
│   ├── 05_POC_*.go               # ユニットテストPoC
│   ├── 06_POC_*.go               # 統合テストPoC
│   └── 07_REPORT_*.md            # Bug Bountyレポート
└── docs/
    └── ethereum/
        ├── spec_*.json           # Ethereum仕様
        └── bugs_*.json           # 既知バグデータベース
```

## 📝 注釈フォーマット

```go
// @audit <category>: <short description>
// ↳ <detailed multi-line explanation if needed>

// @audit-ok: <reason why safe>
```

## ⚙️ 各コマンドの詳細

### 監査順序の決定方法
- 信頼境界の外側から内側へ
- ネットワーク入力 → 暗号検証 → 状態変更 → ユーティリティ
- チャンクあたり最大12関数

### 監査アルゴリズム
1. `02_ORDER.json`から`review_count`が最も低い関数を選択
2. 既存の`@audit`/`@audit-ok`はスキップ
3. 仕様とバグDBとのパターンマッチング
4. 脆弱性の分類と注釈の追加
5. `03_AUDITMAP.json`への記録
6. `review_count`のインクリメント

---

このヘルプを表示するには: `/security`