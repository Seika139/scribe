# Changelog

<!-- Markdownlint-disable MD024 -->

このプロジェクトの注目すべき変更はこのファイルで文書化されています。

フォーマットは [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) に基づいており、
このプロジェクトは [セマンティック バージョニング](https://semver.org/lang/ja/spec/v2.0.0.html) を遵守しています。

## [0.2.1] - 2025-04-24

### 追加

- .gitignore ファイルの読み込み機能を追加し、圧縮時に除外ルールを適用
- テストケース: .gitignore のパターンマッチングのテストを追加

### 改善

- エラーハンドリングを強化:
  - 不正なファイルパスの検証を追加
  - パスワード不一致時のエラーメッセージを改善
  - 暗号化/復号化失敗時の一時ファイルの自動クリーンアップを実装

### ドキュメント

- README.md にバージョン情報とインストール手順を追加

## [0.2.0] - 2025-04-23

### 追加

- 暗号化を使用したセキュアなファイル圧縮・解凍機能を実装
- 暗号化キー生成関数のテストケースを追加

### 変更

- 関数の引数フォーマットを改善し、コードの可読性を向上
- test-local ターゲットで pytest の詳細出力オプションを追加

## [0.1.1] - 2025-04-21

### 追加

- file_sorter.py: ファイルの検索と並べ替え機能を実装
- Docker 環境のセットアップ:
  - 複数の Python バージョン（3.10-3.13）に対応したテスト環境
  - Docker Compose による環境構築の自動化
- Makefile を追加し、テストとフォーマット実行を統一化
- エディタ設定:
  - .editorconfig による改行コードの統一
  - .gitattributes による行末の設定統一

### 変更

- CI: actions/setup-python を v5 に更新
- DEVELOPMENT.md: 推奨パッケージセクションを追加

## [0.1.0] - 2025-04-16

### 追加

- FileScribe クラス: 複数エンコーディングに対応したファイル読み書き機能
- CI/CD:
  - GitHub Actions ワークフローの設定
  - Python 3.10-3.13 での自動テスト実行
- プロジェクトドキュメント:
  - README.md: インストール手順、使用例、貢献方法
  - DEVELOPMENT.md: 開発者向けガイドライン
  - ライセンスバッジと CI バッジの追加

### 変更

- Poetry によるプロジェクト管理の導入
- 依存関係の更新: flake8-pyproject の追加
- Python バージョン要件を 3.10 以上に更新

### 修正

- README.md のインストール手順とリポジトリ URL を修正
- CI ワークフローのアクションバージョンを v4 に更新

[0.2.1]: https://github.com/Seika139/scribe/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Seika139/scribe/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Seika139/scribe/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Seika139/scribe/releases/tag/v0.1.0
