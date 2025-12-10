# Implementation Plan - mise run check 警告修正

## Goal Description
`mise run check` コマンドを実行した際に発生する警告を解消する。
まず、エージェント環境で `mise` コマンドが正常に実行できない ("Current directory does not exist") 問題を調査・解決する。

## User Review Required
- エージェント環境での `run_command` の挙動について、ローカル環境との差異がある可能性があるため、ログ提供などを依頼する場合がある。

## Proposed Changes
### .github/scripts/
以下のスクリプトファイルに実行権限 (`chmod +x`) を付与する（Shebangを活用するため）。
- [MODIFY] [.github/scripts/determine_next_version.py](file:///Users/suzukikenichi/programs/scribe/.github/scripts/determine_next_version.py)
- [MODIFY] [.github/scripts/update_changelog.py](file:///Users/suzukikenichi/programs/scribe/.github/scripts/update_changelog.py)
- [MODIFY] [.github/scripts/update_pyproject_version.py](file:///Users/suzukikenichi/programs/scribe/.github/scripts/update_pyproject_version.py)

### scribe/ & tests/
パッケージコードおよびテストコードから Shebang 行 (`#!/usr/bin/env python3`) を削除する（直接実行ではなくモジュールとして、またはランナー経由で実行されるため）。

#### [MODIFY] scribe/
- `scribe/__init__.py`
- `scribe/file_scribe.py`
- `scribe/file_sorter.py`
- `scribe/zipper.py`

#### [MODIFY] tests/
- `tests/__init__.py`
- `tests/test_file_scribe.py`
- `tests/test_file_sorter.py`
- `tests/test_zipper.py`
  - `test_gitignore_case_sensitive` を `sys.platform` ではなく、実行時に動的にファイルシステムの大文字小文字区別を判定してスキップするように修正する。
  - 具体的には、一時ファイルを作成して大文字小文字違いの名前でアクセスできるかを確認する。

## Verification Plan
### Automated Tests
- `cd .. && cd scribe && mise run check` を実行し、`ruff`、`mypy`、`pytest` が全て成功することを確認する。
- 特に `EXE001` の警告が消えていること、かつ `test_gitignore_case_sensitive` が（スキップまたは成功で）落ちないことを確認する。

### Manual Verification
- ユーザーにローカル環境での動作確認を依頼する。
