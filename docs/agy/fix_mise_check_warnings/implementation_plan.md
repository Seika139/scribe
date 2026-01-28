# 実装計画: `mise run check` の警告修正

`mise run check` (ruff, mypy, ty, vulture, pytest, yamllint) で報告された警告を修正し、静的解析をパスするようにします。

## 提案される変更

### 1. [MODIFY] [file_scribe.py](file:///Users/suzukikenichi/programs/scribe/scribe/file_scribe.py)

- `read` メソッド内で `last_exception` が未定義のまま参照される可能性があるため、ループ前に `None` で初期化します。
- `UnicodeDecodeError` を再送出する際、`last_exception` が `None` の場合のフォールバックを強化します。

### 2. [MODIFY] [zipper.py](file:///Users/suzukikenichi/programs/scribe/scribe/zipper.py)

- `pathspec.PathSpec.from_lines(GitWildMatchPattern, f)` を `pathspec.PathSpec.from_lines("gitignore", f)` に変更します。
- これにより、`GitWildMatchPattern` の非推奨警告と、`ty` による型エラーの両方を解決します。
- 不要になった `from pathspec.patterns.gitwildmatch import GitWildMatchPattern` のインポートを削除し、型ヒントを `pathspec.patterns.GitIgnorePattern` (または単に `Any`) に調整します。

### 3. YAML ファイルの修正

各 YAML ファイルに `---` を追加し、`yamllint` の警告に対応します。

#### [MODIFY] [compose.yml](file:///Users/suzukikenichi/programs/scribe/Docker/compose.yml)

- `---` を追加。

#### [MODIFY] [dependabot.yml](file:///Users/suzukikenichi/programs/scribe/.github/dependabot.yml)

- `---` を追加。

#### [MODIFY] [update-version.yml](file:///Users/suzukikenichi/programs/scribe/.github/workflows/update-version.yml)

- `---` を追加。
- `truthy` 警告への対応 (boolean 値の修正)。

#### [MODIFY] [lint-markdown.yml](file:///Users/suzukikenichi/programs/scribe/.github/workflows/lint-markdown.yml)

- `---` を追加。
- `truthy` 警告への対応。

#### [MODIFY] [uv-qualify.yml](file:///Users/suzukikenichi/programs/scribe/.github/workflows/uv-qualify.yml)

- `---` を追加。
- `truthy` 警告への対応。
- コメント前のスペース不足を修正。

## 修正内容の確認

### 自動テスト

- `mise run check` を実行し、すべてのツール (ruff, mypy, ty, vulture, pytest, yamllint) が警告なしでパスすることを確認します。
- 特に `pytest` で `DeprecationWarning` が消えていることを確認します。
