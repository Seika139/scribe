# scribe

ファイルを読み書きする際によく使う処理をまとめたライブラリです。
複数のエンコーディングを自動判別して読み込む機能や、UTF-8 での書き込みをサポートします。

<!-- markdownlint-disable MD033 -->

<div align="center">
  <a href="./LICENSE">
    <img alt="LICENSE" src="https://img.shields.io/badge/license-MIT-blue.svg">
  </a>
  <a href="https://github.com/Seika139/scribe/actions/workflows/ci.yml">
    <img alt="CI" src="https://github.com/Seika139/scribe/actions/workflows/ci.yml/badge.svg">
  </a>
  <a href="https://github.com/Seika139/scribe/releases/tag/v0.2.1">
    <img alt="version" src="https://img.shields.io/badge/version-v0.2.1-white.svg">
  </a>
</div>

## Installation

poetry を利用してこのパッケージを利用する場合は以下のコマンドを実行してください。

```bash
poetry add git+https://github.com/Seika139/scribe.git
```

特定のバージョンやコミットを指定してインストールすることも可能です。

```bash
# 特定のバージョンを指定する場合
poetry add git+https://github.com/Seika139/scribe.git@v0.2.1
# 特定のコミットを指定する場合
poetry add git+https://github.com/Seika139/scribe.git@<commit_hash>
```

## Usage

```python
from scribe.file_scribe import FileScribe

# ファイルを読み込む場合
file_scribe = FileScribe().read("path/to/file.txt")
# ここで、path/to/file.txt は実在するファイルで
# エンコーディングが utf-8, shift_jis, ISO-8859-1 のいずれかである必要があります。

# ファイルに書き込む場合
file_scribe = FileScribe().write(
    filepath="path/to/file.txt",
    content="Hello, World!",
)
# ここで、path/to/file.txt は書き込み先のファイルパスで、存在しない場合は新規作成されます。
# エンコーディングは自動的に utf-8 になります。
# ファイル内容は自動的に上書きされます。
# 上書きではなく、追記したい場合は、append=True を指定します。
file_scribe = FileScribe().write(
    filepath="path/to/file.txt",
    content="Hello, World!",
    append=True,
)

# プロパティ
print(file_scribe.filepath) # ファイルのパスを返します (Path)
print(file_scribe.encoding) # ファイルのエンコーディングを返します (str)
print(file_scribe.content) # ファイルの内容を返します (str)
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

GitHub のタグを利用して、リリースの履歴を管理しています。

## For Developers

See [DEVELOPMENT.md](DEVELOPMENT.md).

## How to Contribute

貢献は大歓迎です！Issue の報告や Pull Request の作成をお待ちしています。

Issue を報告する際は、具体的な状況と再現手順を記載してください。
Pull Request を作成する際は、関連する Issue を参照し、変更内容を明確に記述してください。

## Author

[Seika139](https://github.com/Seika139)
