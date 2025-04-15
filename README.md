# scribe

ファイルを読み書きする際によく使う処理をまとめたライブラリです。
複数のエンコーディングを自動判別して読み込む機能や、UTF-8 での書き込みをサポートします。

## Installation

GitHub Packages からインストールする場合:

<!-- TODO -->

## Usage

```python
from scribe import FileScribe

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

## How to Contribute

貢献は大歓迎です！Issue の報告や Pull Request の作成をお待ちしています。

Issue を報告する際は、具体的な状況と再現手順を記載してください。
Pull Request を作成する際は、関連する Issue を参照し、変更内容を明確に記述してください。
コードスタイルは black と flake8 に準拠してください。

## License

MIT License

See the [LICENSE](LICENSE) file for details.

## Author

Seika139
