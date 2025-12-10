#!/usr/bin/env python3
from pathlib import Path


class FileScribe:
    """ファイルを読み書きするための基底クラス。

    Scribe は日本語で「書記官」を意味する。
    """

    def read(self, filepath: str | Path) -> None:
        """複数エンコーディング(utf-8/shift_jis/ISO-8859-1)で読み込みを試行する。

        読み込めた内容を `self._content` に格納し、失敗時は例外を送出する。

        Args:
            filepath: 読み込むファイルのパス

        Raises:
            FileNotFoundError: ファイルが見つからない場合
            UnicodeDecodeError: いずれのエンコーディングでも読み込めなかった場合
        """
        if isinstance(filepath, str):
            filepath = Path(filepath)
        filepath = filepath.resolve()

        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        self._filepath: Path = filepath

        # よく使われるエンコードでファイルの読み込みを試す
        encodings = ["utf-8", "utf-8-sig", "shift_jis", "ISO-8859-1"]
        for encoding in encodings:
            try:
                with self._filepath.open("r", encoding=encoding) as file:
                    self._content: str = file.read()
                    self._encoding: str = encoding
                    break
            except UnicodeDecodeError as e:
                print(f"Failed to read the file with encoding: {encoding}")
                last_exception = e
                continue  # 次のエンコーディングを試す
        else:
            # 全てのエンコーディングで失敗した場合エラーを投げる
            # 必要な属性を持つ例外を投げるとエラーの詳細を保持する
            raise UnicodeDecodeError(
                (
                    last_exception.encoding
                    if isinstance(last_exception, UnicodeDecodeError)
                    else "unknown"
                ),
                (
                    last_exception.object
                    if isinstance(last_exception, UnicodeDecodeError)
                    else b""
                ),
                (
                    last_exception.start
                    if isinstance(last_exception, UnicodeDecodeError)
                    else -1
                ),
                (
                    last_exception.end
                    if isinstance(last_exception, UnicodeDecodeError)
                    else -1
                ),
                (
                    "Unable to read the file with utf-8, shift_jis, or "
                    "ISO-8859-1 encodings."
                ),
            )

    def write(self, filepath: str | Path, content: str, append: bool = False) -> None:
        """内容をUTF-8で書き込む。append=True なら追記モード。

        Args:
            filepath: 書き込み先のパス
            content: 書き込むテキスト
            append: 追記モードにする場合は True
        """
        if isinstance(filepath, str):
            filepath = Path(filepath)
        filepath = filepath.resolve()
        if not filepath.parent.exists():
            filepath.parent.mkdir(parents=True, exist_ok=True)
        self._filepath = filepath
        mode = "a" if append else "w"
        self._encoding = "utf-8"
        with self._filepath.open(mode, encoding=self._encoding) as file:
            file.write(content)
        self._content = content

    @property
    def filepath(self) -> Path:
        """このインスタンスが扱うファイルのパスを返す。

        Returns:
            Path: ファイルのパス

        Raises:
            ValueError: まだパスが設定されていない場合
        """
        if not hasattr(self, "_filepath"):
            raise ValueError("Attribute '_filepath' is not set.")
        return self._filepath

    @property
    def content(self) -> str:
        """読み込んだファイルの内容を文字列として返す。

        Returns:
            str: ファイルの内容

        Raises:
            ValueError: まだ内容が設定されていない場合
        """
        if not hasattr(self, "_content"):
            raise ValueError("Attribute '_content' is not set.")
        return self._content

    @property
    def encoding(self) -> str:
        """ファイルのエンコーディングを返す。

        Returns:
            str: ファイルのエンコーディング

        Raises:
            ValueError: まだエンコーディングが設定されていない場合
        """
        if not hasattr(self, "_encoding"):
            raise ValueError("Attribute '_encoding' is not set.")
        return self._encoding
