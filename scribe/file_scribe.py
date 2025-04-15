from pathlib import Path


class FileScribe:
    """
    ファイルを読み書きするための基底クラス。
    Scribe は日本語で「書記官」を意味する。
    """

    def read(self, filepath: str | Path) -> None:
        """
        メジャーなエンコーディング（utf-8, shift_jis, ISO-8859-1）でファイルの読み込みを試す。
        ファイルが見つからない場合、エラーを投げる。
        読み込んだファイルの内容は self._content に格納される。

        Parameters
        ----------
        filepath : str | Path
            読み込むファイルのパス

        Raises
        ------
        FileNotFoundError
            ファイルが見つからない場合
        UnicodeDecodeError
            utf-8, shift_jis, or ISO-8859-1 のいずれのエンコーディングでもファイルを読み込めなかった場合
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
                "Unable to read the file with utf-8, shift_jis, or ISO-8859-1 encodings.",
            )

    def write(self, filepath: str | Path, content: str, append: bool = False) -> None:
        """
        filepath に content を utf-8 エンコーディングで書き込む。
        指定したファイルが存在しない場合、新規作成する。
        ファイルが存在する場合は上書きする。
        上書きではなく追記したい場合は append を True にする。

        Parameters
        ----------
        filepath : str | Path
            書き込むファイルのパス
        content : str
            書き込む内容
        append : bool, optional
            追記モードで書き込むかどうか, by default False
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
        """
        このインスタンスが扱うファイルのパスを返す。

        Returns
        -------
        Path
            ファイルのパス
        """
        if not hasattr(self, "_filepath"):
            raise ValueError("Attribute '_filepath' is not set.")
        return self._filepath

    @property
    def content(self) -> str:
        """
        読み込んだファイルの内容を文字列として返す。

        Returns
        -------
        str
            ファイルの内容
        """
        if not hasattr(self, "_content"):
            raise ValueError("Attribute '_content' is not set.")
        return self._content

    @property
    def encoding(self) -> str:
        """
        ファイルのエンコーディングを返す。

        Returns
        -------
        str
            ファイルのエンコーディング
        """
        if not hasattr(self, "_encoding"):
            raise ValueError("Attribute '_encoding' is not set.")
        return self._encoding
