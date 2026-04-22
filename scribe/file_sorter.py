import re
from pathlib import Path


def get_matching_files(dir_path_str: str, regex: str) -> list[Path]:
    """正規表現に合致するファイルの Path 一覧を返す。

    Args:
        dir_path_str: 検索するディレクトリのパス。
        regex: ファイル名をマッチさせる正規表現。不正な場合は `re.error` が送出される。

    Returns:
        正規表現に合致する Path のリスト。見つからない場合は空。

    Raises:
        FileNotFoundError: 指定されたパスが存在しない場合。
        NotADirectoryError: 指定されたパスが存在するがディレクトリではない場合。
    """
    dir_path = Path(dir_path_str)
    if not dir_path.exists():
        msg = f"指定されたパス '{dir_path_str}' は存在しません。"
        raise FileNotFoundError(msg)
    if not dir_path.is_dir():
        msg = f"指定されたパス '{dir_path_str}' はディレクトリではありません。"
        raise NotADirectoryError(msg)
    pattern = re.compile(regex)

    return [
        entry
        for entry in dir_path.iterdir()
        if entry.is_file() and pattern.search(entry.name)
    ]


def sort_files_by_name(file_list: list[Path], reverse: bool = False) -> list[Path]:
    """指定された Path リストをファイル名で並べ替える。

    Args:
        file_list: 並べ替える Path オブジェクトのリスト。
        reverse: 降順で並べ替える場合は True (デフォルトは False)。

    Returns:
        ファイル名で並べ替えられた Path オブジェクトのリスト。
    """
    return sorted(file_list, key=lambda path: path.name, reverse=reverse)


def sort_files_by_mtime(file_list: list[Path], reverse: bool = False) -> list[Path]:
    """指定された Path リストを最終更新日で並べ替える。

    Args:
        file_list: 並べ替える Path オブジェクトのリスト。
        reverse: 新しい順 (降順) で並べ替える場合は True (デフォルトは False)。

    Returns:
        最終更新日で並べ替えられた Path オブジェクトのリスト。
    """
    return sorted(
        file_list, key=lambda path: Path(path).stat().st_mtime, reverse=reverse
    )
