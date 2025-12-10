#!/usr/bin/env python3
import re
from pathlib import Path


def get_matching_files(dir_path_str: str, regex: str) -> list[Path]:
    """正規表現に合致するファイルの Path 一覧を返す。

    Args:
        dir_path_str: 検索するディレクトリのパス。
        regex: ファイル名をマッチさせる正規表現。

    Returns:
        正規表現に合致する Path のリスト。見つからない場合は空。
    """
    dir_path = Path(dir_path_str)
    if not dir_path.is_dir():
        print(f"エラー: 指定されたパス '{dir_path_str}' はディレクトリではありません。")
        return []

    return [
        entry
        for entry in dir_path.iterdir()
        if entry.is_file() and re.search(regex, entry.name)
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
