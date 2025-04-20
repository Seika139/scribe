import os
import re
from pathlib import Path


def get_matching_files(dir_path_str: str, regex: str) -> list[Path]:
    """
    指定されたディレクトリパス内の、特定の正規表現に合致するファイルの Path オブジェクトのリストを取得します。

    Args:
        dir_path_str: 検索するディレクトリのパス (文字列)。
        regex: ファイル名をマッチさせる正規表現 (文字列)。

    Returns:
        正規表現に合致するファイルの Path オブジェクトのリスト。
        ファイルが見つからない場合は空のリストを返します。
    """
    dir_path = Path(dir_path_str)
    if not dir_path.is_dir():
        print(f"エラー: 指定されたパス '{dir_path_str}' はディレクトリではありません。")
        return []

    matching_files = [
        entry
        for entry in dir_path.iterdir()
        if entry.is_file() and re.search(regex, entry.name)
    ]
    return matching_files


def sort_files_by_name(file_list: list[Path], reverse: bool = False) -> list[Path]:
    """
    指定された Path オブジェクトのリストをファイル名で並べ替えます。

    Args:
        file_list: 並べ替える Path オブジェクトのリスト。
        reverse: 降順で並べ替える場合は True (デフォルトは False)。

    Returns:
        ファイル名で並べ替えられた Path オブジェクトのリスト。
    """
    return sorted(file_list, key=lambda path: path.name, reverse=reverse)


def sort_files_by_mtime(file_list: list[Path], reverse: bool = False) -> list[Path]:
    """
    指定された Path オブジェクトのリストをファイルの最終更新日で並べ替えます。

    Args:
        file_list: 並べ替える Path オブジェクトのリスト。
        reverse: 新しい順 (降順) で並べ替える場合は True (デフォルトは False)。

    Returns:
        最終更新日で並べ替えられた Path オブジェクトのリスト。
    """
    return sorted(file_list, key=lambda path: os.path.getmtime(path), reverse=reverse)


if __name__ == "__main__":
    # テスト用のディレクトリとファイルを作成
    test_dir = Path("./test_files")
    test_dir.mkdir(exist_ok=True)
    (test_dir / "image1.png").touch()
    (test_dir / "data_20231026.txt").touch()
    (test_dir / "log_20231027.log").touch()
    (test_dir / "image2.jpeg").touch()
    (test_dir / "backup_20231025.zip").touch()

    # 正規表現に合致するファイルを取得 (例: "image" を含むファイル)
    matching_images = get_matching_files(str(test_dir), r"image\d+\.(png|jpeg)")
    print("正規表現に合致するファイル:")
    for file in matching_images:
        print(file)

    # ファイル名で並べ替え
    sorted_by_name = sort_files_by_name(matching_images)
    print("\nファイル名で並べ替え:")
    for file in sorted_by_name:
        print(file)

    # ファイル名で降順に並べ替え
    sorted_by_name_desc = sort_files_by_name(matching_images, reverse=True)
    print("\nファイル名で降順に並べ替え:")
    for file in sorted_by_name_desc:
        print(file)

    # 最終更新日で並べ替え
    sorted_by_mtime = sort_files_by_mtime(matching_images)
    print("\n最終更新日で並べ替え:")
    for file in sorted_by_mtime:
        print(file)

    # 最終更新日で降順に並べ替え (新しい順)
    sorted_by_mtime_desc = sort_files_by_mtime(matching_images, reverse=True)
    print("\n最終更新日で降順に並べ替え (新しい順):")
    for file in sorted_by_mtime_desc:
        print(file)

    # テスト用のディレクトリとファイルを削除 (必要に応じてコメントアウト)
    import shutil

    shutil.rmtree(test_dir)
