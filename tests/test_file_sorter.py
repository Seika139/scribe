#!/usr/bin/env python3
import os
from pathlib import Path

import pytest

from scribe.file_sorter import (
    get_matching_files,
    sort_files_by_mtime,
    sort_files_by_name,
)


@pytest.fixture
def test_directory(tmp_path: Path) -> Path:
    """テスト用のディレクトリとファイルを作成するフィクスチャ。

    Returns:
        Path: 作成したディレクトリのパス
    """
    test_dir = tmp_path / "test_files"
    test_dir.mkdir()

    def _set_file_times(path: Path, atime: float, mtime: float) -> None:
        path.touch()
        os.utime(str(path), (atime, mtime))  # Path オブジェクトを文字列に変換

    _set_file_times(test_dir / "image1.png", 1666876800, 1666876800)  # 2022-10-27
    _set_file_times(
        test_dir / "data_20231026.txt", 1698259200, 1698259200
    )  # 2023-10-26
    _set_file_times(test_dir / "log_20231027.log", 1698345600, 1698345600)  # 2023-10-27
    _set_file_times(test_dir / "image2.jpeg", 1666963200, 1666963200)  # 2022-10-28
    _set_file_times(
        test_dir / "backup_20231025.zip", 1698172800, 1698172800
    )  # 2023-10-25
    (test_dir / "other_file").mkdir()  # ディレクトリも作成してテスト
    return test_dir


def test_get_matching_files(test_directory: Path) -> None:
    """get_matching_files 関数のテスト"""
    matching_images = get_matching_files(str(test_directory), r"image\d+\.(png|jpeg)")
    assert len(matching_images) == 2
    assert any(file.name == "image1.png" for file in matching_images)
    assert any(file.name == "image2.jpeg" for file in matching_images)
    assert all(file.is_file() for file in matching_images)

    matching_logs = get_matching_files(str(test_directory), r"\.log$")
    assert len(matching_logs) == 1
    assert matching_logs[0].name == "log_20231027.log"

    matching_none = get_matching_files(str(test_directory), r"\.csv$")
    assert len(matching_none) == 0

    # 存在しないディレクトリを指定した場合
    non_existent_dir = test_directory / "non_existent"
    result = get_matching_files(str(non_existent_dir), r".*")
    assert len(result) == 0
    # エラーメッセージの出力を捕捉してテストすることも可能ですが、ここでは割愛します


def test_sort_files_by_name(test_directory: Path) -> None:
    """sort_files_by_name 関数のテスト"""
    files_to_sort = [
        test_directory / "file_c.txt",
        test_directory / "file_a.txt",
        test_directory / "file_b.txt",
    ]
    for file in files_to_sort:
        file.touch()

    sorted_files_asc = sort_files_by_name(files_to_sort)
    assert [f.name for f in sorted_files_asc] == [
        "file_a.txt",
        "file_b.txt",
        "file_c.txt",
    ]

    sorted_files_desc = sort_files_by_name(files_to_sort, reverse=True)
    assert [f.name for f in sorted_files_desc] == [
        "file_c.txt",
        "file_b.txt",
        "file_a.txt",
    ]


def test_sort_files_by_mtime(test_directory: Path) -> None:
    """sort_files_by_mtime 関数のテスト"""
    file1 = test_directory / "file1.txt"
    file2 = test_directory / "file2.txt"
    file3 = test_directory / "file3.txt"

    def _set_file_times(path: Path, atime: float, mtime: float) -> None:
        path.touch()
        os.utime(str(path), (atime, mtime))  # Path オブジェクトを文字列に変換

    _set_file_times(file1, 1698000000, 1698000000)  # 古い
    _set_file_times(file2, 1698100000, 1698100000)
    _set_file_times(file3, 1698200000, 1698200000)  # 新しい

    files_to_sort = [file1, file2, file3]

    sorted_files_asc = sort_files_by_mtime(files_to_sort)
    assert [f.name for f in sorted_files_asc] == ["file1.txt", "file2.txt", "file3.txt"]

    sorted_files_desc = sort_files_by_mtime(files_to_sort, reverse=True)
    assert [f.name for f in sorted_files_desc] == [
        "file3.txt",
        "file2.txt",
        "file1.txt",
    ]
