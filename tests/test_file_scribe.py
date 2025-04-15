from pathlib import Path

import pytest

from scribe.file_scribe import FileScribe


def test_read_success(tmp_path: Path) -> None:
    test_file: Path = tmp_path / "test.txt"
    test_file.write_text("This is a test.", encoding="utf-8")
    scribe = FileScribe()
    scribe.read(test_file)
    assert scribe.content == "This is a test."
    assert scribe.encoding == "utf-8"
    assert scribe.filepath == test_file


def test_read_file_not_found() -> None:
    scribe = FileScribe()
    with pytest.raises(FileNotFoundError):
        scribe.read("non_existent_file.txt")


def test_read_encoding_fallback(tmp_path: Path) -> None:
    test_file: Path = tmp_path / "test_sjis.txt"
    test_file.write_text("これはShift-JISのテストです。", encoding="shift_jis")
    scribe = FileScribe()
    scribe.read(test_file)
    assert scribe.content == "これはShift-JISのテストです。"
    assert scribe.encoding == "shift_jis"


def test_write_success(tmp_path: Path) -> None:
    test_file: Path = tmp_path / "output.txt"
    scribe = FileScribe()
    content_to_write = "This will be written."
    scribe.write(test_file, content_to_write)
    assert test_file.read_text(encoding="utf-8") == content_to_write
    assert scribe.content == content_to_write
    assert scribe.filepath == test_file
    assert scribe.encoding == "utf-8"


def test_write_append(tmp_path: Path) -> None:
    test_file: Path = tmp_path / "append.txt"
    test_file.write_text("Initial content.", encoding="utf-8")
    scribe = FileScribe()
    scribe.write(test_file, " Appended content.", append=True)
    assert test_file.read_text(encoding="utf-8") == "Initial content. Appended content."


def test_filepath_property_not_set() -> None:
    scribe = FileScribe()
    with pytest.raises(ValueError, match="Attribute '_filepath' is not set."):
        _ = scribe.filepath


def test_content_property_not_set() -> None:
    scribe = FileScribe()
    with pytest.raises(ValueError, match="Attribute '_content' is not set."):
        _ = scribe.content


def test_encoding_property_not_set() -> None:
    scribe = FileScribe()
    with pytest.raises(ValueError, match="Attribute '_encoding' is not set."):
        _ = scribe.encoding
